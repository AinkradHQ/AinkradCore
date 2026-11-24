//! Ends `ainkrad-ptyhost` processes this runner no longer tracks: ones whose terminal has no
//! record or socket in the terminals directory. Nobody can reach such a host to close it, and it
//! would hold its shell forever (seen: 142 of them, 2 days old, for 1 registered terminal).
//! Only our own uid, only this `--dir`, only older than `MIN_AGE`, and by exact pid.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// A host being started has no files for a moment: younger ones are left alone.
pub const MIN_AGE: Duration = Duration::from_secs(60);

/// `[[dd-]hh:]mm:ss` (ps `etime`) in seconds.
fn etime(s: &str) -> Option<u64> {
    let (days, rest) = s
        .split_once('-')
        .map_or((0, s), |(d, r)| (d.parse().unwrap_or(0), r));
    let mut secs = 0u64;
    for part in rest.split(':') {
        secs = secs * 60 + part.parse::<u64>().ok()?;
    }
    Some(days * 86_400 + secs)
}

/// Pids in a `ps -axww -o pid=,uid=,etime=,command=` table that are our hosts for `dir`, older
/// than `min_age`, whose id is not in `tracked`.
fn strays(table: &str, uid: u32, dir: &Path, tracked: &HashSet<String>, min_age: u64) -> Vec<u32> {
    let dir = dir.to_string_lossy();
    table
        .lines()
        .filter_map(|line| {
            let mut rest = line.trim_start();
            let mut field = || {
                let (head, tail) = rest.split_once(char::is_whitespace)?;
                rest = tail.trim_start();
                Some(head)
            };
            let pid: u32 = field()?.parse().ok()?;
            let owner: u32 = field()?.parse().ok()?;
            let age = etime(field()?)?;
            let cmd = rest;
            let (bin, rest) = cmd.split_once(" serve --dir ")?;
            let (host_dir, id) = rest.rsplit_once(" --id ")?;
            let ours = bin.trim_end().ends_with("ainkrad-ptyhost") && host_dir == dir;
            (owner == uid
                && ours
                && ainkrad_ptyhost::wire::valid_id(id)
                && age >= min_age
                && !tracked.contains(id))
            .then_some(pid)
        })
        .collect()
}

/// The ids that have a record or a socket in `dir`.
fn tracked(dir: &Path) -> HashSet<String> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let id = name.split('.').next()?;
            (name.ends_with(".json") || name.ends_with(".sock")).then(|| id.to_owned())
        })
        .collect()
}

/// Ends the stray hosts of `dir` (SIGTERM, to the exact pid); returns how many.
pub fn sweep(dir: &Path, min_age: Duration) -> usize {
    let Ok(out) = Command::new("ps")
        .args(["-axww", "-o", "pid=,uid=,etime=,command="])
        .output()
    else {
        return 0;
    };
    let table = String::from_utf8_lossy(&out.stdout);
    let found = strays(
        &table,
        ainkrad_sys::getuid(),
        dir,
        &tracked(dir),
        min_age.as_secs(),
    );
    for pid in &found {
        tracing::warn!(pid, "ending a terminal host this runner no longer tracks");
        let _ = ainkrad_sys::kill_pid(*pid, 15);
    }
    found.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = "/home/u/.r/terminals";

    #[test]
    fn only_old_untracked_hosts_of_this_dir_and_user_are_picked() {
        let table = format!(
            "  10 501 2-03:04:05 /app/ainkrad-ptyhost serve --dir {DIR} --id t_aaaaaaaaaaaaaaaa\n\
             11 501 2-03:04:05 /app/ainkrad-ptyhost serve --dir {DIR} --id t_bbbbbbbbbbbbbbbb\n\
             12 501 00:05 /app/ainkrad-ptyhost serve --dir {DIR} --id t_cccccccccccccccc\n\
             13 502 2-03:04:05 /app/ainkrad-ptyhost serve --dir {DIR} --id t_dddddddddddddddd\n\
             14 501 2-03:04:05 /app/ainkrad-ptyhost serve --dir /other --id t_eeeeeeeeeeeeeeee\n\
             15 501 2-03:04:05 /bin/zsh -l\n"
        );
        let tracked = HashSet::from(["t_bbbbbbbbbbbbbbbb".to_owned()]);
        assert_eq!(strays(&table, 501, Path::new(DIR), &tracked, 60), [10]);
    }

    #[test]
    fn the_sweep_ends_an_untracked_host_and_keeps_a_tracked_one() {
        let root = std::path::PathBuf::from(format!("/tmp/sw-{}", std::process::id()));
        let dir = root.join("t");
        std::fs::create_dir_all(&dir).unwrap();
        // Stand-ins named like the host, so `ps` shows `<script> serve --dir <dir> --id <id>`.
        let bin = root.join("ainkrad-ptyhost");
        std::fs::write(&bin, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let start = |id: &str| {
            Command::new(&bin)
                .args(["serve", "--dir"])
                .arg(&dir)
                .args(["--id", id])
                .spawn()
                .unwrap()
        };
        let (mut lost, mut kept) = (start("t_1111111111111111"), start("t_2222222222222222"));
        std::fs::write(dir.join("t_2222222222222222.json"), "{}").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(sweep(&dir, Duration::ZERO), 1);
        assert!(lost.wait().is_ok_and(|s| !s.success()));
        assert!(kept.try_wait().unwrap().is_none());
        kept.kill().unwrap();
        let _ = kept.wait();
        let _ = std::fs::remove_dir_all(&root);
    }
}
