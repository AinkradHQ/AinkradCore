//! RAII cleanup for real PTY integration tests, including panic paths.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct TestDir(pub PathBuf);
impl std::ops::Deref for TestDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}
impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Append host and terminal process groups before the test makes any assertions.
pub fn register(dir: &Path, host: u32, child: Option<u32>) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("test-pids"))
        .unwrap();
    writeln!(f, "{host} {}", child.unwrap_or(0)).unwrap();
}

fn kill(pid: u32, group: bool) {
    if pid <= 1 || pid == std::process::id() {
        return;
    }
    let id = if group {
        format!("-{pid}")
    } else {
        pid.to_string()
    };
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
impl Drop for TestDir {
    fn drop(&mut self) {
        // Hosts that were launched by the stand-in runner have records even on a failed test.
        if let Ok(entries) = std::fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                if entry.path().extension().is_some_and(|e| e == "out")
                    && let Ok(text) = std::fs::read_to_string(entry.path())
                    && let Some(json) = text.lines().next().and_then(|s| s.strip_prefix("ready "))
                    && let Ok(info) = serde_json::from_str::<ainkrad_ptyhost::wire::HostInfo>(json)
                {
                    kill(info.child.unwrap_or(0), true);
                    kill(info.pid, false);
                }
            }
        }
        for dir in [&self.0, &self.0.join("t")] {
            if let Ok(pids) = std::fs::read_to_string(dir.join("test-pids")) {
                for line in pids.lines() {
                    let ids = line
                        .split_whitespace()
                        .filter_map(|n| n.parse::<u32>().ok())
                        .collect::<Vec<_>>();
                    if ids.len() == 2 {
                        kill(ids[1], true);
                        kill(ids[0], false);
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[allow(dead_code)]
pub struct ChildGuard(pub Child);
impl std::ops::Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
