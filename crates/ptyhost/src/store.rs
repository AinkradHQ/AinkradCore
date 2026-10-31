//! The on-disk scrollback ring of one terminal (E2-04.3, E2-06.2).
//!
//! - **What it holds.** Only the terminal's OUTPUT, as the PTY produced it, never input. (A
//!   shell that echoes typed text prints it, so typed text can come back as output: that is
//!   the terminal's own output, not a copy of the input path.) It is not redacted (decision
//!   P2.11: terminal bytes are transport-only and the Core never stores them; the host's disk
//!   is the one place they rest, in a `0700` directory of the runner's user).
//! - **Shape.** Two generation files, `<id>.<n>.ring` (`0600`, created exclusively, so a
//!   planted file or symlink is refused). Writes go to the newest. When it holds half the cap,
//!   a new one starts and the older of the previous two is deleted: a terminal's disk use is
//!   bounded by its cap (plus one record), nothing is rewritten, and what was dropped is
//!   explicit: the oldest retained `seq` moves forward and a resume before it gets a snapshot.
//! - **Crash safety.** A file is a header (magic, the `seq` of its first byte) and records
//!   `len, crc32, payload`. A reader stops at the first short or corrupt record, so a torn
//!   tail (a crash mid-write) is detected and dropped, and `open` truncates it.
//! - **Failure.** A write error (a full disk) is returned; the host drops the disk ring for
//!   that terminal and serves from memory, so one terminal's disk trouble touches nobody else.
//! - **Deleting.** `destroy` truncates and unlinks. That is deletion, not a secure erase: the
//!   blocks may remain on the device until reused.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"AKRING01";
const HEAD: usize = 16;
const REC: usize = 8;
/// The largest record: output arrives from the PTY in reads of at most this much.
const PIECE: usize = 64 * 1024;

/// The bounds of a terminal's disk cap. The floor keeps a generation (half the cap) larger
/// than one record.
pub const CAP_MIN: u64 = 256 << 10;
pub const CAP_MAX: u64 = 64 << 20;
pub const CAP_DEFAULT: u64 = 8 << 20;

/// The path of generation `n` of terminal `id` in `dir`.
pub fn ring_path(dir: &Path, id: &str, n: u64) -> PathBuf {
    dir.join(format!("{id}.{n}.ring"))
}

/// `(terminal id, generation)` when `name` is a ring file's name.
pub fn parse_name(name: &str) -> Option<(&str, u64)> {
    let stem = name.strip_suffix(".ring")?;
    let (id, n) = stem.rsplit_once('.')?;
    Some((id, n.parse().ok()?))
}

const fn table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC: [u32; 256] = table();

/// CRC-32 (IEEE) of `b`.
pub fn crc32(b: &[u8]) -> u32 {
    !b.iter().fold(!0u32, |c, x| {
        CRC[usize::from((c ^ u32::from(*x)) as u8)] ^ (c >> 8)
    })
}

/// One generation: the file `n`, the `seq` of its first byte, the `seq` after its last, and its
/// size on disk.
#[derive(Clone, Copy, Debug)]
struct Gen {
    n: u64,
    start: u64,
    end: u64,
    len: u64,
}

/// A generation read back: its payload and how many bytes of the file were valid.
struct Read {
    start: u64,
    payload: Vec<u8>,
    valid: u64,
}

/// Reads a generation file, stopping at the first short or corrupt record. `None` when the
/// file is missing or its header is not ours.
fn read_gen(path: &Path) -> Option<Read> {
    // A symlink or other non-file under a ring's name is never followed.
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    let b = std::fs::read(path).ok()?;
    if b.len() < HEAD || &b[..8] != MAGIC {
        return None;
    }
    let start = u64::from_le_bytes(b[8..16].try_into().ok()?);
    let (mut at, mut payload) = (HEAD, Vec::new());
    while b.len() - at >= REC {
        let len = u32::from_le_bytes(b[at..at + 4].try_into().ok()?) as usize;
        let crc = u32::from_le_bytes(b[at + 4..at + 8].try_into().ok()?);
        let Some(body) = b.get(at + REC..at + REC + len) else {
            break;
        };
        if len > PIECE || crc32(body) != crc {
            break;
        }
        payload.extend_from_slice(body);
        at += REC + len;
    }
    Some(Read {
        start,
        payload,
        valid: at as u64,
    })
}

fn create(path: &Path, start: u64) -> io::Result<File> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let mut head = [0u8; HEAD];
    head[..8].copy_from_slice(MAGIC);
    head[8..].copy_from_slice(&start.to_le_bytes());
    f.write_all(&head)?;
    Ok(f)
}

/// Truncates then unlinks `path` (best effort).
fn wipe(path: &Path) {
    // Only a regular file is truncated: a symlink is removed itself, its target untouched.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
        && let Ok(f) = OpenOptions::new().write(true).open(path)
    {
        let _ = f.set_len(0);
    }
    let _ = std::fs::remove_file(path);
}

/// The disk ring of one terminal.
pub struct DiskRing {
    dir: PathBuf,
    id: String,
    half: u64,
    file: File,
    cur: Gen,
    prev: Option<Gen>,
    next: u64,
}

impl DiskRing {
    /// Opens the ring of `id` in `dir` (which must already be private) with `cap` bytes
    /// (clamped to the bounds). Files already there are recovered: a torn tail is cut, and an
    /// older generation that does not join the newer is deleted. With none, a new ring starts
    /// at `seq` 0.
    pub fn open(dir: &Path, id: &str, cap: u64) -> io::Result<Self> {
        let half = cap.clamp(CAP_MIN, CAP_MAX) / 2;
        let mut found: Vec<u64> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let (i, n) = parse_name(&name)?;
                (i == id).then_some(n)
            })
            .collect();
        found.sort_unstable();
        let mut gens: Vec<Gen> = Vec::new();
        for n in found {
            let path = ring_path(dir, id, n);
            match read_gen(&path) {
                Some(r) => gens.push(Gen {
                    n,
                    start: r.start,
                    end: r.start + r.payload.len() as u64,
                    len: r.valid,
                }),
                None => wipe(&path),
            }
        }
        // Keep the newest, and the one before it only when it joins.
        let cur = gens.pop();
        let prev = match (gens.pop(), cur) {
            (Some(p), Some(c)) if p.end == c.start => Some(p),
            (Some(p), _) => {
                wipe(&ring_path(dir, id, p.n));
                None
            }
            _ => None,
        };
        for g in gens {
            wipe(&ring_path(dir, id, g.n));
        }
        match cur {
            Some(c) => {
                let path = ring_path(dir, id, c.n);
                let file = OpenOptions::new().write(true).open(&path)?;
                file.set_len(c.len)?;
                let mut file = file;
                std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0))?;
                Ok(Self {
                    dir: dir.to_path_buf(),
                    id: id.to_owned(),
                    half,
                    file,
                    cur: c,
                    prev,
                    next: c.end,
                })
            }
            None => Ok(Self {
                dir: dir.to_path_buf(),
                id: id.to_owned(),
                half,
                file: create(&ring_path(dir, id, 0), 0)?,
                cur: Gen {
                    n: 0,
                    start: 0,
                    end: 0,
                    len: HEAD as u64,
                },
                prev: None,
                next: 0,
            }),
        }
    }

    /// The `seq` of the next byte.
    pub fn end(&self) -> u64 {
        self.next
    }

    /// The `seq` of the oldest byte held.
    pub fn start(&self) -> u64 {
        self.prev.map_or(self.cur.start, |p| p.start)
    }

    /// Bytes this ring takes on disk.
    pub fn bytes(&self) -> u64 {
        self.cur.len + self.prev.map_or(0, |p| p.len)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let n = self.cur.n + 1;
        let file = create(&ring_path(&self.dir, &self.id, n), self.next)?;
        if let Some(p) = self.prev.take() {
            wipe(&ring_path(&self.dir, &self.id, p.n));
        }
        self.prev = Some(self.cur);
        self.file = file;
        self.cur = Gen {
            n,
            start: self.next,
            end: self.next,
            len: HEAD as u64,
        };
        Ok(())
    }

    /// Appends output whose first byte is `seq` (it must be the next one).
    pub fn append(&mut self, seq: u64, bytes: &[u8]) -> io::Result<()> {
        if seq != self.next {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gap in the ring",
            ));
        }
        for piece in bytes.chunks(PIECE) {
            let rec = (REC + piece.len()) as u64;
            if self.cur.len + rec > self.half && self.cur.end > self.cur.start {
                self.rotate()?;
            }
            let mut buf = Vec::with_capacity(REC + piece.len());
            buf.extend_from_slice(&(piece.len() as u32).to_le_bytes());
            buf.extend_from_slice(&crc32(piece).to_le_bytes());
            buf.extend_from_slice(piece);
            self.file.write_all(&buf)?;
            self.cur.len += rec;
            self.cur.end += piece.len() as u64;
            self.next += piece.len() as u64;
        }
        Ok(())
    }

    /// The bytes from `seq` to the end, or `None` when `seq` is before what is held, past the
    /// end, or the files no longer hold what the bookkeeping says (damaged: a snapshot is
    /// the safe answer).
    pub fn since(&self, seq: u64) -> Option<Vec<u8>> {
        if seq < self.start() || seq > self.next {
            return None;
        }
        let mut out = Vec::new();
        for g in self.prev.iter().chain(std::iter::once(&self.cur)) {
            if g.end <= seq {
                continue;
            }
            let r = read_gen(&ring_path(&self.dir, &self.id, g.n))?;
            if r.start != g.start || r.payload.len() as u64 != g.end - g.start {
                return None;
            }
            let skip = usize::try_from(seq.saturating_sub(g.start)).ok()?;
            out.extend_from_slice(r.payload.get(skip..)?);
        }
        Some(out)
    }

    /// Frees disk on request (the budget, E2-06.2): drops the older generation, or, with none,
    /// everything held (the newest becomes the older and goes). Later output is kept again.
    pub fn shed(&mut self) -> io::Result<()> {
        if let Some(p) = self.prev.take() {
            wipe(&ring_path(&self.dir, &self.id, p.n));
            return Ok(());
        }
        if self.cur.end > self.cur.start {
            self.rotate()?;
            if let Some(p) = self.prev.take() {
                wipe(&ring_path(&self.dir, &self.id, p.n));
            }
        }
        Ok(())
    }

    /// Deletes the ring (the terminal closed). Truncate then unlink: deletion, not erasure.
    pub fn destroy(self) {
        let DiskRing {
            dir, id, cur, prev, ..
        } = self;
        for g in prev.iter().chain(std::iter::once(&cur)) {
            wipe(&ring_path(&dir, &id, g.n));
        }
    }
}

/// Removes every ring file of `id` in `dir` (a host that is gone for good).
pub fn remove_all(dir: &Path, id: &str) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.filter_map(Result::ok) {
        if let Some(name) = e.file_name().to_str()
            && parse_name(name).is_some_and(|(i, _)| i == id)
        {
            wipe(&e.path());
        }
    }
}

/// Bytes on disk per terminal in `dir`: `(id, bytes, newest modification in unix ms)`.
pub fn usage(dir: &Path) -> Vec<(String, u64, u64)> {
    let mut by: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.filter_map(Result::ok) {
            let Some(name) = e.file_name().into_string().ok() else {
                continue;
            };
            let Some((id, _)) = parse_name(&name) else {
                continue;
            };
            let Ok(m) = e.metadata() else { continue };
            let ms = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
            let slot = by.entry(id.to_owned()).or_default();
            slot.0 += m.len();
            slot.1 = slot.1.max(ms);
        }
    }
    by.into_iter().map(|(i, (b, m))| (i, b, m)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ainkrad-store-{}",
            crate::host::random_hex().unwrap()
        ));
        crate::host::private_dir(&d).unwrap();
        d
    }

    struct Clean(PathBuf);
    impl Drop for Clean {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_caps_are_the_bounds_the_core_and_runner_use() {
        use ainkrad_proto::v2::SCROLLBACK_BYTES as B;
        assert_eq!((CAP_MIN, CAP_MAX, CAP_DEFAULT), B);
    }

    #[test]
    fn crc_matches_the_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn output_round_trips_and_files_are_private() {
        let d = tmp();
        let _c = Clean(d.clone());
        let mut r = DiskRing::open(&d, "t_a", 1 << 20).unwrap();
        r.append(0, b"hello ").unwrap();
        r.append(6, b"world").unwrap();
        assert_eq!(r.since(0).unwrap(), b"hello world");
        assert_eq!(r.since(6).unwrap(), b"world");
        assert_eq!(r.since(11).unwrap(), b"");
        assert!(r.since(12).is_none(), "not written yet");
        assert!(r.append(99, b"x").is_err(), "a gap is refused");
        let mode = std::fs::metadata(ring_path(&d, "t_a", 0))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn the_ring_is_bounded_and_a_stale_seq_is_refused() {
        let d = tmp();
        let _c = Clean(d.clone());
        let cap = CAP_MIN;
        let mut r = DiskRing::open(&d, "t_b", cap).unwrap();
        let chunk = vec![b'x'; 50_000];
        let mut seq = 0;
        for _ in 0..200 {
            r.append(seq, &chunk).unwrap();
            seq += chunk.len() as u64;
            assert!(
                r.bytes() <= cap + (PIECE + REC + HEAD) as u64,
                "{}",
                r.bytes()
            );
        }
        assert!(r.start() > 0, "the oldest was dropped");
        assert!(
            r.since(0).is_none(),
            "before the ring: a snapshot is needed"
        );
        assert_eq!(r.since(r.start()).unwrap().len() as u64, seq - r.start());
        let files = std::fs::read_dir(&d).unwrap().count();
        assert!(files <= 2, "{files} files");
    }

    #[test]
    fn a_torn_tail_is_dropped_and_the_rest_replays() {
        let d = tmp();
        let _c = Clean(d.clone());
        {
            let mut r = DiskRing::open(&d, "t_c", 1 << 20).unwrap();
            r.append(0, b"good-one ").unwrap();
            r.append(9, b"good-two").unwrap();
        }
        // A crash mid-record: half of a third record is on disk.
        let p = ring_path(&d, "t_c", 0);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[20, 0, 0, 0, 1, 2, 3, 4, b'p', b'a', b'r'])
            .unwrap();
        drop(f);
        let r = DiskRing::open(&d, "t_c", 1 << 20).unwrap();
        assert_eq!(r.since(0).unwrap(), b"good-one good-two");
        assert_eq!(r.end(), 17);
        // And it keeps going cleanly from there.
        let mut r = r;
        r.append(17, b"!").unwrap();
        assert_eq!(
            DiskRing::open(&d, "t_c", 1 << 20)
                .unwrap()
                .since(0)
                .unwrap(),
            b"good-one good-two!"
        );
    }

    #[test]
    fn a_flipped_byte_stops_the_replay_there() {
        let d = tmp();
        let _c = Clean(d.clone());
        {
            let mut r = DiskRing::open(&d, "t_d", 1 << 20).unwrap();
            r.append(0, b"aaaa").unwrap();
            r.append(4, b"bbbb").unwrap();
        }
        let p = ring_path(&d, "t_d", 0);
        let mut b = std::fs::read(&p).unwrap();
        let last = b.len() - 1;
        b[last] ^= 0xFF;
        std::fs::write(&p, b).unwrap();
        let r = DiskRing::open(&d, "t_d", 1 << 20).unwrap();
        assert_eq!(
            r.since(0).unwrap(),
            b"aaaa",
            "the corrupt record is dropped"
        );
    }

    #[test]
    fn a_symlink_under_a_ring_name_is_removed_not_followed() {
        let d = tmp();
        let _c = Clean(d.clone());
        let victim = d.join("victim");
        std::fs::write(&victim, b"keep me").unwrap();
        std::os::unix::fs::symlink(&victim, ring_path(&d, "t_s", 0)).unwrap();
        let mut r = DiskRing::open(&d, "t_s", 1 << 20).unwrap();
        r.append(0, b"out").unwrap();
        r.destroy();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
    }

    #[test]
    fn a_write_error_is_returned_so_the_host_can_stop_using_the_disk() {
        let d = tmp();
        let _c = Clean(d.clone());
        let mut r = DiskRing::open(&d, "t_e", 1 << 20).unwrap();
        r.file = File::open(ring_path(&d, "t_e", 0)).unwrap(); // read-only: writes fail
        assert!(r.append(0, b"x").is_err());
    }

    #[test]
    fn shed_frees_disk_and_destroy_deletes_everything() {
        let d = tmp();
        let _c = Clean(d.clone());
        let mut r = DiskRing::open(&d, "t_f", CAP_MIN).unwrap();
        let chunk = vec![b'y'; 40_000];
        let mut seq = 0;
        for _ in 0..10 {
            r.append(seq, &chunk).unwrap();
            seq += chunk.len() as u64;
        }
        let before = r.bytes();
        r.shed().unwrap();
        assert!(r.bytes() < before);
        r.shed().unwrap();
        assert_eq!(r.bytes(), HEAD as u64, "all shed");
        assert!(r.since(0).is_none());
        r.append(seq, b"after").unwrap();
        assert_eq!(r.since(seq).unwrap(), b"after");
        r.destroy();
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
    }

    #[test]
    fn names_parse_and_remove_all_only_touches_one_terminal() {
        assert_eq!(parse_name("t_ab.3.ring"), Some(("t_ab", 3)));
        assert_eq!(parse_name("t_ab.json"), None);
        let d = tmp();
        let _c = Clean(d.clone());
        DiskRing::open(&d, "t_g", 1 << 20)
            .unwrap()
            .append(0, b"1")
            .unwrap();
        DiskRing::open(&d, "t_h", 1 << 20)
            .unwrap()
            .append(0, b"2")
            .unwrap();
        remove_all(&d, "t_g");
        let u = usage(&d);
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].0, "t_h");
    }
}
