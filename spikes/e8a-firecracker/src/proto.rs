use std::io::{self, Read, Write};

pub const MAX_FRAME: u32 = 1 << 20;
pub const VSOCK_PORT: u32 = 5000;
pub const T_PING: u8 = 1;
pub const T_EXEC: u8 = 2;
pub const T_SHUTDOWN: u8 = 3;
pub const R_PONG: u8 = 0x81;
pub const R_OUT: u8 = 0x82;
pub const R_ERR: u8 = 0x83;
pub const R_EXIT: u8 = 0x84;
pub const R_ERROR: u8 = 0x85;
pub const R_ACK: u8 = 0x86;

const MAX_ITEMS: u32 = 4096;

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

pub fn write_frame(w: &mut impl Write, t: u8, p: &[u8]) -> io::Result<()> {
    let n = p.len() as u64 + 1;
    if n > MAX_FRAME as u64 {
        return Err(bad("frame too large"));
    }
    let mut buf = Vec::with_capacity(5 + p.len());
    buf.extend_from_slice(&(n as u32).to_be_bytes());
    buf.push(t);
    buf.extend_from_slice(p);
    w.write_all(&buf)
}

pub fn read_frame(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h)?;
    let n = u32::from_be_bytes(h);
    if n == 0 || n > MAX_FRAME {
        return Err(bad("bad frame length"));
    }
    let mut b = vec![0u8; n as usize];
    r.read_exact(&mut b)?;
    let t = b.remove(0);
    Ok((t, b))
}

/// An exec request. Caps are enforced by the guest (cgroup v2) and the deadline by both sides.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct Exec {
    pub argv: Vec<String>,
    pub env: Vec<String>, // "K=V"
    pub cwd: String,
    pub timeout_ms: u64,
    pub mem_max: u64,  // bytes, cgroup memory.max
    pub pids_max: u32, // cgroup pids.max
    pub stdin: Vec<u8>,
}

fn put_u32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_be_bytes());
}
fn put_b(o: &mut Vec<u8>, b: &[u8]) {
    put_u32(o, b.len() as u32);
    o.extend_from_slice(b);
}

impl Exec {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        put_u32(&mut o, self.argv.len() as u32);
        for a in &self.argv {
            put_b(&mut o, a.as_bytes());
        }
        put_u32(&mut o, self.env.len() as u32);
        for a in &self.env {
            put_b(&mut o, a.as_bytes());
        }
        put_b(&mut o, self.cwd.as_bytes());
        put_u64(&mut o, self.timeout_ms);
        put_u64(&mut o, self.mem_max);
        put_u32(&mut o, self.pids_max);
        put_b(&mut o, &self.stdin);
        o
    }

    pub fn decode(mut b: &[u8]) -> io::Result<Exec> {
        fn take<'a>(b: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
            if b.len() < n {
                return Err(bad("short exec"));
            }
            let (h, t) = b.split_at(n);
            *b = t;
            Ok(h)
        }
        fn u32_(b: &mut &[u8]) -> io::Result<u32> {
            Ok(u32::from_be_bytes(take(b, 4)?.try_into().unwrap()))
        }
        fn u64_(b: &mut &[u8]) -> io::Result<u64> {
            Ok(u64::from_be_bytes(take(b, 8)?.try_into().unwrap()))
        }
        fn bytes<'a>(b: &mut &'a [u8]) -> io::Result<&'a [u8]> {
            let n = u32_(b)? as usize;
            take(b, n)
        }
        fn string(b: &mut &[u8]) -> io::Result<String> {
            String::from_utf8(bytes(b)?.to_vec()).map_err(|_| bad("not utf-8"))
        }
        let mut e = Exec::default();
        let n = u32_(&mut b)?;
        if n == 0 || n > MAX_ITEMS {
            return Err(bad("argc"));
        }
        for _ in 0..n {
            e.argv.push(string(&mut b)?);
        }
        let n = u32_(&mut b)?;
        if n > MAX_ITEMS {
            return Err(bad("envc"));
        }
        for _ in 0..n {
            e.env.push(string(&mut b)?);
        }
        e.cwd = string(&mut b)?;
        e.timeout_ms = u64_(&mut b)?;
        e.mem_max = u64_(&mut b)?;
        e.pids_max = u32_(&mut b)?;
        e.stdin = bytes(&mut b)?.to_vec();
        if !b.is_empty() {
            return Err(bad("trailing bytes"));
        }
        Ok(e)
    }
}

/// Exit report: code (-1 if signalled), signal (0 if none), flags bit0 = deadline hit, bit1 = oom kill.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Exit {
    pub code: i32,
    pub signal: i32,
    pub timed_out: bool,
    pub oom: bool,
}

impl Exit {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.code.to_be_bytes());
        o.extend_from_slice(&self.signal.to_be_bytes());
        o.push(self.timed_out as u8 | (self.oom as u8) << 1);
        o
    }
    pub fn decode(b: &[u8]) -> io::Result<Exit> {
        if b.len() != 9 {
            return Err(bad("exit len"));
        }
        Ok(Exit {
            code: i32::from_be_bytes(b[0..4].try_into().unwrap()),
            signal: i32::from_be_bytes(b[4..8].try_into().unwrap()),
            timed_out: b[8] & 1 != 0,
            oom: b[8] & 2 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_round_trips() {
        let e = Exec {
            argv: vec!["/bin/echo".into(), "hi".into()],
            env: vec!["A=b".into()],
            cwd: "/work".into(),
            timeout_ms: 5000,
            mem_max: 1 << 28,
            pids_max: 64,
            stdin: b"in".to_vec(),
        };
        assert_eq!(Exec::decode(&e.encode()).unwrap(), e);
        let x = Exit { code: 3, signal: 0, timed_out: true, oom: false };
        assert_eq!(Exit::decode(&x.encode()).unwrap(), x);
    }

    #[test]
    fn frames_are_bounded_and_truncation_is_rejected() {
        // oversize length prefix must be rejected before allocating
        let mut big = (MAX_FRAME + 1).to_be_bytes().to_vec();
        big.push(1);
        assert!(read_frame(&mut &big[..]).is_err());
        assert!(read_frame(&mut &0u32.to_be_bytes()[..]).is_err());
        assert!(write_frame(&mut Vec::new(), 1, &vec![0; MAX_FRAME as usize]).is_err());
        let mut ok = Vec::new();
        write_frame(&mut ok, T_PING, b"").unwrap();
        assert_eq!(read_frame(&mut &ok[..]).unwrap(), (T_PING, vec![]));
        // truncated payload
        assert!(read_frame(&mut &ok[..4]).is_err());
        // hostile exec payloads
        let enc = Exec { argv: vec!["x".into()], ..Default::default() }.encode();
        for n in 0..enc.len() {
            assert!(Exec::decode(&enc[..n]).is_err(), "prefix {n} accepted");
        }
        let mut extra = enc.clone();
        extra.push(0);
        assert!(Exec::decode(&extra).is_err());
        assert!(Exec::decode(&u32::MAX.to_be_bytes()).is_err());
        assert!(Exec::decode(&0u32.to_be_bytes()).is_err());
    }
}
