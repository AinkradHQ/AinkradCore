//! An in-memory SFTP server for the fixture `russh` servers (Y2-03 tests). Paths are keys as received:
//! nothing is normalised, so `../x` or a name with a newline is a plain name, and `paths` records
//! every path the runner sent, byte for byte.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use russh_sftp::server::Handler;

#[derive(Default)]
pub(super) struct MemFs {
    pub(super) files: HashMap<String, Vec<u8>>,
    pub(super) dirs: HashSet<String>,
    /// link path to target path.
    pub(super) links: HashMap<String, String>,
    /// Sizes the host claims for a file (to test the cap without moving 2 GiB).
    pub(super) claimed: HashMap<String, u64>,
    /// Every path (and rename target) the client named, in order.
    pub(super) paths: Vec<String>,
}

pub(super) type Fs = Arc<Mutex<MemFs>>;

impl MemFs {
    pub(super) fn with_root() -> Fs {
        let mut fs = Self::default();
        fs.dirs.insert("/".into());
        Arc::new(Mutex::new(fs))
    }

    fn attrs(&self, path: &str, follow: bool) -> Result<FileAttributes, StatusCode> {
        let mut a = FileAttributes {
            mtime: Some(1_700_000_000),
            uid: Some(1000),
            gid: Some(1000),
            ..FileAttributes::default()
        };
        if let Some(t) = self.links.get(path) {
            if !follow {
                a.permissions = Some(0o120_777);
                a.size = Some(t.len() as u64);
                return Ok(a);
            }
            return self.attrs(&t.clone(), false);
        }
        if let Some(f) = self.files.get(path) {
            a.permissions = Some(0o100_644);
            a.size = Some(self.claimed.get(path).copied().unwrap_or(f.len() as u64));
        } else if self.dirs.contains(path) {
            a.permissions = Some(0o040_755);
            a.size = Some(4096);
        } else {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(a)
    }

    fn exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.dirs.contains(path) || self.links.contains_key(path)
    }

    /// `(name, path)` of the direct children of `dir`.
    fn children(&self, dir: &str) -> Vec<(String, String)> {
        let prefix = if dir.ends_with('/') {
            dir.to_owned()
        } else {
            format!("{dir}/")
        };
        let all = (self.files.keys())
            .chain(self.dirs.iter())
            .chain(self.links.keys());
        let mut out: Vec<_> = all
            .filter(|p| p.len() > prefix.len() && p.starts_with(&prefix))
            .filter(|p| !p[prefix.len()..].contains('/'))
            .map(|p| (p[prefix.len()..].to_owned(), p.clone()))
            .collect();
        out.sort();
        out
    }
}

enum Open {
    File(String),
    Dir(String, bool),
}

pub(super) struct Sftp {
    pub(super) fs: Fs,
    open: HashMap<String, Open>,
    next: u32,
}

impl Sftp {
    pub(super) fn new(fs: Fs) -> Self {
        Self {
            fs,
            open: HashMap::new(),
            next: 0,
        }
    }

    fn see(&self, p: &str) {
        self.fs.lock().unwrap().paths.push(p.to_owned());
    }

    fn ok(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        }
    }
}

impl Handler for Sftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, StatusCode> {
        self.see(&filename);
        {
            let mut fs = self.fs.lock().unwrap();
            let there = fs.exists(&filename);
            if pflags.contains(OpenFlags::EXCLUDE) && there {
                return Err(StatusCode::Failure);
            }
            if !there {
                if !pflags.contains(OpenFlags::CREATE) {
                    return Err(StatusCode::NoSuchFile);
                }
                fs.files.insert(filename.clone(), Vec::new());
            } else if fs.dirs.contains(&filename) && pflags.contains(OpenFlags::WRITE) {
                return Err(StatusCode::Failure);
            }
            if pflags.contains(OpenFlags::TRUNCATE) {
                fs.files.insert(filename.clone(), Vec::new());
            }
        }
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.open.insert(handle.clone(), Open::File(filename));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusCode> {
        self.open.remove(&handle);
        Ok(Self::ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusCode> {
        let Some(Open::File(path)) = self.open.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let fs = self.fs.lock().unwrap();
        let bytes = fs.files.get(path).ok_or(StatusCode::NoSuchFile)?;
        let from = usize::try_from(offset).unwrap_or(usize::MAX);
        if from >= bytes.len() {
            return Err(StatusCode::Eof);
        }
        let to = bytes.len().min(from + len as usize);
        Ok(Data {
            id,
            data: bytes[from..to].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusCode> {
        let Some(Open::File(path)) = self.open.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let mut fs = self.fs.lock().unwrap();
        let bytes = fs.files.get_mut(path).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        bytes[offset as usize..end].copy_from_slice(&data);
        Ok(Self::ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        self.see(&path);
        let attrs = self.fs.lock().unwrap().attrs(&path, false)?;
        Ok(Attrs { id, attrs })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        self.see(&path);
        let attrs = self.fs.lock().unwrap().attrs(&path, true)?;
        Ok(Attrs { id, attrs })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, StatusCode> {
        let Some(Open::File(path)) = self.open.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let attrs = self.fs.lock().unwrap().attrs(path, true)?;
        Ok(Attrs { id, attrs })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, StatusCode> {
        self.see(&path);
        if !self.fs.lock().unwrap().dirs.contains(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.open.insert(handle.clone(), Open::Dir(path, false));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, StatusCode> {
        let Some(Open::Dir(path, sent)) = self.open.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        if std::mem::replace(sent, true) {
            return Err(StatusCode::Eof);
        }
        let fs = self.fs.lock().unwrap();
        let mut files = vec![File::new(".", FileAttributes::dummy())];
        for (name, full) in fs.children(path) {
            files.push(File::new(name, fs.attrs(&full, false)?));
        }
        Ok(Name { id, files })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _: FileAttributes,
    ) -> Result<Status, StatusCode> {
        self.see(&path);
        let mut fs = self.fs.lock().unwrap();
        if fs.exists(&path) {
            return Err(StatusCode::Failure);
        }
        fs.dirs.insert(path);
        Ok(Self::ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, StatusCode> {
        self.see(&path);
        let mut fs = self.fs.lock().unwrap();
        if !fs.children(&path).is_empty() || !fs.dirs.remove(&path) {
            return Err(StatusCode::Failure);
        }
        Ok(Self::ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, StatusCode> {
        self.see(&filename);
        let mut fs = self.fs.lock().unwrap();
        let gone = fs.files.remove(&filename).is_some() | fs.links.remove(&filename).is_some();
        match gone {
            true => Ok(Self::ok(id)),
            false => Err(StatusCode::NoSuchFile),
        }
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, StatusCode> {
        self.see(&oldpath);
        self.see(&newpath);
        let mut fs = self.fs.lock().unwrap();
        if fs.exists(&newpath) {
            return Err(StatusCode::Failure);
        }
        if let Some(f) = fs.files.remove(&oldpath) {
            fs.files.insert(newpath, f);
        } else if fs.dirs.remove(&oldpath) {
            fs.dirs.insert(newpath);
        } else if let Some(l) = fs.links.remove(&oldpath) {
            fs.links.insert(newpath, l);
        } else {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Self::ok(id))
    }
}
