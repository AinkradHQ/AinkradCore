//! `export <file>` (E1-13.3): the home's state as a portable, signed archive (`archive`), not
//! encrypted, for moving a Core between hosts; `import` reads it into an empty home. The SQLite
//! file format is the same on every OS and architecture, so the database goes as it is.
//! ponytail: a file-level archive, not a logical per-table dump; write one if the store ever
//! leaves SQLite.

use std::io::BufWriter;
use std::path::Path;

use super::config::Config;
use super::{Result_, private_file};
use crate::ops::backup::archive_home;

pub async fn export(config: &Config, dest: &Path) -> Result_ {
    let file = private_file(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let mut out = BufWriter::new(file);
    let written = archive_home(&config.home(), "export", &mut out).await;
    let written = written.and_then(|m| {
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(m)
    });
    match written {
        Ok(m) => {
            eprintln!(
                "exported {} ({} bytes of database), signed by {}. It holds the master key in \
                 clear: move it like a private key. Import it with --signer {}.",
                dest.display(),
                m.files[0].size,
                m.signer_fp,
                m.signer_fp
            );
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(dest);
            Err(e)
        }
    }
}
