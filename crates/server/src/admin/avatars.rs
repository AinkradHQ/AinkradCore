//! Agent avatars (decision #61), as the admin: an agent's palette, and an image shown instead
//! of its figure, through the same store calls (checks and audit) the API uses.

use std::path::{Path, PathBuf};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::AgentId;
use ainkrad_core_server::store::{self, org::avatars};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str =
    "  ainkrad-core-server agent appearance set <db> <agent-id> --palette <id> [--figure <version>]
  ainkrad-core-server agent appearance palettes <db>
  ainkrad-core-server agent avatar set <db> <agent-id> --file <image> [--artifacts <dir>]
  ainkrad-core-server agent avatar reset <db> <agent-id>
An agent is drawn by the app as an animated figure in one of the palettes (appearance
palettes lists them), given at hire and changed with appearance set. avatar set uploads a PNG,
JPEG or WebP (at most avatar.max_bytes) shown instead of the figure, stored with the artifacts
(--artifacts as given to serve; default artifacts/ next to the database); avatar reset removes
it.";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs an avatar command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["agent", "appearance", "set", db, agent, rest @ ..] => {
            let f = flags(rest, &["--palette", "--figure"])?;
            let palette = *f.get("--palette")?;
            let agent = AgentId(id(agent).ok()?);
            appearance(Path::new(db), agent, palette, f.get("--figure").copied()).await
        }
        ["agent", "appearance", "palettes", db] => palettes(Path::new(db)).await,
        ["agent", "avatar", "set", db, agent, rest @ ..] => {
            let f = flags(rest, &["--file", "--artifacts"])?;
            let file = PathBuf::from(f.get("--file")?);
            let root = f
                .get("--artifacts")
                .map_or_else(|| Path::new(db).with_file_name("artifacts"), PathBuf::from);
            upload(Path::new(db), AgentId(id(agent).ok()?), &file, &root).await
        }
        ["agent", "avatar", "reset", db, agent] => {
            reset(Path::new(db), AgentId(id(agent).ok()?)).await
        }
        _ => return None,
    })
}

async fn appearance(db: &Path, agent: AgentId, palette: &str, figure: Option<&str>) -> Result_ {
    let pool = store::connect(db).await?;
    let a = avatars::set_appearance(&pool, agent, palette, figure, BY).await?;
    eprintln!(
        "agent {}: figure {} in palette {}",
        a.id.0, a.figure_version, a.palette_id
    );
    println!("{}", a.id.0);
    Ok(())
}

/// `<id>\t<name>`, one per palette.
async fn palettes(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    for (id, name) in avatars::list_palettes(&pool).await? {
        println!("{id}\t{name}");
    }
    Ok(())
}

async fn upload(db: &Path, agent: AgentId, file: &Path, root: &Path) -> Result_ {
    let bytes = std::fs::read(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let pool = store::connect(db).await?;
    let a = avatars::upload_avatar(&pool, root, agent, &bytes, BY).await?;
    let sha = a.avatar_sha256.unwrap_or_default();
    eprintln!("agent {}: avatar image {sha}", a.id.0);
    println!("{}", a.id.0);
    Ok(())
}

async fn reset(db: &Path, agent: AgentId) -> Result_ {
    let pool = store::connect(db).await?;
    let a = avatars::reset_avatar(&pool, agent, BY).await?;
    eprintln!("agent {}: avatar image removed; its figure shows", a.id.0);
    println!("{}", a.id.0);
    Ok(())
}
