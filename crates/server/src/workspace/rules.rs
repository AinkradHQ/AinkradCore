//! What a workspace sync includes (E15-2, spec 4.4). The rules themselves are shared with the
//! runner (`ainkrad_proto::v2::synctree`); this reads a project's overrides.
//!
//! The project's overrides come from `.ainkrad/jobs.toml`:
//! ```toml
//! [sync]
//! include = [".env.example", "certs/*.pem"]   # secret-shaped files this project does sync
//! exclude = ["big-fixtures/**"]               # more to leave out
//! outputs = ["target/release/app"]            # build output that comes back
//! ```

pub use ainkrad_proto::v2::synctree::{
    BUILD_DIRS, Rules, Skip, glob, has_git, in_build_dir, is_secret,
};
use serde::Deserialize;

/// The `[sync]` table of `.ainkrad/jobs.toml`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SyncConfig {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Deserialize, Default)]
struct JobsToml {
    #[serde(default)]
    sync: SyncConfig,
}

/// The rules of the text of `.ainkrad/jobs.toml`; a file that does not parse gives the defaults
/// (the strict ones: nothing extra is included).
pub fn from_toml(text: &str) -> Rules {
    let SyncConfig {
        include,
        exclude,
        outputs,
    } = toml::from_str::<JobsToml>(text).unwrap_or_default().sync;
    Rules {
        include,
        exclude,
        outputs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_toml_sets_the_project_lists_and_a_bad_file_gives_the_strict_defaults() {
        let r = from_toml(
            "[sync]\ninclude=[\".env.example\"]\nexclude=[\"big/**\"]\noutputs=[\"target/release/app\"]\n",
        );
        assert_eq!(r.sync_in(".env.example"), None);
        assert_eq!(r.sync_in("big/x"), Some(Skip::Excluded));
        assert_eq!(r.sync_out("target/release/app"), None);
        let w = r.to_wire();
        assert!(
            w.exclude.contains(&"target/".to_owned()) && w.exclude.contains(&"big/**".to_owned())
        );
        assert_eq!(from_toml("[sync\n"), Rules::default());
        assert_eq!(from_toml("[sync\n").sync_in(".env"), Some(Skip::Secret));
    }
}
