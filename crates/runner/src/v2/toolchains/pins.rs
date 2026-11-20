//! The pinned toolchains and their digests (E15-4, spec §6), the same shape as `aitools/pins.rs`.
//! Every digest is SHA-256 of the exact download, from the vendor's own manifest:
//! - Node 22.22.1: `https://nodejs.org/dist/v22.22.1/SHASUMS256.txt` (the `.tar.gz` files).
//! - rustup 1.29.3: `https://static.rust-lang.org/rustup/archive/1.29.3/<triple>/rustup-init.sha256`.
//!   The Rust toolchain itself (1.100.0) is fetched by that `rustup-init`, which checks it against
//!   the release manifest's own hashes (ponytail: not re-pinned here; pin the channel manifest hash
//!   if rustup's own check is not enough).
//! - Go 1.27.4: `https://go.dev/dl/?mode=json` (the `archive` files).
//! - Python 3.13.18 (python-build-standalone 20261110, `install_only_stripped`): the GitHub release
//!   assets' `digest` field.
//!
//! Bumping a version means fetching its digests again; a test checks the table's shape.

/// How a download becomes an install.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// A `.tar.gz` with one top folder, unpacked with that folder stripped.
    Tarball,
    /// A single executable (`rustup-init`), run once to install the toolchain.
    Installer,
}

pub(super) struct Build {
    /// `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`.
    pub platform: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    /// The rustup triple (Installer only): what `rustup-init` is asked to install for.
    pub triple: &'static str,
}

pub(super) struct Pin {
    /// The `Capacity::toolchains` key.
    pub tool: &'static str,
    pub version: &'static str,
    pub kind: Kind,
    /// Folders (relative to the install) holding the executables, put first on `PATH`.
    pub bin: &'static [&'static str],
    pub builds: &'static [Build],
}

/// The Rust toolchain `rustup-init` installs (a `stable` `rust-toolchain.toml` means this).
pub(super) const RUST_TOOLCHAIN: &str = "1.100.0";

pub(super) const PINS: &[Pin] = &[
    Pin {
        tool: "node",
        version: "22.22.1",
        kind: Kind::Tarball,
        bin: &["bin"],
        builds: &[
            Build {
                platform: "linux-x64",
                url: "https://nodejs.org/dist/v22.22.1/node-v22.22.1-linux-x64.tar.gz",
                sha256: "07c8aafa60644fb81adefa1ee7da860eb1920851ffdc9a37020ab0be47fbc10e",
                triple: "",
            },
            Build {
                platform: "linux-arm64",
                url: "https://nodejs.org/dist/v22.22.1/node-v22.22.1-linux-arm64.tar.gz",
                sha256: "1d1690e9aba47e887a275abc6d8f7317e571a0700deaef493f768377e99155f5",
                triple: "",
            },
            Build {
                platform: "darwin-x64",
                url: "https://nodejs.org/dist/v22.22.1/node-v22.22.1-darwin-x64.tar.gz",
                sha256: "07b13722d558790fca20bb1ecf61bde24b7a4863111f7be77fc57251a407359a",
                triple: "",
            },
            Build {
                platform: "darwin-arm64",
                url: "https://nodejs.org/dist/v22.22.1/node-v22.22.1-darwin-arm64.tar.gz",
                sha256: "679ad4966339e4ef4900f57996714864e4211b898825bb840c3086c419fbcef2",
                triple: "",
            },
        ],
    },
    Pin {
        tool: "go",
        version: "1.27.4",
        kind: Kind::Tarball,
        bin: &["bin"],
        builds: &[
            Build {
                platform: "linux-x64",
                url: "https://go.dev/dl/go1.27.4.linux-amd64.tar.gz",
                sha256: "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840",
                triple: "",
            },
            Build {
                platform: "linux-arm64",
                url: "https://go.dev/dl/go1.27.4.linux-arm64.tar.gz",
                sha256: "3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92",
                triple: "",
            },
            Build {
                platform: "darwin-x64",
                url: "https://go.dev/dl/go1.27.4.darwin-amd64.tar.gz",
                sha256: "2b799377704ef12db39bd254995d5c348c9cc8d86562ca817724390e56c38f43",
                triple: "",
            },
            Build {
                platform: "darwin-arm64",
                url: "https://go.dev/dl/go1.27.4.darwin-arm64.tar.gz",
                sha256: "91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4",
                triple: "",
            },
        ],
    },
    Pin {
        tool: "python",
        version: "3.13.18",
        kind: Kind::Tarball,
        bin: &["bin"],
        builds: &[
            Build {
                platform: "linux-x64",
                url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18%2B20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
                sha256: "f2d2199eb25880e07863b391cf7124e7ffa1338b0d65600dfcec117c4223a7fb",
                triple: "",
            },
            Build {
                platform: "linux-arm64",
                url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18%2B20261110-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
                sha256: "55c00325f7c1fddf325dfc621aabdfbbac4dc54adda224af88ec411dc12db239",
                triple: "",
            },
            Build {
                platform: "darwin-x64",
                url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18%2B20261110-x86_64-apple-darwin-install_only_stripped.tar.gz",
                sha256: "d27d59a722db9f69926eb6d9564071247221f45a04da920ea7f3001c97e32f9b",
                triple: "",
            },
            Build {
                platform: "darwin-arm64",
                url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18%2B20261110-aarch64-apple-darwin-install_only_stripped.tar.gz",
                sha256: "7a2384641584ab9984221fcb0fc9265df465922af71be71410529e2a9c3f0540",
                triple: "",
            },
        ],
    },
    Pin {
        tool: "rust",
        // The pin is the toolchain; the installer's own version is in its URL.
        version: RUST_TOOLCHAIN,
        kind: Kind::Installer,
        bin: &["cargo/bin"],
        builds: &[
            Build {
                platform: "linux-x64",
                url: "https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-unknown-linux-gnu/rustup-init",
                sha256: "b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55",
                triple: "x86_64-unknown-linux-gnu",
            },
            Build {
                platform: "linux-arm64",
                url: "https://static.rust-lang.org/rustup/archive/1.29.3/aarch64-unknown-linux-gnu/rustup-init",
                sha256: "9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282",
                triple: "aarch64-unknown-linux-gnu",
            },
            Build {
                platform: "darwin-x64",
                url: "https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-apple-darwin/rustup-init",
                sha256: "bc107f1fb0228de7fa32413c89c1b305cea9cd256e94b01150cd054128145429",
                triple: "x86_64-apple-darwin",
            },
            Build {
                platform: "darwin-arm64",
                url: "https://static.rust-lang.org/rustup/archive/1.29.3/aarch64-apple-darwin/rustup-init",
                sha256: "63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f",
                triple: "aarch64-apple-darwin",
            },
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_pins_the_four_platforms_with_a_sha256_and_an_https_url() {
        let platforms = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"];
        for p in PINS {
            for want in platforms {
                let b = p.builds.iter().find(|b| b.platform == want);
                let b = b.unwrap_or_else(|| panic!("{} has no {want} build", p.tool));
                assert_eq!(b.sha256.len(), 64, "{} {want}", p.tool);
                assert!(
                    b.sha256
                        .bytes()
                        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
                    "{} {want}",
                    p.tool
                );
                assert!(b.url.starts_with("https://"), "{} {want}", p.tool);
                assert_eq!(
                    p.kind == Kind::Installer,
                    !b.triple.is_empty(),
                    "{}",
                    p.tool
                );
            }
            assert_eq!(p.builds.len(), platforms.len(), "{}", p.tool);
        }
        assert_eq!(
            PINS.iter().find(|p| p.tool == "node").map(|p| p.version),
            Some("22.22.1")
        );
    }
}
