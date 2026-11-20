//! The pinned versions and their digests. A version goes here only after it is inside
//! `harness::compat`'s tested range (a test checks it); the digests come from Anthropic's release
//! manifest and from npm's `dist.integrity` for that exact version.

use super::{Build, Check, Pin, Tool};

pub(super) const PINS: &[Pin] = &[
    Pin {
        tool: Tool::Claude,
        version: "2.1.318",
        packed: false,
        builds: &[
            Build {
                platform: "darwin-arm64",
                url: "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/2.1.318/darwin-arm64/claude",
                check: Check::Sha256(
                    "677a2ea7bf576cedd20e191d973914ed8a41796f53a63b1923381ddc4d5b5e7d",
                ),
                entry: "claude",
            },
            Build {
                platform: "darwin-x64",
                url: "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/2.1.318/darwin-x64/claude",
                check: Check::Sha256(
                    "ee9c8577a528aa8efa478bf552b17efa40bb58aa4981d2913c13d383a4d409a4",
                ),
                entry: "claude",
            },
            Build {
                platform: "linux-arm64",
                url: "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/2.1.318/linux-arm64/claude",
                check: Check::Sha256(
                    "53a0d7e219d7b0804ecba5dbc002745e89f786cc946d2de85a6470d5b2d1fb06",
                ),
                entry: "claude",
            },
            Build {
                platform: "linux-x64",
                url: "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/2.1.318/linux-x64/claude",
                check: Check::Sha256(
                    "708c77b204db30086ff6f1ed34577bda03e1be74ced80557cbf7b54249ebf0bd",
                ),
                entry: "claude",
            },
        ],
    },
    Pin {
        tool: Tool::Codex,
        version: "0.167.1",
        packed: true,
        builds: &[
            Build {
                platform: "darwin-arm64",
                url: "https://registry.npmjs.org/@openai/codex/-/codex-0.167.1-darwin-arm64.tgz",
                check: Check::Sha512(
                    "IMUByWGPhdbJFZzuk18iIdF/mfd21cPwalRTp5vGYIsOCyv3SJGRY5snbzZd0zO37WGuNjfUvH/62LvQHqNT2A==",
                ),
                entry: "package/vendor/aarch64-apple-darwin/bin/codex",
            },
            Build {
                platform: "darwin-x64",
                url: "https://registry.npmjs.org/@openai/codex/-/codex-0.167.1-darwin-x64.tgz",
                check: Check::Sha512(
                    "SwJf87Qtuktk8qHSDsbNkjVjOerqQRCBgdrqw6gvAlF3tO8UizEp/Vs8qQVznNI1aJfFc6GoJLvcgBGVWVylDg==",
                ),
                entry: "package/vendor/x86_64-apple-darwin/bin/codex",
            },
            Build {
                platform: "linux-arm64",
                url: "https://registry.npmjs.org/@openai/codex/-/codex-0.167.1-linux-arm64.tgz",
                check: Check::Sha512(
                    "z13jj4X4GDk7CTd1kXHkhXC8Gj8zomd1jYsU2//0KjevbLelPxowWLSTqIcR1rarJCtzveBHsS8gR7B9pAWB0g==",
                ),
                entry: "package/vendor/aarch64-unknown-linux-musl/bin/codex",
            },
            Build {
                platform: "linux-x64",
                url: "https://registry.npmjs.org/@openai/codex/-/codex-0.167.1-linux-x64.tgz",
                check: Check::Sha512(
                    "qZteglyvMCj1QVymMyPyKdtw38HaXCv5gvw8WN+N0+JJstu3k/d8xiYj9ciL7OwFLhcujgP8bCGJgaREeqrHkw==",
                ),
                entry: "package/vendor/x86_64-unknown-linux-musl/bin/codex",
            },
        ],
    },
    Pin {
        tool: Tool::Opencode,
        version: "1.18.34",
        packed: true,
        builds: &[
            Build {
                platform: "darwin-arm64",
                url: "https://registry.npmjs.org/opencode-darwin-arm64/-/opencode-darwin-arm64-1.18.34.tgz",
                check: Check::Sha512(
                    "ioBEvc3nUA64waDIVsphh92LgJgyTbq+uRd0OurdqqT9WEI9rp4J7NrA24NfL6epCa1Xr06TnRx5+th9W3T/sA==",
                ),
                entry: "package/bin/opencode",
            },
            Build {
                platform: "darwin-x64",
                url: "https://registry.npmjs.org/opencode-darwin-x64/-/opencode-darwin-x64-1.18.34.tgz",
                check: Check::Sha512(
                    "o8KXQ4jP5zfEHJAYpCz5Ifs0aa5dX+26wyLbxHEvfyGJu8hrBoNiJed3PE0uiPIlHCrj5yzF0b6k5aWonaPcTw==",
                ),
                entry: "package/bin/opencode",
            },
            Build {
                platform: "linux-arm64",
                url: "https://registry.npmjs.org/opencode-linux-arm64/-/opencode-linux-arm64-1.18.34.tgz",
                check: Check::Sha512(
                    "ZSjqcH0MEbAzLEmkRC9Aop1PbWZxe2NuKONAE/x8MRQdjKdOepX7M50UpjbsNoiLMkP584Z98Mg4a42fJhouvA==",
                ),
                entry: "package/bin/opencode",
            },
            Build {
                platform: "linux-x64",
                url: "https://registry.npmjs.org/opencode-linux-x64/-/opencode-linux-x64-1.18.34.tgz",
                check: Check::Sha512(
                    "RTAMjCve4euxP2QKLuvRmdoW5J5DQK1DiZqt+7slfixyjAEi79QC2Df2oYKogibaAI4IEU8uzenoJeEl3k+UEw==",
                ),
                entry: "package/bin/opencode",
            },
        ],
    },
];
