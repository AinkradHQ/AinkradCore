//! Test adapters: two kinds with data-only descriptors. `test` answers by the token's text.

use std::sync::Arc;

use futures_util::future::{BoxFuture, FutureExt};

use super::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity, KindAdapter, LimitKey, Registry, TestError,
};
use super::material::Material;

pub const FAKE: Descriptor = Descriptor {
    kind: "fake",
    title: "Fake service",
    summary: "A test double.",
    auth_methods: &[
        AuthMethodSpec {
            id: "oauth",
            title: "Sign in",
            help: "Sign in on the fake site.",
            steps: &["Open the site", "Approve"],
            advanced: false,
        },
        AuthMethodSpec {
            id: "token",
            title: "Token",
            help: "Paste a token.",
            steps: &["Make a token", "Paste it"],
            advanced: true,
        },
    ],
    capabilities: &[
        Capability {
            name: "read_items",
            title: "Read items",
            write: false,
            operations: &["fake.get_item", "fake.list_items"],
        },
        Capability {
            name: "write_items",
            title: "Change items",
            write: true,
            operations: &["fake.create_item"],
        },
    ],
    hosts: &["api.fake.test"],
    limits: &[LimitKey {
        key: "projects",
        title: "Projects",
        help: "Only these projects.",
    }],
    token_shapes: &["fake_token"],
    refresh_prefixes: &[],
    self_limited: &["fake.list_items"],
};

pub const OTHER: Descriptor = Descriptor {
    kind: "other",
    title: "Other service",
    summary: "A second test double.",
    auth_methods: &[AuthMethodSpec {
        id: "token",
        title: "Token",
        help: "Paste a token.",
        steps: &[],
        advanced: false,
    }],
    capabilities: &[Capability {
        name: "read_things",
        title: "Read things",
        write: false,
        operations: &["other.get_thing"],
    }],
    hosts: &["api.other.test"],
    limits: &[],
    token_shapes: &[],
    refresh_prefixes: &[],
    self_limited: &[],
};

pub struct Fake(pub &'static Descriptor);

impl KindAdapter for Fake {
    fn descriptor(&self) -> &Descriptor {
        self.0
    }

    /// `reject-*` is refused, `down-*` is inconclusive, anything else is `acct-<first 4>`.
    fn test<'a>(&'a self, m: &'a Material) -> BoxFuture<'a, Result<Identity, TestError>> {
        let t = m.access();
        let out = match t {
            _ if t.starts_with("reject-") => Err(TestError::Rejected),
            _ if t.starts_with("down-") => Err(TestError::Inconclusive),
            _ => Ok(Identity {
                subject: format!("acct-{}", &t[..4.min(t.len())]),
            }),
        };
        async move { out }.boxed()
    }
}

pub fn registry() -> Registry {
    let mut r = Registry::new();
    r.register(Arc::new(Fake(&FAKE))).unwrap();
    r.register(Arc::new(Fake(&OTHER))).unwrap();
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_are_valid_and_malformed_ones_are_refused() {
        assert_eq!(FAKE.problem(), None);
        assert_eq!(OTHER.problem(), None);
        assert_eq!(FAKE.read_only(), ["read_items"]);
        assert_eq!(
            FAKE.capability_of("fake.create_item").unwrap().name,
            "write_items"
        );
        assert!(FAKE.allows_host("API.fake.test") && !FAKE.allows_host("evil.test"));
        let bad = |d: Descriptor| d.problem().is_some();
        assert!(bad(Descriptor {
            kind: "Fake",
            ..FAKE
        }));
        assert!(bad(Descriptor {
            hosts: &["https://api.fake.test"],
            ..FAKE
        }));
        assert!(bad(Descriptor { hosts: &[], ..FAKE }));
        assert!(bad(Descriptor {
            capabilities: &[],
            ..FAKE
        }));
        const TWICE: &[Capability] = &[
            Capability {
                name: "a",
                title: "",
                write: false,
                operations: &["fake.x"],
            },
            Capability {
                name: "b",
                title: "",
                write: true,
                operations: &["fake.x"],
            },
        ];
        assert!(
            bad(Descriptor {
                capabilities: TWICE,
                ..FAKE
            }),
            "one operation, one capability"
        );
        const FOREIGN: &[Capability] = &[Capability {
            name: "a",
            title: "",
            write: false,
            operations: &["other.x"],
        }];
        assert!(
            bad(Descriptor {
                capabilities: FOREIGN,
                ..FAKE
            }),
            "an operation names its kind"
        );
        let mut r = registry();
        assert!(
            r.register(Arc::new(Fake(&FAKE))).is_err(),
            "a kind registers once"
        );
        assert_eq!(r.descriptors().len(), 2);
        let kinds: Vec<_> = Registry::builtin()
            .descriptors()
            .iter()
            .map(|d| d.kind)
            .collect();
        assert_eq!(kinds, ["github"]);
    }
}
