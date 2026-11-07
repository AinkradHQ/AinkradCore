//! C6: grants, limits and resources against an ORACLE. The oracle below restates the documented
//! rules (design §4, decision 7; PR #146) without calling the store's own helpers, then random
//! grants (user, role, agent), limits (exact, `owner/*`), resources (with `..`, empty segments,
//! case, percent-encoding, unicode) and callers are thrown at `resolve`. Access is never wider than
//! the intersection of what the user side and the agent side granted, the effective limits handed
//! to an adapter admit nothing the oracle refuses, and an ambiguous use is never guessed.
//!
//! A failing run prints its seed; `CORE_C6_SEED=<n>` replays that one.

use super::*;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from((self.0 >> 33) % n as u64).unwrap()
    }

    fn chance(&mut self, pct: usize) -> bool {
        self.below(100) < pct
    }

    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
}

fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("CORE_C6_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(s) => vec![s],
        None => default.to_vec(),
    }
}

/// A limit entry against a resource: exactly, or under `prefix/*` (one or more clean segments).
fn accepts(entry: &str, v: &str) -> bool {
    match entry.strip_suffix("/*") {
        Some(p) => {
            v.len() > p.len() + 1
                && v.starts_with(p)
                && v.as_bytes()[p.len()] == b'/'
                && v[p.len() + 1..]
                    .split('/')
                    .all(|s| !s.is_empty() && s != "." && s != "..")
        }
        None => entry == v,
    }
}

fn accepts_any(list: &[&str], v: &str) -> bool {
    list.iter().any(|e| accepts(e, v))
}

/// A resource name a use may carry: 1 to 128 of `[A-Za-z0-9._:/-]`, no empty or dot segment.
fn plain(v: &str) -> bool {
    (1..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        && v.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// A limit value a grant may carry (an independent restatement).
fn limit_ok(v: &str) -> bool {
    let body = v.strip_suffix("/*").unwrap_or(v);
    (1..=100).contains(&v.len())
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        && body
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

struct Gr {
    kind: &'static str,
    who: &'static str,
    caps: &'static [&'static str],
    limits: Option<Vec<&'static str>>,
}

const GRANTEES: [(&str, &str); 5] = [
    ("role", "member"),
    ("role", "admin"),
    ("user", "1"),
    ("agent", "bot"),
    ("agent", "other"),
];
const CAPSETS: [&[&str]; 3] = [
    &["read_items"],
    &["write_items"],
    &["read_items", "write_items"],
];
const ENTRIES: [&str; 10] = [
    "acme/*",
    "acme/app",
    "acme/app/x",
    "tools/*",
    "P1",
    "P2",
    "p1",
    "a/b/*",
    "a/*",
    "acme/app/*",
];
const RES: [&str; 40] = [
    "P1",
    "p1",
    "acme/app",
    "acme/app/x",
    "acme/other",
    "acme",
    "acme/",
    "tools/x",
    "tools/",
    "a/b/c",
    "a/b",
    "..",
    "acme/..",
    "acme/../tools/x",
    "acme//app",
    "acme/./app",
    "/acme/app",
    "acme/app/",
    "ACME/app",
    "acme%2Fapp",
    "acme%2e%2e/x",
    "acme/\u{ff41}pp",
    "acme/app\0",
    "acme/app ",
    "acme/app\n",
    "",
    "*",
    "acme/*",
    "tools/*",
    "a/b/*",
    "acme/app/..",
    "acme\\app",
    "tools/x/../../acme/app",
    "\u{ff41}/b",
    "acme/\u{e1}pp",
    "Acme/app",
    "P1/",
    "P1/x",
    "P2",
    "a/b/c/d",
];

/// What the oracle says a use comes to.
#[derive(Debug, PartialEq, Eq)]
enum Want {
    Code(&'static str),
    Conn(i64),
    /// Refused, whatever the reason.
    Refused,
}

struct Use<'a> {
    role: &'a str,
    agent: Option<&'a str>,
    allow: Option<&'a [String]>,
    cap: &'a str,
}

fn covers(grants: &[Gr], u: &Use<'_>, v: &str) -> bool {
    let reaches =
        |g: &Gr| g.caps.contains(&u.cap) && g.limits.as_ref().is_none_or(|l| accepts_any(l, v));
    let user_side = grants.iter().any(|g| {
        ((g.kind == "user" && g.who == "1") || (g.kind == "role" && g.who == u.role)) && reaches(g)
    });
    let agent_side = u.agent.is_none_or(|a| {
        grants
            .iter()
            .any(|g| g.kind == "agent" && g.who == a && reaches(g))
    });
    user_side && agent_side
}

fn expect(conns: &[(i64, Vec<Gr>)], default: Option<i64>, u: &Use<'_>, v: &str) -> Want {
    if u.agent.is_some() && u.allow.is_none() {
        return Want::Code("allowlist_required");
    }
    if u.allow.is_some_and(|l| !l.iter().any(|c| c == u.cap)) {
        return Want::Code("not_allowlisted");
    }
    if !plain(v) {
        return Want::Code("bad_request");
    }
    let hits: Vec<i64> = conns
        .iter()
        .filter(|(_, g)| covers(g, u, v))
        .map(|(id, _)| *id)
        .collect();
    match hits.as_slice() {
        [] => Want::Refused,
        [one] => Want::Conn(*one),
        many => match default.filter(|d| many.contains(d)) {
            Some(d) => Want::Conn(d),
            None => Want::Code("ambiguous"),
        },
    }
}

async fn one(seed: u64) {
    let mut r = Rng(seed);
    let fx = fx().await;
    let n = 1 + r.below(3);
    let mut conns: Vec<(i64, Vec<Gr>)> = Vec::new();
    for i in 0..n {
        let c = make(&fx, "fake", &format!("c{i}")).await;
        let mut pool = GRANTEES.to_vec();
        let mut grs = Vec::new();
        for _ in 0..2 + r.below(4) {
            let (kind, who) = pool.swap_remove(r.below(pool.len()));
            let caps = r.pick(&CAPSETS);
            let limits = r.chance(65).then(|| {
                let mut l = Vec::new();
                for _ in 0..=r.below(3) {
                    let e = r.pick(&ENTRIES);
                    if !l.contains(&e) {
                        l.push(e);
                    }
                }
                l
            });
            let wall: grants::Limits = limits
                .iter()
                .map(|l| {
                    (
                        "projects".to_owned(),
                        l.iter().map(|e| (*e).to_owned()).collect(),
                    )
                })
                .collect();
            let names: Vec<String> = caps.iter().map(|c| (*c).to_owned()).collect();
            let new = grants::NewGrant {
                grantee_kind: kind,
                grantee: who,
                capabilities: Some(&names),
                limits: &wall,
            };
            grants::set(&fx.pool, &fx.reg, c.id, &new, w(NOW))
                .await
                .unwrap_or_else(|e| panic!("seed {seed}: grant {kind}/{who}: {e}"));
            grs.push(Gr {
                kind,
                who,
                caps,
                limits,
            });
        }
        conns.push((c.id, grs));
    }
    let mut default = None;
    if r.chance(50) {
        let id = conns[r.below(n)].0;
        bind(&fx, id, ("workspace", "")).await;
        default = Some(id);
    }
    for probe in 0..40 {
        let role = r.pick(&["member", "admin"]);
        let agent = r.pick(&[None, Some("bot"), Some("bot"), Some("other"), Some("ghost")]);
        let all: Vec<String> = ["read_items", "write_items"]
            .iter()
            .filter(|_| r.chance(70))
            .map(|c| (*c).to_owned())
            .collect();
        let allow = (agent.is_some() || r.chance(25)).then_some(all.as_slice());
        let cap = r.pick(&["read_items", "write_items"]);
        let res = r.pick(&RES);
        let u = Use {
            role,
            agent,
            allow,
            cap,
        };
        let want = expect(&conns, default, &u, res);
        let ctx = Context {
            role,
            agent,
            allowlist: allow,
            resource: Some(("projects", res)),
            ..cx(cap)
        };
        let got = resolve::resolve(&fx.pool, &fx.reg, "fake", &ctx, NOW).await;
        let tag = format!(
            "seed {seed} probe {probe}: {role} {agent:?} {allow:?} {cap} on {res:?}, default {default:?}"
        );
        match (&want, got) {
            (Want::Conn(id), Ok(ok)) => {
                assert_eq!(ok.connection.id, *id, "{tag}");
                // The limits the adapter will be handed admit this resource, and nothing the
                // oracle refuses.
                let key = ok.limits.get("projects");
                let admit = |w: &str| key.is_none_or(|l| l.iter().any(|e| accepts(e, w)));
                assert!(
                    admit(res),
                    "{tag}: the effective limits refuse the use itself"
                );
                let mine = &conns.iter().find(|(c, _)| c == id).unwrap().1;
                for w in RES.iter().filter(|w| plain(w)) {
                    assert!(
                        !admit(w) || covers(mine, &u, w),
                        "{tag}: the effective limits {:?} admit {w:?}, wider than the grants",
                        ok.limits
                    );
                }
            }
            (Want::Conn(id), Err(e)) => panic!("{tag}: wanted {id}, refused: {e}"),
            (Want::Code(c), Err(e)) => assert_eq!(code::<()>(Err(e)), *c, "{tag}"),
            (Want::Refused, Err(e)) => {
                code::<()>(Err(e));
            }
            (want, Ok(ok)) => panic!(
                "{tag}: {want:?} but connection {} was used",
                ok.connection.id
            ),
        }
    }
}

#[tokio::test]
async fn resolve_is_never_wider_than_the_intersection_of_the_grants_whatever_the_resource() {
    for seed in seeds(&(1..=40).collect::<Vec<u64>>()) {
        one(seed).await;
    }
}

#[tokio::test]
async fn a_grant_takes_only_clean_limits_and_a_refused_one_changes_nothing() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let mut r = Rng(0xC6);
    let atoms = [
        "acme", "app", "..", ".", "", "*", "a b", "%2e", "\u{ff41}", "x\0", "A", "tools", "-", "_",
        ":", "\n",
    ];
    for i in 0..400 {
        let values: Vec<String> = (0..1 + r.below(3))
            .map(|_| {
                let mut s = (0..1 + r.below(4))
                    .map(|_| r.pick(&atoms))
                    .collect::<Vec<_>>()
                    .join("/");
                if r.chance(30) {
                    s.push_str("/*");
                }
                if r.chance(3) {
                    s = "x".repeat(101);
                }
                s
            })
            .collect();
        let wall = grants::Limits::from([("projects".to_owned(), values.clone())]);
        let new = grants::NewGrant {
            grantee_kind: "role",
            grantee: "member",
            capabilities: None,
            limits: &wall,
        };
        let before = grants::list(&fx.pool, 1, c.id).await.unwrap();
        let got = grants::set(&fx.pool, &fx.reg, c.id, &new, w(NOW)).await;
        let clean = values.iter().all(|v| limit_ok(v));
        assert_eq!(got.is_ok(), clean, "try {i}: {values:?}");
        if !clean {
            assert_eq!(code(got), "bad_request");
            assert_eq!(
                grants::list(&fx.pool, 1, c.id).await.unwrap(),
                before,
                "a refused grant changed the stored one: {values:?}"
            );
        }
    }
    // Whatever is stored is clean.
    for g in grants::list(&fx.pool, 1, c.id).await.unwrap() {
        assert!(g.limits["projects"].iter().all(|v| limit_ok(v)));
    }
    // More values than a key may hold, and a key the kind does not have.
    let many = grants::Limits::from([(
        "projects".to_owned(),
        (0..65).map(|i| format!("P{i}")).collect(),
    )]);
    let odd = grants::Limits::from([("repos".to_owned(), vec!["a/b".to_owned()])]);
    for wall in [many, odd] {
        let new = grants::NewGrant {
            grantee_kind: "role",
            grantee: "member",
            capabilities: None,
            limits: &wall,
        };
        assert_eq!(
            code(grants::set(&fx.pool, &fx.reg, c.id, &new, w(NOW)).await),
            "bad_request"
        );
    }
}
