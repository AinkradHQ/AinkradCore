//! Tests of the credential envelope and the strict shapes of ids.

use super::*;

pub const TEAM: &str = "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b";
pub const OID: &str = "8ea0e38b-efb3-4757-924a-5f94061cf8c2";
pub const CH: &str = "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2";

#[test]
fn base32_round_trips_and_has_no_key_shape_characters() {
    for len in 0..40usize {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        assert_eq!(unb32(&b32(&bytes)).unwrap(), bytes, "{len}");
    }
    let jwt =
        "eyJ0eXAi.OiJKV1Qi_sk-AbCdEfGhIjKlMnOpQrStUv.sig-AIzaSyA1234567890123456789012345678901";
    let wrapped = b32(jwt.as_bytes());
    assert!(
        wrapped
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    );
    for bad in ["A", "ab=", "ab-", "a b", "ab9", "b"] {
        assert!(unb32(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn ids_are_strict() {
    assert!(guid(TEAM) && tenant_id(TEAM));
    let upper = TEAM.to_uppercase();
    for bad in [
        "",
        upper.as_str(),
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508",
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b ",
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b/..",
        "{fbe2bf47-16c8-47cf-b4a5-4b9b187c508b}",
        "fbe2bf4716c847cfb4a54b9b187c508b",
        "fbe2bf47_16c8_47cf_b4a5_4b9b187c508b",
        "%66be2bf47-16c8-47cf-b4a5-4b9b187c508b",
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508g",
    ] {
        assert!(!guid(bad), "{bad:?}");
    }
    assert!(!tenant_id(CONSUMER_TENANT));
    assert!(channel_id(CH));
    assert!(channel_id(
        "19:ZmNjZDMxYmQtYzA3Zi00MGQ5LTk4MTAtMzg0NTA4NTg4YjQ2\u{40}thread.skype"
    ));
    for bad in [
        "",
        "19:abc@thread.tacv2",
        "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.v2",
        "19:4a95f7d8db4c4e7fae857bcebe0623e6\u{40}unq.gbl.spaces",
        "19:meeting_4a95f7d8db4c4e7fae857bcebe0623e6@thread.v2",
        "20:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2",
        "19:4a95f7d8db4c4e7f/../e6@thread.tacv2",
        "19%3A4a95f7d8db4c4e7fae857bcebe0623e6%40thread.tacv2",
        "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2/messages",
        "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2?x=1",
        "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2 ",
        "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2\n",
        "19:4a95f7d8db4c4e7f@e857bcebe0623e6@thread.tacv2",
        TEAM,
        "general",
    ] {
        assert!(!channel_id(bad), "{bad:?}");
    }
    let key = channel_key(TEAM, CH).unwrap();
    assert_eq!(key, format!("{TEAM}/4a95f7d8db4c4e7fae857bcebe0623e6"));
    assert!(key_ok(&key));
    let old = channel_key(TEAM, "19:abcdefgh12345678\u{40}thread.skype").unwrap();
    assert!(old.ends_with(".skype") && key_ok(&old));
    assert_eq!(channel_key(&upper, CH), None);
    assert_eq!(channel_key(CH, TEAM), None, "swapped");
    let (slash, dots) = (format!("{TEAM}/"), format!("{TEAM}/../../x1234567"));
    for bad in ["", TEAM, "x/y", slash.as_str(), dots.as_str()] {
        assert!(!key_ok(bad), "{bad:?}");
    }
    assert!(message_id("1616990032035") && message_id("16169900320"));
    for bad in [
        "",
        "123",
        "16169900320a",
        "-1616990032035",
        "1616990032035 ",
    ] {
        assert!(!message_id(bad), "{bad:?}");
    }
    assert!(cursor("abcDEF-_09") && !cursor("a=b") && !cursor("a&b") && !cursor(""));
}

#[test]
fn the_credential_round_trips_prints_nothing_and_is_a_bearer() {
    let (a, r) = (
        "eyJhbGciOi.payload-111.sig-abc-222",
        "0.ARoA-refresh-token-333-444",
    );
    let m = oauth_material(TEAM, a, r, "2026-11-06T11:00:00.000Z").unwrap();
    for text in [format!("{m:?}"), format!("{m}")] {
        assert!(!text.contains("111") && !text.contains("333"), "{text}");
    }
    assert!(!m.access().contains("eyJ") && !m.refresh().unwrap().contains("0.AR"));
    let c = unpack(&m).unwrap();
    assert_eq!(c.tenant(), TEAM);
    assert_eq!(c.refresh(), r);
    assert!(!format!("{c:?}").contains("111"));
    let h = c.authorization().unwrap();
    assert!(h.is_sensitive() && !format!("{h:?}").contains("eyJ"));
    assert_eq!(h.to_str().unwrap(), format!("Bearer {a}"));
    assert_eq!(c.secrets(), vec![a.to_owned(), r.to_owned()]);
    for (t, x, y) in [
        ("not-a-tenant", a, r),
        (CONSUMER_TENANT, a, r),
        (TEAM, "short", r),
        (TEAM, a, "short"),
        (TEAM, "has a space in the access token", r),
    ] {
        assert!(
            oauth_material(t, x, y, "2026-11-06T11:00:00.000Z").is_none(),
            "{t} {x}"
        );
    }
    // What is stored is trusted no further than what would be accepted.
    let raw = Material::new(a, Some(r), None).unwrap();
    assert!(unpack(&raw).is_none());
    let other = Material::new(
        &format!("v1|not-a-tenant|{}", b32(a.as_bytes())),
        Some(&b32(r.as_bytes())),
        None,
    )
    .unwrap();
    assert!(unpack(&other).is_none());
    let none = Material::new(m.access(), None, None).unwrap();
    assert!(unpack(&none).is_none(), "no refresh token, no credential");
}

#[test]
fn identity_lines_name_ids_and_the_tenant_check_compares_ids() {
    let oid = "8ea0e38b-efb3-4757-924a-5f94061cf8c2";
    let line = subject(oid, TEAM);
    assert_eq!(tenant_of(&line), Some(TEAM));
    let (name, at) = (format!("{oid} in Contoso"), format!("{oid} at {TEAM}"));
    let bads = [
        "",
        TEAM,
        "Robin Kline in fbe2bf47-16c8-47cf-b4a5-4b9b187c508b",
        name.as_str(),
        at.as_str(),
    ];
    for bad in bads {
        assert_eq!(tenant_of(bad), None, "{bad}");
    }
    let other = "2432b57b-0abd-43db-aa7b-16eadd115d34";
    assert_eq!(check_tenant(Some(&line), TEAM), TenantCheck::Same);
    assert_eq!(check_tenant(Some(&line), other), TenantCheck::Different);
    assert_eq!(check_tenant(None, TEAM), TenantCheck::Unknown);
    let u2 = "11111111-2222-4333-8444-555555555555";
    assert_eq!(check_signer(Some(&line), oid, TEAM), SignerCheck::Same);
    assert_eq!(check_signer(Some(&line), u2, TEAM), SignerCheck::OtherUser);
    assert_eq!(
        check_signer(Some(&line), oid, other),
        SignerCheck::OtherTenant
    );
    assert_eq!(
        check_signer(Some(&line), u2, other),
        SignerCheck::OtherTenant
    );
    assert_eq!(check_signer(None, oid, TEAM), SignerCheck::Unknown);
    assert_eq!(
        check_signer(Some("Robin in Contoso"), oid, TEAM),
        SignerCheck::Unknown
    );
    assert_eq!(check_tenant(Some("Robin"), TEAM), TenantCheck::Unknown);
}

fn jwt(payload: &str) -> String {
    format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload))
}

#[test]
fn the_tenant_comes_from_an_id_token_issued_to_this_client() {
    let ok = jwt(&format!(
        r#"{{"aud":"cli-1","tid":"{TEAM}","oid":"{OID}"}}"#
    ));
    assert_eq!(id_token_tenant(&ok, "cli-1").as_deref(), Some(TEAM));
    assert_eq!(id_token_tenant(&ok, "cli-2"), None, "another audience");
    assert_eq!(
        id_token_claims(&ok, "cli-1"),
        Some((TEAM.to_owned(), OID.to_owned()))
    );
    let no_oid = jwt(&format!(r#"{{"aud":"cli-1","tid":"{TEAM}"}}"#));
    assert_eq!(
        id_token_claims(&no_oid, "cli-1"),
        None,
        "no user id, no sign-in"
    );
    for bad in [
        jwt(&format!(r#"{{"aud":"cli-1","tid":"{CONSUMER_TENANT}"}}"#)),
        jwt(r#"{"aud":"cli-1","tid":"contoso.onmicrosoft.com"}"#),
        jwt(r#"{"aud":"cli-1"}"#),
        jwt("not json"),
        "a.b".to_owned(),
        format!("{ok}.extra"),
        "x".repeat(20_000),
    ] {
        assert_eq!(id_token_tenant(&bad, "cli-1"), None, "{bad:.40}");
    }
}
