//! `GET /api/v1/metrics` (E1-13.4): signed, `admin` only, Prometheus text, nothing identifying.

use super::*;

async fn text(app: &App, dev: Option<&TestDevice>) -> (StatusCode, String) {
    let res = router(app.clone())
        .oneshot(req(Method::GET, "/api/v1/metrics", dev, None))
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn metrics_need_a_signature_and_the_admin_scope() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(1000, 1.0),
    });
    // Unsigned, a stranger's signature, and a device without `admin`: no metrics, whatever the
    // listener (the loopback test router has no more trust than the public one).
    let stranger = fx.stranger();
    for dev in [None, Some(&stranger)] {
        let (s, body) = text(&fx.app, dev).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(!body.contains("ainkrad_"), "{body}");
    }
    for scopes in [&["read"][..], &["read", "approve", "agent", "terminal"][..]] {
        let weak = fx.enroll("weak", scopes).await;
        let (s, body) = text(&fx.app, Some(&weak)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{scopes:?}");
        assert!(!body.contains("ainkrad_"), "{body}");
    }
    let (s, _) = text(&fx.app, Some(&fx.dev)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn metrics_are_prometheus_text_with_no_names_or_ids() {
    let fx = fx().await;
    // A planted name and a push token must never surface.
    let planted = fx.enroll("planted-device-name-7f3a", &["read"]).await;
    let (s, body) = text(&fx.app, Some(&fx.dev)).await;
    assert_eq!(s, StatusCode::OK);
    for family in [
        "ainkrad_uptime_seconds",
        "ainkrad_events_head_seq",
        "ainkrad_audit_head_seq",
        "ainkrad_audit_head_age_seconds",
        "ainkrad_devices_active{kind=\"app\"} 2",
        "ainkrad_runners{state=\"connected\"} 0",
        "ainkrad_terminals{state=\"running\"} 0",
        "ainkrad_agent_sessions{state=\"running\"} 0",
        "ainkrad_jobs_lag_seconds 0",
        "ainkrad_http_responses_total{class=\"2xx\"}",
        "ainkrad_alarm_active{alarm=\"disk_free\"} 0",
    ] {
        assert!(body.contains(family), "{family} missing in:\n{body}");
    }
    assert!(!body.contains("planted-device-name") && !body.contains(&planted.id));
    assert!(
        !body.contains(&fx.dev.id) && !body.contains("test"),
        "no device names or ids"
    );
    // Every sample line is `name` or `name{label="word"}` and a number; HELP/TYPE before it.
    for line in body.lines().filter(|l| !l.starts_with('#')) {
        let (series, value) = line.rsplit_once(' ').unwrap();
        assert!(value.parse::<f64>().is_ok(), "{line}");
        let labels = series.split_once('{').map_or("", |(_, l)| l);
        assert!(
            labels.is_empty() || labels.matches('"').count() == 2,
            "one fixed label word: {line}"
        );
    }
    // The first answer is counted by the time the second is rendered.
    assert!(body.contains("class=\"2xx\"} 0"), "{body}");
    let (_, again) = text(&fx.app, Some(&fx.dev)).await;
    assert!(again.contains("class=\"2xx\"} 1"), "{again}");
}
