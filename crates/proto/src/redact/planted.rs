//! One fake secret of each shape, with its kind: see [`PLANTED`].

/// One fake secret of each shape with its kind, shaped like the real thing but never valid:
/// for tests here and in the crates that redact.
pub const PLANTED: &[(&str, &str)] = &[
    (
        "anthropic_key",
        "sk-ant-api03-Zx9QWERTYuiopASDFghjkl0123456789-_abcdEF",
    ),
    ("openai_key", "sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ("openai_key", "sk-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ("google_key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"),
    ("github_token", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
    (
        "github_token",
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    ),
    (
        "linear_token",
        "lin_api_Zx9QWERTYuiopASDFghjkl0123456789abcdEF",
    ),
    (
        "linear_token",
        "lin_oauth_Zx9QWERTYuiopASDFghjkl0123456789abcdEF",
    ),
    // Split so the source holds no whole token, and with no digit groups; never valid.
    (
        "slack_token",
        concat!("xoxb", "-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    (
        "slack_token",
        concat!("xoxe.xoxp", "-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    (
        "slack_token",
        concat!("xoxe", "-1-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    (
        "slack_app_token",
        concat!("xapp", "-1-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    (
        "slack_app_token",
        concat!("xoxa", "-2-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    (
        "slack_app_token",
        concat!("xoxr", "-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    (
        "slack_app_token",
        concat!("xoxs", "-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ),
    ("aws_key", "AKIAIOSFODNN7EXAMPLE"),
    (
        "aws_secret",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    (
        "run_token",
        "cit_run_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    (
        "runner_key",
        "cit_runner_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    (
        "bearer",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
    ),
    (
        "pem_block",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
    ),
];
