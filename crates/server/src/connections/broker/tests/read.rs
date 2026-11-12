//! A module's read (`Broker::read`): the owner's grants decide, there is no session, a write is
//! never run, and the answer is the same scrubbed one a tool call gets.

use super::*;

#[tokio::test]
async fn a_module_reads_with_the_owners_grant_and_never_writes() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    let args = json!({"repo": "acme/app", "number": 7});
    // No grant to the owner: refused, nothing went upstream.
    let e =
        f.b.read(&f.env(), 1, "d_test", "github.get_issue", &args)
            .await
            .unwrap_err();
    assert_eq!(e.code, "not_granted");
    assert!(f.gh.seen().is_empty());
    // The owner (role admin) grants read: it runs with the token.
    f.grant(c.id, ("role", "admin"), &["read_repo", "issues_write"], &[])
        .await;
    f.default(c.id).await;
    f.gh.push(200, &[], ISSUE);
    let v =
        f.b.read(&f.env(), 1, "d_test", "github.get_issue", &args)
            .await
            .unwrap();
    assert_eq!(v["title"], "Broken build");
    assert_eq!(
        f.gh.seen()[0].header("authorization"),
        Some(format!("Bearer {GH_TOKEN}").as_str())
    );
    // A write operation is never run through this door, even with the capability granted.
    let w = json!({"repo": "acme/app", "number": 7, "body": {"body": "hi"}});
    let e =
        f.b.read(&f.env(), 1, "d_test", "github.comment_issue", &w)
            .await
            .unwrap_err();
    assert_eq!(e.code, "not_a_read");
    assert_eq!(f.gh.seen().len(), 1);
    // The new review read is a read, built against the reviews path.
    f.gh.push(200, &[], "[]");
    f.b.read(&f.env(), 1, "d_test", "github.list_pr_reviews", &args)
        .await
        .unwrap();
    assert_eq!(f.gh.seen()[1].path, "/repos/acme/app/pulls/7/reviews");
    // Every use is recorded without a payload.
    let uses = f.uses().await;
    assert_eq!(
        uses.len(),
        3,
        "the refused write is not a use of any connection"
    );
    assert!(!uses.iter().any(|u| u.to_string().contains("Broken build")));
}
