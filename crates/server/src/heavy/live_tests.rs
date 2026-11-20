use super::copy_lock;

#[tokio::test]
async fn one_job_at_a_time_per_working_copy() {
    // M5: a second job on the same runner cache waits; another cache or runner does not.
    let held = copy_lock("d_lock", 7).lock_owned().await;
    assert!(copy_lock("d_lock", 7).try_lock().is_err());
    assert!(copy_lock("d_lock", 8).try_lock().is_ok());
    assert!(copy_lock("d_other", 7).try_lock().is_ok());
    drop(held);
    assert!(copy_lock("d_lock", 7).try_lock().is_ok());
}
