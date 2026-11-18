//! Round-2 review fix (PR #303): a helper stopped at its wall clock (`design_limit`, which load can
//! cause) leaves the asset pending; a crash or a memory/CPU limit on the file is still a refusal.

use ainkrad_proto::v2::{Body, DesignChecked, ErrorCode, Reply, StreamError};

use super::verdict;

fn err(code: ErrorCode) -> Result<Body, StreamError> {
    Err(StreamError::new(code, "x"))
}

#[test]
fn only_a_verdict_on_the_file_decides_it() {
    let ok = Ok(Body::Result(Reply::DesignCheck(DesignChecked {
        ok: true,
        reason: None,
    })));
    assert_eq!(verdict(&ok), Some(true));
    assert_eq!(verdict(&err(ErrorCode::DesignFailed)), Some(false));
    assert_eq!(verdict(&err(ErrorCode::TooLarge)), Some(false));
    for later in [
        ErrorCode::DesignLimit,
        ErrorCode::SpawnFailed,
        ErrorCode::Busy,
        ErrorCode::Lost,
    ] {
        assert_eq!(verdict(&err(later)), None, "{later:?} decided the asset");
    }
}

#[test]
fn only_a_wall_clock_stop_counts_as_a_timeout() {
    use super::timed_out;
    assert!(timed_out(&err(ErrorCode::DesignLimit)));
    for other in [
        ErrorCode::DesignFailed,
        ErrorCode::Busy,
        ErrorCode::SpawnFailed,
        ErrorCode::Lost,
    ] {
        assert!(!timed_out(&err(other)), "{other:?} counted");
    }
}
