//! The plan's aggregates, kept honest (R17): rounded percentages, an ETA only from enough data,
//! a burndown that carries its scope. Counting leaf product tasks is the store's job.

/// Days of history before a pace means anything.
pub const MIN_PACE_DAYS: f64 = 3.0;

/// `done` over `total` as a whole percent, rounded half up; 0 with nothing to do.
pub fn percent(done: u32, total: u32) -> u32 {
    if total == 0 {
        return 0;
    }
    ((u64::from(done) * 100 + u64::from(total) / 2) / u64::from(total)) as u32
}

/// Whole days until `left` points are done at the pace of `done` points over `days`; `None`
/// before [`MIN_PACE_DAYS`] of data or before anything is done.
pub fn eta_days(left: u32, done: u32, days: f64) -> Option<u32> {
    if days < MIN_PACE_DAYS || done == 0 {
        return None;
    }
    Some((f64::from(left) / (f64::from(done) / days)).ceil() as u32)
}

/// Points left on a day: that day's scope less what was done by then.
pub fn left(scope: u32, done: u32) -> u32 {
    scope.saturating_sub(done)
}

/// Whether a label marks documentation work, which is not product progress.
pub fn is_docs_label(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "doc" | "docs" | "documentation"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_rounds_not_truncates() {
        assert_eq!(percent(3, 61), 5); // 4.9 %
        assert_eq!(percent(1, 3), 33);
        assert_eq!(percent(2, 3), 67);
        assert_eq!(percent(0, 0), 0);
        assert_eq!(percent(7, 7), 100);
    }

    #[test]
    fn eta_needs_three_days_and_progress() {
        assert_eq!(eta_days(7, 3, 2.0), None);
        assert_eq!(eta_days(7, 0, 5.0), None);
        // 3 points in 3 days is 1 a day: 7 left is 7 days.
        assert_eq!(eta_days(7, 3, 3.0), Some(7));
    }

    #[test]
    fn left_follows_the_days_scope() {
        assert_eq!(left(41, 3), 38);
        assert_eq!(left(2, 5), 0);
    }

    #[test]
    fn docs_labels() {
        assert!(is_docs_label("Docs") && is_docs_label("doc"));
        assert!(!is_docs_label("backend"));
    }
}
