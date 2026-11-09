//! Five-field cron in UTC: `minute hour day-of-month month day-of-week`, each field `*`, a value,
//! `a-b`, or a comma list of those, any of them with `/step`. Day-of-week is 0-7 (0 and 7 are
//! Sunday). As in classic cron, when both day fields are restricted a day matches if either does.
//! No names (`mon`, `jan`) and no `@daily` shorthands.

/// A parsed expression: one bit per allowed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cron {
    minutes: u64,
    hours: u64,
    days: u64,
    months: u64,
    weekdays: u64,
    days_any: bool,
    weekdays_any: bool,
}

fn field(text: &str, lo: u32, hi: u32) -> Result<(u64, bool), String> {
    let any = text == "*";
    let mut bits = 0u64;
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (
                r,
                s.parse::<u32>()
                    .map_err(|_| format!("bad step in {part:?}"))?,
            ),
            None => (part, 1),
        };
        if step == 0 {
            return Err(format!("step 0 in {part:?}"));
        }
        let (from, to) = match range {
            "*" => (lo, hi),
            r => match r.split_once('-') {
                Some((a, b)) => (num(a, part)?, num(b, part)?),
                None if part.contains('/') => (num(r, part)?, hi),
                None => (num(r, part)?, num(r, part)?),
            },
        };
        if from < lo || to > hi || from > to {
            return Err(format!("{part:?} is outside {lo}-{hi}"));
        }
        let mut v = from;
        while v <= to {
            bits |= 1 << v;
            v += step;
        }
    }
    Ok((bits, any))
}

fn num(s: &str, part: &str) -> Result<u32, String> {
    s.parse().map_err(|_| format!("bad number in {part:?}"))
}

impl Cron {
    pub fn parse(expr: &str) -> Result<Self, String> {
        let f: Vec<&str> = expr.split_whitespace().collect();
        let [minute, hour, day, month, weekday] = f[..] else {
            return Err(format!("{expr:?} is not five fields"));
        };
        let (minutes, _) = field(minute, 0, 59)?;
        let (hours, _) = field(hour, 0, 23)?;
        let (days, days_any) = field(day, 1, 31)?;
        let (months, _) = field(month, 1, 12)?;
        let (mut weekdays, weekdays_any) = field(weekday, 0, 7)?;
        if weekdays & (1 << 7) != 0 {
            weekdays = weekdays & !(1 << 7) | 1;
        }
        Ok(Self {
            minutes,
            hours,
            days,
            months,
            weekdays,
            days_any,
            weekdays_any,
        })
    }

    fn day_matches(&self, month: i64, day: i64, weekday: i64) -> bool {
        if self.months & (1 << month) == 0 {
            return false;
        }
        let by_day = self.days & (1 << day) != 0;
        let by_weekday = self.weekdays & (1 << weekday) != 0;
        match (self.days_any, self.weekdays_any) {
            (false, false) => by_day || by_weekday,
            (false, true) => by_day,
            (true, false) => by_weekday,
            (true, true) => true,
        }
    }

    /// The first matching minute strictly after `unix` (seconds), if there is one within eight
    /// years (`0 0 30 2 *` never matches).
    pub fn next_after(&self, unix: i64) -> Option<i64> {
        let start = (unix.div_euclid(60) + 1) * 60;
        let first_day = start.div_euclid(86_400);
        for day in first_day..first_day + 366 * 8 {
            let (month, dom) = month_day(day);
            let weekday = (day + 4).rem_euclid(7); // 1970-01-01 was a Thursday
            if !self.day_matches(month, dom, weekday) {
                continue;
            }
            let from = if day == first_day {
                start.rem_euclid(86_400) / 60
            } else {
                0
            };
            let slot = (from..24 * 60)
                .find(|m| self.hours & (1 << (m / 60)) != 0 && self.minutes & (1 << (m % 60)) != 0);
            if let Some(m) = slot {
                return Some(day * 86_400 + m * 60);
            }
        }
        None
    }
}

/// `(month, day of month)` of a day count since 1970-01-01 (Hinnant's civil-from-days).
fn month_day(days: i64) -> (i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    (if mp < 10 { mp + 3 } else { mp - 9 }, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{iso_of_unix, unix_secs};

    fn next(expr: &str, after: &str) -> String {
        let t = unix_secs(after).unwrap();
        iso_of_unix(Cron::parse(expr).unwrap().next_after(t).unwrap())
    }

    #[test]
    fn finds_the_next_matching_minute() {
        // 2026-10-30 is a Friday.
        assert_eq!(
            next("* * * * *", "2026-10-30T10:00:00Z"),
            "2026-10-30T10:01:00.000Z"
        );
        assert_eq!(
            next("*/15 * * * *", "2026-10-30T10:15:00Z"),
            "2026-10-30T10:30:00.000Z"
        );
        assert_eq!(
            next("30 9 * * *", "2026-10-30T10:00:00Z"),
            "2026-10-31T09:30:00.000Z"
        );
        assert_eq!(
            next("0 0 1 1 *", "2026-10-30T10:00:00Z"),
            "2027-01-01T00:00:00.000Z"
        );
        assert_eq!(
            next("0 12 * * 1", "2026-10-30T10:00:00Z"),
            "2026-11-02T12:00:00.000Z"
        );
        assert_eq!(
            next("0 12 * * 7", "2026-10-30T10:00:00Z"),
            "2026-11-01T12:00:00.000Z"
        );
        assert_eq!(
            next("0 0 29 2 *", "2026-10-30T10:00:00Z"),
            "2028-02-29T00:00:00.000Z"
        );
        assert_eq!(
            next("5,10-12 1 * * *", "2026-10-30T01:10:30Z"),
            "2026-10-30T01:11:00.000Z"
        );
        // Both day fields restricted: either matches (the 31st, or any Monday).
        assert_eq!(
            next("0 0 31 * 1", "2026-11-02T00:00:00Z"),
            "2026-11-09T00:00:00.000Z"
        );
    }

    #[test]
    fn refuses_what_is_not_cron() {
        for bad in [
            "",
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "*/0 * * * *",
            "a * * * *",
            "5-1 * * * *",
            "* * * * * *",
        ] {
            assert!(Cron::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Cron::parse("0 0 30 2 *").unwrap().next_after(0), None);
    }
}
