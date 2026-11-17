//! Strict SVG path-data grammar (SVG 1.1 `d`): the only vector input the engine accepts (imported vectors are
//! fill/stroke only). Linear time, no recursion, no allocation beyond the cursor; total on any `&str`.

use crate::limits::{MAX_COORD, MAX_PATH_BYTES, MAX_PATH_SEGMENTS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError {
    pub at: usize,
    pub msg: &'static str,
}

fn err<T>(at: usize, msg: &'static str) -> Result<T, PathError> {
    Err(PathError { at, msg })
}

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl Cur<'_> {
    fn skip_sep(&mut self) {
        while self
            .b
            .get(self.i)
            .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0c))
        {
            self.i += 1;
        }
    }

    /// Whitespace and at most one comma between arguments.
    fn skip_arg_sep(&mut self) {
        self.skip_sep();
        if self.b.get(self.i) == Some(&b',') {
            self.i += 1;
            self.skip_sep();
        }
    }

    fn digits(&mut self) -> usize {
        let s = self.i;
        while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        self.i - s
    }

    /// `[+-]? (digits [. digits?] | . digits) ([eE][+-]?digits)?`, finite and within `MAX_COORD`.
    fn number(&mut self) -> Result<f64, PathError> {
        let start = self.i;
        if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
            self.i += 1;
        }
        let int = self.digits();
        let mut frac = 0;
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            frac = self.digits();
        }
        if int + frac == 0 {
            return err(start, "expected a number");
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return err(start, "bad exponent");
            }
        }
        // The slice is ASCII digits/signs/dot/e only, so it is valid UTF-8 and `f64::from_str` accepts it.
        let v: f64 = std::str::from_utf8(&self.b[start..self.i])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(PathError {
                at: start,
                msg: "bad number",
            })?;
        if !v.is_finite() || v.abs() > MAX_COORD {
            return err(start, "number out of range");
        }
        Ok(v)
    }

    /// Arc flags are a single `0` or `1`, and may be glued to the next number (`a1 1 0 00.5.5`).
    fn flag(&mut self) -> Result<(), PathError> {
        match self.b.get(self.i) {
            Some(b'0' | b'1') => {
                self.i += 1;
                Ok(())
            }
            _ => err(self.i, "arc flag must be 0 or 1"),
        }
    }
}

fn arity(cmd: u8) -> usize {
    match cmd.to_ascii_lowercase() {
        b'z' => 0,
        b'h' | b'v' => 1,
        b'm' | b'l' | b't' => 2,
        b's' | b'q' => 4,
        b'c' => 6,
        _ => 7, // a
    }
}

/// Validate path data; returns the number of segments. The first command must be `M`/`m`, numbers may only follow
/// a command that takes arguments, `z` takes none, arc flags are `0`/`1`.
pub fn validate(d: &str) -> Result<usize, PathError> {
    if d.len() > MAX_PATH_BYTES {
        return err(0, "path data too long");
    }
    let mut c = Cur {
        b: d.as_bytes(),
        i: 0,
    };
    c.skip_sep();
    if c.i == c.b.len() {
        return err(0, "empty path");
    }
    let mut segments = 0usize;
    let mut first = true;
    while c.i < c.b.len() {
        let cmd = c.b[c.i];
        if !b"MmLlHhVvCcSsQqTtAaZz".contains(&cmd) {
            return err(c.i, "expected a path command");
        }
        if first && !matches!(cmd, b'M' | b'm') {
            return err(c.i, "path must start with a moveto");
        }
        first = false;
        c.i += 1;
        let n = arity(cmd);
        let is_arc = cmd.eq_ignore_ascii_case(&b'a');
        if n == 0 {
            segments += 1;
        } else {
            // One mandatory group, then implicit repeats while the next token is not a command.
            let mut first_group = true;
            loop {
                c.skip_sep();
                if !first_group {
                    // between groups a comma is allowed only if more arguments follow
                    if c.i >= c.b.len() || c.b[c.i].is_ascii_alphabetic() {
                        break;
                    }
                }
                for k in 0..n {
                    if k > 0 {
                        c.skip_arg_sep();
                    } else if !first_group && c.b.get(c.i) == Some(&b',') {
                        c.i += 1;
                        c.skip_sep();
                    }
                    if is_arc && (k == 3 || k == 4) {
                        c.flag()?;
                    } else {
                        let v = c.number()?;
                        if is_arc && k < 2 && v < 0.0 {
                            return err(c.i, "negative arc radius");
                        }
                    }
                }
                first_group = false;
                segments += 1;
                if segments > MAX_PATH_SEGMENTS {
                    return err(c.i, "too many segments");
                }
            }
        }
        c.skip_sep();
        if segments > MAX_PATH_SEGMENTS {
            return err(c.i, "too many segments");
        }
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts() {
        assert_eq!(validate("M0 0L10 10z"), Ok(3));
        assert_eq!(validate("M 0,0 10,10 20,20"), Ok(3)); // implicit lineto
        assert_eq!(validate("m1.5e2-3.5.5.5Z"), Ok(3));
        assert_eq!(validate("M0 0a1 1 0 00.5.5"), Ok(2)); // glued flags
        assert_eq!(validate("M0 0 C1 2 3 4 5 6 7 8 9 10 11 12"), Ok(3));
        assert_eq!(validate("M0 0 h5 v5 H0 V0 z m1 1 l1 1 z"), Ok(9));
    }

    #[test]
    fn refuses() {
        for bad in [
            "",
            "  ",
            "L0 0",
            "M",
            "M0",
            "M0 0 L1",
            "M0 0 z 5",
            "M0 0 a1 1 0 2 0 1 1",
            "M0 0 a-1 1 0 0 0 1 1",
            "M0 0 X1 1",
            "M0 0 L1e999 1",
            "M0 0 L1e 1",
            "M0 0 L,1 1",
            "M0 0 L1,,1",
            "M0 0 L1 1,",
            "M NaN 0",
            "M0 0 L inf 1",
            "M0 0 L1 1 <script>",
            "M0 0 L2000000 0",
        ] {
            assert!(validate(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn limits() {
        assert!(validate(&format!("M0 0{}", "l1 1".repeat(20_000))).is_err());
        assert!(validate(&"M0 0 ".repeat(20_000)).is_err());
    }
}
