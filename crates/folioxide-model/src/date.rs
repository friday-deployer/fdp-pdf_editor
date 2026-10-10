//! Dates (ISO 32000-2 §7.9.4).
//!
//! A PDF date is a text string `D:YYYYMMDDHHmmSSOHH'mm`, where every field after the year is
//! optional (the month and day default to 01, the time fields to 00) and `O` is `Z` (UT), `+`
//! or `-` followed by the offset from UT. PDF 1.x writers put an apostrophe after the minutes
//! too (`+01'00'`); PDF 2.0 dropped it. [`PdfDate::parse`] reads both, and the variants found
//! in real files; [`PdfDate::to_pdf_string`] writes the full form.
//!
//! ```
//! use folioxide_model::PdfDate;
//!
//! let date = PdfDate::parse(b"D:20240229133005+05'30'").unwrap();
//! assert_eq!((date.year, date.month, date.day), (2024, 2, 29));
//! assert_eq!((date.hour, date.minute, date.second), (13, 30, 5));
//! assert_eq!(date.offset_minutes, Some(330));
//! assert_eq!(date.to_rfc3339(), "2024-02-29T13:30:05+05:30");
//! assert_eq!(date.to_pdf_string(), "D:20240229133005+05'30'");
//! ```

use std::fmt::Write as _;

use folioxide_syntax::Error;

/// The largest UT offset accepted, 23 hours 59 minutes, in minutes.
const MAX_OFFSET: i32 = 23 * 60 + 59;

/// A date and time from a PDF date string (§7.9.4).
///
/// Fields hold calendar values (`month` 1–12, `day` 1–31, `hour` 0–23, `minute` and `second`
/// 0–59); [`PdfDate::parse`] and [`PdfDate::new`] only produce valid dates. The struct is
/// `#[non_exhaustive]`: build one with [`PdfDate::new`] and [`PdfDate::with_offset`].
///
/// With the `serde` feature a date is its PDF date string ([`PdfDate::to_pdf_string`], for
/// example `"D:20240229133005+05'30'"`); deserializing parses it with [`PdfDate::parse`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "String", try_from = "String")
)]
pub struct PdfDate {
    /// The year, 0–9999.
    pub year: u16,
    /// The month, 1–12.
    pub month: u8,
    /// The day of the month, 1–31 (at most the length of the month).
    pub day: u8,
    /// The hour, 0–23.
    pub hour: u8,
    /// The minute, 0–59.
    pub minute: u8,
    /// The second, 0–59.
    pub second: u8,
    /// The offset of the local time from UT in minutes (east positive; `+05'30'` is 330), or
    /// `None` when the date does not say (§7.9.4: its relationship to UT is then unknown).
    /// `Z` is `Some(0)`.
    pub offset_minutes: Option<i32>,
}

impl PdfDate {
    /// A date with the given calendar fields and no UT offset, or `None` when a field is out of
    /// range (including a day past the end of its month; leap years follow the Gregorian
    /// calendar).
    ///
    /// ```
    /// use folioxide_model::PdfDate;
    ///
    /// let date = PdfDate::new(2024, 12, 31, 23, 59, 59).unwrap().with_offset(Some(-480)).unwrap();
    /// assert_eq!(date.to_pdf_string(), "D:20241231235959-08'00'");
    /// assert!(PdfDate::new(2023, 2, 29, 0, 0, 0).is_none());
    /// ```
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Self> {
        let date = PdfDate {
            year,
            month,
            day,
            hour,
            minute,
            second,
            offset_minutes: None,
        };
        date.is_valid().then_some(date)
    }

    /// This date with the UT offset `offset_minutes` (see [`PdfDate::offset_minutes`]), or
    /// `None` when the offset is more than 23 hours 59 minutes either way.
    #[must_use]
    pub fn with_offset(self, offset_minutes: Option<i32>) -> Option<Self> {
        let date = PdfDate {
            offset_minutes,
            ..self
        };
        date.is_valid().then_some(date)
    }

    /// Whether every field is in range.
    fn is_valid(&self) -> bool {
        self.year <= 9999
            && (1..=12).contains(&self.month)
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
            && self
                .offset_minutes
                .is_none_or(|m| (-MAX_OFFSET..=MAX_OFFSET).contains(&m))
    }

    /// Parses a PDF date string, leniently; `None` when `bytes` is not a date.
    ///
    /// Accepted, besides the standard form `D:YYYYMMDDHHmmSSOHH'mm`:
    ///
    /// - a missing `D:` prefix, and white-space or NUL bytes around the date;
    /// - partial dates: `YYYY`, `YYYYMM`, `YYYYMMDD`, `YYYYMMDDHH`, `YYYYMMDDHHmm` (§7.9.4
    ///   defaults: month and day 01, time fields 00), with or without an offset;
    /// - the offset as `Z`, `Z00'00'` (Acrobat), `+HH`, `+HH'mm`, `+HH'mm'` (PDF 1.x), `+HHmm`
    ///   or `+HH:mm`, and the same with `-`;
    /// - the ISO 8601 form some producers write, `YYYY-MM-DDTHH:mm:SS+HH:mm` (the date alone,
    ///   a space instead of `T`, seconds and offset optional). `YYYY-MM` is not taken for it:
    ///   that is a PDF year with a UT offset.
    ///
    /// Fields must be in range (a 13th month, a 30th of February or a 24th hour is not a date)
    /// and each field after the year must have exactly two digits. Text strings stored as
    /// UTF-16 must be decoded first (`text::decode_text_string`).
    ///
    /// ```
    /// use folioxide_model::PdfDate;
    ///
    /// let full = PdfDate::parse(b"D:20230115093000Z").unwrap();
    /// assert_eq!(full.offset_minutes, Some(0));
    /// let partial = PdfDate::parse(b"D:2023").unwrap();
    /// assert_eq!((partial.month, partial.day, partial.hour), (1, 1, 0));
    /// assert_eq!(partial.offset_minutes, None);
    /// assert_eq!(PdfDate::parse(b"2023-01-15T09:30:00-05:00").unwrap().offset_minutes, Some(-300));
    /// assert!(PdfDate::parse(b"D:20231301").is_none());
    /// assert!(PdfDate::parse(b"yesterday").is_none());
    /// ```
    pub fn parse(bytes: &[u8]) -> Option<PdfDate> {
        let trimmed = trim(bytes);
        let body = trimmed.strip_prefix(b"D:").unwrap_or(trimmed);
        let mut cur = Cursor { s: body, pos: 0 };
        let year = cur.number(4)?;
        let mut date = PdfDate {
            year: u16::try_from(year).ok()?,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            offset_minutes: None,
        };
        // `YYYY-MM-DD…` is ISO 8601; `YYYY-08'00'` stays a year with an offset.
        let iso = cur.peek() == Some(b'-')
            && cur.peek_at(1).is_some_and(|b| b.is_ascii_digit())
            && cur.peek_at(2).is_some_and(|b| b.is_ascii_digit())
            && cur.peek_at(3) == Some(b'-');
        if iso {
            parse_iso_rest(&mut date, &mut cur)?;
        } else {
            for field in [
                &mut date.month,
                &mut date.day,
                &mut date.hour,
                &mut date.minute,
                &mut date.second,
            ] {
                if !cur.peek().is_some_and(|b| b.is_ascii_digit()) {
                    break;
                }
                *field = u8::try_from(cur.number(2)?).ok()?;
            }
        }
        date.offset_minutes = cur.offset()?;
        // Writers that end every offset with an apostrophe sometimes add one more.
        while cur.peek() == Some(b'\'') {
            cur.pos += 1;
        }
        if cur.pos != body.len() {
            return None;
        }
        date.is_valid().then_some(date)
    }

    /// The date in the full PDF form `D:YYYYMMDDHHmmSS` followed by `Z` (offset 0), by
    /// `+HH'mm'` or `-HH'mm'`, or by nothing (offset unknown).
    ///
    /// The apostrophe after the minutes is the PDF 1.x form, which every reader accepts
    /// (ISO 32000-2 made it optional). Fields out of range, possible only when they were
    /// assigned directly, are clamped into range.
    pub fn to_pdf_string(&self) -> String {
        let d = self.clamped();
        let mut out = format!(
            "D:{:04}{:02}{:02}{:02}{:02}{:02}",
            d.year, d.month, d.day, d.hour, d.minute, d.second
        );
        match d.offset_minutes {
            None => {}
            Some(0) => out.push('Z'),
            Some(m) => {
                let sign = if m < 0 { '-' } else { '+' };
                let m = m.unsigned_abs();
                let _ = write!(out, "{sign}{:02}'{:02}'", m / 60, m % 60);
            }
        }
        out
    }

    /// The date in RFC 3339 form, `YYYY-MM-DDTHH:mm:SS` followed by `Z` or `+HH:mm`/`-HH:mm`.
    ///
    /// When the offset is unknown (`offset_minutes` is `None`), the result has no offset: an
    /// ISO 8601 local date-time, which RFC 3339 itself cannot express (its `-00:00` would claim
    /// the time is UT). Fields out of range are clamped as in [`PdfDate::to_pdf_string`].
    pub fn to_rfc3339(&self) -> String {
        let d = self.clamped();
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            d.year, d.month, d.day, d.hour, d.minute, d.second
        );
        match d.offset_minutes {
            None => {}
            Some(0) => out.push('Z'),
            Some(m) => {
                let sign = if m < 0 { '-' } else { '+' };
                let m = m.unsigned_abs();
                let _ = write!(out, "{sign}{:02}:{:02}", m / 60, m % 60);
            }
        }
        out
    }

    /// This date with every field forced into range.
    fn clamped(&self) -> PdfDate {
        let year = self.year.min(9999);
        let month = self.month.clamp(1, 12);
        PdfDate {
            year,
            month,
            day: self.day.clamp(1, days_in_month(year, month)),
            hour: self.hour.min(23),
            minute: self.minute.min(59),
            second: self.second.min(59),
            offset_minutes: self
                .offset_minutes
                .map(|m| m.clamp(-MAX_OFFSET, MAX_OFFSET)),
        }
    }
}

impl std::fmt::Display for PdfDate {
    /// The date as a PDF date string ([`PdfDate::to_pdf_string`]).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_pdf_string())
    }
}

impl std::str::FromStr for PdfDate {
    type Err = Error;

    /// Parses a PDF date string ([`PdfDate::parse`], lenient).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument) when `s` is
    /// not a date.
    fn from_str(s: &str) -> Result<PdfDate, Error> {
        PdfDate::parse(s.as_bytes()).ok_or_else(|| {
            let short: String = s.chars().take(40).collect();
            Error::invalid_argument(format!("{short:?} is not a PDF date (§7.9.4)"))
        })
    }
}

impl TryFrom<String> for PdfDate {
    type Error = Error;

    /// Parses a PDF date string; see [`PdfDate::from_str`](std::str::FromStr::from_str).
    fn try_from(s: String) -> Result<PdfDate, Error> {
        s.parse()
    }
}

impl From<PdfDate> for String {
    /// The date as a PDF date string ([`PdfDate::to_pdf_string`]).
    fn from(date: PdfDate) -> String {
        date.to_pdf_string()
    }
}

/// The number of days in `month` (1–12) of `year`, Gregorian calendar; 0 for an invalid month.
fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

/// `bytes` without leading and trailing white-space and NUL bytes.
fn trim(bytes: &[u8]) -> &[u8] {
    let junk = |b: &u8| b.is_ascii_whitespace() || *b == 0;
    let start = bytes.iter().position(|b| !junk(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !junk(b))
        .map_or(start, |p| p + 1);
    bytes.get(start..end).unwrap_or_default()
}

/// The rest of an ISO 8601 date after the year: `-MM-DD`, then optionally `T` or a space and
/// `HH:mm`, then optionally `:SS`.
fn parse_iso_rest(date: &mut PdfDate, cur: &mut Cursor<'_>) -> Option<()> {
    cur.expect(b'-')?;
    date.month = u8::try_from(cur.number(2)?).ok()?;
    cur.expect(b'-')?;
    date.day = u8::try_from(cur.number(2)?).ok()?;
    if !matches!(cur.peek(), Some(b'T' | b't' | b' ')) {
        return Some(());
    }
    cur.pos += 1;
    date.hour = u8::try_from(cur.number(2)?).ok()?;
    cur.expect(b':')?;
    date.minute = u8::try_from(cur.number(2)?).ok()?;
    if cur.peek() == Some(b':') {
        cur.pos += 1;
        date.second = u8::try_from(cur.number(2)?).ok()?;
    }
    Some(())
}

/// A position in the bytes of a date.
struct Cursor<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.s.get(self.pos.checked_add(ahead)?).copied()
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        (self.peek() == Some(byte)).then(|| self.pos += 1)
    }

    /// Exactly `digits` decimal digits as a number.
    fn number(&mut self, digits: usize) -> Option<u32> {
        let end = self.pos.checked_add(digits)?;
        let field = self.s.get(self.pos..end)?;
        if !field.iter().all(u8::is_ascii_digit) {
            return None;
        }
        self.pos = end;
        Some(field.iter().fold(0, |n, &d| n * 10 + u32::from(d - b'0')))
    }

    /// The UT offset: `Some(None)` when there is none, `None` when it is malformed.
    fn offset(&mut self) -> Option<Option<i32>> {
        match self.peek() {
            None | Some(b'\'') => Some(None),
            Some(b'Z' | b'z') => {
                self.pos += 1;
                // Acrobat writes `Z00'00'`: the zero offset again.
                while self
                    .peek()
                    .is_some_and(|b| b.is_ascii_digit() || b == b'\'' || b == b':')
                {
                    self.pos += 1;
                }
                Some(Some(0))
            }
            Some(sign @ (b'+' | b'-')) => {
                self.pos += 1;
                let hours = self.number(2)?;
                if matches!(self.peek(), Some(b'\'' | b':')) {
                    self.pos += 1;
                }
                let minutes = if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.number(2)?
                } else {
                    0
                };
                if hours > 23 || minutes > 59 {
                    return None;
                }
                let total = i32::try_from(hours * 60 + minutes).ok()?;
                Some(Some(if sign == b'-' { -total } else { total }))
            }
            Some(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(s: &str) -> PdfDate {
        PdfDate::parse(s.as_bytes()).unwrap_or_else(|| panic!("{s:?} should parse"))
    }

    #[test]
    fn standard_forms() {
        let d = date("D:19981223195200-08'00'");
        assert_eq!(
            (d.year, d.month, d.day, d.hour, d.minute, d.second),
            (1998, 12, 23, 19, 52, 0)
        );
        assert_eq!(d.offset_minutes, Some(-480));
        assert_eq!(date("D:19981223195200-08'00").offset_minutes, Some(-480));
        assert_eq!(date("D:19981223195200-0800").offset_minutes, Some(-480));
        assert_eq!(date("D:19981223195200-08").offset_minutes, Some(-480));
        assert_eq!(date("D:19981223195200+08:30").offset_minutes, Some(510));
        assert_eq!(date("D:19981223195200Z").offset_minutes, Some(0));
        assert_eq!(date("D:19981223195200Z00'00'").offset_minutes, Some(0));
        assert_eq!(date("D:19981223195200-00'00'").offset_minutes, Some(0));
        assert_eq!(date("D:19981223195200").offset_minutes, None);
    }

    #[test]
    fn partial_dates_use_the_defaults() {
        let cases = [
            ("D:2001", (2001, 1, 1, 0, 0, 0)),
            ("D:200105", (2001, 5, 1, 0, 0, 0)),
            ("D:20010531", (2001, 5, 31, 0, 0, 0)),
            ("D:2001053113", (2001, 5, 31, 13, 0, 0)),
            ("D:200105311307", (2001, 5, 31, 13, 7, 0)),
            ("200105311307+01", (2001, 5, 31, 13, 7, 0)),
        ];
        for (s, fields) in cases {
            let d = date(s);
            assert_eq!(
                (d.year, d.month, d.day, d.hour, d.minute, d.second),
                fields,
                "{s}"
            );
        }
        assert_eq!(date("D:2001Z").offset_minutes, Some(0));
    }

    #[test]
    fn rejects_non_dates() {
        for s in [
            "",
            "D:",
            "D:20",
            "D:2001-",
            "D:2001x",
            "D:200113",
            "D:20010230",
            "D:20230229",
            "D:2001010124",
            "D:200101010060",
            "D:20010101000060",
            "D:2001010100000",
            "D:20010101000000+24'00'",
            "D:20010101000000+01'60'",
            "D:20010101000000+1",
            "D:20010101000000 junk",
            "D:20010101000000+01'00'x",
            "2001-13-01",
            "2001-01-01T10",
        ] {
            assert_eq!(PdfDate::parse(s.as_bytes()), None, "{s:?}");
        }
        // Leap years follow the Gregorian rules.
        assert!(PdfDate::parse(b"D:20000229").is_some());
        assert!(PdfDate::parse(b"D:19000229").is_none());
        assert!(PdfDate::parse(b"D:20240229").is_some());
    }

    #[test]
    fn surrounding_junk_and_extra_apostrophes() {
        assert_eq!(date("  D:20200101\0\0").year, 2020);
        assert_eq!(date("D:20200101120000+01'00''").offset_minutes, Some(60));
        assert_eq!(date("D:20200101120000'").offset_minutes, None);
    }

    #[test]
    fn iso_8601_variants() {
        let d = date("2020-02-03 04:05");
        assert_eq!(
            (d.year, d.month, d.day, d.hour, d.minute, d.second),
            (2020, 2, 3, 4, 5, 0)
        );
        assert_eq!(date("2020-02-03T04:05:06Z").offset_minutes, Some(0));
        assert_eq!(date("D:2020-02-03T04:05:06+01:00").offset_minutes, Some(60));
        assert_eq!(date("2020-02-03").day, 3);
        // Not ISO 8601: a year with a UT offset.
        let d = date("2020-02");
        assert_eq!((d.year, d.month, d.offset_minutes), (2020, 1, Some(-120)));
        assert_eq!(date("D:2001-08'00'").offset_minutes, Some(-480));
    }

    #[test]
    fn formatting() {
        let d = date("D:20010203040506+05'30'");
        assert_eq!(d.to_pdf_string(), "D:20010203040506+05'30'");
        assert_eq!(d.to_rfc3339(), "2001-02-03T04:05:06+05:30");
        let utc = d.with_offset(Some(0)).unwrap();
        assert_eq!(utc.to_pdf_string(), "D:20010203040506Z");
        assert_eq!(utc.to_rfc3339(), "2001-02-03T04:05:06Z");
        let local = d.with_offset(None).unwrap();
        assert_eq!(local.to_pdf_string(), "D:20010203040506");
        assert_eq!(local.to_rfc3339(), "2001-02-03T04:05:06");
        let west = d.with_offset(Some(-(9 * 60 + 30))).unwrap();
        assert_eq!(west.to_pdf_string(), "D:20010203040506-09'30'");
        assert_eq!(west.to_rfc3339(), "2001-02-03T04:05:06-09:30");
        // What to_pdf_string writes parses back to the same date.
        for s in [d, utc, local, west] {
            assert_eq!(PdfDate::parse(s.to_pdf_string().as_bytes()), Some(s));
        }
        assert!(d.with_offset(Some(24 * 60)).is_none());
    }

    #[test]
    fn out_of_range_fields_are_clamped_when_formatting() {
        let mut d = PdfDate::new(2023, 2, 28, 0, 0, 0).unwrap();
        d.day = 31;
        d.month = 0;
        d.hour = 99;
        d.offset_minutes = Some(10_000);
        assert_eq!(d.to_pdf_string(), "D:20230131230000+23'59'");
        assert_eq!(d.to_rfc3339(), "2023-01-31T23:00:00+23:59");
    }
}
