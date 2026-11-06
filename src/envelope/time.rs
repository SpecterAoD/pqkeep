//! DE: Zeitstempel im strengen RFC-3339-Format `JJJJ-MM-TTThh:mm:ssZ` (nur UTC,
//! keine Sekundenbruchteile), ohne zusätzliche Crate. Umrechnung nach dem
//! bekannten „days from civil“-Verfahren (proleptischer gregorianischer Kalender).
//!
//! EN: Timestamps in strict RFC 3339 form `YYYY-MM-DDThh:mm:ssZ` (UTC only, no
//! fractional seconds), without an extra crate. Conversion uses the well-known
//! "days from civil" algorithm (proleptic Gregorian calendar).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

const MAX_YEAR: i64 = 9999;
const DAY: i64 = 86_400;

fn invalid() -> Error {
    Error::InvalidInput {
        field: "created_utc",
    }
}

/// DE: Aktuelle Zeit als RFC 3339. EN: Current time as RFC 3339.
#[must_use]
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_unix(i64::try_from(secs).unwrap_or(0))
}

/// DE: Unix-Sekunden → RFC 3339 (UTC). EN: Unix seconds → RFC 3339 (UTC).
#[must_use]
pub fn format_unix(secs: i64) -> String {
    let days = secs.div_euclid(DAY);
    let rem = secs.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// DE: RFC 3339 (streng, s. o.) → Unix-Sekunden.
/// EN: RFC 3339 (strict, see above) → Unix seconds.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] mit Feld `created_utc` / with field `created_utc`.
pub fn parse_rfc3339(text: &str) -> Result<i64> {
    let bytes = text.as_bytes();
    let shape_ok = bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z';
    if !shape_ok {
        return Err(invalid());
    }
    let num = |range: std::ops::Range<usize>| -> Result<i64> {
        let part = &bytes[range];
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(invalid());
        }
        Ok(part
            .iter()
            .fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0')))
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let valid = (1970..=MAX_YEAR).contains(&year)
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60;
    if !valid {
        return Err(invalid());
    }
    Ok(days_from_civil(year, month, day) * DAY + hour * 3600 + minute * 60 + second)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// DE: Tage seit 1970-01-01 für ein Datum. EN: Days since 1970-01-01 for a date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// DE: Datum für Tage seit 1970-01-01. EN: Date for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}
