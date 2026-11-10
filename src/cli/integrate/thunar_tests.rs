#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::stamp;

#[test]
fn stamp_is_utc_date_and_time() {
    assert_eq!(stamp(0), "1970-01-01_0000");
    assert_eq!(stamp(951_868_800), "2000-03-01_0000");
    assert_eq!(stamp(1_709_251_140), "2024-02-29_2359");
    assert_eq!(stamp(1_794_319_679), "2026-11-10_1407");
}
