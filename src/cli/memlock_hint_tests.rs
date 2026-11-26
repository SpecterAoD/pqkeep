#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::io::localize;
use super::message;
use pqkeep::security::Lang;

#[test]
fn message_splits_into_both_languages() {
    let text = message();
    assert_eq!(text.matches(" / ").count(), 1, "{text}");
    let de = localize(&text, Lang::De);
    let en = localize(&text, Lang::En);
    assert!(de.starts_with("Geheimer Speicher"), "{de}");
    assert!(en.starts_with("secret memory"), "{en}");
    #[cfg(target_os = "linux")]
    for part in [&de, &en] {
        assert!(
            part.contains("cap_ipc_lock+ep") && part.contains("MiB"),
            "{part}"
        );
    }
}
