use super::root_warning_wanted;

/// DE: Die root-Warnung erscheint nur für root und nicht in Kindprozessen von Fensterabläufen.
/// EN: The root warning appears only for root and not in child processes of window flows.
#[test]
fn root_warning_only_for_root_outside_window_flows() {
    assert!(root_warning_wanted(true, false));
    assert!(!root_warning_wanted(false, false), "normal users get none");
    assert!(
        !root_warning_wanted(true, true),
        "would fake an incomplete result"
    );
    assert!(!root_warning_wanted(false, true));
}
