//! DE: Echte WER-Aufrufe; keine Simulation als Plattformnachweis ausgeben.
//! EN: Real WER calls; never present simulation as platform evidence.
#![allow(clippy::unwrap_used)]

use super::*;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::System::ErrorReporting::WER_FAULT_REPORTING_FLAG_NOHEAP;

#[test]
fn native_wer_noheap_is_confirmed_preserves_flags_and_is_idempotent() {
    assert_eq!(crate::wer::NOHEAP, WER_FAULT_REPORTING_FLAG_NOHEAP);
    let before = current_wer_flags().unwrap();
    suppress_wer_heap_reporting().unwrap();
    let after = current_wer_flags().unwrap();
    assert_eq!(after & before, before);
    assert_ne!(after & WER_FAULT_REPORTING_FLAG_NOHEAP, 0);
    suppress_wer_heap_reporting().unwrap();
    assert_eq!(current_wer_flags().unwrap(), after);
}

#[test]
fn native_wer_query_rejects_non_process_handles_and_failed_hresult() {
    let file = std::env::current_exe()
        .and_then(std::fs::File::open)
        .unwrap();
    assert!(wer_flags(file.as_raw_handle()).is_err());
    assert!(hresult(-1).is_err());
    assert!(hresult(1).is_err());
    assert!(hresult(0).is_ok());
}
