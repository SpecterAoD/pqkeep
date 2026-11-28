//! DE: Isolierte Plattform-FFI; Secret-Speicherbesitz bleibt im Root-Projekt.
//! EN: Isolated platform FFI; root retains ownership of protected secret storage.
#![deny(unsafe_op_in_unsafe_fn)]

mod wer;
pub use wer::WerFlags;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{current_wer_flags, is_console, suppress_wer_heap_reporting, write_console};
#[cfg(windows)]
mod console_input;
#[cfg(windows)]
mod console_input_mode;
#[cfg(windows)]
mod console_input_record;
#[cfg(windows)]
pub use console_input::{ConsoleInputEvent, read_console_input};
#[cfg(windows)]
pub use console_input_mode::ConsoleInputMode;
#[cfg(windows)]
pub use console_input_record::CONSOLE_INPUT_STORAGE;

#[cfg(all(windows, feature = "native-input-fixture"))]
pub mod input_fixture;

#[cfg(all(windows, feature = "native-memory-fixture"))]
pub mod memory_fixture;

#[cfg(windows)]
mod path_windows;
#[cfg(windows)]
pub use path_windows::{absolute_path_into, open_file_read};

#[cfg(any(target_os = "linux", windows))]
mod source_metadata;
#[cfg(any(target_os = "linux", windows))]
pub use source_metadata::SourceMetadata;
