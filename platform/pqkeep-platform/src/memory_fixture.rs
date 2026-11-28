//! DE: Ausschließlich lesende eigene Windows-Seitensperrprobe für native Tests.
//! EN: Read-only own Windows page-lock observation for native tests only.

use std::io;
use windows_sys::Win32::System::{
    ProcessStatus::{K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION},
    Threading::GetCurrentProcess,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Öffentlich leer konstruieren, vor der ersten Abfrage im Caller sperren.
/// EN: Construct public-empty and lock in the caller before the first query.
/// No Clone/Debug; the caller owns the stable protected query storage.
#[repr(C)]
pub struct MemoryLockQuery {
    address: usize,
    flags: usize,
}

// DE: Zwei native ABI-Wörter, kein Rust-Dereferenzieren der abgefragten Adresse.
// EN: Two native ABI words; Rust never dereferences the queried numeric address.
const _: () =
    assert!(size_of::<MemoryLockQuery>() == size_of::<PSAPI_WORKING_SET_EX_INFORMATION>());
const _: () =
    assert!(align_of::<MemoryLockQuery>() == align_of::<PSAPI_WORKING_SET_EX_INFORMATION>());

impl MemoryLockQuery {
    /// DE: Nur öffentliche Anfangswerte. EN: Only public initial values.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            address: 0,
            flags: 0,
        }
    }

    /// DE: Tatsächlichen Valid-/Locked-Status einer eigenen Seite lesen.
    /// EN: Read the actual Valid/Locked status of one own-process page.
    ///
    /// # Errors
    /// DE/EN: Native Abfrageverweigerung / native query refusal.
    pub fn is_locked(&mut self, address: usize) -> io::Result<bool> {
        self.address = address;
        self.flags.zeroize();
        let size = u32::try_from(size_of::<Self>()).map_err(|_| io::ErrorKind::InvalidInput)?;
        // DE: Initialisierte, ABI-geprüfte Wörter im exklusiven lebenden Caller-Record;
        // nur eigene Seiteneigenschaften, keine Inhalte und keine Pointeraufbewahrung.
        // SAFETY: repr(C), compile-checked ABI and fully initialized integer words.
        // The exclusive live request is writable for exactly size bytes. The API
        // queries only this process, retains no pointer and reads no page contents.
        let ok = unsafe {
            K32QueryWorkingSetEx(GetCurrentProcess(), std::ptr::from_mut(self).cast(), size)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // DE/EN: Locked ist nur bei Valid gültig / Locked is meaningful only if Valid.
        Ok(self.flags & 1 != 0 && self.flags & (1 << 22) != 0)
    }
}

impl Zeroize for MemoryLockQuery {
    fn zeroize(&mut self) {
        self.address.zeroize();
        self.flags.zeroize();
    }
}
impl Drop for MemoryLockQuery {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for MemoryLockQuery {}
