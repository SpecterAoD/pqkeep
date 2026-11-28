use crate::{Result, os, util};

/// Locks one or more memory regions to RAM.
///
/// The memory pages within the address range is guaranteed to stay in RAM
/// except for specials cases, such as hibernation and memory starvation. It
/// returns a [`LockGuard`], which [`unlock`]s the affected regions once
/// dropped.
///
/// # Parameters
///
/// - The range is `[address, address + size)`
/// - The address is rounded down to the closest page boundary.
/// - The size may not be zero.
/// - The size is rounded up to the closest page boundary, relative to the
///   address.
///
/// # Errors
///
/// - If an interaction with the underlying operating system fails, an error
///   will be returned.
/// - If size is zero,
///   [`Error::InvalidParameter`](crate::Error::InvalidParameter) will be
///   returned.
///
/// # Examples
///
/// ```
/// # fn main() -> region::Result<()> {
/// let data = [0; 100];
/// let _guard = region::lock(data.as_ptr(), data.len())?;
/// # Ok(())
/// # }
/// ```
#[inline]
pub fn lock<T>(address: *const T, size: usize) -> Result<LockGuard> {
  let (address, size) = util::round_to_page_boundaries(address, size)?;
  os::lock(address.cast(), size).map(|_| LockGuard::new(address, size))
}

/// Unlocks one or more memory regions from RAM.
///
/// Prefer [`lock`] with [`LockGuard`] when possible. This function is marked
/// `unsafe` because unlocking arbitrary pages can reverse another caller's
/// intentional locking and introduce paging hazards for critical data.
///
/// # Parameters
///
/// - The range is `[address, address + size)`
/// - The address is rounded down to the closest page boundary.
/// - The size may not be zero.
/// - The size is rounded up to the closest page boundary, relative to the
///   address.
///
/// # Errors
///
/// - If an interaction with the underlying operating system fails, an error
///   will be returned.
/// - If size is zero,
///   [`Error::InvalidParameter`](crate::Error::InvalidParameter) will be
///   returned.
///
/// # Safety
///
/// The caller must ensure the range is intentionally unlockable. On many
/// platforms, locking is tracked per page rather than per allocation, so
/// unlocking one mapping may unlock another mapping that shares the same page.
#[inline]
pub unsafe fn unlock<T>(address: *const T, size: usize) -> Result<()> {
  let (address, size) = util::round_to_page_boundaries(address, size)?;
  os::unlock(address.cast(), size)
}

/// A RAII implementation of a scoped lock.
///
/// When this structure is dropped (falls out of scope), the virtual lock will be
/// released.
#[must_use]
pub struct LockGuard {
  // DE/EN: Numerische OS-Adressen, niemals dereferenzieren / numeric OS addresses, never dereferenced.
  address: usize,
  size: usize,
}

impl LockGuard {
  #[inline(always)]
  fn new<T>(address: *const T, size: usize) -> Self {
    Self { address: address.addr(), size }
  }

  /// DE: Öffentlich leer, zum Aufbau im bereits gesperrten Ziel.
  /// EN: Public-empty guard for initialization in an already locked destination.
  #[inline]
  pub const fn empty() -> Self { Self { address: 0, size: 0 } }

  /// DE: Besitzt eine erfolgreiche native Sperre. EN: Owns a successful native lock.
  #[inline]
  pub const fn is_active(&self) -> bool { self.size != 0 }

  /// DE: Leeren Guard direkt befüllen; vorhandenes Eigentum niemals ersetzen.
  /// EN: Populate an empty guard in place without replacing existing ownership.
  ///
  /// # Errors
  /// DE/EN: Aktiver Guard, ungültige Spanne oder native Verweigerung / active guard,
  /// invalid range or native refusal. The guard stays unchanged on failure.
  #[inline]
  pub fn acquire<T>(&mut self, address: *const T, size: usize) -> Result<()> {
    if self.is_active() { return Err(crate::Error::InvalidParameter("active guard")); }
    let page = crate::page::size();
    if size == 0 || address.addr().checked_add(size).is_none()
      || size.checked_add(page - 1).and_then(|n| n.checked_add(page - 1)).is_none() {
      return Err(crate::Error::InvalidParameter("lock range"));
    }
    let (address, size) = util::round_to_page_boundaries(address, size)?;
    os::lock(address.cast(), size)?;
    self.address = address.addr();
    self.size = size;
    Ok(())
  }

  /// DE: Eigentum zwischen zwei Guards feldweise übertragen, ohne Gesamtrecord-Kopie.
  /// EN: Exchange owned guards field by field, without moving a private aggregate record.
  #[inline]
  pub fn swap(&mut self, other: &mut Self) {
    core::mem::swap(&mut self.address, &mut other.address);
    core::mem::swap(&mut self.size, &mut other.size);
  }

  /// DE: Nur eigene Sperre freigeben; gespeicherte Felder vor Unlock löschen.
  /// EN: Release only this guard's lock; wipe retained fields before unlocking.
  ///
  /// # Errors
  /// DE/EN: Native Unlock-Verweigerung / native unlock refusal. Like Drop, the
  /// ownership is consumed; this never grants authority over an arbitrary range.
  #[inline]
  pub fn release(&mut self) -> Result<()> {
    use zeroize::Zeroize;
    if !self.is_active() { return Ok(()); }
    let address = self.address;
    let size = self.size;
    self.address.zeroize();
    self.size.zeroize();
    os::unlock(core::ptr::without_provenance(address), size)
  }
}

impl Drop for LockGuard {
  #[inline]
  fn drop(&mut self) {
    let result = self.release();
    debug_assert!(result.is_ok(), "unlocking region: {:?}", result);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tests::util::alloc_pages;
  use crate::{Protection, page};
  use core::mem;

  #[test]
  fn lock_mapped_pages_succeeds() -> Result<()> {
    let map = alloc_pages(&[Protection::READ_WRITE]);
    let _guard = lock(map.as_ptr(), page::size())?;
    Ok(())
  }

  #[test]
  fn unlock_mapped_pages_succeeds() -> Result<()> {
    let map = alloc_pages(&[Protection::READ_WRITE]);
    mem::forget(lock(map.as_ptr(), page::size())?);
    unsafe { unlock(map.as_ptr(), page::size()) }
  }
}
