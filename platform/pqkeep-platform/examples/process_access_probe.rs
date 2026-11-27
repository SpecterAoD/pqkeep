//! DE: Öffentliche, ausdrücklich gestartete Prozessobjekt-Probe; kein Produktions-Gate.
//! Keine Threadsperre, Alt-Handle-Rücknahme, WER-/Dump-Garantie oder R7-Abnahme.
//! EN: Public explicitly invoked process-object probe, not a production gate.
//! No thread protection, existing-handle revocation, dump guarantee or R7 acceptance.

#[cfg(windows)]
mod windows {
    use std::io::{self, Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SetKernelObjectSecurity,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess};

    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    // DE: Nur QueryLimited/Terminate/Synchronize/ReadControl für den Besitzer.
    // EN: Owner gets QueryLimited/Terminate/Synchronize/ReadControl only.
    const POLICY: windows_sys::core::PCWSTR = windows_sys::w!("D:P(A;;0x00121001;;;OW)");

    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: Successful ConvertStringSecurityDescriptor allocated this exact
            // pointer with LocalAlloc; one owner, no use after this destructor.
            unsafe { LocalFree(self.0) };
        }
    }

    fn open(pid: u32, rights: u32) -> io::Result<OwnedHandle> {
        // SAFETY: Public process ID and documented access mask; never inherit.
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcess returned a new, valid, uniquely owned real handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    fn descriptor() -> io::Result<(Descriptor, u32)> {
        let (mut descriptor, mut length) = (std::ptr::null_mut(), 0);
        // SAFETY: Static NUL-terminated public SDDL, revision1, initialized exclusive
        // out parameters. The API allocates only on success; ownership goes to Descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                POLICY,
                1,
                &raw mut descriptor,
                &raw mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if descriptor.is_null() {
            return Err(io::Error::other("missing descriptor"));
        }
        Ok((Descriptor(descriptor), length))
    }

    fn restrict(handle: HANDLE) -> io::Result<()> {
        let (descriptor, length) = descriptor()?;
        if !(20..=256).contains(&length) {
            return Err(io::Error::other("unexpected public descriptor length"));
        }
        // SAFETY: Live own-process handle opened with WRITE_DAC; complete valid
        // descriptor retained through this synchronous call; no other object touched.
        if unsafe {
            SetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // DE/EN: Ausschließlich feste öffentliche Policybytes / fixed public policy only.
        let (mut actual, mut needed) = ([0u32; 64], 0);
        // SAFETY: Retained handle has READ_CONTROL. The initialized destination
        // is256bytes with DWORD alignment, exactly matching nLength;
        // out count is exclusively borrowed.
        if unsafe {
            GetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION,
                actual.as_mut_ptr().cast(),
                256,
                &raw mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Conversion reported a live allocation of length bytes; validated
        //20..=256 above; Descriptor retains ownership throughout this borrow.
        let expected =
            unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length as usize) };
        // SAFETY: Initialized64-DWORD array owns256bytes; u8 permits every
        // bit pattern and alignment; immutable view does not outlive the array.
        let actual = unsafe { std::slice::from_raw_parts(actual.as_ptr().cast::<u8>(), 256) };
        if needed != length || actual.get(..needed as usize) != Some(expected) {
            return Err(io::Error::other("process descriptor readback mismatch"));
        }
        Ok(())
    }

    fn target() -> io::Result<()> {
        // SAFETY: No arguments/pointers; returns only this process's public ID.
        let pid = unsafe { GetCurrentProcessId() };
        let handle = open(pid, READ_CONTROL | WRITE_DAC)?;
        restrict(handle.as_raw_handle())?;
        writeln!(io::stdout(), "READY {pid}")?;
        io::stdout().flush()?;
        // DE: Nur öffentlicher Steuerkanal, keine Geheimnisse; EOF beendet die Probe.
        // EN: Public control only, no secrets; EOF terminates the probe.
        let mut control = [0u8; 1];
        let _ = io::stdin().read(&mut control)?;
        Ok(())
    }

    fn inspect(pid: u32) -> io::Result<()> {
        for rights in [0x10, 0x20, 0x08, 0x40, 0x02, WRITE_DAC, 0x80000] {
            match open(pid, rights) {
                Ok(_) => {
                    return Err(io::Error::other(format!(
                        "sensitive process access allowed: {rights:#x}"
                    )));
                }
                Err(error) if error.raw_os_error() == Some(5) => (),
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "unexpected process query failure: {rights:#x}: {error}"
                    )));
                }
            }
        }
        let _query = open(pid, 0x1000 | 0x0010_0000)?;
        println!("PASS: sensitive access denied; limited query and synchronization allowed");
        Ok(())
    }

    pub(super) fn run() -> io::Result<()> {
        let mut args = std::env::args().skip(1);
        match (args.next().as_deref(), args.next()) {
            (Some("target"), None) => target(),
            (Some("inspect"), Some(pid)) if args.next().is_none() => inspect(
                pid.parse()
                    .map_err(|_| io::Error::other("invalid process ID"))?,
            ),
            _ => Err(io::Error::other("invalid public probe arguments")),
        }
    }
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    windows::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("DE/EN: Nur Windows-Prozessprobe / Windows process probe only");
    std::process::exit(2);
}
