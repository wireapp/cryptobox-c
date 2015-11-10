// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use std::error::Error;
use std::io::Result;

pub fn error<E: Error>(e: &E) -> Result<()> {
    target::error(e)
}

// ANDROID //////////////////////////////////////////////////////////////////

#[cfg(target_os = "android")]
mod target {
    use libc::{c_char, c_int};
    use std::error::Error;
    use std::ffi::CStr;
    use std::io::Result;

    const TAG: &'static str = "CryptoBox\0";
    const LEVEL_ERROR: c_int = 6;

    pub fn error<E: Error>(e: &E) -> Result<()> {
        log(&format!("{}\0", e), LEVEL_ERROR)
    }

    #[cfg(any(target_arch = "arm", target_arch = "x86"))]
    fn log(msg: &str, lvl: c_int) -> Result<()> {
        unsafe {
            let tag = CStr::from_ptr(TAG.as_ptr() as *const i8);
            let msg = CStr::from_ptr(msg.as_ptr() as *const i8);
            __android_log_write(lvl, tag.as_ptr() as *const u8, msg.as_ptr() as *const u8);
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn log(msg: &str, lvl: c_int) -> Result<()> {
        unsafe {
            let tag = CStr::from_ptr(TAG.as_ptr());
            let msg = CStr::from_ptr(msg.as_ptr());
            __android_log_write(lvl, tag.as_ptr(), msg.as_ptr());
        }
        Ok(())
    }

    #[link(name = "log")]
    extern {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
}

// FALLBACK /////////////////////////////////////////////////////////////////

#[cfg(not(target_os = "android"))]
mod target {
    use std::error::Error;
    use std::io::{Write, stderr, Result};

    pub fn error<E: Error>(e: &E) -> Result<()> {
        writeln!(&mut stderr(), "ERROR: {}", e)
    }
}
