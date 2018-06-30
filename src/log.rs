// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
