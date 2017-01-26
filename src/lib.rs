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

extern crate cryptobox;
extern crate libc;
extern crate proteus;

use cryptobox::{CBox, CBoxError, CBoxSession, Identity, IdentityMode};
use cryptobox::store::Store;
use cryptobox::store::file::FileStore;
use libc::{c_char, c_ushort, size_t, uint8_t, uint16_t};
use proteus::{DecodeError, EncodeError};
use proteus::keys::{self, PreKeyId, PreKeyBundle};
use proteus::session;
use std::borrow::Cow;
use std::ffi::CStr;
use std::fmt;
use std::mem;
use std::path::Path;
use std::{slice, str, u16};
use std::panic::{self, UnwindSafe};

mod log;

/// Variant of std::try! that returns the unwrapped error.
macro_rules! try_unwrap {
    ($expr:expr) => (match $expr {
        Ok(val)  => val,
        Err(err) => return From::from(err)
    })
}

#[repr(C)]
#[no_mangle]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CBoxIdentityMode {
    Complete = 0,
    Public   = 1
}

#[no_mangle]
pub extern
fn cbox_file_open(c_path: *const c_char, out: *mut *mut CBox<FileStore>) -> CBoxResult {
    catch_unwind(|| {
        let path = try_unwrap!(to_str(c_path, 4096));
        let cbox = try_unwrap!(CBox::file_open(&Path::new(path)));
        assign(out, Box::into_raw(Box::new(cbox)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_file_open_with(c_path:   *const c_char,
                       c_id:     *const uint8_t,
                       c_id_len: size_t,
                       c_mode:   CBoxIdentityMode,
                       out:      *mut *mut CBox<FileStore>) -> CBoxResult
{
    catch_unwind(|| {
        let path     = try_unwrap!(to_str(c_path, 4096));
        let id_slice = to_slice(c_id, c_id_len);
        let ident    = match try_unwrap!(Identity::deserialise(id_slice)) {
            Identity::Sec(i) => i.into_owned(),
            Identity::Pub(_) => return CBoxResult::IdentityError
        };
        let mode = match c_mode {
            CBoxIdentityMode::Complete => IdentityMode::Complete,
            CBoxIdentityMode::Public   => IdentityMode::Public
        };
        let cbox = try_unwrap!(CBox::file_open_with(&Path::new(path), ident, mode));
        assign(out, Box::into_raw(Box::new(cbox)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_close(b: *mut CBox<FileStore>) {
    debug_assert!(!b.is_null());
    catch_unwind(|| {
        unsafe { Box::from_raw(b); }
        CBoxResult::Success
    });
}

#[no_mangle]
pub extern
fn cbox_identity_copy(cbox: *const CBox<FileStore>, out: *mut *mut Vec<u8>) -> CBoxResult {
    catch_unwind(|| {
        let i = try_unwrap!(Identity::Sec(Cow::Borrowed(ptr2ref(cbox).identity())).serialise());
        assign(out, Box::into_raw(Box::new(i)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_session_save(b: *const CBox<FileStore>, s: *mut CBoxSession<FileStore>) -> CBoxResult {
    catch_unwind(move || {
        try_unwrap!(ptr2ref(b).session_save(ptr2mut(s)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_session_delete(cbox: *const CBox<FileStore>, c_sid: *const c_char) -> CBoxResult {
    catch_unwind(|| {
        let sid = try_unwrap!(to_str(c_sid, 1024));
        try_unwrap!(ptr2ref(cbox).session_delete(sid));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_random_bytes(_: *const CBox<FileStore>, n: size_t, out: *mut *mut Vec<u8>) -> CBoxResult {
    catch_unwind(|| {
        assign(out, Box::into_raw(Box::new(keys::rand_bytes(n as usize))));
        CBoxResult::Success
    })
}

// Prekeys //////////////////////////////////////////////////////////////////

#[no_mangle]
pub static CBOX_LAST_PREKEY_ID: c_ushort = u16::MAX;

#[no_mangle]
pub extern
fn cbox_new_prekey(cbox: *const CBox<FileStore>, pkid: uint16_t, out: *mut *mut Vec<u8>) -> CBoxResult {
    catch_unwind(|| {
        let bundle = try_unwrap!(ptr2ref(cbox).new_prekey(PreKeyId::new(pkid)));
        let bytes  = try_unwrap!(bundle.serialise());
        assign(out, Box::into_raw(Box::new(bytes)));
        CBoxResult::Success
    })
}

// Session //////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern fn cbox_session_init_from_prekey
    (cbox:         *const CBox<FileStore>,
     c_sid:        *const c_char,
     c_prekey:     *const uint8_t,
     c_prekey_len: size_t,
     out:          *mut *mut CBoxSession<FileStore>) -> CBoxResult
{
    catch_unwind(|| {
        let sid     = try_unwrap!(to_str(c_sid, 1024));
        let prekey  = to_slice(c_prekey, c_prekey_len);
        let session = try_unwrap!(ptr2ref(cbox).session_from_prekey(String::from(sid), prekey));
        assign(out, Box::into_raw(Box::new(session)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_session_init_from_message
    (cbox:         *const CBox<FileStore>,
     c_sid:        *const c_char,
     c_cipher:     *const uint8_t,
     c_cipher_len: size_t,
     c_sess:       *mut *mut CBoxSession<FileStore>,
     c_plain:      *mut *mut Vec<u8>) -> CBoxResult
{
    catch_unwind(|| {
        let sid    = try_unwrap!(to_str(c_sid, 1024));
        let env    = to_slice(c_cipher, c_cipher_len);
        let (s, v) = try_unwrap!(ptr2ref(cbox).session_from_message(String::from(sid), env));
        assign(c_plain, Box::into_raw(Box::new(v)));
        assign(c_sess, Box::into_raw(Box::new(s)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_session_load
    (cbox:  *const CBox<FileStore>,
     c_sid: *const c_char,
     out:   *mut *mut CBoxSession<FileStore>) -> CBoxResult
{
    catch_unwind(|| {
        let sid     = try_unwrap!(to_str(c_sid, 1024));
        let session = match try_unwrap!(ptr2ref(cbox).session_load(String::from(sid))) {
            None    => return CBoxResult::SessionNotFound,
            Some(s) => s
        };
        assign(out, Box::into_raw(Box::new(session)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_session_close(b: *mut CBoxSession<FileStore>) {
    debug_assert!(!b.is_null());
    catch_unwind(|| {
        unsafe { Box::from_raw(b); }
        CBoxResult::Success
    });
}

#[no_mangle]
pub extern fn cbox_encrypt
    (session:     *mut CBoxSession<FileStore>,
     c_plain:     *const uint8_t,
     c_plain_len: size_t,
     out:         *mut *mut Vec<u8>) -> CBoxResult
{
    catch_unwind(move || {
        let plain  = to_slice(c_plain, c_plain_len);
        let cipher = try_unwrap!(ptr2mut(session).encrypt(plain));
        assign(out, Box::into_raw(Box::new(cipher)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_decrypt
    (session:      *mut CBoxSession<FileStore>,
     c_cipher:     *const uint8_t,
     c_cipher_len: size_t,
     out:          *mut *mut Vec<u8>) -> CBoxResult
{
    catch_unwind(move || {
        let env   = to_slice(c_cipher, c_cipher_len);
        let plain = try_unwrap!(ptr2mut(session).decrypt(env));
        assign(out, Box::into_raw(Box::new(plain)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_fingerprint_local(b: *const CBox<FileStore>, out: *mut *mut Vec<u8>) -> CBoxResult {
    catch_unwind(|| {
        let fp = ptr2ref(b).fingerprint().into_bytes();
        assign(out, Box::into_raw(Box::new(fp)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_fingerprint_remote(session: *const CBoxSession<FileStore>, out: *mut *mut Vec<u8>) -> CBoxResult {
    catch_unwind(|| {
        let fp = ptr2ref(session).fingerprint_remote().into_bytes();
        assign(out, Box::into_raw(Box::new(fp)));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_is_prekey(c_prekey: *const uint8_t, c_prekey_len: size_t, id: *mut uint16_t) -> CBoxResult {
    catch_unwind(|| {
        let prekey = to_slice(c_prekey, c_prekey_len);
        let prekey = try_unwrap!(PreKeyBundle::deserialise(prekey));
        assign(id, prekey.prekey_id.value());
        CBoxResult::Success
    })
}

// CBoxVec //////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern fn cbox_vec_free(b: *mut Vec<u8>) {
    debug_assert!(!b.is_null());
    unsafe { Box::from_raw(b); }
}

#[no_mangle]
pub extern fn cbox_vec_data(v: *const Vec<u8>) -> *const uint8_t {
    ptr2ref(v).as_ptr()
}

#[no_mangle]
pub extern fn cbox_vec_len(v: *const Vec<u8>) -> size_t {
    ptr2ref(v).len() as size_t
}

// Unsafe ///////////////////////////////////////////////////////////////////

fn to_str<'r>(s: *const c_char, n: size_t) -> Result<&'r str, CBoxResult> {
    debug_assert!(!s.is_null());
    let slen =
        match unsafe { libc::strnlen(s, n) } {
            k if k == n => return Err(CBoxResult::NulError),
            k           => k + 1 // count \0-byte
        };
    let cstr = unsafe {
        let bytes = slice::from_raw_parts(s, slen);
        CStr::from_bytes_with_nul_unchecked(mem::transmute(bytes))
    };
    cstr.to_str().map_err(From::from)
}

#[inline]
fn to_slice<'r, A>(xs: *const A, len: size_t) -> &'r [A] {
    debug_assert!(!xs.is_null());
    unsafe {
        slice::from_raw_parts(xs, len as usize)
    }
}

#[inline]
fn assign<A>(to: *mut A, from: A) {
    debug_assert!(!to.is_null());
    unsafe { *to = from }
}

#[inline]
fn ptr2ref<'a, A>(p: *const A) -> &'a A {
    debug_assert!(!p.is_null());
    unsafe { &*p }
}

#[inline]
fn ptr2mut<'a, A>(p: *mut A) -> &'a mut A {
    debug_assert!(!p.is_null());
    unsafe { &mut *p }
}

// CBoxResult ///////////////////////////////////////////////////////////////

#[repr(C)]
#[no_mangle]
#[derive(Clone, Copy, Debug)]
pub enum CBoxResult {
    Success               = 0,
    StorageError          = 1,
    SessionNotFound       = 2,
    DecodeError           = 3,
    RemoteIdentityChanged = 4,
    InvalidSignature      = 5,
    InvalidMessage        = 6,
    DuplicateMessage      = 7,
    TooDistantFuture      = 8,
    OutdatedMessage       = 9,
    Utf8Error             = 10,
    NulError              = 11,
    EncodeError           = 12,
    IdentityError         = 13,
    PreKeyNotFound        = 14,
    Panic                 = 15,
    InitError             = 16,
    DegeneratedKey        = 17
}

impl<S: Store + fmt::Debug> From<CBoxError<S>> for CBoxResult {
    fn from(e: CBoxError<S>) -> CBoxResult {
        let _ = log::error(&e);
        match e {
            CBoxError::ProteusError(session::Error::RemoteIdentityChanged) => CBoxResult::RemoteIdentityChanged,
            CBoxError::ProteusError(session::Error::InvalidSignature)      => CBoxResult::InvalidSignature,
            CBoxError::ProteusError(session::Error::InvalidMessage)        => CBoxResult::InvalidMessage,
            CBoxError::ProteusError(session::Error::DuplicateMessage)      => CBoxResult::DuplicateMessage,
            CBoxError::ProteusError(session::Error::TooDistantFuture)      => CBoxResult::TooDistantFuture,
            CBoxError::ProteusError(session::Error::OutdatedMessage)       => CBoxResult::OutdatedMessage,
            CBoxError::ProteusError(session::Error::PreKeyNotFound(_))     => CBoxResult::PreKeyNotFound,
            CBoxError::ProteusError(session::Error::PreKeyStoreError(_))   => CBoxResult::StorageError,
            CBoxError::ProteusError(session::Error::DegeneratedKey)        => CBoxResult::DegeneratedKey,
            CBoxError::StorageError(_)                                     => CBoxResult::StorageError,
            CBoxError::DecodeError(_)                                      => CBoxResult::DecodeError,
            CBoxError::EncodeError(_)                                      => CBoxResult::EncodeError,
            CBoxError::IdentityError                                       => CBoxResult::IdentityError,
            CBoxError::InitError                                           => CBoxResult::InitError
        }
    }
}

impl From<str::Utf8Error> for CBoxResult {
    fn from(e: str::Utf8Error) -> CBoxResult {
        let _ = log::error(&e);
        CBoxResult::Utf8Error
    }
}

impl From<DecodeError> for CBoxResult {
    fn from(e: DecodeError) -> CBoxResult {
        let _ = log::error(&e);
        CBoxResult::DecodeError
    }
}

impl From<EncodeError> for CBoxResult {
    fn from(e: EncodeError) -> CBoxResult {
        let _ = log::error(&e);
        CBoxResult::EncodeError
    }
}

fn catch_unwind<F>(f: F) -> CBoxResult where F: FnOnce() -> CBoxResult + UnwindSafe {
    match panic::catch_unwind(f) {
        Ok(x)  => x,
        Err(_) => CBoxResult::Panic
    }
}
