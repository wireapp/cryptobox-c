// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

#![feature(catch_panic)]

extern crate cryptobox;
extern crate libc;
extern crate proteus;

use cryptobox::{CBox, CBoxError, CBoxSession, Identity, IdentityMode};
use cryptobox::store::Store;
use cryptobox::store::file::FileStore;
use libc::{c_char, c_ushort, size_t, uint8_t};
use proteus::{DecodeError, EncodeError};
use proteus::keys::{self, PreKeyId};
use proteus::session::DecryptError;
use std::borrow::Cow;
use std::ffi::{CStr, NulError};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::{slice, str, u16};
use std::thread::catch_panic;

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
    let c_path = AssertPanicSafe(c_path);
    let out    = AssertPanicSafe(out);
    recover(move || {
        let path = try_unwrap!(to_str(*c_path));
        let cbox = try_unwrap!(CBox::file_open(&Path::new(path)));
        assign(*out, Box::new(cbox));
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
    let c_path = AssertPanicSafe(c_path);
    let c_id   = AssertPanicSafe(c_id);
    let out    = AssertPanicSafe(out);
    recover(move || {
        let path     = try_unwrap!(to_str(*c_path));
        let id_slice = try_unwrap!(to_slice(*c_id, c_id_len as usize));
        let ident    = match try_unwrap!(Identity::deserialise(id_slice)) {
            Identity::Sec(i) => i.into_owned(),
            Identity::Pub(_) => return CBoxResult::IdentityError
        };
        let mode = match c_mode {
            CBoxIdentityMode::Complete => IdentityMode::Complete,
            CBoxIdentityMode::Public   => IdentityMode::Public
        };
        let cbox = try_unwrap!(CBox::file_open_with(&Path::new(path), ident, mode));
        assign(*out, Box::new(cbox));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_close(b: *mut CBox<FileStore>) {
    let b = AssertPanicSafe(b);
    recover(move || {
        unsafe { Box::from_raw(*b); }
        CBoxResult::Success
    });
}

#[no_mangle]
pub extern
fn cbox_identity_copy(cbox: &'static CBox<FileStore>, out: *mut *mut Vec<u8>) -> CBoxResult {
    let out = AssertPanicSafe(out);
    recover(move || {
        let i = try_unwrap!(Identity::Sec(Cow::Borrowed(cbox.identity())).serialise());
        assign(*out, Box::new(i));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_session_save(cbox: &'static CBox<FileStore>, s: &'static mut CBoxSession<'static, FileStore>) -> CBoxResult {
    recover(move || {
        try_unwrap!(cbox.session_save(s));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_session_delete(cbox: &'static CBox<FileStore>, c_sid: *const c_char) -> CBoxResult {
    let c_sid = AssertPanicSafe(c_sid);
    recover(move || {
        let sid = try_unwrap!(to_str(*c_sid));
        try_unwrap!(cbox.session_delete(sid));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_random_bytes(_: &CBox<FileStore>, n: size_t, out: *mut *mut Vec<u8>) -> CBoxResult {
    let out = AssertPanicSafe(out);
    recover(move || {
        assign(*out, Box::new(keys::rand_bytes(n as usize)));
        CBoxResult::Success
    })
}

// Prekeys //////////////////////////////////////////////////////////////////

#[no_mangle]
pub static CBOX_LAST_PREKEY_ID: c_ushort = u16::MAX;

#[no_mangle]
pub extern
fn cbox_new_prekey(cbox: &'static CBox<FileStore>, pkid: c_ushort, out: *mut *mut Vec<u8>) -> CBoxResult {
    let out  = AssertPanicSafe(out);
    recover(move || {
        let bundle = try_unwrap!(cbox.new_prekey(PreKeyId::new(pkid)));
        let bytes  = try_unwrap!(bundle.serialise());
        assign(*out, Box::new(bytes));
        CBoxResult::Success
    })
}

// Session //////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern fn cbox_session_init_from_prekey
    (cbox:         &'static CBox<FileStore>,
     c_sid:        *const c_char,
     c_prekey:     *const uint8_t,
     c_prekey_len: size_t,
     out:          *mut *mut CBoxSession<'static, FileStore>) -> CBoxResult
{
    let c_sid    = AssertPanicSafe(c_sid);
    let c_prekey = AssertPanicSafe(c_prekey);
    let out      = AssertPanicSafe(out);
    recover(move || {
        let sid     = try_unwrap!(to_str(*c_sid));
        let prekey  = try_unwrap!(to_slice(*c_prekey, c_prekey_len as usize));
        let session = try_unwrap!(cbox.session_from_prekey(String::from(sid), prekey));
        assign(*out, Box::new(session));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_session_init_from_message
    (cbox:         &'static CBox<FileStore>,
     c_sid:        *const c_char,
     c_cipher:     *const uint8_t,
     c_cipher_len: size_t,
     c_sess:       *mut *mut CBoxSession<'static, FileStore>,
     c_plain:      *mut *mut Vec<u8>) -> CBoxResult
{
    let c_sid    = AssertPanicSafe(c_sid);
    let c_cipher = AssertPanicSafe(c_cipher);
    let c_sess   = AssertPanicSafe(c_sess);
    let c_plain  = AssertPanicSafe(c_plain);
    recover(move || {
        let sid    = try_unwrap!(to_str(*c_sid));
        let env    = try_unwrap!(to_slice(*c_cipher, c_cipher_len as usize));
        let (s, v) = try_unwrap!(cbox.session_from_message(String::from(sid), env));
        assign(*c_plain, Box::new(v));
        assign(*c_sess, Box::new(s));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_session_load
    (cbox:  &'static CBox<FileStore>,
     c_sid: *const c_char,
     out:   *mut *mut CBoxSession<'static, FileStore>) -> CBoxResult
{
    let c_sid = AssertPanicSafe(c_sid);
    let out   = AssertPanicSafe(out);
    recover(move || {
        let sid     = try_unwrap!(to_str(*c_sid));
        let session = match try_unwrap!(cbox.session_load(String::from(sid))) {
            None    => return CBoxResult::SessionNotFound,
            Some(s) => s
        };
        assign(*out, Box::new(session));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_session_close(b: *mut CBoxSession<'static, FileStore>) {
    let b = AssertPanicSafe(b);
    recover(move || {
        unsafe { Box::from_raw(*b); }
        CBoxResult::Success
    });
}

#[no_mangle]
pub extern fn cbox_encrypt
    (session:     &'static mut CBoxSession<'static, FileStore>,
     c_plain:     *const uint8_t,
     c_plain_len: size_t,
     out:         *mut *mut Vec<u8>) -> CBoxResult
{
    let c_plain = AssertPanicSafe(c_plain);
    let out     = AssertPanicSafe(out);
    recover(move || {
        let plain  = try_unwrap!(to_slice(*c_plain, c_plain_len as usize));
        let cipher = try_unwrap!(session.encrypt(plain));
        assign(*out, Box::new(cipher));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern fn cbox_decrypt
    (session:      &'static mut CBoxSession<'static, FileStore>,
     c_cipher:     *const uint8_t,
     c_cipher_len: size_t,
     out:          *mut *mut Vec<u8>) -> CBoxResult
{
    let c_cipher = AssertPanicSafe(c_cipher);
    let out      = AssertPanicSafe(out);
    recover(move || {
        let env   = try_unwrap!(to_slice(*c_cipher, c_cipher_len as usize));
        let plain = try_unwrap!(session.decrypt(env));
        assign(*out, Box::new(plain));
        CBoxResult::Success
    })
}

#[no_mangle]
pub extern
fn cbox_fingerprint_local(b: &'static CBox<FileStore>, out: *mut *mut Vec<u8>) {
    let out = AssertPanicSafe(out);
    recover(move || {
        let fp = b.fingerprint().into_bytes();
        assign(*out, Box::new(fp));
        CBoxResult::Success
    });
}

#[no_mangle]
pub extern
fn cbox_fingerprint_remote(session: &'static CBoxSession<'static, FileStore>, out: *mut *mut Vec<u8>) {
    let out = AssertPanicSafe(out);
    recover(move || {
        let fp = session.fingerprint_remote().into_bytes();
        assign(*out, Box::new(fp));
        CBoxResult::Success
    });
}

// CBoxVec //////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern fn cbox_vec_free(b: *mut Vec<u8>) {
    unsafe { Box::from_raw(b); }
}

#[no_mangle]
pub extern fn cbox_vec_data(v: &Vec<u8>) -> *const uint8_t {
    v.as_ptr()
}

#[no_mangle]
pub extern fn cbox_vec_len(v: &Vec<u8>) -> size_t {
    v.len() as size_t
}

// Unsafe ///////////////////////////////////////////////////////////////////

#[cfg(not(target_os = "android"))]
fn to_str<'r>(s: *const c_char) -> Result<&'r str, str::Utf8Error> {
    unsafe { CStr::from_ptr(s).to_str() }
}

#[cfg(target_os = "android")]
#[cfg(any(target_arch = "arm", target_arch = "x86"))]
fn to_str<'r>(s: *const c_char) -> Result<&'r str, str::Utf8Error> {
    unsafe { CStr::from_ptr(s as *const i8).to_str() }
}

#[cfg(target_os = "android")]
#[cfg(target_arch = "aarch64")]
fn to_str<'r>(s: *const c_char) -> Result<&'r str, str::Utf8Error> {
    unsafe { CStr::from_ptr(s).to_str() }
}

fn to_slice<'r, A>(xs: *const A, len: usize) -> Result<&'r [A], CBoxResult> {
    unsafe { Ok(slice::from_raw_parts(xs, len)) }
}

fn assign<A>(to: *mut *mut A, from: Box<A>) {
    unsafe { *to = Box::into_raw(from) }
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
    Panic                 = 15
}

impl<S: Store + fmt::Debug> From<CBoxError<S>> for CBoxResult {
    fn from(e: CBoxError<S>) -> CBoxResult {
        let _ = log::error(&e);
        match e {
            CBoxError::DecryptError(DecryptError::RemoteIdentityChanged) => CBoxResult::RemoteIdentityChanged,
            CBoxError::DecryptError(DecryptError::InvalidSignature)      => CBoxResult::InvalidSignature,
            CBoxError::DecryptError(DecryptError::InvalidMessage)        => CBoxResult::InvalidMessage,
            CBoxError::DecryptError(DecryptError::DuplicateMessage)      => CBoxResult::DuplicateMessage,
            CBoxError::DecryptError(DecryptError::TooDistantFuture)      => CBoxResult::TooDistantFuture,
            CBoxError::DecryptError(DecryptError::OutdatedMessage)       => CBoxResult::OutdatedMessage,
            CBoxError::DecryptError(DecryptError::PreKeyNotFound(_))     => CBoxResult::PreKeyNotFound,
            CBoxError::DecryptError(DecryptError::PreKeyStoreError(_))   => CBoxResult::StorageError,
            CBoxError::StorageError(_)                                   => CBoxResult::StorageError,
            CBoxError::DecodeError(_)                                    => CBoxResult::DecodeError,
            CBoxError::EncodeError(_)                                    => CBoxResult::EncodeError,
            CBoxError::IdentityError                                     => CBoxResult::IdentityError
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

// catch_panic helpers //////////////////////////////////////////////////////

fn recover<F>(f: F) -> CBoxResult where F: FnOnce() -> CBoxResult + Send + 'static {
    match catch_panic(f) {
        Ok(x)  => x,
        Err(_) => CBoxResult::Panic
    }
}

struct AssertPanicSafe<T>(pub T);

unsafe impl<T> Send for AssertPanicSafe<T> {}

impl<T> Deref for AssertPanicSafe<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for AssertPanicSafe<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
