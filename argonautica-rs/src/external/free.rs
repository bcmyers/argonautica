#![allow(non_camel_case_types)]

use std::ffi::CString;

use libc::c_char;

/// Frees memory associated with a `char *` that was returned from `argonautica_hash`
#[no_mangle]
pub extern "C" fn argonautica_free(string: *mut c_char) {
    if string.is_null() {
        return;
    }
    unsafe { CString::from_raw(string) };
}
