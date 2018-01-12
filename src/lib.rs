use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::{mem, ptr};

const ROTATE: u32 = 'z' as u32 - 'a' as u32 + 1;

/// Frees the Rust-owned string in a safe way
#[no_mangle]
pub extern fn rot26_free(input: *mut c_char) {
    unsafe { CString::from_raw(input); }
}

/// Encrypts the input using rot26.
#[no_mangle]
pub extern fn rot26_encrypt(input: *const c_char) -> *const c_char {
    rot26_encrypt_any(input, 26)
}

/// Decrypts the input using rot26.
#[no_mangle]
pub extern fn rot26_decrypt(input: *const c_char) -> *const c_char {
    rot26_decrypt_any(input, 26)
}

/// Encrypts the input using rot13.
/// Warning: Security researchers have managed to crack rot13.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_encrypt_rot13(input: *const c_char) -> *const c_char {
    rot26_encrypt_any(input, 13)
}

/// Decrypts the input using rot13.
/// Warning: Security researchers have managed to crack rot13.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_decrypt_rot13(input: *const c_char) -> *const c_char {
    rot26_decrypt_any(input, 13)
}

/// Encrypt using any amount.
/// Warning: Please carefully choose the right amount.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_encrypt_any(input: *const c_char, amount: u32) -> *const c_char {
    let input = match unsafe { CStr::from_ptr(input).to_str() } {
        Ok(input) => input,
        Err(_) => return ptr::null()
    };
    let output: String = input.chars().map(|c| {
        let base = if c > 'a' && c < 'z' {
            'a' as u32
        } else if c > 'A' && c < 'Z' {
            'A' as u32
        } else {
            return c;
        };

        std::char::from_u32(((c as u32 - base + amount) % ROTATE) + base).unwrap()
    }).collect();
    let output = match CString::new(output) {
        Ok(output) => output,
        Err(_) => return ptr::null()
    };
    let ptr = output.as_ptr();
    mem::forget(output);
    ptr
}

/// Decrypt using any amount.
/// Warning: Please carefully choose the right amount.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_decrypt_any(input: *const c_char, amount: u32) -> *const c_char {
    let input = match unsafe { CStr::from_ptr(input).to_str() } {
        Ok(input) => input,
        Err(_) => return ptr::null()
    };
    let output: String = input.chars().map(|c| {
        let base = if c > 'a' && c < 'z' {
            'a' as u32
        } else if c > 'A' && c < 'Z' {
            'A' as u32
        } else {
            return c;
        };

        std::char::from_u32(((c as u32 - base + ROTATE - amount) % ROTATE) + base).unwrap()
    }).collect();
    let output = match CString::new(output) {
        Ok(output) => output,
        Err(_) => return ptr::null()
    };
    let ptr = output.as_ptr();
    mem::forget(output);
    ptr
}
