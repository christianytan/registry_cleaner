//! Tiny FFI helpers, declared directly so the app needs no extra crates.

use std::os::raw::c_void;

// ---------------------------------------------------------------- elevation

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION_CLASS: i32 = 20; // TokenElevation

#[repr(C)]
struct TokenElevationInfo {
    elevation: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// True when the process holds an elevated (admin) token.
/// Deleting HKLM uninstall keys requires this.
pub fn is_elevated() -> bool {
    unsafe {
        let process = GetCurrentProcess();
        let mut token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut info = TokenElevationInfo { elevation: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<TokenElevationInfo>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && info.elevation != 0
    }
}

// ---------------------------------------------------------------- windows installer

const ERROR_MORE_DATA: u32 = 1403;
const ERROR_UNKNOWN_PRODUCT: u32 = 1605;
const ERROR_UNKNOWN_FEATURE: u32 = 1630;
const ERROR_UNKNOWN_COMPONENT: u32 = 1606;

#[link(name = "msi")]
extern "system" {
    fn MsiGetProductInfoW(
        product: *const u16,
        attribute: *const u16,
        buffer: *mut u16,
        buffer_len: *mut u32,
    ) -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Ask the Windows Installer database whether a product code is still registered.
/// `Some(true)`  -> the product is still installed
/// `Some(false)` -> the product is gone (its uninstall key is a ghost)
/// `None`        -> could not be determined, so do not judge the entry
pub fn msi_product_installed(product_code: &str) -> Option<bool> {
    let product = wide(product_code);
    let attribute = wide("ProductName");
    let mut buffer = vec![0u16; 1024];
    let mut len = (buffer.len() - 1) as u32;

    let code = unsafe {
        MsiGetProductInfoW(
            product.as_ptr(),
            attribute.as_ptr(),
            buffer.as_mut_ptr(),
            &mut len,
        )
    };

    match code {
        0 => Some(true),
        // The product exists but the name did not fit; that is still "installed".
        ERROR_MORE_DATA => Some(true),
        ERROR_UNKNOWN_PRODUCT | ERROR_UNKNOWN_FEATURE | ERROR_UNKNOWN_COMPONENT => Some(false),
        _ => None,
    }
}
