//! UprobeStats library
pub mod atom;
pub mod bpf_handler;
pub mod bpf_map;
mod bridge_service;
mod device_properties;
mod offsets;
mod process;
pub mod task;
pub mod uprobestats_service;

use rustutils::android::system_properties;
use std::ffi::c_int;

/// Returns true if the build is a user build.
pub fn is_user_build() -> bool {
    if let Ok(Some(val)) = system_properties::read("ro.build.type") {
        return val == "user";
    }
    true
}

// NDK function to get the current device API level
extern "C" {
    fn android_get_device_api_level() -> c_int;
}

/// Returns true if the build is at least SDK level CINNAMON_BUN (37).
pub fn is_at_least_cinnamon_bun() -> bool {
    // SAFETY: This is a NDK function that is available on all Android devices. Trivially safe to call.
    let level = unsafe { android_get_device_api_level() };
    level >= 37
}
