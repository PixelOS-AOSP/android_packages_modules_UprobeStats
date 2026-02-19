//! UprobeStats library
mod atom;
pub mod bpf_handler;
pub mod bpf_map;
#[cfg(feature = "bridge-service")]
mod bridge_service;
#[cfg(feature = "bridge-service")]
mod device_properties;
mod offsets;
mod process;
pub mod task;
pub mod uprobestats_service;

use rustutils::android::system_properties;

/// Returns true if the build is a user build.
pub fn is_user_build() -> bool {
    if let Ok(Some(val)) = system_properties::read("ro.build.type") {
        return val == "user";
    }
    true
}
