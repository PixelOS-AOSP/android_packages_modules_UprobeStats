//! UprobeStats library
pub mod bpf_map;
mod process;
mod resolver_impl;
pub mod task;
#[cfg(feature = "bridge-service")]
mod uprobestats_bridge_service;
#[cfg(feature = "binder-service")]
pub mod uprobestats_service;

use rustutils::android::system_properties;

/// Returns true if the build is a user build.
pub fn is_user_build() -> bool {
    if let Ok(Some(val)) = system_properties::read("ro.build.type") {
        return val == "user";
    }
    true
}
