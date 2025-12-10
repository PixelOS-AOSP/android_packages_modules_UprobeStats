//! DeviceProperties impl
use crate::is_user_build;
use uprobestats_core::device_properties::DeviceProperties;

#[derive(Default)]
pub(crate) struct DefaultDeviceProperties {}
impl DeviceProperties for DefaultDeviceProperties {
    fn is_user_build(&self) -> bool {
        is_user_build()
    }
}
