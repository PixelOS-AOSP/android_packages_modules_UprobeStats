use super::{bytes_as_str, Handler};
use crate::is_user_build;
use crate::uprobestats_bridge_service::UPROBESTATS_BRIDGE_SERVICE;
use anyhow::{anyhow, Result};
use log::{debug, trace};
use statslog_uprobestats::{
    bind_service_locked_with_bal_flags_reported, bind_service_locked_with_bal_flags_uids_reported,
    disabled_launcher_activity_uids_reported, set_component_enabled_setting_reported,
};
use std::ffi::c_long;
use uprobestats_bpf_bindgen::{BindServiceLocked, ComponentEnabledSetting};
use uprobestats_core::config_resolver::ResolvedTask;

const COMPONENT_ENABLED_STATE_DISABLED: i32 = 2; // PackageManager#COMPONENT_ENABLED_STATE_DISABLED (all values greater than or equal to are disabled states)

#[derive(Default)]
pub struct ComponentEnabledSettingHandler {}

// SAFETY: `ComponentEnabledSetting` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for ComponentEnabledSettingHandler {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_ComponentEnabledSetting_output_buf";
    type T = ComponentEnabledSetting;
    fn on_item(&mut self, _task: &ResolvedTask, data: &ComponentEnabledSetting) -> Result<()> {
        let package_name = bytes_as_str(&data.package_name)?;
        let class_name = bytes_as_str(&data.class_name)?;
        let new_state = data.new_state;
        let calling_package_name = bytes_as_str(&data.calling_package_name)?;

        let service = UPROBESTATS_BRIDGE_SERVICE.as_ref().map_err(|e| anyhow!(e))?;
        let is_launcher_activity = service.isLauncherActivity(package_name, class_name, true)?;

        debug!("ComponentEnabledSetting: package_name={package_name:?}, class_name={class_name:?}, new_state={new_state:?}, calling_package_name={calling_package_name:?}, is_launcher_activity={is_launcher_activity}");

        if new_state < COMPONENT_ENABLED_STATE_DISABLED {
            return Ok(());
        }
        if !is_user_build() {
            set_component_enabled_setting_reported::stats_write(
                package_name,
                class_name,
                new_state,
                calling_package_name,
                is_launcher_activity,
            )?;
        }
        if is_launcher_activity {
            let calling_uid = if calling_package_name == "shell" {
                // special case for shell, needs com.android prepended
                service.getUidForPackage("com.android.shell")?
            } else {
                service.getUidForPackage(calling_package_name)?
            };
            trace!("uid for package: {calling_package_name} = {calling_uid}");
            let disabled_activity_uid = service.getUidForPackage(package_name)?;
            trace!("uid for package: {package_name} = {disabled_activity_uid}");
            disabled_launcher_activity_uids_reported::stats_write(
                calling_uid,
                disabled_activity_uid,
            )?;
        }
        Ok(())
    }
}

const BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS: c_long = 0x00100000; // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS

#[derive(Default)]
pub struct BindServiceLockedHandler {}

// SAFETY: `BindServiceLocked` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for BindServiceLockedHandler {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_BindServiceLocked_output_buf";
    type T = BindServiceLocked;
    fn on_item(&mut self, _task: &ResolvedTask, data: &BindServiceLocked) -> Result<()> {
        let intent_package = bytes_as_str(&data.intent_package)?;
        let intent_action = bytes_as_str(&data.intent_action)?;
        let intent_component_name_package = bytes_as_str(&data.intent_component_name_package)?;
        let intent_component_name_class = bytes_as_str(&data.intent_component_name_class)?;
        let flags = data.bind_flags;
        let calling_package = bytes_as_str(&data.calling_package)?;
        let has_bal_flag = (data.bind_flags & BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS) != 0;
        debug!(
            "BindServiceLocked: intent_package={intent_package:?}, intent_action={intent_action:?}, intent_component_name_package={intent_component_name_package:?}, intent_component_name_class={intent_component_name_class:?} flags={flags:?}, calling_package={calling_package:?}, has_bal_flag={has_bal_flag}"
        );
        if has_bal_flag {
            if !is_user_build() {
                bind_service_locked_with_bal_flags_reported::stats_write(
                    intent_package,
                    flags as _,
                    calling_package,
                    intent_action,
                    intent_component_name_package,
                    intent_component_name_class,
                )?;
            }

            let service = UPROBESTATS_BRIDGE_SERVICE.as_ref().map_err(|e| anyhow!(e))?;
            let binder_uid = service.getUidForPackage(calling_package)?;
            let bindee_uid = if intent_package.is_empty() {
                service.getUidForPackage(intent_component_name_package)?
            } else {
                service.getUidForPackage(intent_package)?
            };

            bind_service_locked_with_bal_flags_uids_reported::stats_write(binder_uid, bindee_uid)?;
        }
        Ok(())
    }
}
