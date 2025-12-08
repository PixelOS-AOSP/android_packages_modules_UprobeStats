use crate::{
    atom::{AtomWriter, CodegenAtom},
    bpf_handler::Handler,
    bridge_service::UprobeStatsBridgeService,
    config_resolver::ResolvedTask,
    device_properties::DeviceProperties,
    string::bytes_as_str,
};
use anyhow::Result;
use log::{debug, trace};
use std::ffi::c_long;
use uprobestats_bpf_structs::{BindServiceLocked, ComponentEnabledSetting};

const COMPONENT_ENABLED_STATE_DISABLED: i32 = 2; // PackageManager#COMPONENT_ENABLED_STATE_DISABLED (all values greater than or equal to are disabled states)

/// Handler for component disabling events.
#[derive(Default)]
pub struct ComponentEnabledSettingHandler<A, B, D> {
    writer: A,
    bridge_service: B,
    device_properties: D,
}

// SAFETY: `ComponentEnabledSetting` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A, B, D> Handler for ComponentEnabledSettingHandler<A, B, D>
where
    A: AtomWriter<CodegenAtom>,
    B: UprobeStatsBridgeService,
    D: DeviceProperties,
{
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_ComponentEnabledSetting_output_buf";
    type T = ComponentEnabledSetting;
    fn on_item(&mut self, _task: &ResolvedTask, data: &ComponentEnabledSetting) -> Result<()> {
        let package_name = bytes_as_str(&data.package_name)?;
        let class_name = bytes_as_str(&data.class_name)?;
        let new_state = data.new_state;
        let calling_package_name = bytes_as_str(&data.calling_package_name)?;

        let service = self.bridge_service.get()?;
        let is_launcher_activity = service.isLauncherActivity(package_name, class_name, true)?;

        debug!("ComponentEnabledSetting: package_name={package_name:?}, class_name={class_name:?}, new_state={new_state:?}, calling_package_name={calling_package_name:?}, is_launcher_activity={is_launcher_activity}");

        if new_state < COMPONENT_ENABLED_STATE_DISABLED {
            return Ok(());
        }
        if !self.device_properties.is_user_build() {
            self.writer.write(CodegenAtom::SetComponentEnabledSettingReported {
                package_name: package_name.to_string(),
                class_name: class_name.to_string(),
                new_state,
                calling_package_name: calling_package_name.to_string(),
                is_launcher_activity,
            })?;
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
            self.writer.write(CodegenAtom::DisabledLauncherActivityUidsReported {
                calling_uid,
                disabled_activity_uid,
            })?;
        }
        Ok(())
    }
}

const BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS: c_long = 0x00100000; // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS

/// Handler for bind service with BAL events.
#[derive(Default)]
pub struct BindServiceLockedHandler<A, B, D> {
    writer: A,
    bridge_service: B,
    device_properties: D,
}

// SAFETY: `BindServiceLocked` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A, B, D> Handler for BindServiceLockedHandler<A, B, D>
where
    A: AtomWriter<CodegenAtom>,
    B: UprobeStatsBridgeService,
    D: DeviceProperties,
{
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
            if !self.device_properties.is_user_build() {
                self.writer.write(CodegenAtom::BindServiceLockedWithBalFlagsReported {
                    intent_package: intent_package.to_string(),
                    flags: flags as _,
                    calling_package: calling_package.to_string(),
                    intent_action: intent_action.to_string(),
                    intent_component_name_package: intent_component_name_package.to_string(),
                    intent_component_name_class: intent_component_name_class.to_string(),
                })?;
            }

            let service = self.bridge_service.get()?;
            let binder_uid = service.getUidForPackage(calling_package)?;
            let bindee_uid = if intent_package.is_empty() {
                service.getUidForPackage(intent_component_name_package)?
            } else {
                service.getUidForPackage(intent_package)?
            };

            self.writer.write(CodegenAtom::BindServiceLockedWithBalFlagsUidsReported {
                binder_uid,
                bindee_uid,
            })?;
        }
        Ok(())
    }
}
