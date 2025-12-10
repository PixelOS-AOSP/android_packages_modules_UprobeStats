use anyhow::{anyhow, Result};
use statslog_uprobestats::{
    bind_service_locked_with_bal_flags_reported, bind_service_locked_with_bal_flags_uids_reported,
    disabled_launcher_activity_uids_reported, set_component_enabled_setting_reported,
};
use uprobestats_core::atom::{AtomWriter, CodegenAtom};

#[derive(Default)]
pub(crate) struct CodegenAtomWriter {}
impl AtomWriter<CodegenAtom> for CodegenAtomWriter {
    fn write(&mut self, atom: CodegenAtom) -> Result<()> {
        match atom {
            CodegenAtom::SetComponentEnabledSettingReported {
                package_name,
                class_name,
                new_state,
                calling_package_name,
                is_launcher_activity,
            } => set_component_enabled_setting_reported::stats_write(
                &package_name,
                &class_name,
                new_state,
                &calling_package_name,
                is_launcher_activity,
            ),
            CodegenAtom::DisabledLauncherActivityUidsReported {
                calling_uid,
                disabled_activity_uid,
            } => disabled_launcher_activity_uids_reported::stats_write(
                calling_uid,
                disabled_activity_uid,
            ),
            CodegenAtom::BindServiceLockedWithBalFlagsReported {
                intent_package,
                flags,
                calling_package,
                intent_action,
                intent_component_name_package,
                intent_component_name_class,
            } => bind_service_locked_with_bal_flags_reported::stats_write(
                &intent_package,
                flags,
                &calling_package,
                &intent_action,
                &intent_component_name_package,
                &intent_component_name_class,
            ),
            CodegenAtom::BindServiceLockedWithBalFlagsUidsReported { binder_uid, bindee_uid } => {
                bind_service_locked_with_bal_flags_uids_reported::stats_write(
                    binder_uid, bindee_uid,
                )
            }
        }
        .map_err(|e| anyhow!(e))
    }
}
