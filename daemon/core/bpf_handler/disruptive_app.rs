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

        if new_state < COMPONENT_ENABLED_STATE_DISABLED {
            return Ok(());
        }

        let service = self.bridge_service.get()?;
        let is_launcher_activity = service.isLauncherActivity(package_name, class_name, true)?;

        debug!("ComponentEnabledSetting: package_name={package_name:?}, class_name={class_name:?}, new_state={new_state:?}, calling_package_name={calling_package_name:?}, is_launcher_activity={is_launcher_activity}");
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        atom::{test::TestAtomWriter, CodegenAtom},
        bridge_service::test::TestUprobeStatsBridgeService,
        config_resolver::ResolvedTask,
        device_properties::test::TestDeviceProperties,
    };
    use anyhow::Result;
    use mockall::predicate::*;
    use std::collections::HashSet;
    use std::ffi::c_long;
    use std::sync::{Arc, Mutex};
    use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::IUprobeStatsBridgeService::MockIUprobeStatsBridgeService;
    use uprobestats_proto::config::uprobestats_config::Task;
    use zerocopy::FromBytes;

    fn setup_component_handler(
        mock_bridge: MockIUprobeStatsBridgeService,
        is_user_build: bool,
    ) -> (
        ComponentEnabledSettingHandler<
            TestAtomWriter<CodegenAtom>,
            TestUprobeStatsBridgeService,
            TestDeviceProperties,
        >,
        ResolvedTask,
    ) {
        let test_bridge = TestUprobeStatsBridgeService { mock: Arc::new(Mutex::new(mock_bridge)) };
        let device_properties = TestDeviceProperties { is_user_build };
        let handler = ComponentEnabledSettingHandler {
            writer: TestAtomWriter::<CodegenAtom>::default(),
            bridge_service: test_bridge,
            device_properties,
        };
        let task = ResolvedTask {
            task: Task::new(),
            pid: 0,
            uid: 0,
            process_name: "".to_string(),
            duration_seconds: 0,
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
        };
        (handler, task)
    }

    fn create_component_enabled_setting(
        package_name: &str,
        class_name: &str,
        new_state: i32,
        calling_package_name: &str,
    ) -> ComponentEnabledSetting {
        let mut data = ComponentEnabledSetting {
            package_name: [0; 128],
            class_name: [0; 128],
            new_state: 0,
            calling_package_name: [0; 128],
        };
        let package_name_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(package_name.as_bytes()).unwrap();
        data.package_name[..package_name_bytes.len()].copy_from_slice(package_name_bytes);

        let class_name_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(class_name.as_bytes()).unwrap();
        data.class_name[..class_name_bytes.len()].copy_from_slice(class_name_bytes);

        data.new_state = new_state;

        let calling_package_name_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(calling_package_name.as_bytes()).unwrap();
        data.calling_package_name[..calling_package_name_bytes.len()]
            .copy_from_slice(calling_package_name_bytes);
        data
    }

    #[test]
    fn component_enabled_setting_enabled_is_ignored() -> Result<()> {
        let (mut handler, task) =
            setup_component_handler(MockIUprobeStatsBridgeService::new(), false);
        let data = create_component_enabled_setting("pkg", "cls", 1, "caller");
        handler.on_item(&task, &data)?;
        assert!(handler.writer.written.is_empty());
        Ok(())
    }

    #[test]
    fn component_enabled_setting_user_build() -> Result<()> {
        const CALLING_PKG: &str = "caller";
        const DISABLED_PKG: &str = "pkg";
        const CALLING_UID: i32 = 123;
        const DISABLED_UID: i32 = 456;

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_isLauncherActivity().returning(|_, _, _| Ok(true));
        mock_bridge.expect_getUidForPackage().with(eq(CALLING_PKG)).returning(|_| Ok(CALLING_UID));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(DISABLED_PKG))
            .returning(|_| Ok(DISABLED_UID));

        let (mut handler, task) =
            setup_component_handler(mock_bridge, true /* is_user_build */);
        let data = create_component_enabled_setting(
            DISABLED_PKG,
            "cls",
            COMPONENT_ENABLED_STATE_DISABLED,
            CALLING_PKG,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        if let CodegenAtom::DisabledLauncherActivityUidsReported {
            calling_uid,
            disabled_activity_uid,
        } = atom
        {
            assert_eq!(*calling_uid, CALLING_UID);
            assert_eq!(*disabled_activity_uid, DISABLED_UID);
        } else {
            panic!("Wrong atom written: {:?}", atom);
        }
        Ok(())
    }

    #[test]
    fn component_enabled_setting_non_user_build_launcher_activity() -> Result<()> {
        const CALLING_PKG: &str = "caller";
        const DISABLED_PKG: &str = "pkg";
        const CLASS_NAME: &str = "cls";
        const CALLING_UID: i32 = 123;
        const DISABLED_UID: i32 = 456;

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_isLauncherActivity().returning(|_, _, _| Ok(true));
        mock_bridge.expect_getUidForPackage().with(eq(CALLING_PKG)).returning(|_| Ok(CALLING_UID));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(DISABLED_PKG))
            .returning(|_| Ok(DISABLED_UID));

        let (mut handler, task) =
            setup_component_handler(mock_bridge, false /* is_user_build */);
        let data = create_component_enabled_setting(
            DISABLED_PKG,
            CLASS_NAME,
            COMPONENT_ENABLED_STATE_DISABLED,
            CALLING_PKG,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 2);

        let atom1 = &handler.writer.written[0];
        if let CodegenAtom::SetComponentEnabledSettingReported {
            package_name,
            class_name,
            new_state,
            calling_package_name,
            is_launcher_activity,
        } = atom1
        {
            assert_eq!(package_name, DISABLED_PKG);
            assert_eq!(class_name, CLASS_NAME);
            assert_eq!(*new_state, COMPONENT_ENABLED_STATE_DISABLED);
            assert_eq!(calling_package_name, CALLING_PKG);
            assert!(*is_launcher_activity);
        } else {
            panic!("Wrong atom written: {:?}", atom1);
        }

        let atom2 = &handler.writer.written[1];
        if let CodegenAtom::DisabledLauncherActivityUidsReported {
            calling_uid,
            disabled_activity_uid,
        } = atom2
        {
            assert_eq!(*calling_uid, CALLING_UID);
            assert_eq!(*disabled_activity_uid, DISABLED_UID);
        } else {
            panic!("Wrong atom written: {:?}", atom2);
        }
        Ok(())
    }

    #[test]
    fn component_enabled_setting_non_launcher_activity() -> Result<()> {
        const CALLING_PKG: &str = "caller";
        const DISABLED_PKG: &str = "pkg";
        const CLASS_NAME: &str = "cls";

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_isLauncherActivity().returning(|_, _, _| Ok(false));

        let (mut handler, task) =
            setup_component_handler(mock_bridge, false /* is_user_build */);
        let data = create_component_enabled_setting(
            DISABLED_PKG,
            CLASS_NAME,
            COMPONENT_ENABLED_STATE_DISABLED,
            CALLING_PKG,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        if let CodegenAtom::SetComponentEnabledSettingReported { .. } = atom {
            // Correct atom type
        } else {
            panic!("Wrong atom written: {:?}", atom);
        }
        Ok(())
    }

    #[test]
    fn component_enabled_setting_shell_caller() -> Result<()> {
        const CALLING_PKG: &str = "shell";
        const DISABLED_PKG: &str = "pkg";
        const CALLING_UID: i32 = 123;
        const DISABLED_UID: i32 = 456;

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_isLauncherActivity().returning(|_, _, _| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq("com.android.shell"))
            .returning(|_| Ok(CALLING_UID));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(DISABLED_PKG))
            .returning(|_| Ok(DISABLED_UID));

        let (mut handler, task) =
            setup_component_handler(mock_bridge, true /* is_user_build */);
        let data = create_component_enabled_setting(
            DISABLED_PKG,
            "cls",
            COMPONENT_ENABLED_STATE_DISABLED,
            CALLING_PKG,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        if let CodegenAtom::DisabledLauncherActivityUidsReported {
            calling_uid,
            disabled_activity_uid,
        } = atom
        {
            assert_eq!(*calling_uid, CALLING_UID);
            assert_eq!(*disabled_activity_uid, DISABLED_UID);
        } else {
            panic!("Wrong atom written: {:?}", atom);
        }
        Ok(())
    }

    fn setup_bind_service_handler(
        mock_bridge: MockIUprobeStatsBridgeService,
        is_user_build: bool,
    ) -> (
        BindServiceLockedHandler<
            TestAtomWriter<CodegenAtom>,
            TestUprobeStatsBridgeService,
            TestDeviceProperties,
        >,
        ResolvedTask,
    ) {
        let test_bridge = TestUprobeStatsBridgeService { mock: Arc::new(Mutex::new(mock_bridge)) };
        let device_properties = TestDeviceProperties { is_user_build };
        let handler = BindServiceLockedHandler {
            writer: TestAtomWriter::<CodegenAtom>::default(),
            bridge_service: test_bridge,
            device_properties,
        };
        let task = ResolvedTask {
            task: Task::new(),
            pid: 0,
            uid: 0,
            process_name: "".to_string(),
            duration_seconds: 0,
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
        };
        (handler, task)
    }

    fn create_bind_service_locked(
        intent_package: &str,
        intent_component_name_package: &str,
        calling_package: &str,
        bind_flags: c_long,
    ) -> BindServiceLocked {
        let mut data = BindServiceLocked {
            intent_package: [0; 128],
            intent_action: [0; 128],
            intent_component_name_package: [0; 128],
            intent_component_name_class: [0; 128],
            calling_package: [0; 128],
            bind_flags: 0,
        };

        let intent_package_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(intent_package.as_bytes()).unwrap();
        data.intent_package[..intent_package_bytes.len()].copy_from_slice(intent_package_bytes);

        let intent_component_name_package_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(intent_component_name_package.as_bytes()).unwrap();
        data.intent_component_name_package[..intent_component_name_package_bytes.len()]
            .copy_from_slice(intent_component_name_package_bytes);

        let calling_package_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(calling_package.as_bytes()).unwrap();
        data.calling_package[..calling_package_bytes.len()].copy_from_slice(calling_package_bytes);

        data.bind_flags = bind_flags;
        data
    }

    #[test]
    fn bind_service_locked_no_bal_is_ignored() -> Result<()> {
        let (mut handler, task) =
            setup_bind_service_handler(MockIUprobeStatsBridgeService::new(), false);
        let data = create_bind_service_locked("pkg", "comp_pkg", "caller", 0);
        handler.on_item(&task, &data)?;
        assert!(handler.writer.written.is_empty());
        Ok(())
    }

    #[test]
    fn bind_service_locked_with_bal_user_build() -> Result<()> {
        const BINDER_PKG: &str = "caller";
        const BINDEE_PKG: &str = "pkg";
        const BINDER_UID: i32 = 123;
        const BINDEE_UID: i32 = 456;

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_getUidForPackage().with(eq(BINDER_PKG)).returning(|_| Ok(BINDER_UID));
        mock_bridge.expect_getUidForPackage().with(eq(BINDEE_PKG)).returning(|_| Ok(BINDEE_UID));

        let (mut handler, task) =
            setup_bind_service_handler(mock_bridge, true /* is_user_build */);
        let data = create_bind_service_locked(
            BINDEE_PKG,
            "",
            BINDER_PKG,
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 1);

        let atom = &handler.writer.written[0];
        if let CodegenAtom::BindServiceLockedWithBalFlagsUidsReported { binder_uid, bindee_uid } =
            atom
        {
            assert_eq!(*binder_uid, BINDER_UID);
            assert_eq!(*bindee_uid, BINDEE_UID);
        } else {
            panic!("Wrong atom written: {:?}", atom);
        }
        Ok(())
    }

    #[test]
    fn bind_service_locked_with_bal_non_user_build() -> Result<()> {
        const BINDER_PKG: &str = "caller";
        const BINDEE_PKG: &str = "pkg";
        const BINDER_UID: i32 = 123;
        const BINDEE_UID: i32 = 456;

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_getUidForPackage().with(eq(BINDER_PKG)).returning(|_| Ok(BINDER_UID));
        mock_bridge.expect_getUidForPackage().with(eq(BINDEE_PKG)).returning(|_| Ok(BINDEE_UID));

        let (mut handler, task) =
            setup_bind_service_handler(mock_bridge, false /* is_user_build */);
        let data = create_bind_service_locked(
            BINDEE_PKG,
            "",
            BINDER_PKG,
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 2);

        let atom1 = &handler.writer.written[0];
        if let CodegenAtom::BindServiceLockedWithBalFlagsReported { .. } = atom1 {
            // correct type
        } else {
            panic!("Wrong atom written: {:?}", atom1);
        }

        let atom2 = &handler.writer.written[1];
        if let CodegenAtom::BindServiceLockedWithBalFlagsUidsReported { binder_uid, bindee_uid } =
            atom2
        {
            assert_eq!(*binder_uid, BINDER_UID);
            assert_eq!(*bindee_uid, BINDEE_UID);
        } else {
            panic!("Wrong atom written: {:?}", atom2);
        }
        Ok(())
    }

    #[test]
    fn bind_service_locked_with_bal_empty_intent_package() -> Result<()> {
        const BINDER_PKG: &str = "caller";
        const BINDEE_PKG: &str = "comp_pkg";
        const BINDER_UID: i32 = 123;
        const BINDEE_UID: i32 = 456;

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_getUidForPackage().with(eq(BINDER_PKG)).returning(|_| Ok(BINDER_UID));
        mock_bridge.expect_getUidForPackage().with(eq(BINDEE_PKG)).returning(|_| Ok(BINDEE_UID));

        let (mut handler, task) =
            setup_bind_service_handler(mock_bridge, true /* is_user_build */);
        let data = create_bind_service_locked(
            "",
            BINDEE_PKG,
            BINDER_PKG,
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
        );
        handler.on_item(&task, &data)?;
        assert_eq!(handler.writer.written.len(), 1);

        let atom = &handler.writer.written[0];
        if let CodegenAtom::BindServiceLockedWithBalFlagsUidsReported { binder_uid, bindee_uid } =
            atom
        {
            assert_eq!(*binder_uid, BINDER_UID);
            assert_eq!(*bindee_uid, BINDEE_UID);
        } else {
            panic!("Wrong atom written: {:?}", atom);
        }
        Ok(())
    }
}
