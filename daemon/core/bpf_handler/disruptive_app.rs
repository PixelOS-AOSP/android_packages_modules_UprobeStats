use crate::{
    atom::{AtomWriter, CodegenAtom},
    bpf_handler::{get_current_timestamp_millis, DynamicInstrumentationPayloadIds, Handler},
    bridge_service::UprobeStatsBridgeService,
    config_resolver::ResolvedTask,
    device_properties::DeviceProperties,
    string::{bytes_as_nonempty_str, bytes_as_str},
};
use anyhow::{bail, Result};
use log::{debug, trace};
use std::ffi::c_long;
use uprobestats_bpf_structs::{BindServiceLocked, ComponentEnabledSetting};
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::{
    Entry::Entry, Event::Event, Value::Value,
};

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
        if data.error_code < 0 {
            bail!("ComponentEnabledSetting BPF error: {}", data.error_code);
        }
        let package_name = bytes_as_nonempty_str(&data.package_name)?;
        let class_name = bytes_as_nonempty_str(&data.class_name)?;
        let new_state = data.new_state;
        let calling_package_name = bytes_as_str(&data.calling_package_name)?;

        let is_disabled_launcher_activity = self
            .check_disabled_launcher_activity_and_log_to_statsd(
                package_name,
                class_name,
                new_state,
                calling_package_name,
            )?;

        if is_disabled_launcher_activity {
            self.enqueue_dynamic_instrumentation_event(
                package_name,
                class_name,
                calling_package_name,
            )?;
        }

        Ok(())
    }
}

impl<A, B, D> ComponentEnabledSettingHandler<A, B, D>
where
    A: AtomWriter<CodegenAtom>,
    B: UprobeStatsBridgeService,
    D: DeviceProperties,
{
    fn check_disabled_launcher_activity_and_log_to_statsd(
        &mut self,
        package_name: &str,
        class_name: &str,
        new_state: i32,
        calling_package_name: &str,
    ) -> Result<bool> {
        if new_state < COMPONENT_ENABLED_STATE_DISABLED {
            return Ok(false);
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
        if is_launcher_activity && !calling_package_name.is_empty() {
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
        Ok(is_launcher_activity)
    }

    fn enqueue_dynamic_instrumentation_event(
        &mut self,
        package_name: &str,
        class_name: &str,
        calling_package_name: &str,
    ) -> Result<()> {
        let service = self.bridge_service.get()?;
        let entries = vec![
            Entry {
                key: "PACKAGE_NAME".to_string(),
                value: Value::StringValue(package_name.to_string()),
            },
            Entry {
                key: "CLASS_NAME".to_string(),
                value: Value::StringValue(class_name.to_string()),
            },
            Entry {
                key: "CALLING_PACKAGE_NAME".to_string(),
                value: Value::StringValue(calling_package_name.to_string()),
            },
        ];

        service.enqueueEvent(
            &Event {
                uid: service.getUidForPackage(package_name)?,
                timestampMs: get_current_timestamp_millis(),
                payloadId: DynamicInstrumentationPayloadIds::DisabledLauncherActivity as i32,
                payload: entries,
            },
            false,
        )?;

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
        if data.error_code < 0 {
            bail!("BindServiceLocked BPF error: {}", data.error_code);
        }
        let calling_package = bytes_as_str(&data.calling_package)?;
        let intent_package = bytes_as_str(&data.intent_package)?;
        let intent_action = bytes_as_str(&data.intent_action)?;
        let intent_component_name_package = bytes_as_str(&data.intent_component_name_package)?;
        let intent_component_name_class = bytes_as_str(&data.intent_component_name_class)?;
        let flags = data.bind_flags;
        let has_bal_flag = (data.bind_flags & BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS) != 0;
        debug!(
            "BindServiceLocked: intent_package={intent_package:?}, intent_action={intent_action:?}, intent_component_name_package={intent_component_name_package:?}, intent_component_name_class={intent_component_name_class:?} flags={flags:?}, calling_package={calling_package:?}, has_bal_flag={has_bal_flag}"
        );

        if calling_package.is_empty()
            && intent_package.is_empty()
            && intent_action.is_empty()
            && intent_component_name_package.is_empty()
            && intent_component_name_class.is_empty()
        {
            bail!("BindServiceLocked: all strings are empty");
        }

        if !has_bal_flag {
            return Ok(());
        }

        self.log_to_statsd(
            intent_package,
            intent_action,
            intent_component_name_package,
            intent_component_name_class,
            flags as _,
            calling_package,
        )?;

        self.enqueue_dynamic_instrumentation_event(
            intent_package,
            intent_action,
            intent_component_name_package,
            intent_component_name_class,
            calling_package,
        )?;

        Ok(())
    }
}

impl<A, B, D> BindServiceLockedHandler<A, B, D>
where
    A: AtomWriter<CodegenAtom>,
    B: UprobeStatsBridgeService,
    D: DeviceProperties,
{
    fn log_to_statsd(
        &mut self,
        intent_package: &str,
        intent_action: &str,
        intent_component_name_package: &str,
        intent_component_name_class: &str,
        flags: i64,
        calling_package: &str,
    ) -> Result<()> {
        if !self.device_properties.is_user_build() {
            self.writer.write(CodegenAtom::BindServiceLockedWithBalFlagsReported {
                intent_package: intent_package.to_string(),
                flags,
                calling_package: calling_package.to_string(),
                intent_action: intent_action.to_string(),
                intent_component_name_package: intent_component_name_package.to_string(),
                intent_component_name_class: intent_component_name_class.to_string(),
            })?;
        }

        let binder_package = calling_package;
        let bindee_package =
            if !intent_package.is_empty() { intent_package } else { intent_component_name_package };

        if !binder_package.is_empty() && !bindee_package.is_empty() {
            let service = self.bridge_service.get()?;
            let binder_uid = service.getUidForPackage(binder_package)?;
            let bindee_uid = service.getUidForPackage(bindee_package)?;

            self.writer.write(CodegenAtom::BindServiceLockedWithBalFlagsUidsReported {
                binder_uid,
                bindee_uid,
            })?;
        }

        Ok(())
    }

    fn enqueue_dynamic_instrumentation_event(
        &mut self,
        intent_package: &str,
        intent_action: &str,
        intent_component_name_package: &str,
        intent_component_name_class: &str,
        calling_package: &str,
    ) -> Result<()> {
        let service = self.bridge_service.get()?;
        let entries = vec![
            Entry {
                key: "CALLING_PACKAGE".to_string(),
                value: Value::StringValue(calling_package.to_string()),
            },
            Entry {
                key: "INTENT_PACKAGE".to_string(),
                value: Value::StringValue(intent_package.to_string()),
            },
            Entry {
                key: "INTENT_ACTION".to_string(),
                value: Value::StringValue(intent_action.to_string()),
            },
            Entry {
                key: "INTENT_COMPONENT_NAME_PACKAGE".to_string(),
                value: Value::StringValue(intent_component_name_package.to_string()),
            },
            Entry {
                key: "INTENT_COMPONENT_NAME_CLASS".to_string(),
                value: Value::StringValue(intent_component_name_class.to_string()),
            },
        ];

        service.enqueueEvent(
            &Event {
                uid: 0,
                timestampMs: get_current_timestamp_millis(),
                payloadId: DynamicInstrumentationPayloadIds::BindAllowBackgroundActivityStarts
                    as i32,
                payload: entries,
            },
            false,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        atom::{test::TestAtomWriter, CodegenAtom},
        bridge_service::test::TestUprobeStatsBridgeService,
        config_resolver::{ResolvedProcess, ResolvedTask},
        device_properties::test::TestDeviceProperties,
    };
    use anyhow::Result;
    use mockall::predicate::*;
    use std::collections::HashSet;
    use std::ffi::c_long;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::IUprobeStatsBridgeService::MockIUprobeStatsBridgeService;
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
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess { pid: 0, uid: 0, name: "".to_string() },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        };
        (handler, task)
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
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess { pid: 0, uid: 0, name: "".to_string() },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        };
        (handler, task)
    }

    fn c_str_arr<const N: usize>(s: &str) -> [libc::c_char; N] {
        let mut arr = [0; N];
        let bytes: &[libc::c_char] = FromBytes::ref_from_bytes(s.as_bytes()).unwrap();
        arr[..bytes.len()].copy_from_slice(bytes);
        arr
    }

    fn create_component_enabled_setting(
        package_name: &str,
        class_name: &str,
        new_state: i32,
        calling_package_name: &str,
    ) -> ComponentEnabledSetting {
        ComponentEnabledSetting {
            error_code: 0,
            package_name: c_str_arr(package_name),
            class_name: c_str_arr(class_name),
            new_state,
            calling_package_name: c_str_arr(calling_package_name),
        }
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

    fn assert_component_enabled_setting_launcher_activity(is_user_build: bool) -> Result<()> {
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
        expect_enqueue_disabled_launcher_activity_event(
            &mut mock_bridge,
            DISABLED_UID,
            DISABLED_PKG,
            CLASS_NAME,
            CALLING_PKG,
        );

        let (mut handler, task) = setup_component_handler(mock_bridge, is_user_build);
        let data = create_component_enabled_setting(
            DISABLED_PKG,
            CLASS_NAME,
            COMPONENT_ENABLED_STATE_DISABLED,
            CALLING_PKG,
        );
        handler.on_item(&task, &data)?;

        let expected_len = if is_user_build { 1 } else { 2 };
        assert_eq!(handler.writer.written.len(), expected_len);

        if !is_user_build {
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
        }

        let atom2 = handler.writer.written.last().unwrap();
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
    fn component_enabled_setting_launcher_activity() -> Result<()> {
        assert_component_enabled_setting_launcher_activity(true)?;
        assert_component_enabled_setting_launcher_activity(false)
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
        const CLASS_NAME: &str = "cls";
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
        expect_enqueue_disabled_launcher_activity_event(
            &mut mock_bridge,
            DISABLED_UID,
            DISABLED_PKG,
            CLASS_NAME,
            CALLING_PKG,
        );

        let (mut handler, task) =
            setup_component_handler(mock_bridge, true /* is_user_build */);
        let data = create_component_enabled_setting(
            DISABLED_PKG,
            CLASS_NAME,
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

    fn create_bind_service_locked(
        intent_package: &str,
        intent_component_name_package: &str,
        calling_package: &str,
        bind_flags: c_long,
        intent_action: Option<&str>,
        intent_component_name_class: Option<&str>,
    ) -> BindServiceLocked {
        BindServiceLocked {
            error_code: 0,
            intent_package: c_str_arr(intent_package),
            intent_component_name_package: c_str_arr(intent_component_name_package),
            calling_package: c_str_arr(calling_package),
            bind_flags,
            intent_action: c_str_arr(intent_action.unwrap_or("")),
            intent_component_name_class: c_str_arr(intent_component_name_class.unwrap_or("")),
        }
    }

    fn expect_enqueue_disabled_launcher_activity_event(
        mock_bridge: &mut MockIUprobeStatsBridgeService,
        disabled_uid: i32,
        disabled_pkg: &str,
        class_name: &str,
        calling_pkg: &str,
    ) {
        let disabled_pkg = disabled_pkg.to_string();
        let class_name = class_name.to_string();
        let calling_pkg = calling_pkg.to_string();
        mock_bridge
            .expect_enqueueEvent()
            .withf(move |event, _flush| {
                if event.uid != disabled_uid {
                    return false;
                }
                if event.payloadId
                    != DynamicInstrumentationPayloadIds::DisabledLauncherActivity as i32
                {
                    return false;
                }
                let has_pkg = event.payload.iter().any(|e| {
                    e.key == "PACKAGE_NAME"
                        && matches!(&e.value, Value::StringValue(s) if s == &disabled_pkg)
                });
                let has_cls = event.payload.iter().any(|e| {
                    e.key == "CLASS_NAME"
                        && matches!(&e.value, Value::StringValue(s) if s == &class_name)
                });
                let has_caller = event.payload.iter().any(|e| {
                    e.key == "CALLING_PACKAGE_NAME"
                        && matches!(&e.value, Value::StringValue(s) if s == &calling_pkg)
                });
                has_pkg && has_cls && has_caller
            })
            .returning(|_, _| Ok(()))
            .once();
    }

    fn expect_enqueue_bind_service_with_bal_event(
        mock_bridge: &mut MockIUprobeStatsBridgeService,
        binder_pkg: &str,
        intent_pkg: &str,
        intent_action: &str,
        component_pkg: &str,
        component_class: &str,
    ) {
        let binder_pkg = binder_pkg.to_string();
        let intent_pkg = intent_pkg.to_string();
        let intent_action = intent_action.to_string();
        let component_pkg = component_pkg.to_string();
        let component_class = component_class.to_string();

        mock_bridge
            .expect_enqueueEvent()
            .withf(move |event, _flush| {
                if event.uid != 0 {
                    return false;
                }
                if event.payloadId
                    != DynamicInstrumentationPayloadIds::BindAllowBackgroundActivityStarts as i32
                {
                    return false;
                }
                let has_caller = event.payload.iter().any(|e| {
                    e.key == "CALLING_PACKAGE"
                        && matches!(&e.value, Value::StringValue(s) if s == &binder_pkg)
                });
                let has_intent_pkg = event.payload.iter().any(|e| {
                    e.key == "INTENT_PACKAGE"
                        && matches!(&e.value, Value::StringValue(s) if s == &intent_pkg)
                });
                let has_intent_action = event.payload.iter().any(|e| {
                    e.key == "INTENT_ACTION"
                        && matches!(&e.value, Value::StringValue(s) if s == &intent_action)
                });
                let has_comp_pkg = event.payload.iter().any(|e| {
                    e.key == "INTENT_COMPONENT_NAME_PACKAGE"
                        && matches!(&e.value, Value::StringValue(s) if s == &component_pkg)
                });
                let has_comp_cls = event.payload.iter().any(|e| {
                    e.key == "INTENT_COMPONENT_NAME_CLASS"
                        && matches!(&e.value, Value::StringValue(s) if s == &component_class)
                });
                has_caller && has_intent_pkg && has_intent_action && has_comp_pkg && has_comp_cls
            })
            .returning(|_, _| Ok(()))
            .once();
    }

    #[test]
    fn bind_service_locked_no_bal_is_ignored() -> Result<()> {
        let (mut handler, task) =
            setup_bind_service_handler(MockIUprobeStatsBridgeService::new(), false);
        let data = create_bind_service_locked("pkg", "comp_pkg", "caller", 0, None, None);
        handler.on_item(&task, &data)?;
        assert!(handler.writer.written.is_empty());
        Ok(())
    }

    fn assert_bind_service_locked_with_bal(is_user_build: bool) -> Result<()> {
        const BINDER_PKG: &str = "caller";
        const BINDEE_PKG: &str = "pkg";
        const BINDER_UID: i32 = 123;
        const BINDEE_UID: i32 = 456;
        const INTENT_ACTION: &str = "action";
        const COMPONENT_PACKAGE: &str = "comp_pkg";
        const COMPONENT_CLASS: &str = "comp_cls";

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_getUidForPackage().with(eq(BINDER_PKG)).returning(|_| Ok(BINDER_UID));
        mock_bridge.expect_getUidForPackage().with(eq(BINDEE_PKG)).returning(|_| Ok(BINDEE_UID));
        expect_enqueue_bind_service_with_bal_event(
            &mut mock_bridge,
            BINDER_PKG,
            BINDEE_PKG,
            INTENT_ACTION,
            COMPONENT_PACKAGE,
            COMPONENT_CLASS,
        );

        let (mut handler, task) = setup_bind_service_handler(mock_bridge, is_user_build);
        let data = create_bind_service_locked(
            BINDEE_PKG,
            COMPONENT_PACKAGE,
            BINDER_PKG,
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
            Some(INTENT_ACTION),
            Some(COMPONENT_CLASS),
        );
        handler.on_item(&task, &data)?;

        let expected_len = if is_user_build { 1 } else { 2 };
        assert_eq!(handler.writer.written.len(), expected_len);

        if !is_user_build {
            let atom1 = &handler.writer.written[0];
            if let CodegenAtom::BindServiceLockedWithBalFlagsReported { .. } = atom1 {
                // correct type
            } else {
                panic!("Wrong atom written: {:?}", atom1);
            }
        }

        let atom2 = handler.writer.written.last().unwrap();
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
    fn bind_service_locked_with_bal() -> Result<()> {
        assert_bind_service_locked_with_bal(true)?;
        assert_bind_service_locked_with_bal(false)
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
        expect_enqueue_bind_service_with_bal_event(
            &mut mock_bridge,
            BINDER_PKG,
            "",
            "",
            BINDEE_PKG,
            "",
        );

        let (mut handler, task) =
            setup_bind_service_handler(mock_bridge, true /* is_user_build */);
        let data = create_bind_service_locked(
            "",
            BINDEE_PKG,
            BINDER_PKG,
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
            None,
            None,
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
    fn component_enabled_setting_empty_fields_fail() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_isLauncherActivity().returning(|_, _, _| Ok(false));

        let (mut handler, task) = setup_component_handler(mock_bridge, false);

        // empty package_name
        let data =
            create_component_enabled_setting("", "cls", COMPONENT_ENABLED_STATE_DISABLED, "caller");
        assert!(handler.on_item(&task, &data).is_err());

        // empty class_name
        let data =
            create_component_enabled_setting("pkg", "", COMPONENT_ENABLED_STATE_DISABLED, "caller");
        assert!(handler.on_item(&task, &data).is_err());

        // empty calling_package_name is allowed
        let data =
            create_component_enabled_setting("pkg", "cls", COMPONENT_ENABLED_STATE_DISABLED, "");
        assert!(handler.on_item(&task, &data).is_ok());

        Ok(())
    }

    #[test]
    fn bind_service_locked_empty_calling_package_no_uid_atom() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        // expect_getUidForPackage should NOT be called.
        expect_enqueue_bind_service_with_bal_event(&mut mock_bridge, "", "pkg", "", "comp_pkg", "");

        let (mut handler, task) =
            setup_bind_service_handler(mock_bridge, false /* is_user_build */);
        let data = create_bind_service_locked(
            "pkg",
            "comp_pkg",
            "",
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
            None,
            None,
        );
        handler.on_item(&task, &data)?;

        // Only BindServiceLockedWithBalFlagsReported should be written.
        assert_eq!(handler.writer.written.len(), 1);
        if let CodegenAtom::BindServiceLockedWithBalFlagsReported { .. } =
            &handler.writer.written[0]
        {
            // correct type
        } else {
            panic!("Wrong atom written: {:?}", handler.writer.written[0]);
        }
        Ok(())
    }

    #[test]
    fn bind_service_locked_empty_intent_packages_no_uid_atom() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        // expect_getUidForPackage should NOT be called.
        expect_enqueue_bind_service_with_bal_event(&mut mock_bridge, "caller", "", "", "", "");

        let (mut handler, task) =
            setup_bind_service_handler(mock_bridge, false /* is_user_build */);
        let data = create_bind_service_locked(
            "",
            "",
            "caller",
            BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
            None,
            None,
        );
        handler.on_item(&task, &data)?;

        // Only BindServiceLockedWithBalFlagsReported should be written.
        assert_eq!(handler.writer.written.len(), 1);
        if let CodegenAtom::BindServiceLockedWithBalFlagsReported { .. } =
            &handler.writer.written[0]
        {
            // correct type
        } else {
            panic!("Wrong atom written: {:?}", handler.writer.written[0]);
        }
        Ok(())
    }

    #[test]
    fn bind_service_locked_all_empty_fails() -> Result<()> {
        let (mut handler, task) =
            setup_bind_service_handler(MockIUprobeStatsBridgeService::new(), false);
        let data = create_bind_service_locked("", "", "", 0, None, None);
        assert!(handler.on_item(&task, &data).is_err());
        Ok(())
    }

    #[test]
    fn component_enabled_setting_with_error_bails() -> Result<()> {
        let (mut handler, task) =
            setup_component_handler(MockIUprobeStatsBridgeService::new(), false);
        let data = ComponentEnabledSetting {
            error_code: -1,
            ..create_component_enabled_setting("pkg", "cls", 2, "caller")
        };
        assert!(handler.on_item(&task, &data).is_err());
        assert!(handler.writer.written.is_empty());
        Ok(())
    }

    #[test]
    fn bind_service_locked_with_error_bails() -> Result<()> {
        let (mut handler, task) =
            setup_bind_service_handler(MockIUprobeStatsBridgeService::new(), false);
        let data = BindServiceLocked {
            error_code: -1,
            ..create_bind_service_locked(
                "pkg",
                "comp_pkg",
                "caller",
                BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS,
                None,
                None,
            )
        };
        assert!(handler.on_item(&task, &data).is_err());
        assert!(handler.writer.written.is_empty());
        Ok(())
    }
}
