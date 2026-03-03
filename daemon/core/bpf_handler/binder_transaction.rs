use crate::{
    bpf_handler::{get_current_timestamp_millis, DynamicInstrumentationPayloadIds, Handler},
    bridge_service::UprobeStatsBridgeService,
    config_resolver::{EventMode, ResolvedTask},
    string::bytes_as_str,
};
use anyhow::{bail, Result};
use log::debug;
use uprobestats_bpf_structs::BinderTransaction;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::{
    Entry::Entry, Event::Event, Value::Value,
};

/// Handler for Binder transaction events.
#[derive(Default)]
pub struct BinderTransactionHandler<B> {
    bridge_service: B,
}

// SAFETY: `BinderTransaction` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<B> Handler for BinderTransactionHandler<B>
where
    B: UprobeStatsBridgeService,
{
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Binder_output_buf";
    type T = BinderTransaction;
    fn on_item(&mut self, task: &ResolvedTask, item: &BinderTransaction) -> Result<()> {
        let name = bytes_as_str(&item.interface_descriptor)?;
        debug!(
            "BinderTransaction: interface_descriptor={}, code={}, calling_uid={}, timestamp_ns={}",
            name, item.code, item.calling_uid, item.timestamp_ns
        );

        let Some(method_config) = task
            .resolved_probes
            .iter()
            .filter_map(|probe| probe.binder_transaction_filters.get(name))
            .find_map(|interface_config| interface_config.get_method(&item.code))
        else {
            bail!(
                "No config found for binder transaction: interface_descriptor={}, code={}",
                name,
                item.code,
            )
        };

        let Some(event_service_config) = &method_config.event_service_config else {
            bail!(
                "No event service config found for binder transaction: interface_descriptor={}, code={}",
                name,
                item.code,
            )
        };

        self.enqueue_event(
            item.calling_uid,
            get_current_timestamp_millis(),
            name,
            item.code.try_into()?,
            match event_service_config.mode {
                EventMode::Flush => true,
                EventMode::Buffer => false,
            },
        )?;

        Ok(())
    }
}

impl<B> BinderTransactionHandler<B>
where
    B: UprobeStatsBridgeService,
{
    fn enqueue_event(
        &mut self,
        uid: i32,
        timestamp_ms: i64,
        interface_name: &str,
        code: i32,
        flush: bool,
    ) -> Result<()> {
        let service = self.bridge_service.get()?;
        service.enqueueEvent(
            &Event {
                uid,
                timestampMs: timestamp_ms,
                payloadId: DynamicInstrumentationPayloadIds::BinderTransaction as i32,
                payload: vec![
                    Entry {
                        key: "INTERFACE_NAME".to_string(),
                        value: Value::StringValue(interface_name.to_string()),
                    },
                    Entry { key: "CODE".to_string(), value: Value::IntValue(code) },
                ],
            },
            flush,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bridge_service::test::TestUprobeStatsBridgeService,
        config_resolver::{
            EventMode, EventServiceConfig, ExecutableMethodFileOffsets, InterfaceConfig,
            MethodConfig, MethodDescriptor, ResolvedProbe, ResolvedProcess, ResolvedTask,
        },
    };
    use mockall::predicate::*;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::ffi::c_ulong;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::{
        self, IUprobeStatsBridgeService::MockIUprobeStatsBridgeService,
    };
    use zerocopy::FromBytes;

    const TEST_INTERFACE_NAME: &str = "com.android.internal.os.IBinderTest";
    const TEST_CODE: u32 = 1;
    const TEST_CALLING_UID: i32 = 1000;
    const TEST_TIMESTAMP_NS: u64 = 1_000_000_000;

    fn make_method_config(flush: bool) -> MethodConfig {
        let mode = if flush { EventMode::Flush } else { EventMode::Buffer };
        MethodConfig { event_service_config: Some(EventServiceConfig { mode }), atom_config: None }
    }

    fn create_task_with_filters(filters: HashMap<String, InterfaceConfig>) -> ResolvedTask {
        ResolvedTask {
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess {
                pid: 0,
                uid: TEST_CALLING_UID,
                name: "test_process".to_string(),
            },
            resolved_probes: vec![ResolvedProbe {
                method_descriptor: MethodDescriptor {
                    fully_qualified_class_name: "test_class".to_string(),
                    method_name: "test_method".to_string(),
                    fully_qualified_parameters: vec![],
                },
                offsets: ExecutableMethodFileOffsets {
                    container_path: "test_path".to_string(),
                    container_offset: 0,
                    method_offset: 0,
                },
                bpf_program_path: "test_bpf".to_string(),
                binder_transaction_filters: filters,
            }],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        }
    }

    fn create_handler(
        mock_bridge: MockIUprobeStatsBridgeService,
    ) -> BinderTransactionHandler<TestUprobeStatsBridgeService> {
        let test_bridge = TestUprobeStatsBridgeService { mock: Arc::new(Mutex::new(mock_bridge)) };
        BinderTransactionHandler { bridge_service: test_bridge }
    }

    fn expect_binder_transaction(
        mock_bridge: &mut MockIUprobeStatsBridgeService,
        expected_interface: &'static str,
        expected_code: u32,
        expected_flush: bool,
    ) {
        mock_bridge
            .expect_enqueueEvent()
            .withf(move |event, flush| {
                if *flush != expected_flush {
                    return false;
                }
                if event.uid != TEST_CALLING_UID {
                    return false;
                }
                if event.payloadId != DynamicInstrumentationPayloadIds::BinderTransaction as i32 {
                    return false;
                }
                let has_interface = event.payload.iter().any(|e| {
                    e.key == "INTERFACE_NAME"
                        && matches!(&e.value, uprobestats::Value::Value::StringValue(s) if s == expected_interface)
                });
                let has_code = event.payload.iter().any(|e| {
                    e.key == "CODE"
                        && matches!(&e.value, uprobestats::Value::Value::IntValue(v) if *v == expected_code as i32)
                });
                has_interface && has_code
            })
            .returning(|_, _| Ok(()))
            .once();
    }

    fn create_binder_transaction(
        interface_name: &str,
        code: u32,
        calling_uid: i32,
        timestamp_ns: u64,
    ) -> BinderTransaction {
        let mut transaction = BinderTransaction {
            interface_descriptor: [0; 128],
            code: code as _,
            calling_uid,
            timestamp_ns: timestamp_ns as _,
        };

        let interface_name_bytes: &[libc::c_char] =
            FromBytes::ref_from_bytes(interface_name.as_bytes())
                .expect("Always valid to convert [u8] to [i8].");
        transaction.interface_descriptor[..interface_name_bytes.len()]
            .copy_from_slice(interface_name_bytes);

        transaction
    }

    #[test]
    fn binder_transaction_event_is_reported() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        expect_binder_transaction(&mut mock_bridge, TEST_INTERFACE_NAME, TEST_CODE, false);

        let mut handler = create_handler(mock_bridge);
        let mut filters = HashMap::new();
        let mut interface_config = InterfaceConfig::default();
        interface_config.insert_method(TEST_CODE as c_ulong, make_method_config(false))?;
        filters.insert(TEST_INTERFACE_NAME.to_string(), interface_config);
        let task = create_task_with_filters(filters);

        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE,
            TEST_CALLING_UID,
            TEST_TIMESTAMP_NS,
        );

        handler.on_item(&task, &transaction)?;

        Ok(())
    }

    #[test]
    fn binder_transaction_ignored_for_unknown_interface() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_enqueueEvent().times(0);

        let mut handler = create_handler(mock_bridge);
        let mut filters = HashMap::new();
        let mut interface_config = InterfaceConfig::default();
        interface_config.insert_method(TEST_CODE as c_ulong, make_method_config(false))?;
        filters.insert("other.interface".to_string(), interface_config);
        let task = create_task_with_filters(filters);

        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE,
            TEST_CALLING_UID,
            TEST_TIMESTAMP_NS,
        );

        let result = handler.on_item(&task, &transaction);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn binder_transaction_ignored_for_unknown_code() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge.expect_enqueueEvent().times(0);

        let mut handler = create_handler(mock_bridge);
        let mut filters = HashMap::new();
        let mut interface_config = InterfaceConfig::default();
        interface_config.insert_method(999 as c_ulong, make_method_config(false))?;
        filters.insert(TEST_INTERFACE_NAME.to_string(), interface_config);
        let task = create_task_with_filters(filters);

        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE,
            TEST_CALLING_UID,
            TEST_TIMESTAMP_NS,
        );

        let result = handler.on_item(&task, &transaction);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn binder_transaction_flush_flag_respected() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        expect_binder_transaction(&mut mock_bridge, TEST_INTERFACE_NAME, TEST_CODE, true);

        let mut handler = create_handler(mock_bridge);
        let mut filters = HashMap::new();
        let mut interface_config = InterfaceConfig::default();
        interface_config.insert_method(TEST_CODE as c_ulong, make_method_config(true))?;
        filters.insert(TEST_INTERFACE_NAME.to_string(), interface_config);
        let task = create_task_with_filters(filters);

        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE,
            TEST_CALLING_UID,
            TEST_TIMESTAMP_NS,
        );

        handler.on_item(&task, &transaction)?;

        Ok(())
    }
}
