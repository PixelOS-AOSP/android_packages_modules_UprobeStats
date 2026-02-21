use crate::{
    bpf_handler::{get_current_timestamp_millis, DynamicInstrumentationPayloadIds, Handler},
    bridge_service::UprobeStatsBridgeService,
    config_resolver::ResolvedTask,
    string::bytes_as_str,
};
use anyhow::Result;
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
    fn on_item(&mut self, _task: &ResolvedTask, item: &BinderTransaction) -> Result<()> {
        let name = bytes_as_str(&item.interface_descriptor)?;
        debug!(
            "BinderTransaction: interface_descriptor={}, code={}, calling_uid={}, timestamp_ns={}",
            name, item.code, item.calling_uid, item.timestamp_ns
        );

        let payload = vec![
            Entry {
                key: "INTERFACE_NAME".to_string(),
                value: Value::StringValue(name.to_string()),
            },
            Entry { key: "CODE".to_string(), value: Value::IntValue(item.code.try_into()?) },
        ];

        let service = self.bridge_service.get()?;
        service.enqueueEvent(
            &Event {
                uid: item.calling_uid,
                timestampMs: get_current_timestamp_millis(),
                payloadId: DynamicInstrumentationPayloadIds::BinderTransaction as i32,
                payload,
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
        bridge_service::test::TestUprobeStatsBridgeService,
        config_resolver::{ResolvedProcess, ResolvedTask},
    };
    use mockall::predicate::*;
    use std::collections::HashSet;
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

    fn setup_handler_and_task(
        mock_bridge: MockIUprobeStatsBridgeService,
    ) -> (BinderTransactionHandler<TestUprobeStatsBridgeService>, ResolvedTask) {
        let test_bridge = TestUprobeStatsBridgeService { mock: Arc::new(Mutex::new(mock_bridge)) };
        let handler = BinderTransactionHandler { bridge_service: test_bridge };
        let task = ResolvedTask {
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess {
                pid: 0,
                uid: TEST_CALLING_UID,
                name: "test_process".to_string(),
            },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        };
        (handler, task)
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
        mock_bridge
            .expect_enqueueEvent()
            .withf(move |event, flush| {
                if *flush {
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
                        && matches!(&e.value, uprobestats::Value::Value::StringValue(s) if s == TEST_INTERFACE_NAME)
                });
                let has_code = event.payload.iter().any(|e| {
                    e.key == "CODE"
                        && matches!(&e.value, uprobestats::Value::Value::IntValue(v) if *v == TEST_CODE as i32)
                });
                has_interface && has_code
            })
            .returning(|_, _| Ok(()))
            .once();

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
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
