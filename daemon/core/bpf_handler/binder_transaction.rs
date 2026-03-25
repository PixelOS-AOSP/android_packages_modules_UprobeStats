use crate::{
    atom::{AtomWriter, Field, FieldAnnotation, UnstructuredAtom, Value as AtomValue},
    bpf_handler::{get_current_timestamp_millis, DynamicInstrumentationPayloadIds, Handler},
    bridge_service::UprobeStatsBridgeService,
    config_resolver::{AtomConfig, EventMode, ResolvedTask},
    string::bytes_as_nonempty_str,
};
use anyhow::{bail, Result};
use log::debug;
use uprobestats_bpf_structs::BinderTransaction;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::{
    Entry::Entry, Event::Event, Value::Value,
};
use uprobestats_proto::config::uprobestats_config::task::binder_transaction_filter::method_config::AtomFieldPosition;

/// Handler for Binder transaction events.
#[derive(Default)]
pub struct BinderTransactionHandler<A, B> {
    atom_writer: A,
    bridge_service: B,
}

// SAFETY: `BinderTransaction` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A, B> Handler for BinderTransactionHandler<A, B>
where
    A: AtomWriter<UnstructuredAtom>,
    B: UprobeStatsBridgeService,
{
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Binder_output_buf";
    type T = BinderTransaction;
    fn on_item(&mut self, task: &ResolvedTask, item: &BinderTransaction) -> Result<()> {
        let name = bytes_as_nonempty_str(&item.interface_descriptor)?;
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

        let code: i32 = item.code.try_into()?;

        if let Some(atom_config) = &method_config.atom_config {
            self.write_to_statsd(
                atom_config,
                item.calling_uid,
                name,
                code,
                item.timestamp_ns.try_into()?,
            )?;
        };

        if let Some(event_service_config) = &method_config.event_service_config {
            let flush = match event_service_config.mode {
                EventMode::Flush => true,
                EventMode::Buffer => false,
            };
            self.enqueue_event(
                item.calling_uid,
                get_current_timestamp_millis(),
                name,
                code,
                flush,
            )?;
        };

        Ok(())
    }
}

impl<A, B> BinderTransactionHandler<A, B>
where
    A: AtomWriter<UnstructuredAtom>,
    B: UprobeStatsBridgeService,
{
    fn write_to_statsd(
        &mut self,
        atom_config: &AtomConfig,
        uid: i32,
        interface_name: &str,
        code: i32,
        timestamp_ns: i64,
    ) -> Result<()> {
        let atom_id = atom_config.atom_id;
        let fields = atom_config
            .atom_field_positions
            .iter()
            .map(|position| match position {
                AtomFieldPosition::CALLING_UID => Ok(Field::new_with_annotation(
                    AtomValue::Int32(uid),
                    FieldAnnotation::IsUid(true),
                )),
                AtomFieldPosition::INTERFACE_NAME => {
                    Ok(Field::new(AtomValue::String(interface_name.to_string())))
                }
                AtomFieldPosition::CODE => Ok(Field::new(AtomValue::Int32(code))),
                AtomFieldPosition::KTIME_NS => Ok(Field::new(AtomValue::Int64(timestamp_ns))),
                AtomFieldPosition::UNKNOWN => bail!("Unknown atom field position"),
            })
            .collect::<Result<Vec<_>>>()?;
        self.atom_writer.write(UnstructuredAtom { atom_id, fields })
    }

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
        atom::{test::TestAtomWriter, UnstructuredAtom, Value},
        bridge_service::test::TestUprobeStatsBridgeService,
        config_resolver::{
            EventMode, EventServiceConfig, ExecutableMethodFileOffsets, InterfaceConfig,
            MethodConfig, MethodDescriptor, ResolvedProbe, ResolvedProcess, ResolvedTask,
        },
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
        method_configs: Vec<(u64, Option<EventServiceConfig>, Option<AtomConfig>)>,
    ) -> (
        BinderTransactionHandler<TestAtomWriter<UnstructuredAtom>, TestUprobeStatsBridgeService>,
        ResolvedTask,
    ) {
        let test_bridge = TestUprobeStatsBridgeService { mock: Arc::new(Mutex::new(mock_bridge)) };
        let handler = BinderTransactionHandler {
            bridge_service: test_bridge,
            atom_writer: TestAtomWriter::default(),
        };

        let mut interface_config = InterfaceConfig::default();
        for (method_id, event_service_config, atom_config) in method_configs {
            interface_config
                .insert_method(method_id, MethodConfig { event_service_config, atom_config })
                .unwrap();
        }
        let mut binder_transaction_filters = std::collections::HashMap::new();
        binder_transaction_filters.insert(TEST_INTERFACE_NAME.to_string(), interface_config);

        let task = ResolvedTask {
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
                binder_transaction_filters,
            }],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        };
        (handler, task)
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

        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![(TEST_CODE.into(), Some(EventServiceConfig { mode: EventMode::Buffer }), None)],
        );

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

        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![(TEST_CODE.into(), Some(EventServiceConfig { mode: EventMode::Buffer }), None)],
        );

        let transaction = create_binder_transaction(
            "com.android.internal.os.IOtherInterface",
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

        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![(TEST_CODE.into(), Some(EventServiceConfig { mode: EventMode::Buffer }), None)],
        );

        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE + 1,
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

        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![(TEST_CODE.into(), Some(EventServiceConfig { mode: EventMode::Flush }), None)],
        );

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
    fn binder_transaction_atom_is_reported() -> Result<()> {
        let mock_bridge = MockIUprobeStatsBridgeService::new();
        let atom_id = 100;
        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![(
                TEST_CODE.into(),
                None,
                Some(AtomConfig {
                    atom_id,
                    atom_field_positions: vec![
                        AtomFieldPosition::INTERFACE_NAME,
                        AtomFieldPosition::CODE,
                        AtomFieldPosition::CALLING_UID,
                        AtomFieldPosition::KTIME_NS,
                    ],
                }),
            )],
        );
        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE,
            TEST_CALLING_UID,
            TEST_TIMESTAMP_NS,
        );

        handler.on_item(&task, &transaction)?;

        assert_eq!(handler.atom_writer.written.len(), 1);
        let atom = &handler.atom_writer.written[0];
        assert_eq!(atom.atom_id, atom_id);
        assert_eq!(atom.fields[0].value, Value::String(TEST_INTERFACE_NAME.to_string()));
        assert_eq!(atom.fields[1].value, Value::Int32(TEST_CODE as i32));
        assert_eq!(atom.fields[2].value, Value::Int32(TEST_CALLING_UID));
        assert_eq!(atom.fields[3].value, Value::Int64(TEST_TIMESTAMP_NS as i64));

        Ok(())
    }

    #[test]
    fn binder_transaction_reports_both_atom_and_event() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        expect_binder_transaction(&mut mock_bridge, TEST_INTERFACE_NAME, TEST_CODE, false);
        let atom_id = 100;

        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![(
                TEST_CODE.into(),
                Some(EventServiceConfig { mode: EventMode::Buffer }),
                Some(AtomConfig {
                    atom_id,
                    atom_field_positions: vec![
                        AtomFieldPosition::INTERFACE_NAME,
                        AtomFieldPosition::CODE,
                        AtomFieldPosition::CALLING_UID,
                        AtomFieldPosition::KTIME_NS,
                    ],
                }),
            )],
        );

        let transaction = create_binder_transaction(
            TEST_INTERFACE_NAME,
            TEST_CODE,
            TEST_CALLING_UID,
            TEST_TIMESTAMP_NS,
        );

        handler.on_item(&task, &transaction)?;

        // Verify Atom was written
        assert_eq!(handler.atom_writer.written.len(), 1);
        let atom = &handler.atom_writer.written[0];
        assert_eq!(atom.atom_id, atom_id);

        // Verify Event was enqueued (checked by mock expectation)
        Ok(())
    }

    #[test]
    fn binder_transaction_handles_multiple_methods() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        expect_binder_transaction(&mut mock_bridge, TEST_INTERFACE_NAME, 1, false);
        expect_binder_transaction(&mut mock_bridge, TEST_INTERFACE_NAME, 2, false);

        let (mut handler, task) = setup_handler_and_task(
            mock_bridge,
            vec![
                (1, Some(EventServiceConfig { mode: EventMode::Buffer }), None),
                (2, Some(EventServiceConfig { mode: EventMode::Buffer }), None),
            ],
        );

        // Transaction 1
        let t1 =
            create_binder_transaction(TEST_INTERFACE_NAME, 1, TEST_CALLING_UID, TEST_TIMESTAMP_NS);
        handler.on_item(&task, &t1)?;

        // Transaction 2
        let t2 =
            create_binder_transaction(TEST_INTERFACE_NAME, 2, TEST_CALLING_UID, TEST_TIMESTAMP_NS);
        handler.on_item(&task, &t2)?;

        Ok(())
    }

    #[test]
    fn binder_transaction_empty_interface_fails() -> Result<()> {
        let (mut handler, task) = setup_handler_and_task(
            MockIUprobeStatsBridgeService::new(),
            vec![(TEST_CODE.into(), Some(EventServiceConfig { mode: EventMode::Buffer }), None)],
        );

        let transaction =
            create_binder_transaction("", TEST_CODE, TEST_CALLING_UID, TEST_TIMESTAMP_NS);

        let result = handler.on_item(&task, &transaction);
        assert!(result.is_err());
        Ok(())
    }
}
