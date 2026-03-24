use crate::{
    atom::{AtomWriter, Field, FieldAnnotation, UnstructuredAtom, Value},
    bpf_handler::Handler,
    bridge_service::UprobeStatsBridgeService,
    config_resolver::ResolvedTask,
    string::bytes_as_nonempty_str,
};
use anyhow::{anyhow, bail, Result};
use log::{debug, trace};
use std::{collections::HashMap, num::TryFromIntError, time::Duration};
use uprobestats_bpf_structs::AccessibilityEvent;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::Entry::Entry;

/// a11y handler
#[derive(Default)]
pub struct AccessibilityHandler<A, B> {
    events: HashMap<i32, Vec<Event>>,
    writer: A,
    bridge_service: B,
}

const A11Y_EVENT_WINDOW: Duration = Duration::from_secs(10);
const ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT: u32 = 1217;

// SAFETY: `AccessibilityEvent` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>, B: UprobeStatsBridgeService> Handler
    for AccessibilityHandler<A, B>
{
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Accessibility_output_buf";
    type T = AccessibilityEvent;
    fn on_item(&mut self, _task: &ResolvedTask, data: &AccessibilityEvent) -> Result<()> {
        let timestamp_ns = data.timestamp_ns;
        #[cfg(target_pointer_width = "32")]
        let timestamp_ns = timestamp_ns.into();
        let variant = data.variant;
        trace!("variant={variant}, timestamp_ns={timestamp_ns}");
        let event: Result<Option<Event>> = if data.variant == 1 {
            handle_permission_grant_event(&mut self.bridge_service, data, timestamp_ns)
        } else if data.variant == 2 {
            handle_a11y_event(&mut self.bridge_service, data, timestamp_ns)
        } else {
            bail!("Invalid variant: {variant}")
        };

        let event = event?;
        let Some(event) = event else {
            return Ok(());
        };
        let events = self.events.entry(event.uid).or_default();
        events.push(event);
        Ok(())
    }

    fn on_finished(&mut self) -> Result<()> {
        let mut a11y_runtime_permission_grants = vec![];
        for events in self.events.values_mut() {
            // Sort the events in descending order of timestamp, so that the most recent permission
            // grant is processed first. This is to ensure that the preceding a11y events
            // are associated with the correct permission grant.
            events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            a11y_runtime_permission_grants.extend(associate_events(events));
        }
        for AccessibilityRuntimePermissionGrant {
            uid,
            timestamp,
            ref permission_name,
            ref preceding_a11y_calls,
        } in a11y_runtime_permission_grants
        {
            debug!("uid={uid}, timestamp={:?}, permission_name={permission_name}", timestamp);
            for preceding_a11y_call in preceding_a11y_calls.iter() {
                debug!("preceding_a11y_call={preceding_a11y_call:?}");
            }
            // Log all runtime permission grants for apps with enabled a11y services. If the permission grant was driven by the same app using a11y,
            // it should be represented in `preceding_a11y_calls`.
            let atom = UnstructuredAtom {
                atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
                fields: vec![
                    Field::new_with_annotation(Value::Int32(uid), FieldAnnotation::IsUid(true)),
                    Field::new(Value::String(permission_name.to_string())),
                    Field::new(Value::Int64(timestamp.as_millis().try_into()?)),
                    Field::new(Value::Int32Vec(
                        preceding_a11y_calls.iter().map(|(c, _)| *c).collect::<Vec<i32>>(),
                    )),
                    Field::new(Value::Int64Vec(
                        preceding_a11y_calls
                            .iter()
                            .map(|(_, t)| {
                                t.as_millis().try_into().map_err(|e: TryFromIntError| anyhow!(e))
                            })
                            .collect::<Result<Vec<i64>>>()?,
                    )),
                ],
            };
            self.writer.write(atom)?;
            trace!("wrote atom {ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT} for permission {permission_name}");
        }
        Ok(())
    }
}

fn handle_permission_grant_event<B: UprobeStatsBridgeService>(
    service: &mut B,
    data: &AccessibilityEvent,
    timestamp_ns: u64,
) -> Result<Option<Event>> {
    // permission grant event
    let package_name = bytes_as_nonempty_str(&data.package_name)?;
    let permission_name = bytes_as_nonempty_str(&data.permission_name)?;

    trace!("package_name={package_name}, permission_name={permission_name}");

    // Only log system permissions.
    if !permission_name.starts_with("android.permission") {
        return Ok(None);
    }

    let service = service.get()?;
    let has_enabled_a11y_service = service.packageHasEnabledAccessibilityService(package_name)?;
    trace!("has_enabled_a11y_service={has_enabled_a11y_service}");

    // Only log if the package in question also has an enabled a11y service.
    if !has_enabled_a11y_service {
        return Ok(None);
    }

    let uid = service.getUidForPackage(package_name)?;

    trace!("uid={uid}");

    let event = Event::new(
        uid,
        timestamp_ns,
        EventType::RuntimePermissionGrant(permission_name.to_string()),
    );

    service.enqueueEvent(&event.clone().into(), false)?;

    Ok(Some(event))
}

fn handle_a11y_event<B: UprobeStatsBridgeService>(
    service: &mut B,
    data: &AccessibilityEvent,
    timestamp_ns: u64,
) -> Result<Option<Event>> {
    // IAccessibilityServiceConnection event
    let uid = data.uid;
    let code = data.code;
    trace!("uid={uid}, code={code}");
    let event = Event::new(uid, timestamp_ns, EventType::A11y(code));
    let service = service.get()?;
    service.enqueueEvent(&event.clone().into(), false)?;
    Ok(Some(Event::new(uid, timestamp_ns, EventType::A11y(code))))
}

// Associate the a11y events with the permission grants. The events are expected to be sorted in
// descending order of timestamp, so that the most recent permission grant is processed first.
// This is to ensure that the preceding a11y events are associated with the correct permission
// grant.
fn associate_events(
    events_sorted_descending_by_timestamp: &[Event],
) -> Vec<AccessibilityRuntimePermissionGrant> {
    let mut a11y_runtime_permission_grants = vec![];
    let mut a11y_runtime_permission_grant = None;
    for event in events_sorted_descending_by_timestamp {
        trace!("event={event:?}");
        match (&mut a11y_runtime_permission_grant, event) {
            // An a11y event happened after any/all permissions were already granted. No-op.
            (None, Event { variant: EventType::A11y(_), .. }) => {}
            // The event is a permission grant, store it as the most recent one.
            (
                _,
                Event {
                    uid,
                    timestamp,
                    variant: EventType::RuntimePermissionGrant(permission_name),
                },
            ) => {
                // Write the preceding permission grant, if any.
                if let Some(a11y_runtime_permission_grant) = a11y_runtime_permission_grant {
                    a11y_runtime_permission_grants.push(a11y_runtime_permission_grant);
                }
                a11y_runtime_permission_grant = Some(AccessibilityRuntimePermissionGrant::new(
                    *uid,
                    timestamp,
                    permission_name,
                ));
            }
            // Else, associate the a11y event as preceding the permission grant,
            // if and only if the a11y event happened within the window.
            (
                Some(AccessibilityRuntimePermissionGrant {
                    timestamp: permission_grant_timestamp,
                    ref mut preceding_a11y_calls,
                    ..
                }),
                Event { timestamp, variant: EventType::A11y(uid), .. },
            ) => {
                if permission_grant_timestamp.saturating_sub(*timestamp) < A11Y_EVENT_WINDOW {
                    preceding_a11y_calls.push((*uid, *timestamp));
                }
            }
        }
    }
    // Write the last permission grant, if any.
    if let Some(a11y_runtime_permission_grant) = a11y_runtime_permission_grant {
        a11y_runtime_permission_grants.push(a11y_runtime_permission_grant);
    }
    a11y_runtime_permission_grants
}

#[derive(Clone, Debug)]
struct Event {
    uid: i32,
    timestamp: Duration,
    variant: EventType,
}

impl Event {
    fn new(uid: i32, timestamp_ns: u64, variant: EventType) -> Self {
        Self { uid, timestamp: Duration::from_nanos(timestamp_ns), variant }
    }
}

impl From<Event> for uprobestats::Event::Event {
    fn from(event: Event) -> Self {
        Self {
            uid: event.uid,
            timestampMs: event.timestamp.as_millis().try_into().unwrap(),
            payloadId: match event.variant {
                EventType::A11y(_) => 1,
                EventType::RuntimePermissionGrant(_) => 2,
            },
            payload: match event.variant {
                EventType::A11y(code) => vec![
                    Entry {
                        key: "CODE".to_string(),
                        value: uprobestats::Value::Value::IntValue(code),
                    },
                    Entry {
                        key: "INTERFACE_NAME".to_string(),
                        value: uprobestats::Value::Value::StringValue(
                            "IAccessibilityServiceConnection".to_string(),
                        ),
                    },
                ],
                EventType::RuntimePermissionGrant(permission_name) => vec![Entry {
                    key: "PERMISSION_NAME".to_string(),
                    value: uprobestats::Value::Value::StringValue(permission_name),
                }],
            },
        }
    }
}

#[derive(Clone, Debug)]
enum EventType {
    RuntimePermissionGrant(String),
    A11y(i32),
}

struct AccessibilityRuntimePermissionGrant {
    uid: i32,
    timestamp: Duration,
    permission_name: String,
    preceding_a11y_calls: Vec<(i32, Duration)>,
}

impl AccessibilityRuntimePermissionGrant {
    fn new(uid: i32, timestamp: &Duration, permission_name: &str) -> Self {
        Self {
            uid,
            timestamp: *timestamp,
            permission_name: permission_name.to_string(),
            preceding_a11y_calls: vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        atom::test::TestAtomWriter,
        bridge_service::test::TestUprobeStatsBridgeService,
        config_resolver::{ResolvedProcess, ResolvedTask},
    };
    use binder::Status;
    use mockall::predicate::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::{
        self, IUprobeStatsBridgeService::MockIUprobeStatsBridgeService,
    };
    use zerocopy::FromBytes;

    const TEST_PACKAGE_NAME: &str = "pkg.name";
    const TEST_PERMISSION_NAME: &str = "android.permission.A";
    const TEST_UID: i32 = 123;
    const TEST_A11Y_CODE: i32 = 456;

    fn setup_handler_and_task(
        mock_bridge: MockIUprobeStatsBridgeService,
    ) -> (
        AccessibilityHandler<TestAtomWriter<UnstructuredAtom>, TestUprobeStatsBridgeService>,
        ResolvedTask,
    ) {
        let test_bridge = TestUprobeStatsBridgeService { mock: Arc::new(Mutex::new(mock_bridge)) };
        let handler = AccessibilityHandler {
            events: HashMap::new(),
            writer: TestAtomWriter::<UnstructuredAtom>::default(),
            bridge_service: test_bridge,
        };
        let task = ResolvedTask {
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess {
                pid: 0,
                uid: TEST_UID,
                name: TEST_PACKAGE_NAME.to_string(),
            },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        };
        (handler, task)
    }

    fn create_permission_event(
        pkg_name: &str,
        perm_name: &str,
        timestamp: Duration,
    ) -> AccessibilityEvent {
        let mut permission_event = AccessibilityEvent {
            variant: 1,
            timestamp_ns: timestamp.as_nanos().try_into().unwrap(),
            uid: 0,
            code: 0,
            package_name: [0; 128],
            permission_name: [0; 128],
        };

        let pkg_name: &[libc::c_char] = FromBytes::ref_from_bytes(pkg_name.as_bytes())
            .expect("Always valid to convert [u8] to [i8].");
        permission_event.package_name[..pkg_name.len()].copy_from_slice(pkg_name);

        let perm_name: &[libc::c_char] = FromBytes::ref_from_bytes(perm_name.as_bytes())
            .expect("Always valid to convert [u8] to [i8].");
        permission_event.permission_name[..perm_name.len()].copy_from_slice(perm_name);

        permission_event
    }

    fn create_a11y_event(uid: i32, code: i32, timestamp: Duration) -> AccessibilityEvent {
        AccessibilityEvent {
            variant: 2,
            uid,
            code,
            timestamp_ns: timestamp.as_nanos().try_into().unwrap(),
            package_name: [0; 128],
            permission_name: [0; 128],
        }
    }

    fn expect_enqueue_a11y_event(
        mock_bridge: &mut MockIUprobeStatsBridgeService,
        uid: i32,
        timestamp: Duration,
        code: i32,
    ) {
        mock_bridge
            .expect_enqueueEvent()
            .withf(move |event, flush| {
                if *flush {
                    return false;
                }
                if event.uid != uid {
                    return false;
                }
                if event.timestampMs != timestamp.as_millis().try_into().unwrap() {
                    return false;
                }
                if event.payloadId != 1 {
                    return false;
                }
                let has_code = event.payload.iter().any(|e| {
                    e.key == "CODE"
                        && matches!(&e.value, uprobestats::Value::Value::IntValue(v) if *v == code)
                });
                let has_interface = event.payload.iter().any(|e| {
                    e.key == "INTERFACE_NAME"
                        && matches!(&e.value, uprobestats::Value::Value::StringValue(s) if s == "IAccessibilityServiceConnection")
                });
                has_code && has_interface
            })
            .returning(|_, _| Ok(()))
            .once();
    }

    fn expect_enqueue_permission_grant_event(
        mock_bridge: &mut MockIUprobeStatsBridgeService,
        uid: i32,
        timestamp: Duration,
        permission_name: &str,
    ) {
        let permission_name = permission_name.to_string();
        mock_bridge
            .expect_enqueueEvent()
            .withf(move |event, flush| {
                if *flush {
                    return false;
                }
                if event.uid != uid {
                    return false;
                }
                if event.timestampMs != timestamp.as_millis().try_into().unwrap() {
                    return false;
                }
                if event.payloadId != 2 {
                    return false;
                }
                let has_permission = event.payload.iter().any(|e| {
                    e.key == "PERMISSION_NAME"
                        && matches!(&e.value, uprobestats::Value::Value::StringValue(s) if s == &permission_name)
                });
                has_permission
            })
            .returning(|_, _| Ok(()))
            .once();
    }

    #[test]
    fn permission_grant_after_a11y_event_is_reported() -> Result<()> {
        let a11y_timestamp = Duration::from_secs(1);
        let permission_timestamp = Duration::from_secs(2);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(move |_| Ok(TEST_UID));
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp, TEST_A11Y_CODE);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp,
            TEST_PERMISSION_NAME,
        );

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(&task, &create_a11y_event(TEST_UID, TEST_A11Y_CODE, a11y_timestamp))?;
        handler.on_item(
            &task,
            &create_permission_event(TEST_PACKAGE_NAME, TEST_PERMISSION_NAME, permission_timestamp),
        )?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = handler.writer.written[0].clone();

        let expected = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(TEST_PERMISSION_NAME.to_string())),
                Field::new(Value::Int64(permission_timestamp.as_millis().try_into().unwrap())),
                Field::new(Value::Int32Vec(vec![TEST_A11Y_CODE])),
                Field::new(Value::Int64Vec(vec![a11y_timestamp.as_millis().try_into().unwrap()])),
            ],
        };

        assert_eq!(atom, expected);
        Ok(())
    }

    #[test]
    fn non_android_permission_is_ignored() -> Result<()> {
        let mock_bridge = MockIUprobeStatsBridgeService::new();

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        let permission_event = create_permission_event(
            TEST_PACKAGE_NAME,
            "com.example.permission",
            Duration::from_millis(2000),
        );
        handler.on_item(&task, &permission_event)?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 0);

        Ok(())
    }

    #[test]
    fn no_enabled_a11y_service_is_ignored() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(false));

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        let permission_event = create_permission_event(
            TEST_PACKAGE_NAME,
            TEST_PERMISSION_NAME,
            Duration::from_millis(2000),
        );
        handler.on_item(&task, &permission_event)?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 0);

        Ok(())
    }

    #[test]
    fn package_has_enabled_a11y_service_error_is_propagated() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Err(Status::new_service_specific_error(-1, None)));

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        let permission_event = create_permission_event(
            TEST_PACKAGE_NAME,
            TEST_PERMISSION_NAME,
            Duration::from_millis(2000),
        );
        let result = handler.on_item(&task, &permission_event);

        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn get_uid_for_package_error_is_propagated() -> Result<()> {
        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Err(Status::new_service_specific_error(-1, None)));

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        let permission_event = create_permission_event(
            TEST_PACKAGE_NAME,
            TEST_PERMISSION_NAME,
            Duration::from_millis(2000),
        );
        let result = handler.on_item(&task, &permission_event);

        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn a11y_event_after_permission_grant_is_ignored() -> Result<()> {
        let permission_timestamp = Duration::from_millis(1);
        let a11y_timestamp = Duration::from_millis(2);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(move |_| Ok(TEST_UID));
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp, TEST_A11Y_CODE);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp,
            TEST_PERMISSION_NAME,
        );

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(&task, &create_a11y_event(TEST_UID, TEST_A11Y_CODE, a11y_timestamp))?;
        handler.on_item(
            &task,
            &create_permission_event(TEST_PACKAGE_NAME, TEST_PERMISSION_NAME, permission_timestamp),
        )?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = handler.writer.written[0].clone();

        let expected = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(TEST_PERMISSION_NAME.to_string())),
                Field::new(Value::Int64(permission_timestamp.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![])),
                Field::new(Value::Int64Vec(vec![])),
            ],
        };

        assert_eq!(atom, expected);
        Ok(())
    }

    #[test]
    fn a11y_event_outside_window_is_ignored() -> Result<()> {
        let a11y_timestamp = Duration::from_nanos(1000);
        let permission_timestamp = A11Y_EVENT_WINDOW + Duration::from_secs(1);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(move |_| Ok(TEST_UID));
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp, TEST_A11Y_CODE);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp,
            TEST_PERMISSION_NAME,
        );

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(&task, &create_a11y_event(TEST_UID, TEST_A11Y_CODE, a11y_timestamp))?;
        handler.on_item(
            &task,
            &create_permission_event(TEST_PACKAGE_NAME, TEST_PERMISSION_NAME, permission_timestamp),
        )?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = handler.writer.written[0].clone();

        let expected = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(TEST_PERMISSION_NAME.to_string())),
                Field::new(Value::Int64(permission_timestamp.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![])),
                Field::new(Value::Int64Vec(vec![])),
            ],
        };

        assert_eq!(atom, expected);
        Ok(())
    }

    #[test]
    fn multiple_a11y_events_are_recorded() -> Result<()> {
        let a11y_code1 = 456;
        let a11y_code2 = 789;
        let a11y_timestamp1 = Duration::from_millis(10);
        let a11y_timestamp2 = Duration::from_millis(15);
        let permission_timestamp = Duration::from_millis(20);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(move |_| Ok(TEST_UID));
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp1, a11y_code1);
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp2, a11y_code2);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp,
            TEST_PERMISSION_NAME,
        );

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(&task, &create_a11y_event(TEST_UID, a11y_code1, a11y_timestamp1))?;
        handler.on_item(&task, &create_a11y_event(TEST_UID, a11y_code2, a11y_timestamp2))?;
        handler.on_item(
            &task,
            &create_permission_event(TEST_PACKAGE_NAME, TEST_PERMISSION_NAME, permission_timestamp),
        )?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = handler.writer.written[0].clone();

        let expected = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(TEST_PERMISSION_NAME.to_string())),
                Field::new(Value::Int64(permission_timestamp.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![a11y_code2, a11y_code1])),
                Field::new(Value::Int64Vec(vec![
                    a11y_timestamp2.as_millis().try_into()?,
                    a11y_timestamp1.as_millis().try_into()?,
                ])),
            ],
        };

        assert_eq!(atom, expected);
        Ok(())
    }

    #[test]
    fn multiple_permission_grants() -> Result<()> {
        let package_name_a = "pkg.name.a";
        let permission_name_a = "android.permission.A";
        let package_name_b = "pkg.name.b";
        let permission_name_b = "android.permission.B";
        let a11y_code1 = 456;
        let a11y_code2 = 789;
        let a11y_timestamp1 = Duration::from_millis(10);
        let permission_timestamp_a = Duration::from_millis(20);
        let a11y_timestamp2 = Duration::from_millis(30);
        let permission_timestamp_b = Duration::from_millis(40);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(package_name_a))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(package_name_b))
            .returning(|_| Ok(true));
        mock_bridge.expect_getUidForPackage().returning(move |pkg| {
            if pkg == package_name_a || pkg == package_name_b {
                Ok(TEST_UID)
            } else {
                panic!("getUidForPackage called with unexpected package name: {}", pkg);
            }
        });
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp_a,
            permission_name_a,
        );
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp1, a11y_code1);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp_b,
            permission_name_b,
        );
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp2, a11y_code2);

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(
            &task,
            &create_permission_event(package_name_a, permission_name_a, permission_timestamp_a),
        )?;
        handler.on_item(&task, &create_a11y_event(TEST_UID, a11y_code1, a11y_timestamp1))?;
        handler.on_item(
            &task,
            &create_permission_event(package_name_b, permission_name_b, permission_timestamp_b),
        )?;
        handler.on_item(&task, &create_a11y_event(TEST_UID, a11y_code2, a11y_timestamp2))?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 2);

        let atom_b = handler.writer.written[0].clone();
        let expected_b = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(permission_name_b.to_string())),
                Field::new(Value::Int64(permission_timestamp_b.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![a11y_code2])),
                Field::new(Value::Int64Vec(vec![a11y_timestamp2.as_millis().try_into()?])),
            ],
        };
        assert_eq!(atom_b, expected_b);

        let atom_a = handler.writer.written[1].clone();
        let expected_a = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(permission_name_a.to_string())),
                Field::new(Value::Int64(permission_timestamp_a.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![a11y_code1])),
                Field::new(Value::Int64Vec(vec![a11y_timestamp1.as_millis().try_into()?])),
            ],
        };
        assert_eq!(atom_a, expected_a);

        Ok(())
    }

    #[test]
    fn no_a11y_events() -> Result<()> {
        let permission_timestamp = Duration::from_millis(20);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(TEST_PACKAGE_NAME))
            .returning(move |_| Ok(TEST_UID));
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            TEST_UID,
            permission_timestamp,
            TEST_PERMISSION_NAME,
        );

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(
            &task,
            &create_permission_event(TEST_PACKAGE_NAME, TEST_PERMISSION_NAME, permission_timestamp),
        )?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = handler.writer.written[0].clone();

        let expected = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(TEST_UID), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(TEST_PERMISSION_NAME.to_string())),
                Field::new(Value::Int64(permission_timestamp.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![])),
                Field::new(Value::Int64Vec(vec![])),
            ],
        };

        assert_eq!(atom, expected);
        Ok(())
    }

    #[test]
    fn no_permission_grants() -> Result<()> {
        let a11y_timestamp = Duration::from_millis(10);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        expect_enqueue_a11y_event(&mut mock_bridge, TEST_UID, a11y_timestamp, TEST_A11Y_CODE);

        let (mut handler, task) = setup_handler_and_task(mock_bridge);
        handler.on_item(&task, &create_a11y_event(TEST_UID, TEST_A11Y_CODE, a11y_timestamp))?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 0);
        Ok(())
    }

    #[test]
    fn invalid_variant_is_an_error() -> Result<()> {
        let (mut handler, task) = setup_handler_and_task(MockIUprobeStatsBridgeService::new());
        let result = handler.on_item(
            &task,
            &AccessibilityEvent {
                variant: 99,
                uid: 0,
                code: 0,
                timestamp_ns: 0,
                package_name: [0; 128],
                permission_name: [0; 128],
            },
        );

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn multiple_uids() -> Result<()> {
        let package_name_a = "pkg.name.a";
        let permission_name_a = "android.permission.A";
        let uid_a = 123;
        let a11y_code_a = 456;
        let a11y_timestamp_a = Duration::from_millis(10);
        let permission_timestamp_a = Duration::from_millis(20);

        let package_name_b = "pkg.name.b";
        let permission_name_b = "android.permission.B";
        let uid_b = 789;
        let a11y_code_b = 101;
        let a11y_timestamp_b = Duration::from_millis(30);
        let permission_timestamp_b = Duration::from_millis(40);

        let mut mock_bridge = MockIUprobeStatsBridgeService::new();
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(package_name_a))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(package_name_a))
            .returning(move |_| Ok(uid_a));
        mock_bridge
            .expect_packageHasEnabledAccessibilityService()
            .with(eq(package_name_b))
            .returning(|_| Ok(true));
        mock_bridge
            .expect_getUidForPackage()
            .with(eq(package_name_b))
            .returning(move |_| Ok(uid_b));
        expect_enqueue_a11y_event(&mut mock_bridge, uid_a, a11y_timestamp_a, a11y_code_a);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            uid_a,
            permission_timestamp_a,
            permission_name_a,
        );
        expect_enqueue_a11y_event(&mut mock_bridge, uid_b, a11y_timestamp_b, a11y_code_b);
        expect_enqueue_permission_grant_event(
            &mut mock_bridge,
            uid_b,
            permission_timestamp_b,
            permission_name_b,
        );

        let (mut handler, task) = setup_handler_and_task(mock_bridge);

        // Events for UID A
        handler.on_item(&task, &create_a11y_event(uid_a, a11y_code_a, a11y_timestamp_a))?;
        handler.on_item(
            &task,
            &create_permission_event(package_name_a, permission_name_a, permission_timestamp_a),
        )?;

        // Events for UID B
        handler.on_item(&task, &create_a11y_event(uid_b, a11y_code_b, a11y_timestamp_b))?;
        handler.on_item(
            &task,
            &create_permission_event(package_name_b, permission_name_b, permission_timestamp_b),
        )?;

        handler.on_finished()?;

        assert_eq!(handler.writer.written.len(), 2);

        handler.writer.written.sort_by_key(|a| {
            if let Value::Int32(uid) = a.fields[0].value {
                uid
            } else {
                0
            }
        });

        let atom_a = handler.writer.written[0].clone();
        let expected_a = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(uid_a), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(permission_name_a.to_string())),
                Field::new(Value::Int64(permission_timestamp_a.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![a11y_code_a])),
                Field::new(Value::Int64Vec(vec![a11y_timestamp_a.as_millis().try_into()?])),
            ],
        };
        assert_eq!(atom_a, expected_a);

        let atom_b = handler.writer.written[1].clone();
        let expected_b = UnstructuredAtom {
            atom_id: ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT,
            fields: vec![
                Field::new_with_annotation(Value::Int32(uid_b), FieldAnnotation::IsUid(true)),
                Field::new(Value::String(permission_name_b.to_string())),
                Field::new(Value::Int64(permission_timestamp_b.as_millis().try_into()?)),
                Field::new(Value::Int32Vec(vec![a11y_code_b])),
                Field::new(Value::Int64Vec(vec![a11y_timestamp_b.as_millis().try_into()?])),
            ],
        };
        assert_eq!(atom_b, expected_b);

        Ok(())
    }

    #[test]
    fn accessibility_event_empty_fields_fail() -> Result<()> {
        let (mut handler, task) = setup_handler_and_task(MockIUprobeStatsBridgeService::new());

        // empty package_name
        let data = create_permission_event("", TEST_PERMISSION_NAME, Duration::from_secs(1));
        assert!(handler.on_item(&task, &data).is_err());

        // empty permission_name
        let data = create_permission_event(TEST_PACKAGE_NAME, "", Duration::from_secs(1));
        assert!(handler.on_item(&task, &data).is_err());

        Ok(())
    }
}
