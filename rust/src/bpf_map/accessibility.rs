use super::{bytes_as_str, Handler};
use crate::uprobestats_bridge_service::UPROBESTATS_BRIDGE_SERVICE;
use anyhow::{anyhow, bail, Result};
use log::{debug, trace};
use statssocket::{AStatsEvent, AnnotationIds_ASTATSLOG_ANNOTATION_ID_IS_UID};
use std::collections::HashMap;
use std::num::TryFromIntError;
use std::time::Duration;
use uprobestats_bpf_bindgen::AccessibilityEvent;
use uprobestats_core::config_resolver::ResolvedTask;

#[derive(Default)]
pub struct AccessibilityHandler {
    events: HashMap<i32, Vec<Event>>,
}

const A11Y_EVENT_WINDOW: Duration = Duration::from_secs(10);
const ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT: u32 = 1217;

// SAFETY: `AccessibilityEvent` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for AccessibilityHandler {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Accessibility_output_buf";
    type T = AccessibilityEvent;
    fn on_item(&mut self, _task: &ResolvedTask, data: &AccessibilityEvent) -> Result<()> {
        let timestamp_ns = data.timestamp_ns;
        #[cfg(target_pointer_width = "32")]
        let timestamp_ns = timestamp_ns.into();
        let variant = data.variant;
        trace!("variant={variant}, timestamp_ns={timestamp_ns}");
        let event: Result<Option<Event>> = if data.variant == 1 {
            handle_permission_grant_event(data, timestamp_ns)
        } else if data.variant == 2 {
            handle_a11y_event(data, timestamp_ns)
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
            permission_name,
            preceding_a11y_calls,
        } in a11y_runtime_permission_grants
        {
            debug!("uid={uid}, timestamp={:?}, permission_name={permission_name}", timestamp);
            for preceding_a11y_call in preceding_a11y_calls.iter() {
                debug!("preceding_a11y_call={preceding_a11y_call:?}");
            }
            // Log all runtime permission grants for apps with enabled a11y services. If the permission grant was driven by the same app using a11y,
            // it should be represented in `preceding_a11y_calls`.
            let mut event = AStatsEvent::new(ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT);
            event.write_int32(uid);
            event.add_bool_annotation(AnnotationIds_ASTATSLOG_ANNOTATION_ID_IS_UID, true);
            event.write_string(&permission_name)?;
            event.write_int64(timestamp.as_millis().try_into()?);
            event.write_int32_slice(
                &preceding_a11y_calls.iter().map(|(c, _)| *c).collect::<Vec<i32>>(),
            );
            event.write_int64_slice(
                &preceding_a11y_calls
                    .iter()
                    .map(|(_, t)| t.as_millis().try_into().map_err(|e: TryFromIntError| anyhow!(e)))
                    .collect::<Result<Vec<i64>>>()?,
            );
            event.write();
            trace!("wrote atom {ATOM_ID_ACCESSIBILITY_RUNTIME_PERMISSION_GRANT} for permission {permission_name}");
        }
        Ok(())
    }
}

fn handle_permission_grant_event(
    data: &AccessibilityEvent,
    timestamp_ns: u64,
) -> Result<Option<Event>> {
    // permission grant event
    let package_name = bytes_as_str(&data.package_name)?;
    let permission_name = bytes_as_str(&data.permission_name)?;

    trace!("package_name={package_name}, permission_name={permission_name}");

    // Only log system permissions.
    if !permission_name.starts_with("android.permission") {
        return Ok(None);
    }

    let service = UPROBESTATS_BRIDGE_SERVICE.as_ref().map_err(|e| anyhow!(e))?;
    let has_enabled_a11y_service = service.packageHasEnabledAccessibilityService(package_name)?;
    trace!("has_enabled_a11y_service={has_enabled_a11y_service}");

    // Only log if the package in question also has an enabled a11y service.
    if !has_enabled_a11y_service {
        return Ok(None);
    }

    let uid = service.getUidForPackage(package_name)?;

    trace!("uid={uid}");

    Ok(Some(Event::new(
        uid,
        timestamp_ns,
        EventType::RuntimePermissionGrant(permission_name.to_string()),
    )))
}

fn handle_a11y_event(data: &AccessibilityEvent, timestamp_ns: u64) -> Result<Option<Event>> {
    // IAccessibilityServiceConnection event
    let uid = data.uid;
    let code = data.code;
    trace!("uid={uid}, code={code}");
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

#[derive(Debug)]
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

#[derive(Debug)]
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
