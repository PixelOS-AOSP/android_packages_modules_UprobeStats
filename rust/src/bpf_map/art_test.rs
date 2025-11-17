use super::{bytes_as_str, Handler};
use crate::config_resolver::ResolvedTask;
use anyhow::{anyhow, Result};
use log::{debug, trace};
use protobuf::MessageField;
use statssocket::AStatsEvent;
use std::sync::{LazyLock, Mutex};
use uprobestats_bpf_bindgen::{StartActivityAsUser, UpdateDeviceIdleTempAllowlistRecord};

// Holds a method identfier returned from the ART API when the requested method is JIT compiled,
// so we can assert it equals the one written from the BPF.
pub(crate) static JIT_METHOD_IDENTIFIER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

// Holds a method identfier returned from the ART API when the requested method is AOT compiled,
// so we can assert it equals the one written from the BPF.
pub(crate) static AOT_METHOD_IDENTIFIER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

#[derive(Default)]
pub(crate) struct JitHandler {}

// SAFETY: `StartActivityAsUser` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for JitHandler {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ArtTest_output_buf_jit";
    type T = StartActivityAsUser;
    fn on_item(&mut self, task: &ResolvedTask, item: &StartActivityAsUser) -> Result<()> {
        let calling_package = bytes_as_str(&item.calling_package)?;
        let api_method_identifier = JIT_METHOD_IDENTIFIER.lock().unwrap();
        let method_identifier = item.method_identifier;
        debug!(
            "StartActivityAsUser: method_identifier={}, api_method_identifier={}, calling_package={}, request_code={}, start_flags={}, user_id={}, validate_incoming_user={}, x0={}",
            method_identifier, api_method_identifier, calling_package, item.request_code, item.start_flags,item.user_id, item.validate_incoming_user, item.x0
        );

        // This BPF is used for a test, but we don't have a way in the java_host_test
        // to assert this. So assert it here.
        // (the only other thing we could do is write true/false to a test statsd atom...meh)
        #[allow(clippy::unnecessary_cast)] // needed to compile on both 32 and 64 bit targets
        let method_identifier = method_identifier as u64;
        assert_eq!(*api_method_identifier, method_identifier);

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        let mut event = AStatsEvent::new(atom_id.try_into()?);
        event.write_int64(item.validate_incoming_user.into());
        event.write_int64(item.user_id.into());
        event.write_int64(string_to_i64_hash(calling_package));
        event.write();
        debug!("successfully wrote atom id: {atom_id}");
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct AotHandler {}

// SAFETY: `UpdateDeviceIdleTempAllowlistRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for AotHandler {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ArtTest_output_buf_aot";
    type T = UpdateDeviceIdleTempAllowlistRecord;
    fn on_item(
        &mut self,
        task: &ResolvedTask,
        item: &UpdateDeviceIdleTempAllowlistRecord,
    ) -> Result<()> {
        let api_method_identifier = AOT_METHOD_IDENTIFIER.lock().unwrap();
        let method_identifier = item.method_identifier;

        debug!("UpdateDeviceIdleTempAllowlistRecord: method_identifier={}, api_method_identifier={}, changing_uid={}, adding={}, duration_ms={}, type={}, reason_code={}, reason={}, calling_uid={}",
            method_identifier,
            api_method_identifier,
            item.changing_uid,
            item.adding,
            item.duration_ms,
            item.type_,
            item.reason_code,
            bytes_as_str(&item.reason)?,
            item.calling_uid
        );

        // This BPF is used for a test, but we don't have a way in the java_host_test
        // to assert this. So assert it here.
        // (the only other thing we could do is write true/false to a test statsd atom...meh)
        #[allow(clippy::unnecessary_cast)] // needed to compile on both 32 and 64 bit targets
        let method_identifier = method_identifier as u64;
        assert_eq!(*api_method_identifier, method_identifier);

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        let mut event = AStatsEvent::new(atom_id.try_into()?);
        event.write_int64(item.adding.into());
        event.write_int64(item.reason_code.into());
        let reason = bytes_as_str(&item.reason)?;
        event.write_int64(string_to_i64_hash(reason));
        event.write();
        debug!("successfully wrote atom id: {atom_id}");
        Ok(())
    }
}

// Represent a string as a number. All we need is something to assert against in a test.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
fn string_to_i64_hash(s: &str) -> i64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    let u64_hash = hasher.finish();
    u64_hash as i64
}
