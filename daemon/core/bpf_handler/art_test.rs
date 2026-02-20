use crate::{
    atom::{AtomWriter, Field, UnstructuredAtom, Value},
    bpf_handler::Handler,
    config_resolver::ResolvedTask,
    string::bytes_as_str,
};
use anyhow::{anyhow, Result};
use log::{debug, trace};
use uprobestats_bpf_structs::{StartActivityAsUser, UpdateDeviceIdleTempAllowlistRecord};

/// Test handler for JIT compiled code.
#[derive(Default)]
pub struct JitHandler<A> {
    writer: A,
}

// SAFETY: `StartActivityAsUser` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler for JitHandler<A> {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ArtTest_output_buf_jit";
    type T = StartActivityAsUser;
    fn on_item(&mut self, task: &ResolvedTask, item: &StartActivityAsUser) -> Result<()> {
        let calling_package = bytes_as_str(&item.calling_package)?;
        let method_identifier = item.method_identifier;
        let api_method_identifier = task.resolved_probes[0].offsets.method_identifier();
        debug!(
            "StartActivityAsUser: method_identifier={}, api_method_identifier={}, calling_package={}, request_code={}, start_flags={}, user_id={}, validate_incoming_user={}, x0={}",
            method_identifier, api_method_identifier, calling_package, item.request_code, item.start_flags,item.user_id, item.validate_incoming_user, item.x0
        );

        // This BPF is used for a test, but we don't have a way in the java_host_test
        // to assert this. So assert it here.
        // (the only other thing we could do is write true/false to a test statsd atom...meh)
        #[cfg(target_pointer_width = "32")]
        let method_identifier = method_identifier as u64;
        assert_eq!(api_method_identifier, method_identifier);

        let Some(ref statsd_logging_config) = task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        let atom = UnstructuredAtom {
            atom_id: atom_id.try_into().unwrap(),
            fields: vec![
                Field::new(Value::Int64(item.validate_incoming_user.into())),
                Field::new(Value::Int64(item.user_id.into())),
                Field::new(Value::Int64(string_to_i64_hash(calling_package))),
            ],
        };
        self.writer.write(atom)?;

        debug!("successfully wrote atom id: {atom_id}");
        Ok(())
    }
}

/// Test handler for AOT compiled code.
#[derive(Default)]
pub struct AotHandler<A> {
    writer: A,
}

// SAFETY: `UpdateDeviceIdleTempAllowlistRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler for AotHandler<A> {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ArtTest_output_buf_aot";
    type T = UpdateDeviceIdleTempAllowlistRecord;
    fn on_item(
        &mut self,
        task: &ResolvedTask,
        item: &UpdateDeviceIdleTempAllowlistRecord,
    ) -> Result<()> {
        let method_identifier = item.method_identifier;
        let api_method_identifier = task.resolved_probes[0].offsets.method_identifier();
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
        #[cfg(target_pointer_width = "32")]
        let method_identifier = method_identifier as u64;
        assert_eq!(api_method_identifier, method_identifier);

        let Some(ref statsd_logging_config) = task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        let reason = bytes_as_str(&item.reason)?;

        let atom = UnstructuredAtom {
            atom_id: atom_id.try_into()?,
            fields: vec![
                Field::new(Value::Int64(item.adding.into())),
                Field::new(Value::Int64(item.reason_code.into())),
                Field::new(Value::Int64(string_to_i64_hash(reason))),
            ],
        };
        self.writer.write(atom)?;

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
