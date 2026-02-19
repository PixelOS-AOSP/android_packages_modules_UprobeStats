//! Deals with process management events from BPF.
use crate::{
    atom::{AtomWriter, Field, UnstructuredAtom, Value},
    bpf_handler::Handler,
    config_resolver::ResolvedTask,
    string::bytes_as_str,
};
use anyhow::{anyhow, Result};
use log::{debug, trace};
use uprobestats_bpf_structs::{
    SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
};

/// Emits an atom when a UID's temporary allowlist state changes.
#[derive(Default)]
pub struct SetUidTempAllowlistStateRecordHandler<A> {
    writer: A,
}

// SAFETY: `SetUidTempAllowlistStateRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler for SetUidTempAllowlistStateRecordHandler<A> {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ProcessManagement_output_buf";
    type T = SetUidTempAllowlistStateRecord;
    fn on_item(
        &mut self,
        task: &ResolvedTask,
        data: &SetUidTempAllowlistStateRecord,
    ) -> Result<()> {
        trace!("SetUidTempAllowlistStateRecord: {data:?}");

        let Some(ref statsd_logging_config) = task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        trace!("attempting to write atom id: {atom_id}");
        let atom = UnstructuredAtom {
            atom_id: atom_id.try_into()?,
            fields: vec![
                Field::new(Value::Int32(data.uid.try_into()?)),
                Field::new(Value::Bool(data.onAllowlist)),
            ],
        };
        self.writer.write(atom)?;
        debug!("successfully wrote atom id: {atom_id}");

        Ok(())
    }
}

/// Emits an atom when the device idle temporary allowlist is updated.
#[derive(Default)]
pub struct UpdateDeviceIdleTempAllowlistRecordHandler<A> {
    writer: A,
}

// SAFETY: `UpdateDeviceIdleTempAllowlistRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler
    for UpdateDeviceIdleTempAllowlistRecordHandler<A>
{
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
    type T = UpdateDeviceIdleTempAllowlistRecord;
    fn on_item(
        &mut self,
        task: &ResolvedTask,
        data: &UpdateDeviceIdleTempAllowlistRecord,
    ) -> Result<()> {
        trace!("UpdateDeviceIdleTempAllowlistRecord: {data:?}");

        let Some(ref statsd_logging_config) = task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        trace!("attempting to write atom id: {atom_id}");
        let atom = UnstructuredAtom {
            atom_id: atom_id.try_into()?,
            fields: vec![
                Field::new(Value::Int32(data.changing_uid)),
                Field::new(Value::Bool(data.adding)),
                Field::new(Value::Int64(data.duration_ms as _)),
                Field::new(Value::Int32(data.type_)),
                Field::new(Value::Int32(data.reason_code)),
                Field::new(Value::String(bytes_as_str(&data.reason)?.to_string())),
                Field::new(Value::Int32(data.calling_uid)),
            ],
        };
        self.writer.write(atom)?;
        debug!("successfully wrote atom id: {atom_id}");

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        atom::{test::TestAtomWriter, Field, UnstructuredAtom, Value},
        config_resolver::{ResolvedProcess, ResolvedTask},
    };
    use anyhow::Result;
    use std::collections::HashSet;
    use std::time::Duration;
    use uprobestats_proto::config::uprobestats_config::task::StatsdLoggingConfig;

    fn create_task_with_atom_id(atom_id: i32) -> ResolvedTask {
        let mut statsd_logging_config = StatsdLoggingConfig::new();
        statsd_logging_config.set_atom_id(atom_id.into());

        ResolvedTask {
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess { pid: 0, uid: 0, name: "".to_string() },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: Some(statsd_logging_config),
        }
    }

    fn create_task_without_logging_config() -> ResolvedTask {
        ResolvedTask {
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess { pid: 0, uid: 0, name: "".to_string() },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        }
    }

    #[test]
    fn set_uid_temp_allowlist_state_record_handler_writes_atom() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = SetUidTempAllowlistStateRecordHandler { writer: atom_writer };
        let task = create_task_with_atom_id(123);
        let data = SetUidTempAllowlistStateRecord { uid: 456, onAllowlist: true };

        handler.on_item(&task, &data)?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        assert_eq!(atom.atom_id, 123);
        assert_eq!(
            atom.fields,
            vec![Field::new(Value::Int32(456)), Field::new(Value::Bool(true)),]
        );
        Ok(())
    }

    #[test]
    fn set_uid_temp_allowlist_state_record_handler_no_logging_config_does_not_write_atom(
    ) -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = SetUidTempAllowlistStateRecordHandler { writer: atom_writer };
        let task = create_task_without_logging_config();
        let data = SetUidTempAllowlistStateRecord { uid: 456, onAllowlist: true };

        handler.on_item(&task, &data)?;

        assert!(handler.writer.written.is_empty());
        Ok(())
    }

    #[test]
    fn update_device_idle_temp_allowlist_record_handler_writes_atom() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = UpdateDeviceIdleTempAllowlistRecordHandler { writer: atom_writer };
        let task = create_task_with_atom_id(123);
        let reason = "test reason".as_bytes();
        let mut reason_bytes = [0i8; 256];
        for (i, byte) in reason.iter().enumerate() {
            reason_bytes[i] = *byte as i8;
        }
        let data = UpdateDeviceIdleTempAllowlistRecord {
            changing_uid: 1001,
            adding: true,
            duration_ms: 5000,
            type_: 1,
            reason_code: 2,
            reason: reason_bytes,
            calling_uid: 1002,
            method_identifier: 0,
        };

        handler.on_item(&task, &data)?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        assert_eq!(atom.atom_id, 123);
        assert_eq!(
            atom.fields,
            vec![
                Field::new(Value::Int32(1001)),
                Field::new(Value::Bool(true)),
                Field::new(Value::Int64(5000)),
                Field::new(Value::Int32(1)),
                Field::new(Value::Int32(2)),
                Field::new(Value::String("test reason".to_string())),
                Field::new(Value::Int32(1002)),
            ]
        );
        Ok(())
    }

    #[test]
    fn update_device_idle_temp_allowlist_record_handler_no_logging_config_does_not_write_atom(
    ) -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = UpdateDeviceIdleTempAllowlistRecordHandler { writer: atom_writer };
        let task = create_task_without_logging_config();
        let data = UpdateDeviceIdleTempAllowlistRecord {
            changing_uid: 0,
            adding: false,
            duration_ms: 0,
            type_: 0,
            reason_code: 0,
            reason: [0i8; 256],
            calling_uid: 0,
            method_identifier: 0,
        };

        handler.on_item(&task, &data)?;

        assert!(handler.writer.written.is_empty());
        Ok(())
    }
}
