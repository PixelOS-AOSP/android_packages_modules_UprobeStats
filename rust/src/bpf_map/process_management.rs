use super::{bytes_as_str, Handler};
use crate::config_resolver::ResolvedTask;
use anyhow::{anyhow, Result};
use log::{debug, trace};
use protobuf::MessageField;
use statssocket::AStatsEvent;
use uprobestats_bpf_bindgen::{
    SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
};

#[derive(Default)]
pub struct SetUidTempAllowlistStateRecordHandler {}

// SAFETY: `SetUidTempAllowlistStateRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for SetUidTempAllowlistStateRecordHandler {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ProcessManagement_output_buf";
    type T = SetUidTempAllowlistStateRecord;
    fn on_item(
        &mut self,
        task: &ResolvedTask,
        data: &SetUidTempAllowlistStateRecord,
    ) -> Result<()> {
        trace!("SetUidTempAllowlistStateRecord: {data:?}");

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        trace!("attempting to write atom id: {atom_id}");
        let mut event = AStatsEvent::new(atom_id.try_into()?);

        event.write_int32(data.uid.try_into()?);
        event.write_bool(data.onAllowlist);

        event.write();
        debug!("successfully wrote atom id: {atom_id}");

        Ok(())
    }
}

#[derive(Default)]
pub struct UpdateDeviceIdleTempAllowlistRecordHandler {}

// SAFETY: `UpdateDeviceIdleTempAllowlistRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for UpdateDeviceIdleTempAllowlistRecordHandler {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
    type T = UpdateDeviceIdleTempAllowlistRecord;
    fn on_item(
        &mut self,
        task: &ResolvedTask,
        data: &UpdateDeviceIdleTempAllowlistRecord,
    ) -> Result<()> {
        trace!("UpdateDeviceIdleTempAllowlistRecord: {data:?}");

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        trace!("attempting to write atom id: {atom_id}");
        let mut event = AStatsEvent::new(atom_id.try_into()?);

        event.write_int32(data.changing_uid);
        event.write_bool(data.adding);
        event.write_int64(data.duration_ms as _);
        event.write_int32(data.type_);
        event.write_int32(data.reason_code);
        event.write_string(bytes_as_str(&data.reason)?)?;
        event.write_int32(data.calling_uid);

        event.write();
        debug!("successfully wrote atom id: {atom_id}");

        Ok(())
    }
}
