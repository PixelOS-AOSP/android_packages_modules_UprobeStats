use super::JAVA_ARGUMENT_REGISTER_OFFSET;
use anyhow::{anyhow, Result};
use log::{debug, trace};
use protobuf::MessageField;
use statssocket::AStatsEvent;
use uprobestats_bpf_bindgen::{CallResult, CallTimestamp};
use uprobestats_core::{bpf_handler::Handler, config_resolver::ResolvedTask};

#[derive(Default)]
pub struct CallTimestampHandler {}

// SAFETY: `CallTimestamp` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for CallTimestampHandler {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_timestamp_buf";
    type T = CallTimestamp;
    fn on_item(&mut self, task: &ResolvedTask, data: &CallTimestamp) -> Result<()> {
        debug!("CallTimestamp - event: {}, timestamp_ns: {}", data.event, data.timestampNs,);

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        trace!("attempting to write atom id: {atom_id}");
        let mut event = AStatsEvent::new(atom_id.try_into()?);
        event.write_int32(data.event.try_into()?);
        event.write_int64(data.timestampNs.try_into()?);
        event.write()?;
        debug!("successfully wrote atom id: {atom_id}");
        Ok(())
    }
}

#[derive(Default)]
pub struct CallResultHandler {}

// SAFETY: `CallResult` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for CallResultHandler {
    const MAP_PATH: &'static str =
        "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_detail_buf";
    type T = CallResult;
    fn on_item(&mut self, task: &ResolvedTask, data: &CallResult) -> Result<()> {
        debug!("CallResult - register: pc = {}", data.pc,);
        for i in 0..10 {
            debug!("CallResult - register: {} = {}", i, data.regs[i],);
        }

        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
            return Ok(());
        };

        trace!("has logging config");
        let atom_id = statsd_logging_config
            .atom_id
            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;

        trace!("attempting to write atom id: {atom_id}");
        let mut event = AStatsEvent::new(atom_id.try_into()?);

        for primitive_argument_position in &statsd_logging_config.primitive_argument_positions {
            let register_index: usize =
                (JAVA_ARGUMENT_REGISTER_OFFSET + primitive_argument_position).try_into()?;
            let primitive_argument: i32 = data.regs[register_index].try_into()?;
            debug!(
                "writing primitive_argument: {primitive_argument} from position: {primitive_argument_position}"
            );
            event.write_int32(primitive_argument);
        }

        event.write()?;
        debug!("successfully wrote atom id: {atom_id}");

        Ok(())
    }
}
