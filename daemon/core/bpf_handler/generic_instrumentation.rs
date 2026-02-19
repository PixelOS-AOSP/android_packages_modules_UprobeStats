use crate::{
    atom::{AtomWriter, Field, UnstructuredAtom, Value},
    bpf_handler::Handler,
    config_resolver::ResolvedTask,
};
use anyhow::{anyhow, Result};
use log::{debug, trace};
use protobuf::MessageField;
use uprobestats_bpf_structs::{CallResult, CallTimestamp};

const JAVA_ARGUMENT_REGISTER_OFFSET: i32 = 2;

/// Handler for generic timestamp events.
#[derive(Default)]
pub struct CallTimestampHandler<A> {
    writer: A,
}

// SAFETY: `CallTimestamp` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler for CallTimestampHandler<A> {
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
        let atom = UnstructuredAtom {
            atom_id: atom_id.try_into()?,
            fields: vec![
                Field::new(Value::Int32(data.event.try_into()?)),
                Field::new(Value::Int64(data.timestampNs.try_into()?)),
            ],
        };
        self.writer.write(atom)?;
        debug!("successfully wrote atom id: {atom_id}");
        Ok(())
    }
}

/// Handler for generic call result events, capturing register values.
#[derive(Default)]
pub struct CallResultHandler<A> {
    writer: A,
}

// SAFETY: `CallResult` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler for CallResultHandler<A> {
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

        let mut fields = Vec::new();
        for primitive_argument_position in &statsd_logging_config.primitive_argument_positions {
            let register_index: usize =
                (JAVA_ARGUMENT_REGISTER_OFFSET + primitive_argument_position).try_into()?;
            let primitive_argument: i32 = data.regs[register_index].try_into()?;
            debug!(
                "writing primitive_argument: {primitive_argument} from position: {primitive_argument_position}"
            );
            fields.push(Field::new(Value::Int32(primitive_argument)));
        }

        let atom = UnstructuredAtom { atom_id: atom_id.try_into()?, fields };
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
        config_resolver::ResolvedTask,
    };
    use anyhow::Result;
    use protobuf::MessageField;
    use std::collections::HashSet;
    use uprobestats_proto::config::uprobestats_config::{task::StatsdLoggingConfig, Task};

    fn create_task_with_atom_id(atom_id: i32) -> ResolvedTask {
        let mut task = Task::new();
        let mut statsd_logging_config = StatsdLoggingConfig::new();
        statsd_logging_config.set_atom_id(atom_id.into());
        task.statsd_logging_config = MessageField::some(statsd_logging_config);

        ResolvedTask {
            task,
            pid: 0,
            uid: 0,
            process_name: "".to_string(),
            duration_seconds: 0,
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
        }
    }

    fn create_task_without_logging_config() -> ResolvedTask {
        ResolvedTask {
            task: Task::new(),
            pid: 0,
            uid: 0,
            process_name: "".to_string(),
            duration_seconds: 0,
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
        }
    }

    #[test]
    fn call_timestamp_handler_writes_atom() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = CallTimestampHandler { writer: atom_writer };
        let task = create_task_with_atom_id(123);
        let data = CallTimestamp { event: 456, timestampNs: 789 };

        handler.on_item(&task, &data)?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        assert_eq!(atom.atom_id, 123);
        assert_eq!(
            atom.fields,
            vec![Field::new(Value::Int32(456)), Field::new(Value::Int64(789)),]
        );
        Ok(())
    }

    #[test]
    fn call_result_handler_writes_atom() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = CallResultHandler { writer: atom_writer };
        let mut task = create_task_with_atom_id(123);
        task.task.statsd_logging_config.as_mut().unwrap().primitive_argument_positions.push(1);
        task.task.statsd_logging_config.as_mut().unwrap().primitive_argument_positions.push(3);

        let mut data = CallResult { pc: 0, regs: [0; 10] };
        data.regs[JAVA_ARGUMENT_REGISTER_OFFSET as usize + 1] = 101;
        data.regs[JAVA_ARGUMENT_REGISTER_OFFSET as usize + 3] = 103;

        handler.on_item(&task, &data)?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        assert_eq!(atom.atom_id, 123);
        assert_eq!(
            atom.fields,
            vec![Field::new(Value::Int32(101)), Field::new(Value::Int32(103)),]
        );
        Ok(())
    }

    #[test]
    fn call_timestamp_handler_no_logging_config_does_not_write_atom() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = CallTimestampHandler { writer: atom_writer };
        let task = create_task_without_logging_config();
        let data = CallTimestamp { event: 456, timestampNs: 789 };

        handler.on_item(&task, &data)?;

        assert!(handler.writer.written.is_empty());
        Ok(())
    }

    #[test]
    fn call_result_handler_no_logging_config_does_not_write_atom() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = CallResultHandler { writer: atom_writer };
        let task = create_task_without_logging_config();
        let data = CallResult { pc: 0, regs: [0; 10] };

        handler.on_item(&task, &data)?;

        assert!(handler.writer.written.is_empty());
        Ok(())
    }
}
