use crate::{
    atom::{AtomWriter, Field, UnstructuredAtom, Value},
    bpf_handler::Handler,
    config_resolver::ResolvedTask,
    string::bytes_as_str,
};
use anyhow::Result;
use log::debug;
use uprobestats_bpf_structs::BinderTransaction;

/// Generic handler for instrumenting Binder transactions served by java in system server.
#[derive(Default)]
pub struct BinderTransactionHandler<A> {
    writer: A,
}

// SAFETY: `BinderTransaction` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<A: AtomWriter<UnstructuredAtom>> Handler for BinderTransactionHandler<A> {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Binder_output_buf";
    type T = BinderTransaction;
    fn on_item(&mut self, _task: &ResolvedTask, item: &BinderTransaction) -> Result<()> {
        let name = bytes_as_str(&item.interface_descriptor)?;
        debug!(
            "BinderTransaction: interface_descriptor={}, code={}, calling_uid={}, timestamp_ns={}",
            name, item.code, item.calling_uid, item.timestamp_ns
        );

        let atom = UnstructuredAtom {
            atom_id: 915, // test_uprobestats_atom_reported
            fields: vec![Field::new(Value::Int32(item.calling_uid))],
        };
        self.writer.write(atom)?;
        debug!("successfully write test_uprobestats_atom_reported");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        atom::{test::TestAtomWriter, Field, UnstructuredAtom, Value},
        bpf_handler::Handler,
        config_resolver::{ResolvedProcess, ResolvedTask},
    };
    use anyhow::Result;
    use std::collections::HashSet;
    use std::time::Duration;
    use uprobestats_bpf_structs::BinderTransaction;

    #[test]
    fn test_binder_transaction_handler() -> Result<()> {
        let atom_writer = TestAtomWriter::<UnstructuredAtom>::default();
        let mut handler = BinderTransactionHandler { writer: atom_writer };
        let task = ResolvedTask {
            id: 1,
            duration: Duration::from_secs(10),
            resolved_process: ResolvedProcess {
                uid: 1000,
                pid: 1,
                name: "test_process".to_string(),
            },
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
            resolved_probes: vec![],
        };
        let item = BinderTransaction {
            interface_descriptor: [0; 128],
            code: 1,
            calling_uid: 1000,
            timestamp_ns: 12345,
        };

        handler.on_item(&task, &item)?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        assert_eq!(atom.atom_id, 915);
        assert_eq!(atom.fields.len(), 1);
        assert_eq!(atom.fields[0], Field::new(Value::Int32(1000)));
        Ok(())
    }
}
