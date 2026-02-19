use anyhow::Result;
use log::debug;
use statssocket::AStatsEvent;
use uprobestats_bpf_bindgen::BinderTransaction;
use uprobestats_core::{bpf_handler::Handler, config_resolver::ResolvedTask, string::bytes_as_str};

#[derive(Default)]
pub(crate) struct BinderTransactionHandler {}

// SAFETY: `BinderTransaction` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for BinderTransactionHandler {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Binder_output_buf";
    type T = BinderTransaction;
    fn on_item(&mut self, _task: &ResolvedTask, item: &BinderTransaction) -> Result<()> {
        let name = bytes_as_str(&item.interface_descriptor)?;
        debug!(
            "BinderTransaction: interface_descriptor={}, code={}, calling_uid={}, timestamp_ns={}",
            name, item.code, item.calling_uid, item.timestamp_ns
        );
        // TODO(b/408256309) call ProtectionLogEvent client when available.
        let mut event = AStatsEvent::new(915); // test_uprobestats_atom_reported
        event.write_int32(item.calling_uid);
        event.write()?;
        debug!("successfully write test_uprobestats_atom_reported");
        Ok(())
    }
}
