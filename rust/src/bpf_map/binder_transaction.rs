// use super::test::print_xxd_like;
use super::{bytes_as_str, BpfMap, BpfMapAccessor, Handler};
use crate::config_resolver::ResolvedTask;
use anyhow::{bail, Result};
use log::debug;
use statssocket::AStatsEvent;
use std::{
    ops::Deref,
    os::raw::{c_char, c_ulong},
};
use uprobestats_bpf_bindgen::{
    BinderCodesBpfMapValue, BinderInterfaceBpfMapKey, BinderTransaction,
};
use zerocopy::transmute_ref;

#[derive(Default)]
pub(crate) struct BinderTransactionHandler {}

// SAFETY: `BpfDebug` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
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
        event.write();
        debug!("successfully write test_uprobestats_atom_reported");
        Ok(())
    }
}

/// A handle to the BPF map that stores binder transaction filters.
///
/// This is a zero-sized type used to implement `BpfMap` for this specific map.
#[derive(Default)]
pub struct BinderInterfaceBpfMap {}

/// A specialized accessor for the BinderInterfaceBpfMap with a `drain` method to remove all keys.
pub struct BinderInterfaceMapAccessor(BpfMapAccessor<BinderInterfaceBpfMap>);

impl BinderInterfaceMapAccessor {
    /// Creates a new accessor for the binder interface map.
    pub fn new() -> Result<Self> {
        Ok(Self(BpfMapAccessor::new()?))
    }

    /// Drains all entries from the map.
    pub fn drain(&self) -> Result<()> {
        while let Some(key) = self.get_first_key()? {
            let deleted = self.delete(&key)?;
            if !deleted {
                bail!("Failed to delete key {}", key);
            }
            debug!("deleted {key} from binder interface bpf map");
        }
        Ok(())
    }
}

impl Deref for BinderInterfaceMapAccessor {
    type Target = BpfMapAccessor<BinderInterfaceBpfMap>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// SAFETY:
// - `BinderInterfaceBpfMap` is a struct defined in the given `MAP_PATH`.
// - `MAP_PATH`` is guaranteed to hold keys of type `BinderInterfaceBpfMapKey` and values
//   of type `BinderCodesBpfMapValue`.
unsafe impl BpfMap for BinderInterfaceBpfMap {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_Binder_interfaces";
    type K = String;
    type V = Vec<c_ulong>;
    type CKey = BinderInterfaceBpfMapKey;
    type CValue = BinderCodesBpfMapValue;

    fn to_c_key(key: &String) -> BinderInterfaceBpfMapKey {
        let mut interface_descriptor: [c_char; 128] = [0; 128];
        let bytes: &[c_char] = transmute_ref!(key.as_bytes());
        let len = std::cmp::min(bytes.len(), interface_descriptor.len());
        interface_descriptor[..len].copy_from_slice(&bytes[..len]);
        BinderInterfaceBpfMapKey { interface_descriptor }
    }

    fn to_c_value(value: &Vec<c_ulong>) -> BinderCodesBpfMapValue {
        let mut codes: [c_ulong; 10] = [0; 10];
        let len = std::cmp::min(value.len(), codes.len());
        codes[..len].copy_from_slice(&value[..len]);
        BinderCodesBpfMapValue { codes }
    }

    fn from_c_value(value: &BinderCodesBpfMapValue) -> Vec<c_ulong> {
        value.codes.into_iter().collect::<Vec<c_ulong>>()
    }

    fn from_c_key(key: &BinderInterfaceBpfMapKey) -> String {
        bytes_as_str(&key.interface_descriptor).unwrap_or_default().to_string()
    }
}
