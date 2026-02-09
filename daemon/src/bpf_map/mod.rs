//! Deals with fetching data BPF ring buffers ("maps").
use crate::atom::CodegenAtomWriter;
use crate::bpf_map::binder_transaction::BinderTransactionHandler;
#[cfg(feature = "bridge-service")]
use crate::bridge_service::DefaultUprobeStatsBridgeService;
#[cfg(feature = "bridge-service")]
use crate::device_properties::DefaultDeviceProperties;
use anyhow::{bail, Result};
use log::{debug, error, trace};
use statssocket::AStatsEventWriter;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, sync::LazyLock, time::Duration};
use uprobestats_bpf::{
    bpf_map_close, bpf_map_delete_elem, bpf_map_get_first_key, bpf_map_lookup_elem,
    bpf_map_open_exclusive_rw, bpf_map_update_elem, poll_ring_buf, UpdateMapElemFlags,
};
use uprobestats_bpf_bindgen::BpfMapHandle;
#[cfg(feature = "art-test")]
use uprobestats_core::bpf_handler::art_test::{AotHandler, JitHandler};
use uprobestats_core::bpf_handler::bitmap_allocation::{
    BitmapAllocationHandlerV0, BitmapAllocationHandlerV1,
};
use uprobestats_core::bpf_handler::generic_instrumentation::{
    CallResultHandler, CallTimestampHandler,
};
use uprobestats_core::bpf_handler::process_management::{
    SetUidTempAllowlistStateRecordHandler, UpdateDeviceIdleTempAllowlistRecordHandler,
};
#[cfg(feature = "bridge-service")]
use uprobestats_core::bpf_handler::{
    accessibility::AccessibilityHandler,
    disruptive_app::{BindServiceLockedHandler, ComponentEnabledSettingHandler},
};
use uprobestats_core::{
    bpf_handler::{Handler, HandlerRegistry},
    config_resolver::ResolvedTask,
    timer::Timer,
};

/// Contains handlers and map writers for Binder transaction-related BPF maps.
pub mod binder_transaction;

/// Polls the given map_path based on the existing registry of handlers.
pub fn poll_registry(map_path: &str, task: &ResolvedTask, duration: Duration) -> Result<()> {
    let Some(poll_loop_fn) = HANDLER_REGISTRY.get(map_path) else {
        bail!("unsupported map_path: {}", map_path);
    };
    poll_loop_fn(map_path, task, duration)
}

fn poll_loop_generic<H: Handler + Default>(
    map_path: &str,
    task: &ResolvedTask,
    duration: Duration,
) -> Result<()> {
    if map_path != H::MAP_PATH {
        bail!("map_path mismatch: {} != {}", map_path, H::MAP_PATH)
    }
    let mut handler = H::default();
    let timer = Timer::new(duration);
    let mut total_events: i64 = 0;
    while let Some(remaining_millis) = timer.remaining_millis() {
        let remaining_millis: i32 = remaining_millis.try_into()?;
        debug!("polling {} for {} seconds", map_path, remaining_millis / 1000);
        // SAFETY: we've just checked that the passed `map_path` is the same as the one
        // expected by the `Handler` implementation, which encodes how the expected type is mapped to the
        // ring buffer's path.
        let result: Result<Vec<H::T>> = unsafe { poll_ring_buf(map_path, remaining_millis) };
        let result = result?;
        trace!("Done polling {}, event count: {}", map_path, result.len());
        total_events += result.len() as i64;
        for i in &result {
            handler.on_item(task, i)?;
        }
    }
    handler.on_finished()?;

    let path_enum = get_map_path_enum(map_path);
    if let Err(e) = statslog_uprobestats::uprobe_stats_bpf_map_polled::stats_write(
        path_enum,
        duration.as_millis().try_into()?,
        total_events,
        task.task.task_id.unwrap_or(0),
    ) {
        error!("Failed to write uprobe_stats_bpf_map_polled atom: {:?}", e);
    };
    Ok(())
}

fn get_map_path_enum(map_path: &str) -> statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath {
    let Some(filename) = map_path.rsplit('/').next() else {
        error!("Failed to extract filename from map_path: {}", map_path);
        return statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathUnspecified;
    };
    match filename {
        "map_Accessibility_output_buf" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathAccessibilityOutputBuf
        }
        "map_Binder_output_buf" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathBinderOutputBuf
        }
        "map_BitmapAllocation_output" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathBitmapAllocationOutput
        }
        "map_DisruptiveApp_BindServiceLocked_output_buf" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathDisruptiveAppBindServiceLockedOutputBuf
        }
        "map_DisruptiveApp_ComponentEnabledSetting_output_buf" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathDisruptiveAppComponentEnabledSettingOutputBuf
        }
        "map_GenericInstrumentation_call_detail_buf" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathGenericInstrumentationCallDetailBuf
        }
        "map_GenericInstrumentation_call_timestamp_buf" => {
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathGenericInstrumentationCallTimestampBuf
        }
        _ => {
            error!("Unspecified map_path filename: {}", filename);
            statslog_uprobestats::uprobe_stats_bpf_map_polled::MapPath::BpfMapPathUnspecified
        }
    }
}

/// Defines the static properties of a BPF map.
/// # Safety
///   - There must exist a BPF map at the path represented by `MAP_PATH`
///   - It must hold items with keys of type `CKey` and values of type `CValue`.
pub unsafe trait BpfMap {
    /// The path to the BPF map in the BPF file system.
    const MAP_PATH: &'static str;
    /// The Rust type for the map key.
    type K: Debug;
    /// The Rust type for the map value.
    type V: Debug;
    /// The C-compatible representation of the key.
    type CKey: Debug + Copy;
    /// The C-compatible representation of the value.
    type CValue: Debug + Copy;

    /// Converts a Rust key to its C representation.
    fn to_c_key(key: &Self::K) -> Self::CKey;
    /// Converts a Rust value to its C representation.
    fn to_c_value(value: &Self::V) -> Self::CValue;
    /// Converts a C value back to its Rust representation.
    fn from_c_value(value: &Self::CValue) -> Self::V;
    /// Converts a C key back to its Rust representation.
    fn from_c_key(key: &Self::CKey) -> Self::K;
}

/// Provides safe access to a BPF map.
///
/// This struct holds a handle to the BPF map, ensuring that it is
/// properly closed when the accessor goes out of scope.
pub struct BpfMapAccessor<M> {
    handle: *mut BpfMapHandle,
    _map: PhantomData<M>,
}

impl<M: BpfMap> BpfMapAccessor<M> {
    /// Creates a new `BpfMapAccessor`.
    ///
    /// This function opens the BPF map at the path specified by `M::MAP_PATH`
    /// and returns a new `BpfMapAccessor` that can be used to interact with it.
    pub fn new() -> Result<Self> {
        let handle = bpf_map_open_exclusive_rw(M::MAP_PATH)?;
        Ok(Self { handle, _map: PhantomData })
    }

    /// Puts a key-value pair into the map.
    ///
    /// Insert/Update/Upsert behavior determined by `UpdateMapElemFlags`.
    pub fn put(&self, key: &M::K, value: &M::V, flags: UpdateMapElemFlags) -> Result<()> {
        // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
        unsafe {
            bpf_map_update_elem::<M::CKey, M::CValue>(
                self.handle,
                M::to_c_key(key),
                M::to_c_value(value),
                flags,
            )
        }
    }

    /// Gets a value from the map for a given key.
    ///
    /// Returns `Ok(Some(value))` if the key exists, and `Ok(None)` if it does not.
    pub fn get(&self, key: &M::K) -> Result<Option<M::V>> {
        let found =
            // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
            unsafe { bpf_map_lookup_elem::<M::CKey, M::CValue>(self.handle, M::to_c_key(key)) }?;
        Ok(found.map(|v| M::from_c_value(&v)))
    }

    /// Gets the first key in the map.
    ///
    /// This is useful for iterating over the map's contents.
    ///
    /// Returns `Ok(Some(key))` if the map is not empty, and `Ok(None)` if it is.
    pub fn get_first_key(&self) -> Result<Option<M::K>> {
        // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
        let found = unsafe { bpf_map_get_first_key::<M::CKey>(self.handle) }?;
        Ok(found.map(|k| M::from_c_key(&k)))
    }

    /// Deletes a key-value pair from the map.
    ///
    /// Returns `Ok(true)` if the element was deleted, `Ok(false)` if it did not exist.
    pub fn delete(&self, key: &M::K) -> Result<bool> {
        // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
        unsafe { bpf_map_delete_elem::<M::CKey>(self.handle, M::to_c_key(key)) }
    }
}

impl<M> Drop for BpfMapAccessor<M> {
    fn drop(&mut self) {
        // SAFETY: The handle is guaranteed to be valid and is not used after this.
        unsafe { bpf_map_close(self.handle) };
    }
}

fn register_handler<H: Handler + Default>(handler_registry: &mut HandlerRegistry) {
    handler_registry.insert(H::MAP_PATH, poll_loop_generic::<H>);
}

#[cfg(feature = "bridge-service")]
type BindServiceLockedHandlerImpl = BindServiceLockedHandler<
    CodegenAtomWriter,
    DefaultUprobeStatsBridgeService,
    DefaultDeviceProperties,
>;

#[cfg(feature = "bridge-service")]
type ComponentEnabledSettingHandlerImpl = ComponentEnabledSettingHandler<
    CodegenAtomWriter,
    DefaultUprobeStatsBridgeService,
    DefaultDeviceProperties,
>;

static HANDLER_REGISTRY: LazyLock<HandlerRegistry> = LazyLock::new(|| {
    let mut map = HashMap::new();
    if uprobestats_mainline_flags_rust::enable_bitmap_snapshot() {
        register_handler::<BitmapAllocationHandlerV1<CodegenAtomWriter>>(&mut map);
    } else {
        register_handler::<BitmapAllocationHandlerV0<CodegenAtomWriter>>(&mut map);
    }
    if uprobestats_mainline_flags_rust::enable_binder_transaction() {
        register_handler::<BinderTransactionHandler>(&mut map);
    }
    register_handler::<CallTimestampHandler<AStatsEventWriter>>(&mut map);
    register_handler::<CallResultHandler<AStatsEventWriter>>(&mut map);
    register_handler::<SetUidTempAllowlistStateRecordHandler<AStatsEventWriter>>(&mut map);
    register_handler::<UpdateDeviceIdleTempAllowlistRecordHandler<AStatsEventWriter>>(&mut map);
    #[cfg(feature = "bridge-service")]
    {
        if uprobestats_flags_rust::a11y_runtime_permission() {
            register_handler::<
                AccessibilityHandler<AStatsEventWriter, DefaultUprobeStatsBridgeService>,
            >(&mut map);
        }
        if uprobestats_mainline_flags_rust::uprobestats_monitor_disruptive_app_activities() {
            register_handler::<BindServiceLockedHandlerImpl>(&mut map);
            register_handler::<ComponentEnabledSettingHandlerImpl>(&mut map);
        }
    }
    #[cfg(feature = "art-test")]
    {
        register_handler::<JitHandler<AStatsEventWriter>>(&mut map);
        register_handler::<AotHandler<AStatsEventWriter>>(&mut map);
    }
    map
});

#[cfg(test)]
mod test {
    use log::debug;
    use zerocopy::{Immutable, IntoBytes};
    // local test only util
    #[allow(dead_code)]
    fn print_xxd_like(prefix: &str, data: &(impl IntoBytes + Immutable)) {
        let data = data.as_bytes();
        let mut offset = 0;
        debug!("{prefix} hex:");
        for chunk in data.chunks(16) {
            // Format the offset
            let offset_str = format!("{offset:08x}:");
            // Format the hexadecimal representation
            let hex_str = chunk
                .iter()
                .enumerate()
                .map(|(i, &byte)| {
                    let hex = format!("{byte:02x}");
                    if (i + 1) % 2 == 0 && i != chunk.len() - 1 {
                        format!("{hex} ")
                    } else {
                        hex
                    }
                })
                .collect::<Vec<String>>()
                .join(" ");
            let padded_hex_str = format!("{hex_str:<48}"); // Pad to align ASCII
                                                           // Format the ASCII representation
            let ascii_str = chunk
                .iter()
                .map(
                    |&byte| {
                        if byte.is_ascii_graphic() || byte == b' ' {
                            byte as char
                        } else {
                            '.'
                        }
                    },
                )
                .collect::<String>();
            debug!("{offset_str} {padded_hex_str}  {ascii_str}");
            offset += chunk.len();
        }
    }
}
