//! Deals with fetching data BPF ring buffers ("maps").
use crate::atom::{bpf_map_path_to_enum, write_internal_error, CodegenAtomWriter};
use crate::bridge_service::DefaultUprobeStatsBridgeService;
use crate::device_properties::DefaultDeviceProperties;
use crate::is_at_least_cinnamon_bun;
use anyhow::{bail, Result};
use log::{debug, error, trace};
use statslog_uprobestats::{uprobe_stats_bpf_map_polled, uprobe_stats_internal_error::ErrorType};
use statssocket::AStatsEventWriter;
use std::{collections::HashMap, sync::LazyLock, time::Duration};
use uprobestats_bpf::BpfRingBuffer;
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
use uprobestats_core::error::{ReportedToStatsd, UprobeStatsError};
use uprobestats_core::{
    bpf_handler::{
        accessibility::AccessibilityHandler,
        binder_transaction::BinderTransactionHandler,
        disruptive_app::{BindServiceLockedHandler, ComponentEnabledSettingHandler},
        Handler, HandlerRegistry,
    },
    config_resolver::ResolvedTask,
    timer::Timer,
};

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
    // SAFETY: we've just checked that the passed `map_path` is the same as the one
    // expected by the `Handler` implementation, which encodes how the expected type is mapped to the
    // ring buffer's path.
    let mut ring_buffer = unsafe { BpfRingBuffer::<H::T>::new(map_path) }.map_err(|e| {
        error!("Failed to create BPF ring buffer for map_path {}: {:?}", map_path, e);
        write_internal_error(
            ErrorType::ErrorTypeBpfRingBufferCreateFailed,
            task.id,
            H::PROG_PATH,
            Some(map_path),
            0,
        );
        ReportedToStatsd(e)
    })?;
    while let Some(remaining_millis) = timer.remaining_millis() {
        let remaining_millis: i32 = remaining_millis.try_into()?;
        debug!("polling {} for {} seconds", map_path, remaining_millis / 1000);
        let result = ring_buffer.poll(remaining_millis).map_err(|e| {
            error!("Failed to poll BPF ring buffer for map_path {}: {:?}", map_path, e);
            write_internal_error(
                ErrorType::ErrorTypeBpfRingBufferPollFailed,
                task.id,
                H::PROG_PATH,
                Some(map_path),
                0,
            );
            ReportedToStatsd(e)
        })?;

        trace!("Done polling {}, event count: {}", map_path, result.len());
        total_events += result.len() as i64;
        for i in &result {
            handler.on_item(task, i).map_err(|e| {
                error!("Error in on_item for map_path {}: {:?}", map_path, e);
                let (error_type, failure_point) = match e.downcast_ref::<UprobeStatsError>() {
                    Some(UprobeStatsError::BpfProgramError(point)) => {
                        (ErrorType::ErrorTypeBpfProgramError, *point)
                    }
                    Some(UprobeStatsError::BpfDataInvalid(point)) => {
                        (ErrorType::ErrorTypeBpfRingBufferDataInvalid, *point)
                    }
                    _ => (ErrorType::ErrorTypeTaskExecutionFailed, 0),
                };
                write_internal_error(
                    error_type,
                    task.id,
                    H::PROG_PATH,
                    Some(map_path),
                    failure_point,
                );
                ReportedToStatsd(e)
            })?;
        }
    }
    handler.on_finished()?;

    let path_enum = bpf_map_path_to_enum(map_path)?;
    if let Err(e) = uprobe_stats_bpf_map_polled::stats_write(
        path_enum,
        duration.as_millis().try_into()?,
        total_events,
        task.id,
    ) {
        error!("Failed to write uprobe_stats_bpf_map_polled atom: {:?}", e);
    };
    Ok(())
}

fn register_handler<H: Handler + Default>(handler_registry: &mut HandlerRegistry) {
    handler_registry.insert(H::MAP_PATH, poll_loop_generic::<H>);
}

type BindServiceLockedHandlerImpl = BindServiceLockedHandler<
    CodegenAtomWriter,
    DefaultUprobeStatsBridgeService,
    DefaultDeviceProperties,
>;

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
    register_handler::<CallTimestampHandler<AStatsEventWriter>>(&mut map);
    register_handler::<CallResultHandler<AStatsEventWriter>>(&mut map);
    register_handler::<SetUidTempAllowlistStateRecordHandler<AStatsEventWriter>>(&mut map);
    register_handler::<UpdateDeviceIdleTempAllowlistRecordHandler<AStatsEventWriter>>(&mut map);
    if uprobestats_mainline_flags_rust::enable_binder_transaction() {
        register_handler::<
            BinderTransactionHandler<AStatsEventWriter, DefaultUprobeStatsBridgeService>,
        >(&mut map);
    }
    if is_at_least_cinnamon_bun() {
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
    if cfg!(feature = "art-test") {
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
