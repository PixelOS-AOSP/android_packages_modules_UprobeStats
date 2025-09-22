//! Resolves UprobestatsConfig protos into a list of concrete probes to be attached.
use crate::bpf_map::binder_transaction::BinderInterfaceMapAccessor;
use crate::prefix_bpf;
use anyhow::{anyhow, bail, ensure, Result};
use binder::ExceptionCode;
use dynamic_instrumentation_manager::{
    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
};
use log::{debug, warn};
use protobuf::Message;
use std::clone::Clone;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::raw::c_ulong;
use std::thread;
use std::time::Duration;
use uprobestats_bpf::UpdateMapElemFlags;
use uprobestats_mainline_flags_rust as uprobestats_flags;
use uprobestats_proto::config::{
    uprobestats_config::{
        task::{ProbeConfig, TargetProcessSelection},
        Task,
    },
    UprobestatsConfig,
};

use crate::{art::get_method_offset_from_oatdump, process::resolve_process};

pub(crate) fn get_executable_method_file_offsets_with_retry(
    target_process: &TargetProcess,
    method_descriptor: &MethodDescriptor,
) -> Result<Option<ExecutableMethodFileOffsets>> {
    if !uprobestats_flags::use_process_observer_api() {
        return ExecutableMethodFileOffsets::get(target_process, method_descriptor)
            .map_err(|e| anyhow!("Failed to get executable method file offsets: {}", e));
    }

    let mut retries = 0;
    const MAX_RETRIES: u32 = 5;
    let mut backoff = Duration::from_millis(10);

    loop {
        match ExecutableMethodFileOffsets::get(target_process, method_descriptor) {
            Ok(offsets) => return Ok(offsets),
            Err(status) => {
                if retries >= MAX_RETRIES {
                    bail!("Failed after {} retries, last error: {}", MAX_RETRIES, status);
                }
                if status.exception_code() != ExceptionCode::SERVICE_SPECIFIC {
                    bail!("Unexpected status: {status}");
                }
                if status.service_specific_error() != ExceptionCode::ILLEGAL_STATE as i32 {
                    bail!("Unexpected service specific error: {status}");
                }
                log::warn!(
                    "Failed to get method offsets (attempt {}/{}), retrying in {:?}: {}",
                    retries + 1,
                    MAX_RETRIES,
                    backoff,
                    status
                );
                thread::sleep(backoff);
                retries += 1;
                backoff *= 2;
            }
        }
    }
}

/// Validated probe proto + probe target's code filename and offset.
pub struct ResolvedProbe {
    _probe: ProbeConfig,
    /// The filename of the code that contains the probe's method.
    pub filename: String,
    /// The offset of the probe's method in the code file.
    pub offset: i32,
    /// Absolute path to the bpf program.
    pub bpf_program_path: String,
}

/// Validated task proto + probe target's pid.
#[derive(Clone)]
pub struct ResolvedTask {
    /// The task proto.
    pub task: Task,
    /// The duration of the task in seconds.
    pub duration_seconds: i32,
    /// Name of the task's target process,
    pub process_name: String,
    /// The pid of the task's target process.
    pub pid: i32,
    /// The uid of the task's target process.
    pub uid: i32,
    /// The set of absolute bpf map paths used by the task.
    pub bpf_map_paths: HashSet<String>,
}

/// Validates a single task proto and adds additional info.
pub fn resolve_single_task(config: UprobestatsConfig) -> Result<ResolvedTask> {
    let mut tasks = config.tasks.into_iter();
    let task = tasks.next().ok_or_else(|| anyhow!("No tasks found in config"))?;

    let bpf_map_paths: Result<HashSet<String>> = task
        .bpf_maps
        .iter()
        .map(|bpf_map| {
            ensure!(is_bpf_file_enabled(bpf_map), "{} is disabled by flag", bpf_map);
            Ok(prefix_bpf(bpf_map))
        })
        .collect();

    let bpf_map_paths = bpf_map_paths?;

    let duration_seconds =
        task.duration_seconds.ok_or_else(|| anyhow!("Task duration is required"))?;
    if duration_seconds <= 0 {
        return Err(anyhow!("Task duration must be greater than 0"));
    }

    let target_process_selection = task
        .target_process_selection
        .unwrap_or(TargetProcessSelection::UNKNOWN.into())
        .enum_value_or_default();

    let resolved_process = resolve_process(
        task.target_process_name.as_deref(), // Pass optional process name
        target_process_selection,
        Duration::from_secs(duration_seconds.try_into()?),
    )?;

    Ok(ResolvedTask {
        duration_seconds,
        task,
        process_name: resolved_process.name,
        pid: resolved_process.pid,
        uid: resolved_process.uid,
        bpf_map_paths,
    })
}

/// Validates a single probe proto and adds additional info.
pub fn resolve_probes(
    resolved_task: &ResolvedTask,
) -> Result<(Vec<ResolvedProbe>, Option<BinderInterfaceMapAccessor>)> {
    let mut binder_interface_bpf_map = None;
    let resolved_probes = resolved_task.task.probe_configs.clone().into_iter().map(|probe| {
        let bpf_name = probe.bpf_name.as_ref().ok_or_else(|| anyhow!("bpf_name is required"))?;
        ensure!(is_bpf_file_enabled(bpf_name), "{} is disabled by flag", bpf_name);
        let bpf_program_path = prefix_bpf(bpf_name);
        if let Some(ref fully_qualified_class_name) = probe.fully_qualified_class_name {
            debug!("using getExecutableMethodFileOffsets to retrieve offsets");
            let method_name =
                probe.method_name.clone().ok_or_else(|| anyhow!("method_name is required"))?;
            let fully_qualified_parameters = probe.fully_qualified_parameters.clone();
            let offsets = get_executable_method_file_offsets_with_retry(
                &TargetProcess::new(
                    resolved_task.uid.try_into()?,
                    resolved_task.pid,
                    &resolved_task.process_name,
                )?,
                &MethodDescriptor::new(
                    &fully_qualified_class_name.clone(),
                    &method_name,
                    fully_qualified_parameters,
                )?,
            )?;
            let offsets = offsets.ok_or_else(|| {
                anyhow!("Failed to get offsets for class: {fully_qualified_class_name}")
            })?;
            let offset: i32 = offsets
                .get_method_offset()
                .try_into()
                .map_err(|e| anyhow!("Failed to convert method offset to i32: {e}"))?;
            let resolved_probe = ResolvedProbe {
                _probe: probe,
                bpf_program_path,
                offset,
                filename: offsets.get_container_path(),
            };
            if resolved_probe.bpf_program_path.contains(BINDER_BPF_PROGRAM_NAME) {
                if binder_interface_bpf_map.is_none() {
                    binder_interface_bpf_map = Some(BinderInterfaceMapAccessor::new()?);
                }
                write_binder_transaction_filter_to_binder_bpf_map(
                    &resolved_probe,
                    binder_interface_bpf_map.as_ref().unwrap(),
                )?;
            }
            Ok(resolved_probe)
        } else {
            debug!("using oatdump to retrieve offsets");
            let method_signature =
                probe.method_signature.clone().ok_or(anyhow!("method_signature is required"))?;
            let mut offset: i32 = 0;
            let mut found_file_path: String = "".to_string();
            for file_path in &probe.file_paths {
                let found_offset = get_method_offset_from_oatdump(file_path, &method_signature)
                    .inspect_err(|e| {
                        warn!("Failed to get offset for {method_signature} from {file_path}: {e}")
                    })
                    .ok()
                    .flatten()
                    .unwrap_or(0);

                if found_offset > 0 {
                    found_file_path = file_path.to_string();
                    offset = found_offset;
                    break;
                }
            }
            if offset > 0 {
                Ok(ResolvedProbe {
                    _probe: probe,
                    bpf_program_path,
                    filename: found_file_path,
                    offset,
                })
            } else {
                Err(anyhow!("Failed to get offset for method: {method_signature}"))
            }
        }
    });

    let resolved_probes = resolved_probes.collect::<Result<Vec<_>>>()?;

    Ok((resolved_probes, binder_interface_bpf_map))
}

/// Reads a config file and parses it into a UprobestatsConfig proto.
pub fn read_config(config_path: &str) -> Result<UprobestatsConfig> {
    let mut file =
        File::open(config_path).map_err(|e| anyhow!("Failed to open config file: {e}"))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| anyhow!("Failed to read config file: {e}"))?;
    UprobestatsConfig::parse_from_bytes(&buffer)
        .map_err(|e| anyhow!("Failed to parse config file: {e}"))
}

const BINDER_BPF_PROGRAM_NAME: &str = "Binder_uprobe_exec_transact_internal";
fn write_binder_transaction_filter_to_binder_bpf_map(
    probe: &ResolvedProbe,
    binder_interface_bpf_map: &BinderInterfaceMapAccessor,
) -> Result<()> {
    if probe._probe.binder_transaction_filters.is_empty() {
        return Err(anyhow!("Binder transaction probe must have at least one filter"));
    }
    for binder_transaction_filter in &probe._probe.binder_transaction_filters {
        let Some(ref interface_name) = binder_transaction_filter.interface_name else {
            return Err(anyhow!("Binder transaction filter must have an interface name"));
        };
        if binder_transaction_filter.method_ids.is_empty() {
            return Err(anyhow!("Binder transaction filter must have at least one method id"));
        }
        let codes: Vec<c_ulong> = binder_transaction_filter
            .method_ids
            .iter()
            .map(|method_id| (*method_id).try_into())
            .collect::<Result<Vec<_>, _>>()?;

        binder_interface_bpf_map.put(interface_name, &codes, UpdateMapElemFlags::Insert)?;
        debug!("wrote {interface_name}:{:?} to binder interface bpf map", codes);
    }
    Ok(())
}

fn is_bpf_file_enabled(bpf_prog_or_map_name: &str) -> bool {
    if bpf_prog_or_map_name.contains("DisruptiveApp") {
        uprobestats_mainline_flags_rust::uprobestats_monitor_disruptive_app_activities()
    } else if bpf_prog_or_map_name
        .contains("prog_BitmapAllocation_uprobe_bitmap_creation_for_snapshot")
        || bpf_prog_or_map_name.contains("prog_BitmapAllocation_uprobe_apply_free_function")
    {
        uprobestats_mainline_flags_rust::enable_bitmap_snapshot()
    } else if bpf_prog_or_map_name.contains("BitmapAllocation") {
        uprobestats_mainline_flags_rust::enable_bitmap_instrumentation()
            || uprobestats_mainline_flags_rust::enable_bitmap_snapshot()
    } else if bpf_prog_or_map_name.contains("Binder") {
        uprobestats_mainline_flags_rust::enable_binder_transaction()
    } else if bpf_prog_or_map_name.contains("prog_BitmapAllocation_uprobe_create_scaled_bitmap") {
        uprobestats_mainline_flags_rust::enable_bitmap_scaled_instrumentation()
    } else {
        true
    }
}
