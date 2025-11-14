//! Resolves UprobestatsConfig protos into a list of concrete probes to be attached.
#[cfg(feature = "art-test")]
use crate::bpf_map::art_test::{AOT_METHOD_IDENTIFIER, JIT_METHOD_IDENTIFIER};
use crate::{prefix_bpf, process::resolve_process};
use anyhow::{anyhow, bail, ensure, Result};
use binder::ExceptionCode;
use dynamic_instrumentation_manager::{
    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
};
use protobuf::Message;
use std::clone::Clone;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use uprobestats_flags_rust as uprobestats_flags;
use uprobestats_mainline_flags_rust as uprobestats_mainline_flags;
use uprobestats_proto::config::{
    uprobestats_config::{
        task::{ProbeConfig, TargetProcessSelection},
        Task,
    },
    UprobestatsConfig,
};

pub(crate) fn get_executable_method_file_offsets_with_retry(
    target_process: &TargetProcess,
    method_descriptor: &MethodDescriptor,
) -> Result<Option<ExecutableMethodFileOffsets>> {
    if !uprobestats_mainline_flags::use_process_observer_api() {
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
    /// The probe proto.
    pub probe: ProbeConfig,
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
pub fn resolve_probes(resolved_task: &ResolvedTask) -> Result<Vec<ResolvedProbe>> {
    resolved_task
        .task
        .probe_configs
        .clone()
        .into_iter()
        .map(|probe| {
            let bpf_name =
                probe.bpf_name.as_ref().ok_or_else(|| anyhow!("bpf_name is required"))?;
            ensure!(is_bpf_file_enabled(bpf_name), "{} is disabled by flag", bpf_name);

            let bpf_program_path = prefix_bpf(bpf_name);
            let fully_qualified_class_name = probe
                .fully_qualified_class_name
                .clone()
                .ok_or_else(|| anyhow!("fully_qualified_class_name is required"))?;
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
            #[cfg(feature = "art-test")]
            {
                if bpf_program_path.contains("ArtTest") {
                    if offsets.get_container_path().ends_with("so") {
                        let mut api_method_identifier = JIT_METHOD_IDENTIFIER.lock().unwrap();
                        *api_method_identifier = offsets.get_container_offset();
                    } else {
                        let mut api_method_identifier = AOT_METHOD_IDENTIFIER.lock().unwrap();
                        *api_method_identifier =
                            offsets.get_container_offset() + offsets.get_method_offset();
                    }
                }
            }
            Ok(ResolvedProbe {
                probe,
                bpf_program_path,
                offset,
                filename: offsets.get_container_path(),
            })
        })
        .collect::<Result<Vec<_>>>()
}

/// Parses a byte array into a UprobestatsConfig proto.
pub fn read_config_from_bytes(config_bytes: &[u8]) -> Result<UprobestatsConfig> {
    UprobestatsConfig::parse_from_bytes(config_bytes)
        .map_err(|e| anyhow!("Failed to parse config from bytes: {e}"))
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
    } else if bpf_prog_or_map_name.contains("Accessibility") {
        uprobestats_flags::a11y_runtime_permission()
    } else {
        true
    }
}
