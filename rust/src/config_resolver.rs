//! Resolves UprobestatsConfig protos into a list of concrete probes to be attached.
#[cfg(feature = "art-test")]
use crate::bpf_map::art_test::{AOT_METHOD_IDENTIFIER, JIT_METHOD_IDENTIFIER};
use anyhow::{anyhow, ensure, Result};
use protobuf::Message;
use std::clone::Clone;
use std::collections::HashSet;
use std::time::Duration;
use uprobestats_proto::config::{
    uprobestats_config::{
        task::{ProbeConfig, TargetProcessSelection},
        Task,
    },
    UprobestatsConfig,
};

#[cfg(not(test))]
mod resolver_impl;

#[derive(Clone, Debug)]
pub(crate) struct ResolvedProcess {
    pub(crate) pid: i32,
    pub(crate) uid: i32,
    pub(crate) name: String,
}

/// Validated probe proto + probe target's code filename and offset.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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

trait ProcessResolver {
    fn resolve_process(
        &self,
        process_name: Option<&str>,
        target_process_selection: TargetProcessSelection,
        timeout: Duration,
    ) -> Result<ResolvedProcess>;
}

/// Validates a single task proto and adds additional info.
#[cfg(not(test))]
pub fn resolve_single_task(config: UprobestatsConfig) -> Result<ResolvedTask> {
    resolve_single_task_impl(config, &resolver_impl::ProcessResolverImpl {})
}

fn resolve_single_task_impl(
    config: UprobestatsConfig,
    resolver: &impl ProcessResolver,
) -> Result<ResolvedTask> {
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

    let resolved_process = resolver.resolve_process(
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

trait OffsetResolver {
    fn resolve_offsets(
        &self,
        target_process: &TargetProcess,
        method_descriptor: &MethodDescriptor,
    ) -> Result<Option<ExecutableMethodFileOffsets>>;
}

/// Mirrors the same struct from `dynamic_instrumentation_manager`, so we don't need to depend on
/// that crate here.
#[cfg_attr(test, allow(dead_code))]
struct TargetProcess {
    uid: u32,
    pid: i32,
    process_name: String,
}

/// Mirrors the same struct from `dynamic_instrumentation_manager`, so we don't need to depend on
/// that crate here.
#[cfg_attr(test, allow(dead_code))]
struct MethodDescriptor {
    fully_qualified_class_name: String,
    method_name: String,
    fully_qualified_parameters: Vec<String>,
}

/// Mirrors the same struct from `dynamic_instrumentation_manager`, so we don't need to depend on
/// that crate here.
struct ExecutableMethodFileOffsets {
    container_path: String,
    container_offset: u64,
    method_offset: u64,
}

/// Validates a single probe proto and adds additional info.
#[cfg(not(test))]
pub fn resolve_probes(task: &ResolvedTask) -> Result<Vec<ResolvedProbe>> {
    resolve_probes_impl(task, &resolver_impl::OffsetResolverImpl {})
}

fn resolve_probes_impl(
    resolved_task: &ResolvedTask,
    resolver: &impl OffsetResolver,
) -> Result<Vec<ResolvedProbe>> {
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

            let offsets = resolver.resolve_offsets(
                &TargetProcess {
                    uid: resolved_task.uid.try_into()?,
                    pid: resolved_task.pid,
                    process_name: resolved_task.process_name.clone(),
                },
                &MethodDescriptor {
                    fully_qualified_class_name: fully_qualified_class_name.clone(),
                    method_name,
                    fully_qualified_parameters,
                },
            )?;
            let offsets = offsets.ok_or_else(|| {
                anyhow!("Failed to get offsets for class: {fully_qualified_class_name}")
            })?;
            let offset: i32 = offsets
                .method_offset
                .try_into()
                .map_err(|e| anyhow!("Failed to convert method offset to i32: {e}"))?;
            #[cfg(feature = "art-test")]
            {
                if bpf_program_path.contains("ArtTest") {
                    if offsets.container_path.ends_with("so") {
                        let mut api_method_identifier = JIT_METHOD_IDENTIFIER.lock().unwrap();
                        *api_method_identifier = offsets.container_offset;
                    } else {
                        let mut api_method_identifier = AOT_METHOD_IDENTIFIER.lock().unwrap();
                        *api_method_identifier = offsets.container_offset + offsets.method_offset;
                    }
                }
            }
            Ok(ResolvedProbe { probe, bpf_program_path, offset, filename: offsets.container_path })
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
        uprobestats_flags_rust::a11y_runtime_permission()
    } else {
        true
    }
}

const BPF_DIR: &str = "/sys/fs/bpf/uprobestats/";
pub(crate) fn prefix_bpf(path: &str) -> String {
    BPF_DIR.to_string() + path
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::Message;
    use uprobestats_proto::config::UprobestatsConfig;

    struct MockProcessResolver {
        result: Result<ResolvedProcess, anyhow::Error>,
    }

    impl ProcessResolver for MockProcessResolver {
        fn resolve_process(
            &self,
            _process_name: Option<&str>,
            _target_process_selection: TargetProcessSelection,
            _timeout: Duration,
        ) -> Result<ResolvedProcess> {
            // A simple way to handle clonable errors for testing purposes
            match &self.result {
                Ok(p) => Ok(p.clone()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        }
    }

    #[test]
    fn resolve_single_task_success() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 123, uid: 456, name: "test_process".to_string() }),
        };
        let mut task = Task::new();
        task.duration_seconds = Some(10);
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };

        let resolved_task = resolve_single_task_impl(config, &resolver).unwrap();
        assert_eq!(resolved_task.pid, 123);
        assert_eq!(resolved_task.uid, 456);
        assert_eq!(resolved_task.process_name, "test_process");
    }

    #[test]
    fn resolve_single_task_no_tasks() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 0, uid: 0, name: "".to_string() }),
        };
        let config = UprobestatsConfig::new(); // No tasks
        let result = resolve_single_task_impl(config, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No tasks found"));
    }

    #[test]
    fn resolve_single_task_no_duration() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 0, uid: 0, name: "".to_string() }),
        };
        let task = Task::new(); // No duration
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };
        let result = resolve_single_task_impl(config, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Task duration is required"));
    }

    #[test]
    fn resolve_single_task_process_resolver_error() {
        let resolver = MockProcessResolver { result: Err(anyhow!("process not found")) };
        let mut task = Task::new();
        task.duration_seconds = Some(10);
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };
        let result = resolve_single_task_impl(config, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("process not found"));
    }

    #[test]
    fn resolve_single_task_multiple_tasks() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 123, uid: 456, name: "test_process".to_string() }),
        };
        let mut task1 = Task::new();
        task1.duration_seconds = Some(10);
        let mut task2 = Task::new();
        task2.duration_seconds = Some(20);
        let config = UprobestatsConfig { tasks: vec![task1, task2], ..Default::default() };

        let resolved_task = resolve_single_task_impl(config, &resolver).unwrap();
        assert_eq!(resolved_task.duration_seconds, 10); // Check it's the first task
    }

    #[test]
    fn resolve_single_task_zero_duration() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 0, uid: 0, name: "".to_string() }),
        };
        let mut task = Task::new();
        task.duration_seconds = Some(0);
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };
        let result = resolve_single_task_impl(config, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be greater than 0"));
    }

    struct MockOffsetResolver {
        result: Result<Option<ExecutableMethodFileOffsets>, anyhow::Error>,
    }

    impl OffsetResolver for MockOffsetResolver {
        fn resolve_offsets(
            &self,
            _target_process: &TargetProcess,
            _method_descriptor: &MethodDescriptor,
        ) -> Result<Option<ExecutableMethodFileOffsets>> {
            match &self.result {
                Ok(Some(offsets)) => Ok(Some(ExecutableMethodFileOffsets {
                    container_path: offsets.container_path.clone(),
                    container_offset: offsets.container_offset,
                    method_offset: offsets.method_offset,
                })),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        }
    }

    #[test]
    fn resolve_probes_success() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        probe.method_name = Some("testMethod".to_string());
        let task = Task { probe_configs: vec![probe], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver {
            result: Ok(Some(ExecutableMethodFileOffsets {
                container_path: "/path/to/file".to_string(),
                container_offset: 0,
                method_offset: 1234,
            })),
        };

        let resolved_probes = resolve_probes_impl(&resolved_task, &resolver).unwrap();
        assert_eq!(resolved_probes.len(), 1);
        assert_eq!(resolved_probes[0].filename, "/path/to/file");
        assert_eq!(resolved_probes[0].offset, 1234);
    }

    #[test]
    fn resolve_probes_offset_not_found() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        probe.method_name = Some("testMethod".to_string());
        let task = Task { probe_configs: vec![probe], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes_impl(&resolved_task, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to get offsets"));
    }

    #[test]
    fn resolve_probes_missing_bpf_name() {
        let probe = ProbeConfig::new(); // No bpf_name
        let task = Task { probe_configs: vec![probe], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes_impl(&resolved_task, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bpf_name is required"));
    }

    #[test]
    fn resolve_probes_missing_method_name() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        // No method name
        let task = Task { probe_configs: vec![probe], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes_impl(&resolved_task, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("method_name is required"));
    }

    #[test]
    fn resolve_probes_multiple_probes() {
        let mut probe1 = ProbeConfig::new();
        probe1.bpf_name = Some("test1.bpf.o".to_string());
        probe1.fully_qualified_class_name = Some("com.example.Test1".to_string());
        probe1.method_name = Some("testMethod1".to_string());
        let mut probe2 = ProbeConfig::new();
        probe2.bpf_name = Some("test2.bpf.o".to_string());
        probe2.fully_qualified_class_name = Some("com.example.Test2".to_string());
        probe2.method_name = Some("testMethod2".to_string());
        let task = Task { probe_configs: vec![probe1, probe2], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver {
            result: Ok(Some(ExecutableMethodFileOffsets {
                container_path: "/path/to/file".to_string(),
                container_offset: 0,
                method_offset: 1234,
            })),
        };

        let resolved_probes = resolve_probes_impl(&resolved_task, &resolver).unwrap();
        assert_eq!(resolved_probes.len(), 2);
    }

    #[test]
    fn resolve_probes_missing_class_name() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.method_name = Some("testMethod".to_string());
        let task = Task { probe_configs: vec![probe], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes_impl(&resolved_task, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fully_qualified_class_name is required"));
    }

    #[test]
    fn resolve_probes_offset_resolver_error() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        probe.method_name = Some("testMethod".to_string());
        let task = Task { probe_configs: vec![probe], ..Default::default() };
        let resolved_task = ResolvedTask {
            task,
            duration_seconds: 10,
            process_name: "test_process".to_string(),
            pid: 123,
            uid: 456,
            bpf_map_paths: HashSet::new(),
        };
        let resolver = MockOffsetResolver { result: Err(anyhow!("resolver error")) };

        let result = resolve_probes_impl(&resolved_task, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("resolver error"));
    }

    #[test]
    fn read_config_from_bytes_valid() {
        let config = UprobestatsConfig { tasks: vec![Task::new()], ..Default::default() };
        let bytes = config.write_to_bytes().unwrap();
        let parsed_config = read_config_from_bytes(&bytes).unwrap();
        assert_eq!(config, parsed_config);
    }

    #[test]
    fn read_config_from_bytes_invalid() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(read_config_from_bytes(&bytes).is_err());
    }

    #[test]
    fn read_config_from_bytes_empty() {
        assert_eq!(read_config_from_bytes(&[]).unwrap(), UprobestatsConfig::new());
    }
}
