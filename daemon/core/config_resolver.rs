//! Resolves UprobestatsConfig protos into a list of concrete probes to be attached.
use anyhow::{anyhow, bail, ensure, Result};
use protobuf::Message;
use std::clone::Clone;
use std::collections::HashSet;
use std::ffi::c_ulong;
use std::time::Duration;
use uprobestats_proto::config::{
    uprobestats_config::task::{ProbeConfig, StatsdLoggingConfig, TargetProcessSelection},
    UprobestatsConfig,
};

mod offsets;
pub use offsets::{ExecutableMethodFileOffsets, MethodDescriptor, OffsetResolver};
mod process;
pub use process::{ProcessResolver, ResolvedProcess};

/// Validated task configuration + resolved process.
#[derive(Clone, Debug)]
pub struct ResolvedTask {
    /// Unique identifier for the task.
    pub id: i64,
    /// The duration of the task in seconds.
    pub duration: Duration,
    /// The resolved target process info.
    pub resolved_process: ResolvedProcess,
    /// The set of absolute bpf map paths used by the task.
    pub bpf_map_paths: HashSet<String>,
    /// The statsd logging config for the task (if applicable)
    pub statsd_logging_config: Option<StatsdLoggingConfig>,
    /// The individual probes for the task.
    pub resolved_probes: Vec<ResolvedProbe>,
}

/// Validated probe configuration + resolved offsets.
#[derive(Clone, Debug)]
pub struct ResolvedProbe {
    /// The descriptor of the method being probed.
    pub method_descriptor: MethodDescriptor,
    /// The offsets of the method being probed.
    pub offsets: ExecutableMethodFileOffsets,
    /// Absolute path to the bpf program.
    pub bpf_program_path: String,
    /// Binder transaction filters (if applicable)
    pub binder_transaction_filters: Vec<BinderTransactionFilter>,
}

/// Required when using generic binder txn uprobes - this specifies which transactions to filter for
#[derive(Clone, Debug)]
pub struct BinderTransactionFilter {
    /// Binder interface name (non-empty)
    pub interface_name: String,
    /// Binder method IDs (non-empty))
    pub method_ids: Vec<c_ulong>,
}

/// Validates a single task proto and enriches it with the information needed to attach
/// uprobes and consume their results.
pub fn resolve_single_task(
    config: UprobestatsConfig,
    process_resolver: &impl ProcessResolver,
    offset_resolver: &impl OffsetResolver,
) -> Result<ResolvedTask> {
    ensure!(
        config.tasks.len() == 1,
        "Config must have exactly one task, got {}",
        config.tasks.len()
    );
    let task = &config.tasks[0];

    let id = task.task_id.unwrap_or(0);

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
    let duration = Duration::from_secs(duration_seconds.try_into()?);

    let statsd_logging_config = task.statsd_logging_config.clone().into_option();

    let target_process_selection = task
        .target_process_selection
        .unwrap_or(TargetProcessSelection::UNKNOWN.into())
        .enum_value_or_default();

    let resolved_process = process_resolver.resolve_process(
        task.target_process_name.as_deref(), // Pass optional process name
        target_process_selection,
        duration,
    )?;

    let resolved_probes =
        resolve_probes(task.probe_configs.clone(), &resolved_process, offset_resolver)?;

    Ok(ResolvedTask {
        id,
        duration,
        resolved_process,
        bpf_map_paths,
        statsd_logging_config,
        resolved_probes,
    })
}

fn resolve_probes(
    probe_configs: Vec<ProbeConfig>,
    resolved_process: &ResolvedProcess,
    resolver: &impl OffsetResolver,
) -> Result<Vec<ResolvedProbe>> {
    probe_configs
        .into_iter()
        .map(|probe| {
            let bpf_name =
                probe.bpf_name.as_ref().ok_or_else(|| anyhow!("bpf_name is required"))?;
            ensure!(is_bpf_file_enabled(bpf_name), "{} is disabled by flag", bpf_name);
            let bpf_program_path = prefix_bpf(bpf_name);

            let binder_transaction_filters = resolve_binder_transaction_filters(&probe, bpf_name)?;

            let fully_qualified_class_name = probe
                .fully_qualified_class_name
                .clone()
                .ok_or_else(|| anyhow!("fully_qualified_class_name is required"))?;
            let method_name =
                probe.method_name.clone().ok_or_else(|| anyhow!("method_name is required"))?;
            let fully_qualified_parameters = probe.fully_qualified_parameters.clone();
            let method_descriptor = MethodDescriptor {
                fully_qualified_class_name,
                method_name,
                fully_qualified_parameters,
            };

            let offsets = resolver.resolve_offsets(resolved_process, &method_descriptor)?;
            let offsets = offsets.ok_or_else(|| {
                anyhow!(
                    "Failed to get offsets for class: {}, method: {}, params: {:?}",
                    method_descriptor.fully_qualified_class_name,
                    method_descriptor.method_name,
                    method_descriptor.fully_qualified_parameters
                )
            })?;

            Ok(ResolvedProbe {
                method_descriptor,
                offsets,
                bpf_program_path,
                binder_transaction_filters,
            })
        })
        .collect::<Result<Vec<_>>>()
}

const BINDER_BPF_PROGRAM_NAME: &str = "prog_Binder_uprobe_exec_transact_internal";
fn resolve_binder_transaction_filters(
    probe: &ProbeConfig,
    bpf_name: &str,
) -> Result<Vec<BinderTransactionFilter>> {
    match bpf_name {
        BINDER_BPF_PROGRAM_NAME => {
            ensure!(
                !probe.binder_transaction_filters.is_empty(),
                "{BINDER_BPF_PROGRAM_NAME} requires at least one binder_transaction_filter",
            );
            probe
                .binder_transaction_filters
                .iter()
                .map(|filter| {
                    let Some(ref interface_name) = filter.interface_name else {
                        bail!("binder_transaction_filter.interface_name is required");
                    };
                    ensure!(
                        !interface_name.is_empty(),
                        "binder_transaction_filter.interface_name must be non-empty"
                    );
                    let interface_name = interface_name.to_string();

                    ensure!(
                        !filter.method_ids.is_empty(),
                        "binder_transaction_filter.method_ids is required"
                    );
                    let method_ids = filter
                        .method_ids
                        .iter()
                        .map(|&id| Ok(id.try_into()?))
                        .collect::<Result<Vec<_>>>()?;

                    Ok(BinderTransactionFilter { interface_name, method_ids })
                })
                .collect()
        }
        _ => {
            ensure!(
                probe.binder_transaction_filters.is_empty(),
                "binder_transaction_filters is only supported for {BINDER_BPF_PROGRAM_NAME} but got {bpf_name}",
            );
            Ok(vec![])
        }
    }
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
/// Returns the full path to a bpf file in the `uprobestats` directory.
pub fn prefix_bpf(path: &str) -> String {
    BPF_DIR.to_string() + path
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::Message;
    use uprobestats_proto::config::{
        uprobestats_config::{
            task::{BinderTransactionFilter, ProbeConfig},
            Task,
        },
        UprobestatsConfig,
    };

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

    struct NoneOffsetResolver {}
    impl OffsetResolver for NoneOffsetResolver {
        fn resolve_offsets(
            &self,
            _target_process: &ResolvedProcess,
            _method_descriptor: &MethodDescriptor,
        ) -> Result<Option<ExecutableMethodFileOffsets>> {
            Ok(None)
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

        let resolved_task = resolve_single_task(config, &resolver, &NoneOffsetResolver {}).unwrap();
        assert_eq!(resolved_task.resolved_process.pid, 123);
        assert_eq!(resolved_task.resolved_process.uid, 456);
        assert_eq!(resolved_task.resolved_process.name, "test_process");
    }

    #[test]
    fn resolve_single_task_no_tasks() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 0, uid: 0, name: "".to_string() }),
        };
        let config = UprobestatsConfig::new(); // No tasks
        let result = resolve_single_task(config, &resolver, &NoneOffsetResolver {});
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Config must have exactly one task, got 0"));
    }

    #[test]
    fn resolve_single_task_no_duration() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 0, uid: 0, name: "".to_string() }),
        };
        let task = Task::new(); // No duration
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };
        let result = resolve_single_task(config, &resolver, &NoneOffsetResolver {});
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Task duration is required"));
    }

    #[test]
    fn resolve_single_task_process_resolver_error() {
        let resolver = MockProcessResolver { result: Err(anyhow!("process not found")) };
        let mut task = Task::new();
        task.duration_seconds = Some(10);
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };
        let result = resolve_single_task(config, &resolver, &NoneOffsetResolver {});
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

        let result = resolve_single_task(config, &resolver, &NoneOffsetResolver {});
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Config must have exactly one task, got 2"));
    }

    #[test]
    fn resolve_single_task_zero_duration() {
        let resolver = MockProcessResolver {
            result: Ok(ResolvedProcess { pid: 0, uid: 0, name: "".to_string() }),
        };
        let mut task = Task::new();
        task.duration_seconds = Some(0);
        let config = UprobestatsConfig { tasks: vec![task], ..Default::default() };
        let result = resolve_single_task(config, &resolver, &NoneOffsetResolver {});
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be greater than 0"));
    }

    struct MockOffsetResolver {
        result: Result<Option<ExecutableMethodFileOffsets>, anyhow::Error>,
    }

    impl OffsetResolver for MockOffsetResolver {
        fn resolve_offsets(
            &self,
            _target_process: &ResolvedProcess,
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
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver {
            result: Ok(Some(ExecutableMethodFileOffsets {
                container_path: "/path/to/file".to_string(),
                container_offset: 0,
                method_offset: 1234,
            })),
        };

        let resolved_probes = resolve_probes(vec![probe], &resolved_process, &resolver).unwrap();
        assert_eq!(resolved_probes.len(), 1);
        assert_eq!(resolved_probes[0].offsets.container_path, "/path/to/file");
        assert_eq!(resolved_probes[0].offsets.method_offset, 1234);
    }

    #[test]
    fn resolve_probes_offset_not_found() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        probe.method_name = Some("testMethod".to_string());
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes(vec![probe], &resolved_process, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to get offsets"));
    }

    #[test]
    fn resolve_probes_missing_bpf_name() {
        let probe = ProbeConfig::new(); // No bpf_name
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes(vec![probe], &resolved_process, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bpf_name is required"));
    }

    #[test]
    fn resolve_probes_missing_method_name() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        // No method name
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes(vec![probe], &resolved_process, &resolver);
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
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver {
            result: Ok(Some(ExecutableMethodFileOffsets {
                container_path: "/path/to/file".to_string(),
                container_offset: 0,
                method_offset: 1234,
            })),
        };

        let resolved_probes =
            resolve_probes(vec![probe1, probe2], &resolved_process, &resolver).unwrap();
        assert_eq!(resolved_probes.len(), 2);
    }

    #[test]
    fn resolve_probes_missing_class_name() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.method_name = Some("testMethod".to_string());
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver { result: Ok(None) };

        let result = resolve_probes(vec![probe], &resolved_process, &resolver);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fully_qualified_class_name is required"));
    }

    #[test]
    fn resolve_probes_offset_resolver_error() {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some("test.bpf.o".to_string());
        probe.fully_qualified_class_name = Some("com.example.Test".to_string());
        probe.method_name = Some("testMethod".to_string());
        let resolved_process =
            ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 };
        let resolver = MockOffsetResolver { result: Err(anyhow!("resolver error")) };

        let result = resolve_probes(vec![probe], &resolved_process, &resolver);
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

    #[test]
    fn resolve_binder_transaction_filters_success() {
        let mut probe = ProbeConfig::new();
        let mut filter = BinderTransactionFilter::new();
        filter.interface_name = Some("test.interface".to_string());
        filter.method_ids = vec![1, 2];
        probe.binder_transaction_filters = vec![filter];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface_name, "test.interface");
        assert_eq!(result[0].method_ids, vec![1, 2]);
    }

    #[test]
    fn resolve_binder_transaction_filters_empty_filters_for_binder_bpf() {
        let probe = ProbeConfig::new(); // No filters
        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires at least one binder_transaction_filter"));
    }

    #[test]
    fn resolve_binder_transaction_filters_with_filters_for_non_binder_bpf() {
        let mut probe = ProbeConfig::new();
        let mut filter = BinderTransactionFilter::new();
        filter.interface_name = Some("test.interface".to_string());
        probe.binder_transaction_filters = vec![filter];

        let result = resolve_binder_transaction_filters(&probe, "other.bpf.o");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("binder_transaction_filters is only supported for"));
    }

    #[test]
    fn resolve_binder_transaction_filters_missing_interface_name() {
        let mut probe = ProbeConfig::new();
        let filter = BinderTransactionFilter::new();
        // No interface name
        probe.binder_transaction_filters = vec![filter];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("binder_transaction_filter.interface_name is required"));
    }

    #[test]
    fn prefix_bpf_test() {
        assert_eq!(prefix_bpf("my_map"), "/sys/fs/bpf/uprobestats/my_map");
    }
}
