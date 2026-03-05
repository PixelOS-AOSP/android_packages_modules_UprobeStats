//! Resolves UprobestatsConfig protos into a list of concrete probes to be attached.
use anyhow::{anyhow, bail, ensure, Result};
use protobuf::Message;
use std::clone::Clone;
use std::collections::{HashMap, HashSet};
use std::ffi::c_ulong;
use std::time::Duration;
use thiserror::Error;
use uprobestats_proto::config::{
    uprobestats_config::{
        task::{
            binder_transaction_filter::method_config,
            binder_transaction_filter::method_config::AtomFieldPosition, ProbeConfig,
            StatsdLoggingConfig, TargetProcessSelection,
        },
        Task,
    },
    UprobestatsConfig,
};

mod guardrail;
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
    /// Binder transaction filters (if applicable), keyed by binder interface name.
    pub binder_transaction_filters: HashMap<String, InterfaceConfig>,
}

/// Configuration for a specific binder interface.
#[derive(Clone, Debug, Default)]
pub struct InterfaceConfig {
    methods: HashMap<c_ulong, MethodConfig>,
}

impl InterfaceConfig {
    /// Inserts a method configuration for the given method ID.
    /// Returns an error if the method ID is already present.
    pub fn insert_method(&mut self, method_id: c_ulong, method_config: MethodConfig) -> Result<()> {
        if self.methods.insert(method_id, method_config).is_some() {
            bail!("Duplicate method_id {}", method_id);
        }
        Ok(())
    }

    /// Returns the method configuration for the given method ID, if it exists.
    pub fn get_method(&self, method_id: &c_ulong) -> Option<&MethodConfig> {
        self.methods.get(method_id)
    }

    /// Returns the method IDs for the interface.
    pub fn method_ids(&self) -> Vec<c_ulong> {
        self.methods.keys().cloned().collect()
    }
}

/// Configuration for a specific binder method.
#[derive(Clone, Debug)]
pub struct MethodConfig {
    /// For sending events to `DynamicInstrumentationEventService`. Required if `atom_config` is `None.
    pub event_service_config: Option<EventServiceConfig>,
    /// For sending atoms to statsd. Required if `event_service_config` is `None`.
    pub atom_config: Option<AtomConfig>,
}

/// Configuration for sending events to `DynamicInstrumentationEventService`.
#[derive(Clone, Debug, PartialEq)]
pub struct EventServiceConfig {
    /// The mode of the event service config.
    pub mode: EventMode,
}

impl From<method_config::EventServiceConfig> for EventServiceConfig {
    fn from(event_service_config: method_config::EventServiceConfig) -> Self {
        EventServiceConfig {
            mode: match event_service_config.flush {
                Some(true) => EventMode::Flush,
                _ => EventMode::Buffer,
            },
        }
    }
}

/// The mode of an event service config - controls how events are sent to `DynamicInstrumentationEventService`.
#[derive(Clone, Debug, PartialEq)]
pub enum EventMode {
    /// Flush the event immediately, including any previously buffered events.
    Flush,
    /// Add the event to the event buffer to be sent with the next flush.
    Buffer,
}

/// Configuration for logging a binder interface method invocation to statsd.
#[derive(Clone, Debug)]
pub struct AtomConfig {
    /// Which atom to log
    pub atom_id: u32,
    /// Where to put any extra data for the atom. If empty, an empty atom with the given ID is logged (which is still useful for e.g. counting invocations)
    pub atom_field_positions: Vec<AtomFieldPosition>,
}

impl TryFrom<method_config::AtomConfig> for AtomConfig {
    type Error = anyhow::Error;
    fn try_from(atom_config: method_config::AtomConfig) -> Result<Self> {
        let Some(atom_id) = atom_config.atom_id else {
            bail!("atom_config.atom_id is required");
        };
        if atom_id <= 0 {
            bail!("atom_config.atom_id must be positive integer");
        }
        let atom_id = atom_id.try_into()?;
        Ok(AtomConfig {
            atom_id,
            atom_field_positions: atom_config
                .atom_field_positions
                .into_iter()
                .map(|e| e.enum_value_or_default())
                .collect(),
        })
    }
}

/// Wraps a config error with the task ID (for the majority case that we at least know the task ID)
#[derive(Debug, Error)]
pub enum ConfigError {
    /// We were able to parse a single task from the config, but it failed validation.
    #[error("Task {task_id}: {error}")]
    TaskValidation {
        /// The ID of the task that failed validation.
        task_id: i64,
        /// The error that occurred.
        error: anyhow::Error,
    },
    /// We failed to parse the config from bytes, it didn't have a task, or some other unexpected error occurred.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ConfigError {
    /// Returns the task ID if this error is for a specific task, -1 otherwise.
    pub fn task_id(&self) -> Option<i64> {
        match self {
            ConfigError::TaskValidation { task_id, .. } => Some(*task_id),
            ConfigError::Other(_) => None,
        }
    }
}

/// Parses a byte array into a UprobestatsConfig proto, validates it, and resolves it into a
/// ResolvedTask.
pub fn resolve_config(
    config_bytes: &[u8],
    is_user_build: bool,
    process_resolver: &impl ProcessResolver,
    offset_resolver: &impl OffsetResolver,
) -> Result<ResolvedTask, ConfigError> {
    let config = read_config_from_bytes(config_bytes).map_err(ConfigError::Other)?;
    if config.tasks.len() != 1 {
        return Err(ConfigError::Other(anyhow!(
            "Config must have exactly one task, got {}",
            config.tasks.len()
        )));
    }

    let task = &config.tasks[0];
    let id = task.task_id.unwrap_or(0);

    // Check guardrails.
    // We assume offsets_api_enabled is true, as the daemon always uses the offsets API now.
    let is_allowed = guardrail::is_allowed(&config, is_user_build, true)
        .map_err(|e| ConfigError::TaskValidation { task_id: id, error: e })?;

    if !is_allowed {
        return Err(ConfigError::TaskValidation {
            task_id: id,
            error: anyhow!("uprobestats probing config disallowed on this device"),
        });
    }

    resolve_single_task(task, id, process_resolver, offset_resolver)
        .map_err(|e| ConfigError::TaskValidation { task_id: id, error: e })
}

/// Validates a single task proto and enriches it with the information needed to attach
/// uprobes and consume their results.
fn resolve_single_task(
    task: &Task,
    id: i64,
    process_resolver: &impl ProcessResolver,
    offset_resolver: &impl OffsetResolver,
) -> Result<ResolvedTask> {
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
) -> Result<HashMap<String, InterfaceConfig>> {
    match bpf_name {
        BINDER_BPF_PROGRAM_NAME => {
            ensure!(
                !probe.binder_transaction_filters.is_empty(),
                "{BINDER_BPF_PROGRAM_NAME} requires at least one binder_transaction_filter",
            );
            let mut filters = HashMap::new();
            for filter in &probe.binder_transaction_filters {
                let Some(ref interface_name) = filter.interface_name else {
                    bail!("binder_transaction_filter.interface_name is required");
                };
                ensure!(
                    !interface_name.is_empty(),
                    "binder_transaction_filter.interface_name must be non-empty"
                );
                ensure!(
                    !filter.method_configs.is_empty(),
                    "binder_transaction_filter.method_configs must be non-empty"
                );

                let mut interface_config = InterfaceConfig::default();
                for method_config_proto in &filter.method_configs {
                    let method_id: c_ulong = method_config_proto.method_id
                               .filter(|&id| id > 0)
                               .map(|id| id.try_into())
                               .transpose()?
                               .ok_or_else(|| {
                                   anyhow!("binder_transaction_filter.method_config.method_id is required and must be a positive integer")
                               })?;

                    ensure!(
                        method_config_proto.event_service_config.is_some()
                            || method_config_proto.atom_config.is_some(),
                        "either method_config.event_service_config, method_config.atom_config, or both, must be present"
                    );

                    let event_service_config = method_config_proto
                        .event_service_config
                        .clone()
                        .into_option()
                        .map(|config| config.try_into())
                        .transpose()?;

                    let atom_config = method_config_proto
                        .atom_config
                        .clone()
                        .into_option()
                        .map(|config| config.try_into())
                        .transpose()?;

                    interface_config.insert_method(
                        method_id,
                        MethodConfig { event_service_config, atom_config },
                    )?;
                }

                if filters.insert(interface_name.to_string(), interface_config).is_some() {
                    bail!("Duplicate interface_name {}", interface_name);
                }
            }
            Ok(filters)
        }
        _ => {
            ensure!(
                probe.binder_transaction_filters.is_empty(),
                "binder_transaction_filters is only supported for {BINDER_BPF_PROGRAM_NAME} but got {bpf_name}",
            );
            Ok(HashMap::new())
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
            task::{
                binder_transaction_filter::method_config::{
                    AtomConfig as ProtoAtomConfig, EventServiceConfig as ProtoEventServiceConfig,
                },
                binder_transaction_filter::MethodConfig as ProtoMethodConfig,
                BinderTransactionFilter, ProbeConfig,
            },
            Task,
        },
        UprobestatsConfig,
    };

    fn make_task(duration: i32) -> Task {
        let mut task = Task::new();
        task.duration_seconds = Some(duration);
        task
    }

    fn make_probe(bpf_name: &str, class: &str, method: &str) -> ProbeConfig {
        let mut probe = ProbeConfig::new();
        probe.bpf_name = Some(bpf_name.to_string());
        probe.fully_qualified_class_name = Some(class.to_string());
        probe.method_name = Some(method.to_string());
        probe
    }

    fn default_probe() -> ProbeConfig {
        make_probe("test.bpf.o", "com.example.Test", "testMethod")
    }

    fn default_resolved_process() -> ResolvedProcess {
        ResolvedProcess { name: "test_process".to_string(), pid: 123, uid: 456 }
    }

    fn make_filter(
        interface: Option<&str>,
        methods: Vec<(i64, Option<bool>, Option<i32>)>,
    ) -> BinderTransactionFilter {
        let mut filter = BinderTransactionFilter::new();
        filter.interface_name = interface.map(|s| s.to_string());
        filter.method_configs = methods
            .into_iter()
            .map(|(method_id, flush, atom_id)| {
                let event_service_config = flush.map(|f| {
                    let mut config = ProtoEventServiceConfig::new();
                    config.flush = Some(f);
                    config
                });
                let atom_config = atom_id.map(|id| {
                    let mut config = ProtoAtomConfig::new();
                    config.atom_id = Some(id);
                    config
                });
                ProtoMethodConfig {
                    method_id: Some(method_id),
                    event_service_config: event_service_config.into(),
                    atom_config: atom_config.into(),
                    ..ProtoMethodConfig::default()
                }
            })
            .collect();
        filter
    }

    fn default_filter() -> BinderTransactionFilter {
        make_filter(Some("test.interface"), vec![(1, Some(false), None)])
    }

    fn assert_err_contains<T: std::fmt::Debug, E: std::fmt::Display + std::fmt::Debug>(
        result: Result<T, E>,
        substring: &str,
    ) {
        let err = result.expect_err("Expected error, got Ok");
        assert!(
            err.to_string().contains(substring),
            "Error {:?} did not contain '{}'",
            err,
            substring
        );
    }

    fn resolve_task_simple(task: &Task) -> Result<ResolvedTask> {
        resolve_single_task(task, 0, &MockProcessResolver::success(), &MockOffsetResolver::none())
    }

    fn resolve_probes_simple(
        probes: Vec<ProbeConfig>,
        resolver: &impl OffsetResolver,
    ) -> Result<Vec<ResolvedProbe>> {
        resolve_probes(probes, &default_resolved_process(), resolver)
    }

    struct MockProcessResolver {
        result: Result<ResolvedProcess, anyhow::Error>,
    }

    impl MockProcessResolver {
        fn success() -> Self {
            Self { result: Ok(default_resolved_process()) }
        }
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

    struct MockOffsetResolver {
        result: Result<Option<ExecutableMethodFileOffsets>, anyhow::Error>,
    }

    impl MockOffsetResolver {
        fn success() -> Self {
            Self {
                result: Ok(Some(ExecutableMethodFileOffsets {
                    container_path: "/path/to/file".to_string(),
                    container_offset: 0,
                    method_offset: 1234,
                })),
            }
        }
        fn none() -> Self {
            Self { result: Ok(None) }
        }
    }

    impl OffsetResolver for MockOffsetResolver {
        fn resolve_offsets(
            &self,
            _target_process: &ResolvedProcess,
            _method_descriptor: &MethodDescriptor,
        ) -> Result<Option<ExecutableMethodFileOffsets>> {
            match &self.result {
                Ok(opt) => Ok(opt.clone()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        }
    }

    #[test]
    fn resolve_single_task_success() {
        let resolved_task = resolve_task_simple(&make_task(10)).unwrap();
        let expected = default_resolved_process();
        assert_eq!(resolved_task.resolved_process.pid, expected.pid);
        assert_eq!(resolved_task.resolved_process.uid, expected.uid);
        assert_eq!(resolved_task.resolved_process.name, expected.name);
    }

    #[test]
    fn resolve_single_task_no_tasks() {
        let config = UprobestatsConfig::new(); // No tasks
        let result = resolve_config(
            &config.write_to_bytes().unwrap(),
            false,
            &MockProcessResolver::success(),
            &MockOffsetResolver::none(),
        );
        assert_err_contains(result, "Config must have exactly one task, got 0");
    }

    #[test]
    fn resolve_single_task_no_duration() {
        assert_err_contains(resolve_task_simple(&Task::new()), "Task duration is required");
    }

    #[test]
    fn resolve_single_task_process_resolver_error() {
        let resolver = MockProcessResolver { result: Err(anyhow!("process not found")) };
        let task = make_task(10);
        let result = resolve_single_task(&task, 0, &resolver, &MockOffsetResolver::none());
        assert_err_contains(result, "process not found");
    }

    #[test]
    fn resolve_single_task_multiple_tasks() {
        let task1 = make_task(10);
        let task2 = make_task(20);
        let config = UprobestatsConfig { tasks: vec![task1, task2], ..Default::default() };

        let result = resolve_config(
            &config.write_to_bytes().unwrap(),
            false,
            &MockProcessResolver::success(),
            &MockOffsetResolver::none(),
        );
        assert_err_contains(result, "Config must have exactly one task, got 2");
    }

    #[test]
    fn resolve_single_task_zero_duration() {
        assert_err_contains(resolve_task_simple(&make_task(0)), "must be greater than 0");
    }

    #[test]
    fn resolve_probes_success() {
        let resolved_probes =
            resolve_probes_simple(vec![default_probe()], &MockOffsetResolver::success()).unwrap();
        assert_eq!(resolved_probes.len(), 1);
        assert_eq!(resolved_probes[0].offsets.container_path, "/path/to/file");
        assert_eq!(resolved_probes[0].offsets.method_offset, 1234);
    }

    #[test]
    fn resolve_probes_offset_not_found() {
        let result = resolve_probes_simple(vec![default_probe()], &MockOffsetResolver::none());
        assert_err_contains(result, "Failed to get offsets");
    }

    #[test]
    fn resolve_probes_missing_bpf_name() {
        let mut probe = default_probe();
        probe.bpf_name = None;
        assert_err_contains(
            resolve_probes_simple(vec![probe], &MockOffsetResolver::none()),
            "bpf_name is required",
        );
    }

    #[test]
    fn resolve_probes_missing_method_name() {
        let mut probe = default_probe();
        probe.method_name = None;
        assert_err_contains(
            resolve_probes_simple(vec![probe], &MockOffsetResolver::none()),
            "method_name is required",
        );
    }

    #[test]
    fn resolve_probes_multiple_probes() {
        let probe1 = make_probe("test1.bpf.o", "com.example.Test1", "testMethod1");
        let probe2 = make_probe("test2.bpf.o", "com.example.Test2", "testMethod2");

        let resolved_probes =
            resolve_probes_simple(vec![probe1, probe2], &MockOffsetResolver::success()).unwrap();
        assert_eq!(resolved_probes.len(), 2);
    }

    #[test]
    fn resolve_probes_missing_class_name() {
        let mut probe = default_probe();
        probe.fully_qualified_class_name = None;
        assert_err_contains(
            resolve_probes_simple(vec![probe], &MockOffsetResolver::none()),
            "fully_qualified_class_name is required",
        );
    }

    #[test]
    fn resolve_probes_offset_resolver_error() {
        let resolver = MockOffsetResolver { result: Err(anyhow!("resolver error")) };
        assert_err_contains(
            resolve_probes_simple(vec![default_probe()], &resolver),
            "resolver error",
        );
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
        probe.binder_transaction_filters = vec![make_filter(
            Some("test.interface"),
            vec![(1, Some(false), None), (2, Some(true), None)],
        )];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME).unwrap();
        assert_eq!(result.len(), 1);
        let interface_config = result.get("test.interface").expect("interface not found");
        assert_eq!(interface_config.methods.len(), 2);

        let method1 = interface_config.get_method(&1).expect("method 1 not found");
        assert_eq!(method1.event_service_config.as_ref().unwrap().mode, EventMode::Buffer);

        let method2 = interface_config.get_method(&2).expect("method 2 not found");
        assert_eq!(method2.event_service_config.as_ref().unwrap().mode, EventMode::Flush);
    }

    #[test]
    fn resolve_binder_transaction_filters_atom_config_success() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters = vec![make_filter(
            Some("test.interface"),
            vec![(1, None, Some(100)), (2, None, Some(200))],
        )];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME).unwrap();
        assert_eq!(result.len(), 1);
        let interface_config = result.get("test.interface").expect("interface not found");
        assert_eq!(interface_config.methods.len(), 2);

        let method1 = interface_config.get_method(&1).expect("method 1 not found");
        assert_eq!(method1.atom_config.as_ref().unwrap().atom_id, 100);

        let method2 = interface_config.get_method(&2).expect("method 2 not found");
        assert_eq!(method2.atom_config.as_ref().unwrap().atom_id, 200);
    }

    #[test]
    fn resolve_binder_transaction_filters_both_configs_success() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters =
            vec![make_filter(Some("test.interface"), vec![(1, Some(true), Some(100))])];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME).unwrap();
        assert_eq!(result.len(), 1);
        let interface_config = result.get("test.interface").expect("interface not found");
        assert_eq!(interface_config.methods.len(), 1);

        let method1 = interface_config.get_method(&1).expect("method 1 not found");
        assert_eq!(method1.event_service_config.as_ref().unwrap().mode, EventMode::Flush);
        assert_eq!(method1.atom_config.as_ref().unwrap().atom_id, 100);
    }

    #[test]
    fn resolve_binder_transaction_filters_atom_config_invalid_id() {
        let mut probe = ProbeConfig::new();
        let mut filter = BinderTransactionFilter::new();
        filter.interface_name = Some("test.interface".to_string());
        // Manually construct the method config with invalid atom_id because make_filter uses u32
        let mut atom_config = ProtoAtomConfig::new();
        atom_config.atom_id = Some(0);
        let method_config = ProtoMethodConfig {
            method_id: Some(1),
            atom_config: Some(atom_config).into(),
            ..ProtoMethodConfig::default()
        };
        filter.method_configs = vec![method_config];
        probe.binder_transaction_filters = vec![filter];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "atom_config.atom_id must be positive integer");
    }

    #[test]
    fn resolve_binder_transaction_filters_negative_method_id() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters =
            vec![make_filter(Some("test.interface"), vec![(-1, Some(false), None)])];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(
            result,
            "binder_transaction_filter.method_config.method_id is required and must be a positive integer",
        );
    }

    #[test]
    fn resolve_binder_transaction_filters_missing_event_service_config() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters =
            vec![make_filter(Some("test.interface"), vec![(1, None, None)])];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(
            result,
            "either method_config.event_service_config, method_config.atom_config, or both, must be present",
        );
    }

    #[test]
    fn resolve_binder_transaction_filters_empty_filters_for_binder_bpf() {
        let probe = ProbeConfig::new();
        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "requires at least one binder_transaction_filter");
    }

    #[test]
    fn resolve_binder_transaction_filters_with_filters_for_non_binder_bpf() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters = vec![default_filter()];
        let result = resolve_binder_transaction_filters(&probe, "other.bpf.o");
        assert_err_contains(result, "binder_transaction_filters is only supported for");
    }

    #[test]
    fn resolve_binder_transaction_filters_missing_interface_name() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters = vec![make_filter(None, vec![(1, Some(false), None)])];
        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "binder_transaction_filter.interface_name is required");
    }

    #[test]
    fn resolve_binder_transaction_filters_empty_interface_name() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters =
            vec![make_filter(Some(""), vec![(1, Some(false), None)])];
        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "binder_transaction_filter.interface_name must be non-empty");
    }

    #[test]
    fn resolve_binder_transaction_filters_duplicate_interface_names() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters = vec![default_filter(), default_filter()];
        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "Duplicate interface_name");
    }

    #[test]
    fn resolve_binder_transaction_filters_duplicate_method_ids() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters = vec![make_filter(
            Some("test.interface"),
            vec![(1, Some(false), None), (1, Some(false), None)],
        )];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "Duplicate method_id");
    }

    #[test]
    fn resolve_binder_transaction_filters_empty_method_ids() {
        let mut probe = ProbeConfig::new();
        probe.binder_transaction_filters = vec![make_filter(Some("test.interface"), vec![])];

        let result = resolve_binder_transaction_filters(&probe, BINDER_BPF_PROGRAM_NAME);
        assert_err_contains(result, "binder_transaction_filter.method_configs must be non-empty");
    }

    #[test]
    fn prefix_bpf_test() {
        assert_eq!(prefix_bpf("my_map"), "/sys/fs/bpf/uprobestats/my_map");
    }
}
