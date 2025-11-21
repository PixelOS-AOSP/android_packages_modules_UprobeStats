//! Core functions for managing the execution of uprobestats tasks.
//! Functions should be called in the order documented.
use crate::{
    bpf_map::{binder_transaction::BinderInterfaceMapAccessor, poll_registry},
    config_resolver::{read_config_from_bytes, resolve_single_task, ResolvedProbe, ResolvedTask},
    guardrail, is_user_build,
};
use anyhow::{anyhow, bail, ensure, Result};
#[cfg(feature = "binder-service")]
use binder::LazyServiceGuard;
use log::{debug, error, trace};
use std::{
    collections::HashSet,
    ffi::c_ulong,
    os::fd::{AsRawFd, OwnedFd},
    sync::MutexGuard,
    thread,
    time::Duration,
};
use uprobestats_bpf::{bpf_perf_event_open, UpdateMapElemFlags};

/// The global state for the uprobestats daemon process.
/// - Some(ActiveState): tracks metadata when there are tasks currently running.
/// - None: means there are no tasks currently running, and the service may be stopped.
pub type GlobalState = Option<ActiveState>;
/// The active state for the uprobestats daemon process.
///
/// This is only set when there are tasks currently running.
pub struct ActiveState {
    polled_bpf_maps: HashSet<String>,
    #[cfg(feature = "binder-service")]
    _lazy_service_guard: LazyServiceGuard,
}

impl ActiveState {
    /// Creates a new instance of ActiveState.
    ///
    /// Should only be called when there are no existing tasks running (as in, `GlobalState` is `None`)
    pub fn new(polled_bpf_maps: HashSet<String>) -> Self {
        ActiveState {
            polled_bpf_maps,
            #[cfg(feature = "binder-service")]
            _lazy_service_guard: LazyServiceGuard::new(),
        }
    }
}

/// Step 1: performs the synchronous setup for a uprobestats task:
/// - parses the configuration
/// - checks guardrails
/// - resolves the BPF probes to be attached
///
/// Returns the task and the probes that were resolved.
pub fn resolve_config(config_bytes: &[u8]) -> Result<ResolvedTask> {
    let config = read_config_from_bytes(config_bytes)?;
    ensure!(
        guardrail::is_allowed(&config, is_user_build(), true)?,
        "uprobestats probing config disallowed on this device"
    );

    let task = resolve_single_task(config)?;

    Ok(task)
}

/// Step 2: checks for conflicts with other tasks, and updates the global state accordingly.
///
/// Once this step completes, step 4 (cleaning up the polled maps) *must* also complete.
pub fn update_polled_bpf_maps(
    state: &mut MutexGuard<GlobalState>,
    task: &ResolvedTask,
) -> Result<()> {
    let new_maps: HashSet<String> = task.bpf_map_paths.iter().cloned().collect();

    let polled_bpf_maps = match &mut **state {
        None => {
            **state = Some(ActiveState::new(new_maps));
            return Ok(());
        }
        Some(ref mut active_state) => &mut active_state.polled_bpf_maps,
    };

    let conflicts: Vec<_> = new_maps.intersection(polled_bpf_maps).collect();
    if !conflicts.is_empty() {
        bail!("BPF maps already in use: {:?}", conflicts);
    }

    polled_bpf_maps.extend(new_maps);
    Ok(())
}

/// Step 3: executes the blocking, long-running part of a task:
/// - sets up the BPF map for binder transaction filters.
/// - attaches the BPF probes
/// - polls the BPF maps for the specified duration
/// - drains the binder transaction filters map when done.
///
/// This step must not fail, as the following cleanup steps are always required.
pub fn execute(task: &ResolvedTask) {
    match setup_binder_transaction_filters(&task.resolved_probes) {
        Ok(map) => {
            if let Err(e) = attach_probes_and_poll_maps(task) {
                error!("task execution failed: {e:?}");
            }
            cleanup_binder_transaction_filters(map);
        }
        Err(e) => {
            error!(
                "Failed to setup binder transaction filters. Abandoning execution of task: {e:?}"
            );
        }
    }
}

/// Step 3a: sets up the BPF map for binder transaction filters.
///
/// This function iterates through the resolved probes and, if any of them are for binder
/// transactions, it creates and populates the necessary BPF map.
///
/// Once this step complete, step 3c (draining the filters) *must* also complete.
fn setup_binder_transaction_filters(
    probes: &[ResolvedProbe],
) -> Result<Option<BinderInterfaceMapAccessor>> {
    let mut maybe_binder_interface_bpf_map = None;
    for probe in probes {
        if probe.bpf_program_path.contains(BINDER_BPF_PROGRAM_NAME) {
            let binder_interface_bpf_map = if let Some(map) = &mut maybe_binder_interface_bpf_map {
                map
            } else {
                maybe_binder_interface_bpf_map = Some(BinderInterfaceMapAccessor::new()?);
                maybe_binder_interface_bpf_map.as_mut().unwrap()
            };
            write_binder_transaction_filter_to_binder_bpf_map(probe, binder_interface_bpf_map)
                .map_err(|e| {
                    // unwrap here, as if we've failed to write to the map *and* failed to drain it,
                    // something is horribly wrong.
                    match binder_interface_bpf_map.drain() {
                        Ok(()) => anyhow!("Failed to write binder transaction filter to bpf map: {}", e),
                        Err(drain_err) => anyhow!("Failed to write *and* drain binder interface bpf map. write error: {}, drain error: {}", e, drain_err),
                    }
                })?;
        }
    }
    Ok(maybe_binder_interface_bpf_map)
}

const BINDER_BPF_PROGRAM_NAME: &str = "Binder_uprobe_exec_transact_internal";
fn write_binder_transaction_filter_to_binder_bpf_map(
    probe: &ResolvedProbe,
    binder_interface_bpf_map: &BinderInterfaceMapAccessor,
) -> Result<()> {
    if probe.probe.binder_transaction_filters.is_empty() {
        return Err(anyhow!("Binder transaction probe must have at least one filter"));
    }
    for binder_transaction_filter in &probe.probe.binder_transaction_filters {
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
        trace!("wrote {interface_name}:{:?} to binder interface bpf map", codes);
    }
    Ok(())
}

/// Step 3b: executes the blocking, long-running part of a task:
/// - attaches the BPF probes
/// - polls the BPF maps for the specified duration
fn attach_probes_and_poll_maps(task: &ResolvedTask) -> Result<()> {
    // keep the fds in scope so they don't get closed immediately. They will be closed when they
    // go out of scope at the end of this function.
    let _perf_event_fds: Vec<OwnedFd> = task
        .resolved_probes
        .iter()
        .map(|probe| -> Result<OwnedFd> {
            debug!(
                "attaching bpf {} to {} at {}",
                probe.bpf_program_path, &probe.filename, &probe.offset
            );
            let fd = bpf_perf_event_open(
                probe.filename.clone(),
                probe.offset,
                task.pid,
                probe.bpf_program_path.clone(),
            )?;
            trace!(
                "successfully attached bpf {} to {} at {}. fd: {}",
                probe.bpf_program_path,
                &probe.filename,
                &probe.offset,
                fd.as_raw_fd(),
            );
            Ok(fd)
        })
        .collect::<Result<Vec<OwnedFd>>>()?;

    let duration = Duration::from_secs(task.duration_seconds.try_into()?);
    let errors = thread::scope(|s| {
        let mut handles = vec![];
        for map_path in &task.bpf_map_paths {
            let task_ref = &task;
            handles.push(s.spawn(move || {
                trace!("Spawned thread for map_path: {map_path}");
                poll_registry(map_path, task_ref, duration)
                    .map_err(|e| anyhow!("poll_registry error: {}", e))
            }));
        }

        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|p| anyhow!("Thread panic: {p:?}")).and_then(|r| r))
            .filter_map(|r| r.err())
            .collect::<Vec<_>>()
    });

    if !errors.is_empty() {
        let msg = errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>().join(",");
        bail!("At least one thread returned error: {}", msg);
    }

    trace!("done with task for maps: {:?}", task.bpf_map_paths);
    Ok(())
}

/// Step 3c: drains the binder transaction filters map.
///
/// This function iterates through the resolved probes and, if any of them are for binder
/// transactions, it drains the necessary BPF map.
///
/// This step must not fail, as the following cleanup steps are always required.
fn cleanup_binder_transaction_filters(
    binder_interface_bpf_map: Option<BinderInterfaceMapAccessor>,
) {
    let Some(binder_interface_bpf_map) = binder_interface_bpf_map else {
        return;
    };
    if let Err(e) = binder_interface_bpf_map.drain() {
        error!("Failed to drain binder interface bpf map: {e:?}");
    }
}

/// Step 4: cleans up the global state.
/// - removes the BPF maps from the actively polled set
/// - if no more maps are being polled, removes the active state entirely.
///
pub fn cleanup_polled_bpf_maps(state: &mut MutexGuard<GlobalState>, task: &ResolvedTask) {
    let polled_bpf_maps = match &mut **state {
        None => {
            panic!("cleanup_active_maps called with no active state. This should never happen.");
        }
        Some(ref mut active_state) => &mut active_state.polled_bpf_maps,
    };

    for map_path in &task.bpf_map_paths {
        polled_bpf_maps.remove(map_path);
    }

    trace!("remaining active maps: {:?}", polled_bpf_maps);

    if polled_bpf_maps.is_empty() {
        **state = None;
    }
}
