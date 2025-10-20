//! Utils for dealing with processes
use crate::{bpf_map::bytes_as_str, prefix_bpf, Timer};
use activity_manager::{ProcessObserver, ProcessObserverCallbacks};
use anyhow::{anyhow, bail, Context, Result};
use dynamic_instrumentation_manager::{
    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
};
use log::debug;
use std::fs::{read, read_dir};
use std::sync::mpsc;
use std::time::Duration;
use uprobestats_bpf::{bpf_perf_event_open, poll_ring_buf};
use uprobestats_bpf_bindgen::ProcessChange;
use uprobestats_mainline_flags_rust as uprobestats_flags;
use uprobestats_proto::config::uprobestats_config::task::TargetProcessSelection;

pub(crate) struct ResolvedProcess {
    pub(crate) pid: i32,
    pub(crate) uid: i32,
    pub(crate) name: String,
}

pub(crate) fn resolve_process(
    target_process_name: Option<&str>, // Make process name optional
    target_process_selection: TargetProcessSelection,
    duration: Duration,
) -> Result<ResolvedProcess> {
    debug!(
        "resolve_process: process_name: {target_process_name:?} process_selection: {target_process_selection:?}"
    );
    match target_process_selection {
        TargetProcessSelection::SPECIFIC_APP_PROCESS_ON_START => {
            wait_for_app_start(target_process_name, duration)
        }
        TargetProcessSelection::ANY_APP_PROCESS_ON_START => wait_for_app_start(None, duration),
        TargetProcessSelection::SPECIFIC_PROCESS_NAME | TargetProcessSelection::UNKNOWN => {
            let process_name = target_process_name.ok_or(anyhow!(
                "Process name is required for selection type {:?}",
                target_process_selection
            ))?;
            let pid =
                get_pid(process_name).ok_or(anyhow!("Can't find pid for {}", process_name))?;
            Ok(ResolvedProcess { pid, uid: 0, name: process_name.to_string() })
        }
    }
}

fn wait_for_app_start(process_name: Option<&str>, duration: Duration) -> Result<ResolvedProcess> {
    if uprobestats_flags::use_process_observer_api() {
        wait_for_app_start_observer(process_name, duration)
    } else {
        wait_for_app_start_uprobe(process_name, duration)
    }
}

struct AppStartObserver {
    sender: mpsc::Sender<ResolvedProcess>,
    target_process_name: Option<String>,
}

impl ProcessObserverCallbacks for AppStartObserver {
    fn on_process_started(
        &mut self,
        pid: i32,
        process_uid: u32,
        _package_uid: u32,
        _package_name: &str,
        process_name: &str,
    ) {
        debug!(
            "Process started via observer: pid={}, uid={}, name={}",
            pid, process_uid, process_name
        );
        if let Some(target_name) = &self.target_process_name {
            if target_name != process_name {
                return;
            }
        }

        let resolved =
            ResolvedProcess { pid, uid: process_uid as i32, name: process_name.to_string() };

        if self.sender.send(resolved).is_err() {
            debug!("Receiver dropped, could not send process start event.");
        }
    }
}

fn wait_for_app_start_observer(
    process_name: Option<&str>,
    duration: Duration,
) -> Result<ResolvedProcess> {
    let (sender, receiver) = mpsc::channel();

    let observer_callbacks =
        AppStartObserver { sender, target_process_name: process_name.map(String::from) };

    // The observer is automatically unregistered when `_observer` is dropped.
    let _observer = ProcessObserver::register(Box::new(observer_callbacks))?;
    debug!("Registered process observer. Waiting for app start...");

    receiver.recv_timeout(duration).map_err(|e| anyhow!("Timeout waiting for process start: {}", e))
}

fn wait_for_app_start_uprobe(
    process_name: Option<&str>,
    duration: Duration,
) -> Result<ResolvedProcess> {
    let system_server_pid =
        get_pid("system_server").ok_or(anyhow!("failed to get system server pid"))?;
    let (offsets, bpf_prog_name) = match get_ProcessRecord_makeActive_offsets() {
        Ok(offsets) => (offsets, BPF_PROG_PROCESS_MANAGEMENT_MAKE_ACTIVE),
        Err(e) => {
            debug!(
                "Could not find offsets for ProcessRecord#makeActive, trying onProcessActive: {e}"
            );
            (get_onProcessActive_offsets()?, BPF_PROG_PROCESS_MANAGEMENT_ON_PROCESS_ACTIVE)
        }
    };

    debug!("attaching process management bpf for app start");
    bpf_perf_event_open(
        offsets.get_container_path(),
        offsets.get_method_offset().try_into()?,
        system_server_pid,
        prefix_bpf(bpf_prog_name),
    )?;

    let timer = Timer::new(duration);
    while let Some(remaining_millis) = timer.remaining_millis() {
        debug!("polling {} for {} seconds", BPF_MAP_PROCESS_MANAGEMENT, remaining_millis / 1000);
        // SAFETY: hard coded `const BPF_MAP_PROCESS_MANAGEMENT` writes the `ProcessChange` struct.
        let result: Result<Vec<ProcessChange>> = unsafe {
            poll_ring_buf(&prefix_bpf(BPF_MAP_PROCESS_MANAGEMENT), remaining_millis.try_into()?)
        };
        let result = result?;
        for process_change in result {
            let result_process_name = bytes_as_str(&process_change.process_name)?;
            if process_name.is_none() || process_name.unwrap() == result_process_name {
                if process_change.pid <= 0 {
                    continue;
                }
                debug!(
                    "detected process start: pid: {} uid: {}",
                    process_change.pid, process_change.uid
                );
                return Ok(ResolvedProcess {
                    pid: process_change.pid,
                    uid: process_change.uid,
                    name: result_process_name.to_string(),
                });
            }
        }
    }

    bail!("Timeout waiting duration {:?} for process_name {:?}", duration, process_name)
}

fn get_pid(process_name: &str) -> Option<i32> {
    for entry in read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.is_dir() {
            let cmdline_path = path.join("cmdline");
            if let Ok(cmdline_bytes) = read(cmdline_path) {
                let cmdline = String::from_utf8_lossy(&cmdline_bytes);
                if cmdline == process_name || cmdline.starts_with(process_name) {
                    if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }

    None
}

#[allow(non_snake_case)]
fn get_ProcessRecord_makeActive_offsets() -> Result<ExecutableMethodFileOffsets> {
    let offsets = ExecutableMethodFileOffsets::get(
        &TargetProcess::system_server()?,
        &MethodDescriptor::new(
            CLASS_PROCESS_RECORD,
            METHOD_MAKE_ACTIVE,
            METHOD_MAKE_ACTIVE_PARAMS.into_iter().map(String::from),
        )?,
    )
    .context("Failed to get offsets for ProcessRecord#makeActive")?;
    offsets.ok_or(anyhow!("Could not find offsets for ProcessRecord#makeActive"))
}

#[allow(non_snake_case)]
fn get_onProcessActive_offsets() -> Result<ExecutableMethodFileOffsets> {
    let offsets = ExecutableMethodFileOffsets::get(
        &TargetProcess::system_server()?,
        &MethodDescriptor::new(
            CLASS_PROCESS_PROFILE_RECORD,
            METHOD_ON_PROCESS_ACTIVE,
            METHOD_ON_PROCESS_ACTIVE_PARAMS.into_iter().map(String::from),
        )?,
    )
    .context("Failed to get offsets for ProcessProfileRecord#onProcessActive")?;
    offsets.ok_or(anyhow!("Could not find offsets for ProcessProfileRecord#onProcessActive"))
}

const CLASS_PROCESS_RECORD: &str = "com.android.server.am.ProcessRecord";
const METHOD_MAKE_ACTIVE: &str = "makeActive";
const METHOD_MAKE_ACTIVE_PARAMS: [&str; 2] = [
    "com.android.server.am.ApplicationThreadDeferred",
    "com.android.server.am.ProcessStatsService",
];
const CLASS_PROCESS_PROFILE_RECORD: &str = "com.android.server.am.ProcessProfileRecord";
const METHOD_ON_PROCESS_ACTIVE: &str = "onProcessActive";
const METHOD_ON_PROCESS_ACTIVE_PARAMS: [&str; 2] =
    ["android.app.IApplicationThread", "com.android.server.am.ProcessStatsService"];

const BPF_PROG_PROCESS_MANAGEMENT_MAKE_ACTIVE: &str = "prog_ProcessManagement_uprobe_make_active";
const BPF_PROG_PROCESS_MANAGEMENT_ON_PROCESS_ACTIVE: &str =
    "prog_ProcessManagement_uprobe_on_process_active";
const BPF_MAP_PROCESS_MANAGEMENT: &str = "map_ProcessManagement_process_change_output_buf";
