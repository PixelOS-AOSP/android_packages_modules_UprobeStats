//! UProbestats executable.
use anyhow::{anyhow, bail, ensure, Result};
use atrace::{atrace_begin, atrace_end, AtraceTag};
use binder::ProcessState;
use log::{debug, error, LevelFilter};
use rustutils::android::system_properties;
use std::{
    cmp::{max, min},
    process::exit,
    str::FromStr,
    thread,
    time::Duration,
};
use uprobestats_bpf::bpf_perf_event_open;
use uprobestats_rs::{bpf_map, config_resolver, guardrail, is_user_build};

fn main() {
    atrace_begin(AtraceTag::App, "uprobestats_rs::main");
    let log_tag_filter = level_filter_from_property_or_info("log.tag.uprobestats");
    let persist_log_tag_filter = level_filter_from_property_or_info("persist.log.tag.uprobestats");
    let log_level_filter = max(log_tag_filter, persist_log_tag_filter);

    logger::init(logger::Config::default().with_tag_on_device("uprobestats").with_max_level(
        if is_user_build() { min(LevelFilter::Info, log_level_filter) } else { log_level_filter },
    ));

    if let Err(e) = main_impl() {
        error!("{e}");
        atrace_end(AtraceTag::App);
        exit(1);
    };

    atrace_end(AtraceTag::App);
}

fn main_impl() -> Result<()> {
    debug!("started");

    ensure!(uprobestats_mainline_flags_rust::enable_uprobestats(), "enable_uprobestats disabled");
    ensure!(
        uprobestats_mainline_flags_rust::uprobestats_support_update_device_idle_temp_allowlist(),
        "uprobestats_support_update_device_idle_temp_allowlist disabled",
    );
    ensure!(
        uprobestats_mainline_flags_rust::executable_method_file_offsets(),
        "executable_method_file_offsets disabled",
    );

    let config = config_resolver::read_config("/data/misc/uprobestats-configs/config")?;
    ensure!(
        guardrail::is_allowed(&config, is_user_build(), true)?,
        "uprobestats probing config disallowed on this device"
    );

    ProcessState::start_thread_pool();

    let task = config_resolver::resolve_single_task(config)?;

    // binder_interface_bpf_map will clear the contents of the map when it goes out of scope.
    let (probes, _binder_interface_bpf_map) = config_resolver::resolve_probes(&task)?;
    for probe in &probes {
        debug!(
            "attaching bpf {} to {} at {}",
            probe.bpf_program_path, &probe.filename, &probe.offset
        );
        bpf_perf_event_open(
            probe.filename.clone(),
            probe.offset,
            task.pid,
            probe.bpf_program_path.clone(),
        )?;
        debug!(
            "successfully attached bpf {} to {} at {}",
            probe.bpf_program_path, &probe.filename, &probe.offset
        );
    }

    let duration = Duration::from_secs(task.duration_seconds.try_into()?);
    let errors = thread::scope(|s| {
        let mut handles = vec![];
        for map_path in &task.bpf_map_paths {
            let task_ref = &task;
            handles.push(s.spawn(move || {
                debug!("Spawned thread for map_path: {map_path}");
                bpf_map::poll_registry(map_path, task_ref, duration)
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

    debug!("done");

    Ok(())
}

fn level_filter_from_property_or_info(property: &str) -> LevelFilter {
    LevelFilter::from_str(
        system_properties::read(property).ok().flatten().unwrap_or("".to_string()).as_str(),
    )
    .unwrap_or(LevelFilter::Info)
}
