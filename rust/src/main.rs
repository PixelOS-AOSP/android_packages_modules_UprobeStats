//! UProbestats executable.
use anyhow::{anyhow, ensure, Result};
use atrace::{atrace_begin, atrace_end, AtraceTag};
use binder::ProcessState;
use log::{debug, error, trace, LevelFilter};
use rustutils::android::system_properties;
use std::{
    cmp::{max, min},
    fs::File,
    io::Read,
    process::exit,
    str::FromStr,
    sync::{Arc, Mutex},
};
use uprobestats_rs::{is_user_build, task};

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

    ProcessState::start_thread_pool();
    trace!("initial flag check done and tread pool started");

    handle_tasks()?;

    debug!("done");

    Ok(())
}

fn handle_tasks() -> Result<()> {
    let config_bytes = file_path_to_bytes("/data/misc/uprobestats-configs/config")?;
    let (task, probes) = task::resolve_config(&config_bytes)?;

    let state = Arc::new(Mutex::new(None));
    let mut state = state.lock().unwrap();

    task::update_polled_bpf_maps(&mut state, &task)?;
    task::execute(&task, &probes);
    task::cleanup_polled_bpf_maps(&mut state, &task);

    Ok(())
}

fn file_path_to_bytes(path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(|e| anyhow!("Failed to open file: {e}"))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| anyhow!("Failed to read file: {e}"))?;
    Ok(buffer)
}

fn level_filter_from_property_or_info(property: &str) -> LevelFilter {
    LevelFilter::from_str(
        system_properties::read(property).ok().flatten().unwrap_or("".to_string()).as_str(),
    )
    .unwrap_or(LevelFilter::Info)
}
