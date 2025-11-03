//! UProbestats executable.
use anyhow::Result;
use atrace::{atrace_begin, atrace_end, AtraceTag};
use binder::ProcessState;
use log::{debug, error, trace, LevelFilter};
use rustutils::android::system_properties;
use std::{
    cmp::{max, min},
    process::exit,
    str::FromStr,
    sync::{Arc, Mutex},
};
use uprobestats_rs::is_user_build;
#[cfg(not(feature = "binder-service"))]
use {
    anyhow::anyhow,
    std::{fs::File, io::Read},
    uprobestats_rs::task,
};
#[cfg(feature = "binder-service")]
use {
    binder::{register_lazy_service, BinderFeatures},
    uprobestats_rs::uprobestats_service::{UprobeStatsService, UPROBESTATS_SERVICE_NAME},
    uprobestats_service_aidl::aidl::com::android::uprobestats::IUprobeStatsService::BnUprobeStatsService,
};

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

    ProcessState::start_thread_pool();
    trace!("initial flag check done and tread pool started");

    handle_tasks()?;

    debug!("done");

    Ok(())
}

#[cfg(not(feature = "binder-service"))]
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

#[cfg(feature = "binder-service")]
fn handle_tasks() -> Result<()> {
    let state = Arc::new(Mutex::new(None));
    let service = BnUprobeStatsService::new_binder(
        UprobeStatsService::new(state.clone()),
        BinderFeatures::default(),
    );

    register_lazy_service(UPROBESTATS_SERVICE_NAME, service.as_binder())?;

    debug!("registered service - joining thread pool");
    ProcessState::join_thread_pool();
    trace!("join_thread_pool done");

    Ok(())
}

#[cfg(not(feature = "binder-service"))]
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
