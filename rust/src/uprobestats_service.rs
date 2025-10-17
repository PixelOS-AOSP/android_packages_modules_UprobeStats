//! UprobeStatsService is a binder service that receives task configurations from the statsd
//! process and starts tasks according to the configuration.
use crate::{task, task::GlobalState};
use anyhow::Context;
use binder::{Interface, IntoBinderResult, Status};
use log::debug;
use std::{
    sync::{Arc, Mutex},
    thread,
};
use uprobestats_service_aidl::aidl::com::android::uprobestats::IUprobeStatsService::{
    IUprobeStatsService, FAILURE_CONFIG_RESOLUTION, FAILURE_CONFLICT,
};

/// The name of the UprobeStatsService.
pub const UPROBESTATS_SERVICE_NAME: &str = "uprobestats_service";

/// UprobeStatsService is a binder service that receives task configurations from the statsd
/// process and starts tasks according to the configuration.
pub struct UprobeStatsService {
    state: Arc<Mutex<GlobalState>>,
}

impl UprobeStatsService {
    /// Constructor
    pub fn new(state: Arc<Mutex<GlobalState>>) -> Self {
        Self { state: state.clone() }
    }
}

impl Interface for UprobeStatsService {}

impl IUprobeStatsService for UprobeStatsService {
    fn startTasks(&self, config: &[u8]) -> Result<(), Status> {
        debug!("received startTasks call");

        let (task, probes) = task::resolve_config(config)
            .context("failed to prepare task")
            .or_service_specific_exception(FAILURE_CONFIG_RESOLUTION)?;

        let mut state = self.state.lock().unwrap();
        task::update_polled_bpf_maps(&mut state, &task)
            .context("conflict found")
            .or_service_specific_exception(FAILURE_CONFLICT)?;

        let state = self.state.clone();
        thread::spawn(move || {
            task::execute(&task, &probes);
            let mut state = state.lock().unwrap();
            task::cleanup_polled_bpf_maps(&mut state, &task);
        });

        Ok(())
    }
}
