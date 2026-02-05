//! UprobeStatsService is a binder service that receives task configurations from the statsd
//! process and starts tasks according to the configuration.
use crate::{task, task::GlobalState};
use binder::{Interface, Status};
use log::{error, trace};
use std::{
    sync::{Arc, Mutex},
    thread,
};
use uprobestats_service_aidl::aidl::com::android::uprobestats::IUprobeStatsService::IUprobeStatsService;

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
        trace!("received startTasks call");

        let config = config.to_vec();
        let state = self.state.clone();
        thread::spawn(move || {
            let task = match task::resolve_config(&config) {
                Ok(task) => task,
                Err(e) => {
                    error!("{e}");
                    return;
                }
            };

            // Create a scope so that the lock is released before executing the task.
            {
                let mut state = state.lock().unwrap();
                if let Err(e) = task::update_polled_bpf_maps(&mut state, &task) {
                    error!("{e}");
                    return;
                }
            }

            task::execute(&task);

            let mut state = state.lock().unwrap();
            task::cleanup_polled_bpf_maps(&mut state, &task);
        });

        Ok(())
    }
}
