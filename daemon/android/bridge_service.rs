//! Client for UprobeStatsService
use anyhow::{anyhow, Context, Result};
use binder::{get_interface, Strong};
use std::sync::LazyLock;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::IUprobeStatsBridgeService::IUprobeStatsBridgeService;
use uprobestats_core::bridge_service::UprobeStatsBridgeService;

const UPROBESTATS_BRIDGE_SERVICE_NAME: &str = "uprobestats_bridge";

pub(crate) static UPROBESTATS_BRIDGE_SERVICE: LazyLock<
    Result<Strong<dyn IUprobeStatsBridgeService>>,
> = LazyLock::new(|| {
    get_interface(UPROBESTATS_BRIDGE_SERVICE_NAME)
        .context("Failed to get {UPROBESTATS_BRIDGE_SERVICE_NAME} service")
});

#[derive(Default)]
pub(crate) struct DefaultUprobeStatsBridgeService {}
impl UprobeStatsBridgeService for DefaultUprobeStatsBridgeService {
    fn get(&mut self) -> Result<Strong<dyn IUprobeStatsBridgeService>> {
        UPROBESTATS_BRIDGE_SERVICE.as_ref().map(|s| s.clone()).map_err(|e| anyhow!("{e}"))
    }
}
