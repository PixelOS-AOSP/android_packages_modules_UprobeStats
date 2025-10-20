//! Client for UprobeStatsService
use anyhow::{Context, Result};
use binder::{get_interface, Strong};
use std::sync::LazyLock;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::IUprobeStatsBridgeService::IUprobeStatsBridgeService;

const UPROBESTATS_BRIDGE_SERVICE_NAME: &str = "uprobestats_bridge_service";

pub(crate) fn get_uprobestats_bridge_service() -> Result<Strong<dyn IUprobeStatsBridgeService>> {
    let service = get_interface(UPROBESTATS_BRIDGE_SERVICE_NAME)
        .context("Failed to get uprobestats service")?;
    Ok(service)
}

pub(crate) static UPROBESTATS_BRIDGE_SERVICE: LazyLock<
    Result<Strong<dyn IUprobeStatsBridgeService>>,
> = LazyLock::new(get_uprobestats_bridge_service);
