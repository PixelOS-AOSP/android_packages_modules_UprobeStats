//! Client for UprobeStatsBridgeService
use anyhow::Result;
use binder::Strong;
use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::IUprobeStatsBridgeService::IUprobeStatsBridgeService;

/// Trait representing the underlying bridge service (or a mock)
pub trait UprobeStatsBridgeService {
    /// Get a client of the service
    fn get(&mut self) -> Result<Strong<dyn IUprobeStatsBridgeService>>;
}

#[cfg(test)]
pub mod test {
    use super::*;
    use binder::{BinderFeatures, Interface};
    use std::sync::{Arc, Mutex};
    use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::{
        Event::Event,
        IUprobeStatsBridgeService::{
            BnUprobeStatsBridgeService, IUprobeStatsBridgeService, MockIUprobeStatsBridgeService,
        },
    };

    #[derive(Clone, Debug)]
    pub(crate) struct TestUprobeStatsBridgeService {
        pub(crate) mock: Arc<Mutex<MockIUprobeStatsBridgeService>>,
    }

    impl Interface for TestUprobeStatsBridgeService {}

    impl IUprobeStatsBridgeService for TestUprobeStatsBridgeService {
        fn getUidForPackage(&self, name: &str) -> binder::Result<i32> {
            self.mock.lock().unwrap().getUidForPackage(name)
        }
        fn packageHasEnabledAccessibilityService(&self, name: &str) -> binder::Result<bool> {
            self.mock.lock().unwrap().packageHasEnabledAccessibilityService(name)
        }
        fn isLauncherActivity(
            &self,
            pkg: &str,
            activity: &str,
            is_relaunch: bool,
        ) -> binder::Result<bool> {
            self.mock.lock().unwrap().isLauncherActivity(pkg, activity, is_relaunch)
        }
        fn enqueueEvent(&self, event: &Event, is_long: bool) -> binder::Result<()> {
            self.mock.lock().unwrap().enqueueEvent(event, is_long)
        }
        fn enableTestMode(&self, pkg: &str, activity_class_name: &str) -> binder::Result<bool> {
            self.mock.lock().unwrap().enableTestMode(pkg, activity_class_name)
        }
        fn disableTestMode(&self) -> binder::Result<bool> {
            self.mock.lock().unwrap().disableTestMode()
        }
        fn waitQueueFlushed(&self) -> binder::Result<bool> {
            self.mock.lock().unwrap().waitQueueFlushed()
        }
    }

    impl UprobeStatsBridgeService for TestUprobeStatsBridgeService {
        fn get(&mut self) -> Result<Strong<dyn IUprobeStatsBridgeService>> {
            Ok(BnUprobeStatsBridgeService::new_binder(self.clone(), BinderFeatures::default()))
        }
    }
}
