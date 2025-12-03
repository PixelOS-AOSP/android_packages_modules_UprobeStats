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
mod test {
    use super::*;
    use binder::BinderFeatures;
    use uprobestats_bridge_service_aidl::aidl::com::android::uprobestats::IUprobeStatsBridgeService::{
        BnUprobeStatsBridgeService,
        MockIUprobeStatsBridgeService
    };

    #[allow(unused)]
    pub(crate) struct TestUprobeStatsBridgeService {
        pub(crate) mock: Option<MockIUprobeStatsBridgeService>,
    }

    impl UprobeStatsBridgeService for TestUprobeStatsBridgeService {
        fn get(&mut self) -> Result<Strong<dyn IUprobeStatsBridgeService>> {
            Ok(BnUprobeStatsBridgeService::new_binder(
                self.mock.take().expect("mock not set"),
                BinderFeatures::default(),
            ))
        }
    }
}
