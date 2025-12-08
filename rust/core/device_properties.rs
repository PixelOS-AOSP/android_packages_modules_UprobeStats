//! Properties of a device that can be stubbed for tests.
/// Trait to wrap device properties.
pub trait DeviceProperties {
    /// True if this is a user build (as opposed to a userdebug or eng build).
    fn is_user_build(&self) -> bool;
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[allow(dead_code)]
    struct TestDeviceProperties {
        is_user_build: bool,
    }

    impl DeviceProperties for TestDeviceProperties {
        fn is_user_build(&self) -> bool {
            self.is_user_build
        }
    }
}
