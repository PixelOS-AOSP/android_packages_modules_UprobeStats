use anyhow::Result;
use std::time::Duration;
use uprobestats_proto::config::uprobestats_config::task::TargetProcessSelection;

/// Resolved process information.
#[derive(Clone, Debug)]
pub struct ResolvedProcess {
    /// PID
    pub pid: i32,
    /// UID
    pub uid: i32,
    /// Process name
    pub name: String,
}

/// Implementations can get actuall process info off a device based on the supplied information.
pub trait ProcessResolver {
    /// Resolves the process metadata to a ResolvedProcess.
    fn resolve_process(
        &self,
        process_name: Option<&str>,
        target_process_selection: TargetProcessSelection,
        timeout: Duration,
    ) -> Result<ResolvedProcess>;
}
