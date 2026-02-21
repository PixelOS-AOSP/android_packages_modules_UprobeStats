//! Handles the data emitted from eBPF programs via their associated maps.
use crate::config_resolver::ResolvedTask;
use anyhow::Result;
use std::{collections::HashMap, fmt::Debug, time::Duration};

/// a11y handler
pub mod accessibility;
/// A module only for testing JIT integration.
pub mod art_test;
/// Binder transaction handlers
pub mod binder_transaction;
/// Bitmap allocation handlers
pub mod bitmap_allocation;
/// Disruptive app handlers
pub mod disruptive_app;
/// Generic instrumentation handlers
pub mod generic_instrumentation;
/// Process management handlers
pub mod process_management;

/// Interface for reading items out of a BPF ring buffer.
/// # Safety
/// There *must* exist a BPF ring buffer at the path represented by `MAP_PATH`
/// which holds items of type `Handler::T`.
pub unsafe trait Handler {
    /// The path to the BPF map backing this handler.
    const MAP_PATH: &'static str;
    /// The type of value emitted by the map at `MAP_PATH`.
    type T: Debug + Copy;
    /// Handle an individual item emitted from the map.
    fn on_item(&mut self, task: &ResolvedTask, data: &Self::T) -> Result<()>;
    /// Called once after the last item is emitted (e.g. the BPF polling has expired).
    fn on_finished(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A registry of handlers for events emitted by eBPF programs.
///
/// The key into the registry is expecte to be a valid BPF map on the filesystem.
pub type HandlerRegistry = HashMap<&'static str, fn(&str, &ResolvedTask, Duration) -> Result<()>>;

enum DynamicInstrumentationPayloadIds {
    BinderTransaction = 1,
    DisabledLauncherActivity = 2,
    BindAllowBackgroundActivityStarts = 3,
}

fn get_current_timestamp_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards") // Handle the potential error
        .as_millis()
        .try_into()
        .expect("Overflow in timestamp")
}
