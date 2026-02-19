use super::process::ResolvedProcess;
use anyhow::Result;

/// Implementations can get the offsets of an executable given the target process and method
/// descriptor.
pub trait OffsetResolver {
    /// Resolves the offsets of an executable method.
    fn resolve_offsets(
        &self,
        target_process: &ResolvedProcess,
        method_descriptor: &MethodDescriptor,
    ) -> Result<Option<ExecutableMethodFileOffsets>>;
}

/// Mirrors the same struct from `dynamic_instrumentation_manager`, so we don't need to depend on
/// that crate here.
#[derive(Clone, Debug)]
#[allow(missing_docs)] // see frameworks/base/native/android/include_platform/android/dynamic_instrumentation_manager.h
pub struct MethodDescriptor {
    pub fully_qualified_class_name: String,
    pub method_name: String,
    pub fully_qualified_parameters: Vec<String>,
}

/// Mirrors the same struct from `dynamic_instrumentation_manager`, so we don't need to depend on
/// that crate here.
#[derive(Clone, Debug)]
#[allow(missing_docs)] // see frameworks/base/native/android/include_platform/android/dynamic_instrumentation_manager.h
pub struct ExecutableMethodFileOffsets {
    pub container_path: String,
    pub container_offset: u64,
    pub method_offset: u64,
}

impl ExecutableMethodFileOffsets {
    /// Returns a unique identifier for the method.
    ///
    /// Used to identify the method under instrumentation in the BPF maps/programs.
    pub fn method_identifier(&self) -> u64 {
        // We the targeted code is JIT compiled, ART gives us the path to the so file
        // of the "stub" entry point that we attach a uprobe to. The container offset
        // is the identifier of the *actual* method we want to instrument.
        if self.container_path.ends_with("so") {
            self.container_offset
        // When the targeted code is AOT compiled,
        // the container offset + method offset is the AOT compiled entry point
        // in the targeted process' memory space.
        } else {
            self.container_offset + self.method_offset
        }
    }
}
