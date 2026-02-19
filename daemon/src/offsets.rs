use anyhow::{anyhow, bail, Result};
use binder::ExceptionCode;
use dynamic_instrumentation_manager::{
    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
};
use std::{thread, time::Duration};
use uprobestats_core::{config_resolver, config_resolver::OffsetResolver};

pub(crate) struct OffsetResolverImpl {}
impl OffsetResolver for OffsetResolverImpl {
    fn resolve_offsets(
        &self,
        target_process: &config_resolver::TargetProcess,
        method_descriptor: &config_resolver::MethodDescriptor,
    ) -> Result<Option<config_resolver::ExecutableMethodFileOffsets>> {
        let target_process = to_target_process(target_process)?;
        let method_descriptor = to_method_descriptor(method_descriptor)?;
        let offsets =
            get_executable_method_file_offsets_with_retry(&target_process, &method_descriptor)?;
        Ok(offsets.as_ref().map(to_config_resolver_offsets))
    }
}

fn get_executable_method_file_offsets_with_retry(
    target_process: &TargetProcess,
    method_descriptor: &MethodDescriptor,
) -> Result<Option<ExecutableMethodFileOffsets>> {
    if !uprobestats_mainline_flags_rust::use_process_observer_api() {
        return ExecutableMethodFileOffsets::get(target_process, method_descriptor)
            .map_err(|e| anyhow!("Failed to get executable method file offsets: {}", e));
    }

    let mut retries = 0;
    const MAX_RETRIES: u32 = 5;
    let mut backoff = Duration::from_millis(10);

    loop {
        match ExecutableMethodFileOffsets::get(target_process, method_descriptor) {
            Ok(offsets) => return Ok(offsets),
            Err(status) => {
                if retries >= MAX_RETRIES {
                    bail!("Failed after {} retries, last error: {}", MAX_RETRIES, status);
                }
                if status.exception_code() != ExceptionCode::SERVICE_SPECIFIC {
                    bail!("Unexpected status: {status}");
                }
                if status.service_specific_error() != ExceptionCode::ILLEGAL_STATE as i32 {
                    bail!("Unexpected service specific error: {status}");
                }
                #[cfg(not(test))]
                {
                    log::warn!(
                        "Failed to get method offsets (attempt {}/{}), retrying in {:?}: {}",
                        retries + 1,
                        MAX_RETRIES,
                        backoff,
                        status
                    );
                }
                thread::sleep(backoff);
                retries += 1;
                backoff *= 2;
            }
        }
    }
}

fn to_method_descriptor(
    method_descriptor: &config_resolver::MethodDescriptor,
) -> Result<MethodDescriptor> {
    MethodDescriptor::new(
        &method_descriptor.fully_qualified_class_name,
        &method_descriptor.method_name,
        method_descriptor.fully_qualified_parameters.clone(),
    )
}

fn to_target_process(target_process: &config_resolver::TargetProcess) -> Result<TargetProcess> {
    TargetProcess::new(target_process.uid, target_process.pid, &target_process.process_name)
}

fn to_config_resolver_offsets(
    offsets: &ExecutableMethodFileOffsets,
) -> config_resolver::ExecutableMethodFileOffsets {
    config_resolver::ExecutableMethodFileOffsets {
        container_path: offsets.get_container_path(),
        container_offset: offsets.get_container_offset(),
        method_offset: offsets.get_method_offset(),
    }
}
