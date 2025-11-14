use super::{OffsetResolver, ProcessResolver, ResolvedProcess};
use crate::process::resolve_process;
use anyhow::{anyhow, bail, Result};
use binder::ExceptionCode;
use dynamic_instrumentation_manager::{
    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
};
use std::{thread, time::Duration};
use uprobestats_proto::config::uprobestats_config::task::TargetProcessSelection;

pub(super) struct ProcessResolverImpl {}
impl ProcessResolver for ProcessResolverImpl {
    fn resolve_process(
        &self,
        process_name: Option<&str>,
        target_process_selection: TargetProcessSelection,
        timeout: Duration,
    ) -> Result<ResolvedProcess> {
        resolve_process(process_name, target_process_selection, timeout)
    }
}

pub(super) struct OffsetResolverImpl {}
impl OffsetResolver for OffsetResolverImpl {
    fn resolve_offsets(
        &self,
        target_process: &super::TargetProcess,
        method_descriptor: &super::MethodDescriptor,
    ) -> Result<Option<super::ExecutableMethodFileOffsets>> {
        let offsets = get_executable_method_file_offsets_with_retry(
            &target_process.into(),
            &method_descriptor.into(),
        )?;
        Ok(offsets.map(|offsets| offsets.into()))
    }
}

impl From<&super::MethodDescriptor> for MethodDescriptor {
    fn from(val: &super::MethodDescriptor) -> Self {
        MethodDescriptor::new(
            &val.fully_qualified_class_name,
            &val.method_name,
            val.fully_qualified_parameters.clone(),
        )
        .unwrap()
    }
}

impl From<&super::TargetProcess> for TargetProcess {
    fn from(val: &super::TargetProcess) -> Self {
        TargetProcess::new(val.uid, val.pid, &val.process_name).unwrap()
    }
}

impl From<ExecutableMethodFileOffsets> for super::ExecutableMethodFileOffsets {
    fn from(val: ExecutableMethodFileOffsets) -> super::ExecutableMethodFileOffsets {
        super::ExecutableMethodFileOffsets {
            container_path: val.get_container_path(),
            container_offset: val.get_container_offset(),
            method_offset: val.get_method_offset(),
        }
    }
}

pub(super) fn get_executable_method_file_offsets_with_retry(
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
