//! Safe wrapper around the platform dynamic_instrumentation_manager API
use anyhow::Result;
use binder::{Result as BinderResult, Status};
use dynamic_instrumentation_manager_bindgen::{
    ADynamicInstrumentationManager_ExecutableMethodFileOffsets,
    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy,
    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset,
    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath,
    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset,
    ADynamicInstrumentationManager_MethodDescriptor,
    ADynamicInstrumentationManager_MethodDescriptor_create,
    ADynamicInstrumentationManager_MethodDescriptor_destroy,
    ADynamicInstrumentationManager_TargetProcess,
    ADynamicInstrumentationManager_TargetProcess_create,
    ADynamicInstrumentationManager_TargetProcess_destroy,
    ADynamicInstrumentationManager_getExecutableMethodFileOffsets,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::NonNull;

mod c_string;
use c_string::c_string;

/// Describes the code offsets for a given method.
pub struct ExecutableMethodFileOffsets {
    instance: NonNull<ADynamicInstrumentationManager_ExecutableMethodFileOffsets>,
}

impl ExecutableMethodFileOffsets {
    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_create` in `dynamic_instrumentation_manager.h`
    pub fn get(
        target_process: &TargetProcess,
        method_descriptor: &MethodDescriptor,
    ) -> BinderResult<Option<Self>> {
        let mut instance: *const ADynamicInstrumentationManager_ExecutableMethodFileOffsets =
            std::ptr::null_mut();
        // SAFETY:
        // - `TargetProcess` and `MethodDescriptor` types wrap valid pointers to the underlying C structs.
        // - We hold an exclusive mutable reference to the `instance` out parameter.
        let status = unsafe {
            ADynamicInstrumentationManager_getExecutableMethodFileOffsets(
                target_process.as_ptr(),
                method_descriptor.as_ptr(),
                &mut instance
                    as *mut *const ADynamicInstrumentationManager_ExecutableMethodFileOffsets,
            )
        };

        if status != 0 {
            return Err(Status::new_service_specific_error(status, None));
        }
        Ok(NonNull::new(
            instance as *mut ADynamicInstrumentationManager_ExecutableMethodFileOffsets,
        )
        .map(|instance| Self { instance }))
    }

    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath` in `dynamic_instrumentation_manager.h`
    pub fn get_container_path(&self) -> String {
        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
        let container_path = unsafe {
            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath(
                self.instance.as_ptr(),
            )
        };
        // SAFETY: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath` returns a valid pointer to a null-terminated C string.
        let cstr = unsafe { CStr::from_ptr(container_path) };
        String::from_utf8_lossy(cstr.to_bytes()).to_string()
    }

    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset` in `dynamic_instrumentation_manager.h`
    pub fn get_container_offset(&self) -> u64 {
        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
        unsafe {
            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset(
                self.instance.as_ptr(),
            )
        }
    }

    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset` in `dynamic_instrumentation_manager.h`
    pub fn get_method_offset(&self) -> u64 {
        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
        unsafe {
            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset(
                self.instance.as_ptr(),
            )
        }
    }
}

impl Drop for ExecutableMethodFileOffsets {
    fn drop(&mut self) {
        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
        unsafe {
            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy(
                self.instance.as_ptr(),
            );
        }
    }
}

/// Describes a method for which we can fetch code offsets.
pub struct MethodDescriptor {
    instance: *const ADynamicInstrumentationManager_MethodDescriptor,
}

impl MethodDescriptor {
    /// See: `ADynamicInstrumentationManager_MethodDescriptor_create` in `dynamic_instrumentation_manager.h`
    pub fn new(
        fully_qualified_class_name: &str,
        method_name: &str,
        fully_qualified_parameters: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let fully_qualified_class_name = c_string(fully_qualified_class_name)?;
        let method_name = c_string(method_name)?;

        let fully_qualified_parameters: Result<Vec<CString>> =
            fully_qualified_parameters.into_iter().map(|s| c_string(&s)).collect();
        let fully_qualified_parameters = fully_qualified_parameters?;
        let mut fully_qualified_parameters: Vec<*const c_char> =
            fully_qualified_parameters.iter().map(|c| c.as_ptr()).collect();
        // SAFETY:
        // - all pointers are valid by virtue of being derived from owned `CString`s.
        // - `ADynamicInstrumentationManager_MethodDescriptor_create` makes copies of the data pointed to by its arguments.
        let instance = unsafe {
            ADynamicInstrumentationManager_MethodDescriptor_create(
                fully_qualified_class_name.as_ptr(),
                method_name.as_ptr(),
                fully_qualified_parameters.as_mut_ptr(),
                fully_qualified_parameters.len(),
            )
        };
        Ok(Self { instance })
    }

    fn as_ptr(&self) -> *const ADynamicInstrumentationManager_MethodDescriptor {
        self.instance
    }
}

impl Drop for MethodDescriptor {
    fn drop(&mut self) {
        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
        unsafe {
            ADynamicInstrumentationManager_MethodDescriptor_destroy(self.instance);
        }
    }
}

/// Identifies a single process on device.
pub struct TargetProcess {
    instance: *const ADynamicInstrumentationManager_TargetProcess,
}

impl TargetProcess {
    /// See: `ADynamicInstrumentationManager_TargetProcess_create` in `dynamic_instrumentation_manager.h`
    pub fn new(uid: u32, pid: i32, process_name: &str) -> Result<Self> {
        let process_name = c_string(process_name)?;
        // SAFETY:
        // - `process_name` is valid by virtue of being derived from an owned `CString`.
        // - `ADynamicInstrumentationManager_TargetProcess_create` makes a copy of `process_name` pointer.
        let instance = unsafe {
            ADynamicInstrumentationManager_TargetProcess_create(uid, pid, process_name.as_ptr())
        };
        Ok(Self { instance })
    }

    /// Returns a `TargetProcess` for system server.
    pub fn system_server() -> Result<Self> {
        Self::new(0, 0, "system_server")
    }

    fn as_ptr(&self) -> *const ADynamicInstrumentationManager_TargetProcess {
        self.instance
    }
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
        unsafe {
            ADynamicInstrumentationManager_TargetProcess_destroy(self.instance);
        }
    }
}
