//! Safe wrapper around the platform activity_manager API for process observation.

use activity_manager_bindgen::{
    ffi_AActivityManager_ProcessObserver_setOnForegroundActivitiesChanged,
    ffi_AActivityManager_ProcessObserver_setOnForegroundServicesChanged,
    ffi_AActivityManager_ProcessObserver_setOnProcessDied,
    ffi_AActivityManager_ProcessObserver_setOnProcessStarted,
    ffi_AActivityManager_createProcessObserver, ffi_AActivityManager_destroyProcessObserver,
    ffi_AActivityManager_registerProcessObserver, AActivityManager_ForegroundActivitiesState,
    AActivityManager_ProcessObserver,
};
use anyhow::Result;
use std::ffi::{c_void, CStr};
use std::ptr::NonNull;

/// The state of foreground activities in a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ForegroundActivitiesState {
    /// The process has no foreground activities.
    NoForegroundActivities = 0,
    /// The process has one or more foreground activities.
    HasForegroundActivities = 1,
}

/// Callbacks for process state changes.
///
/// The callbacks will be invoked on an arbitrary thread. Implementations must be `Send + Sync`.
pub trait ProcessObserverCallbacks: Send + Sync {
    /// Called when a process is started.
    fn on_process_started(
        &mut self,
        _pid: i32,
        _process_uid: u32,
        _package_uid: u32,
        _package_name: &str,
        _process_name: &str,
    ) {
    }

    /// Called when the foreground activities of a process change.
    fn on_foreground_activities_changed(
        &mut self,
        _pid: i32,
        _uid: u32,
        _state: ForegroundActivitiesState,
    ) {
    }

    /// Called when the foreground services of a process change.
    fn on_foreground_services_changed(&mut self, _pid: i32, _uid: u32, _service_types: i32) {}

    /// Called when a process dies.
    fn on_process_died(&mut self, _pid: i32, _uid: u32) {}
}

/// A process observer that receives callbacks about process state changes.
///
/// The observer is automatically unregistered when this struct is dropped.
pub struct ProcessObserver {
    instance: NonNull<AActivityManager_ProcessObserver>,
    // Keep the callbacks alive. The inner Box is for the trait object, the outer one is to have a
    // stable address for the cookie.
    _callbacks: Box<Box<dyn ProcessObserverCallbacks>>,
}

impl ProcessObserver {
    /// Registers a process observer.
    /// See `AActivityManager_registerProcessObserver`.
    pub fn register(callbacks: Box<dyn ProcessObserverCallbacks>) -> Result<Self> {
        let mut boxed_callbacks = Box::new(callbacks);
        let cookie = &mut *boxed_callbacks as *mut _ as *mut c_void;

        // SAFETY: The cookie is a pointer to a Box<dyn ProcessObserverCallbacks> which is kept
        // alive by the returned ProcessObserver. The C API will pass this cookie back to us in
        // the callbacks.
        let observer = unsafe { ffi_AActivityManager_createProcessObserver(cookie) };
        if observer.is_null() {
            anyhow::bail!("Failed to create process observer");
        }

        // SAFETY: observer is a valid pointer.
        unsafe {
            ffi_AActivityManager_ProcessObserver_setOnProcessStarted(
                observer,
                Some(on_process_started_trampoline),
            );
            ffi_AActivityManager_ProcessObserver_setOnForegroundActivitiesChanged(
                observer,
                Some(on_foreground_activities_changed_trampoline),
            );
            ffi_AActivityManager_ProcessObserver_setOnForegroundServicesChanged(
                observer,
                Some(on_foreground_services_changed_trampoline),
            );
            ffi_AActivityManager_ProcessObserver_setOnProcessDied(
                observer,
                Some(on_process_died_trampoline),
            );
        }

        // SAFETY: observer is a valid pointer with callbacks set.
        let status = unsafe { ffi_AActivityManager_registerProcessObserver(observer) };
        if status != 0 {
            // SAFETY: observer is valid and registration failed, so we destroy it.
            unsafe { ffi_AActivityManager_destroyProcessObserver(observer) };
            anyhow::bail!("Failed to register process observer, status: {}", status);
        }

        Ok(Self { instance: NonNull::new(observer).unwrap(), _callbacks: boxed_callbacks })
    }
}

impl Drop for ProcessObserver {
    fn drop(&mut self) {
        // SAFETY: `instance` is a valid pointer to an AActivityManager_ProcessObserver,
        // and it's being destroyed, so it's safe to destroy.
        unsafe {
            ffi_AActivityManager_destroyProcessObserver(self.instance.as_ptr());
        }
    }
}

/// # Safety
/// This function is only safe to call with a valid cookie from the C ActivityManager API.
unsafe fn get_callbacks<'a>(cookie: *mut c_void) -> &'a mut Box<dyn ProcessObserverCallbacks> {
    // SAFETY: The caller guarantees that `cookie` is a valid pointer to a
    // `Box<dyn ProcessObserverCallbacks>`.
    unsafe { &mut *(cookie as *mut Box<dyn ProcessObserverCallbacks>) }
}

/// # Safety
///
/// This function must only be called by the C ActivityManager API with the cookie that was
/// provided when creating the process observer. The C API guarantees that `package_name` and
/// `process_name` are valid, non-null C strings.
unsafe extern "C" fn on_process_started_trampoline(
    pid: i32,
    process_uid: u32,
    package_uid: u32,
    package_name: *const std::os::raw::c_char,
    process_name: *const std::os::raw::c_char,
    cookie: *mut c_void,
) {
    // SAFETY: This function must only called by the C API with the cookie we provided.
    let callbacks = unsafe { get_callbacks(cookie) };
    // SAFETY: The C API guarantees that package_name and process_name are valid, non-null C strings.
    let (package_name_str, process_name_str) = unsafe {
        (
            CStr::from_ptr(package_name).to_str().unwrap_or_default(),
            CStr::from_ptr(process_name).to_str().unwrap_or_default(),
        )
    };
    callbacks.on_process_started(pid, process_uid, package_uid, package_name_str, process_name_str);
}

/// # Safety
///
/// This function must only be called by the C ActivityManager API with the cookie that was
/// provided when creating the process observer.
unsafe extern "C" fn on_foreground_activities_changed_trampoline(
    pid: i32,
    uid: u32,
    state: AActivityManager_ForegroundActivitiesState,
    cookie: *mut c_void,
) {
    // SAFETY: This function must only called by the C API with the cookie we provided.
    let callbacks = unsafe { get_callbacks(cookie) };
    let state = if state == 1 {
        ForegroundActivitiesState::HasForegroundActivities
    } else {
        ForegroundActivitiesState::NoForegroundActivities
    };
    callbacks.on_foreground_activities_changed(pid, uid, state);
}

/// # Safety
///
/// This function must only be called by the C ActivityManager API with the cookie that was
/// provided when creating the process observer.
unsafe extern "C" fn on_foreground_services_changed_trampoline(
    pid: i32,
    uid: u32,
    service_types: i32,
    cookie: *mut c_void,
) {
    // SAFETY: This function must only called by the C API with the cookie we provided.
    let callbacks = unsafe { get_callbacks(cookie) };
    callbacks.on_foreground_services_changed(pid, uid, service_types);
}

/// # Safety
///
/// This function must only be called by the C ActivityManager API with the cookie that was
/// provided when creating the process observer.
unsafe extern "C" fn on_process_died_trampoline(pid: i32, uid: u32, cookie: *mut c_void) {
    // SAFETY: This function must only called by the C API with the cookie we provided.
    let callbacks = unsafe { get_callbacks(cookie) };
    callbacks.on_process_died(pid, uid);
}
