//! Bindings for AStatsEvent NDK API.
use anyhow::Result;
use statssocket_bindgen::{
    AStatsEvent as AStatsEvent_raw, AStatsEvent_addBoolAnnotation, AStatsEvent_obtain,
    AStatsEvent_release, AStatsEvent_setAtomId, AStatsEvent_write, AStatsEvent_writeBool,
    AStatsEvent_writeInt32, AStatsEvent_writeInt32Array, AStatsEvent_writeInt64,
    AStatsEvent_writeInt64Array, AStatsEvent_writeString,
};
use std::ptr::NonNull;

mod c_string;
use c_string::c_string;

pub use statssocket_bindgen::AnnotationIds_ASTATSLOG_ANNOTATION_ID_IS_UID;

/// Safe wrapper around raw `AStatsEvent`.
pub struct AStatsEvent {
    event_raw: NonNull<AStatsEvent_raw>,
}

impl AStatsEvent {
    /// Constructor for an `AStatsEvent` with the given `atom_id`.
    pub fn new(atom_id: u32) -> Self {
        // SAFETY: trivially safe
        let event_raw = unsafe {
            let event = AStatsEvent_obtain();
            AStatsEvent_setAtomId(event, atom_id);
            event
        };
        Self { event_raw: NonNull::new(event_raw).unwrap() }
    }

    /// Writes a `bool` value to the `AStatsEvent`.
    pub fn write_bool(&mut self, value: bool) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_writeBool(self.as_ptr(), value) };
    }

    /// Writes an `i32` value to the `AStatsEvent`.
    pub fn write_int32(&mut self, value: i32) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_writeInt32(self.as_ptr(), value) };
    }

    /// Writes an `i64` value to the `AStatsEvent`.
    pub fn write_int64(&mut self, value: i64) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_writeInt64(self.as_ptr(), value) };
    }

    /// Writes a `str` value to the `AStatsEvent`.
    pub fn write_string(&mut self, value: &str) -> Result<()> {
        let value = c_string(value)?;
        // SAFETY:
        // - `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        // - we've just created a valid &CStr from `value`.
        unsafe { AStatsEvent_writeString(self.as_ptr(), value.as_ptr()) };
        Ok(())
    }

    /// Writes an `i32` slice to the `AStatsEvent`.
    pub fn write_int32_slice(&mut self, value: &[i32]) {
        // SAFETY:
        // - `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        // - `value` is a non-null slice of `i32` values that outlive the function call.
        unsafe { AStatsEvent_writeInt32Array(self.as_ptr(), value.as_ptr(), value.len()) };
    }

    /// Writes an `i64` slice to the `AStatsEvent`.
    pub fn write_int64_slice(&mut self, value: &[i64]) {
        // SAFETY:
        // - `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        // - `value` is a non-null slice of `i64` values that outlive the function call.
        unsafe { AStatsEvent_writeInt64Array(self.as_ptr(), value.as_ptr(), value.len()) };
    }

    /// Adds a boolean annotation to the previous field written.
    pub fn add_bool_annotation(&mut self, annotation_id: u8, value: bool) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_addBoolAnnotation(self.as_ptr(), annotation_id, value) };
    }

    /// Write the event to statsd.
    pub fn write(mut self) {
        // SAFETY: `self` is an owned reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_write(self.as_ptr()) };
    }

    fn as_ptr(&mut self) -> *mut AStatsEvent_raw {
        self.event_raw.as_ptr()
    }
}

impl Drop for AStatsEvent {
    fn drop(&mut self) {
        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
        unsafe { AStatsEvent_release(self.as_ptr()) };
    }
}
