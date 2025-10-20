/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Functions to interact with BPF through C FFI.

use anyhow::{ensure, Result};
use std::{
    ffi::c_void,
    fmt::Debug,
    mem::MaybeUninit,
    os::fd::{FromRawFd, OwnedFd},
};
use uprobestats_bpf_bindgen::{
    bpfMapClose, bpfMapDeleteElem, bpfMapGetFirstKey, bpfMapLookupElem, bpfMapOpenExclusiveRW,
    bpfMapUpdateElem, bpfPerfEventOpen, pollRingBuf, BpfMapHandle,
};

mod c_string;
use c_string::c_string;

/// Polls the BPF ring buffer at the passed `map_path`, collecting any values
/// emitted within `timeout_ms` into a `Vec<T>`, where `T` is expected to be
/// the type written to the ring buffer by a corresponding eBPF program.
///
/// # Safety
///   - `T` matches the type that is written to the BPF ring buffer at `map_path`.
pub unsafe fn poll_ring_buf<T: Copy + Debug>(map_path: &str, timeout_ms: i32) -> Result<Vec<T>> {
    let map_path = c_string(map_path)?;
    let mut data: Vec<T> = Vec::new();
    let data_ptr = &mut data as *mut _ as *mut c_void;
    // SAFETY:
    // - `map_path` is a valid pointer by virtue of coming from a `CString`.
    // - caller has guaranteed that `T` is the right type, which we use to derive its size.
    // - `callback` is a valid function pointer defined below.
    // - `data_ptr` is a valid pointer from the `Vec::new` construction above.
    // - due to all of the above, `callback` will be called with a valid pointer to a `T` and a
    //   valid pointer to a `Vec<T>`, which is safe to mutate because we have an exclusive
    //   reference to the `Vec`.
    let result = unsafe {
        pollRingBuf(map_path.as_ptr(), timeout_ms, size_of::<T>(), Some(callback::<T>), data_ptr)
    };
    ensure!(result >= 0, "Failed to poll ring buffer. Error code: {}", result);
    Ok(data)
}

/// Callback function for `pollRingBuf`.
///
/// # Safety
///   - `value` must be a valid, non-null pointer to a value of type `T` written to the BPF ring buffer.
///   - `cookie` must be a valid, non-null pointer to a `Vec<T>`.
unsafe extern "C" fn callback<T: Copy + Debug>(value: *const c_void, cookie: *mut c_void) {
    let value = value as *const T;
    // SAFETY: the caller has guaranteed a valid pointer to a `T`, which is `Copy`, so we can get an owned value.
    let value = unsafe { *value };
    // SAFETY: the caller has guaranteed a is a valid pointer to a `Vec<T>`.
    let cookie: &mut Vec<T> = unsafe { &mut *(cookie as *mut Vec<T>) };
    cookie.push(value);
}

/// Attaches the eBPF program specified at `bpf_program_path`
/// to the user space program for process `pid`, located by `filename` and `offset`.
/// Returns an `OwnedFd` that represents the perf event, and will be closed when the
/// `OwnedFd` is dropped.
pub fn bpf_perf_event_open(
    filename: String,
    offset: i32,
    pid: i32,
    bpf_program_path: String,
) -> Result<OwnedFd> {
    let filename = c_string(&filename)?;
    let bpf_program_path = c_string(&bpf_program_path)?;
    // SAFETY: `filename` and `bpf_program_path` are valid by virtue of being derived from a `CString`.
    let fd = unsafe { bpfPerfEventOpen(filename.as_ptr(), offset, pid, bpf_program_path.as_ptr()) };
    ensure!(fd >= 0, "Failed to attach BPF. Error code: {}", fd);
    // SAFETY: `bpfPerfEventOpen` returns a valid file descriptor on success. We have checked that the operation was successful.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Flags for `bpf_map_update_elem`.
#[derive(Clone, Copy)]
#[repr(u64)]
pub enum UpdateMapElemFlags {
    /// Create a new element or updates an existing one.
    Upsert = 0, // BPF_ANY
    /// Insert the map element if and only it does not already exist.
    Insert = 1, // BPF_NOEXIST,
    /// Update an element if and only if it already exists.
    Update = 2, // BPF_EXIST,
}

/// Opens a BPF map and returns an owned handle to its underlying file descriptor,
/// on which an exclusive R/W lock has been obtained.
pub fn bpf_map_open_exclusive_rw(path: &str) -> Result<*mut BpfMapHandle> {
    let path = c_string(path)?;
    let mut handle: *mut BpfMapHandle = core::ptr::null_mut();
    // SAFETY: `path` is valid, and we provide a valid pointer for the out-parameter.
    let res = unsafe { bpfMapOpenExclusiveRW(path.as_ptr(), &mut handle) };
    ensure!(res == 0, "Failed to open BPF map at {}: error {}", path.to_str()?, res);
    Ok(handle)
}

/// Closes a BPF map handle.
/// # Safety
///   - `handle` must be a valid pointer returned by `bpf_map_open_exclusive_rw`.
///   - `handle` must not be used after this function is called.
pub unsafe fn bpf_map_close(handle: *mut BpfMapHandle) {
    // SAFETY: Caller guarantees the handle is valid and will not be used again.
    unsafe { bpfMapClose(handle) };
}

/// Writes a value to the BPF map.
/// # Safety
///   - 'handle' is a valid pointer acquired via `bpf_map_open_exclusive_rw`.
///   - `K` and `V` must be the types expected by the BPF map.
pub unsafe fn bpf_map_update_elem<K, V>(
    handle: *mut BpfMapHandle,
    key: K,
    value: V,
    flags: UpdateMapElemFlags,
) -> Result<()> {
    let key_ptr = &key as *const _ as *const c_void;
    let value_ptr = &value as *const _ as *const c_void;
    let res =
        // SAFETY:
        // - `handle` us guaranteed by the caller to be a valid pointer.
        // - `key_ptr` and `value_ptr` are valid pointers to `K` and `V`, and outlive the call.
        unsafe { bpfMapUpdateElem(handle, key_ptr, value_ptr, flags as u64) };
    ensure!(res == 0, "Failed to write to BPF map. Error code: {}", res);
    Ok(())
}

/// Looks up an element in the BPF map.
/// # Safety
///   - 'handle' is a valid pointer acquired via `bpf_map_open_exclusive_rw`.
///   - `K` and `V` must be the types expected by the BPF map.
pub unsafe fn bpf_map_lookup_elem<K, V>(handle: *mut BpfMapHandle, key: K) -> Result<Option<V>> {
    let key_ptr = &key as *const _ as *const c_void;
    let mut value = MaybeUninit::<V>::uninit();
    let value_ptr = value.as_mut_ptr() as *mut c_void;
    let res =
        // SAFETY:
        // - `handle` us guaranteed by the caller to be a valid pointer.
        // - `key_ptr` and `value_ptr` are valid pointers to `K` and `V`, and outlive the call.
        unsafe { bpfMapLookupElem(handle, key_ptr, value_ptr) };

    if res == -libc::ENOENT {
        return Ok(None);
    }
    ensure!(res == 0, "Failed to lookup BPF map element. Error code: {}", res);
    // SAFETY: `bpfMapLookupElem` initializes `value` on success.
    Ok(Some(unsafe { value.assume_init() }))
}

/// Gets the first key in the BPF map.
/// # Safety
///   - 'handle' is a valid pointer acquired via `bpf_map_open_exclusive_rw`.
///   - `K` must be the key type expected by the BPF map.
pub unsafe fn bpf_map_get_first_key<K>(handle: *mut BpfMapHandle) -> Result<Option<K>> {
    let mut key = MaybeUninit::<K>::uninit();
    let key_ptr = key.as_mut_ptr() as *mut c_void;
    let res =
        // SAFETY:
        // - `handle` us guaranteed by the caller to be a valid pointer.
        // - `key_ptr` is a valid pointer to `K`, and outlives the call.
        unsafe { bpfMapGetFirstKey(handle, key_ptr) };

    if res == -libc::ENOENT {
        return Ok(None);
    }
    ensure!(res == 0, "Failed to get first BPF map key. Error code: {}", res);
    // SAFETY: `bpfMapGetFirstKey` initializes `key` on success.
    Ok(Some(unsafe { key.assume_init() }))
}

/// Deletes an element in the BPF map.
/// # Safety
///   - `K` must be the key type expected by the BPF map.
pub unsafe fn bpf_map_delete_elem<K>(handle: *mut BpfMapHandle, key: K) -> Result<bool> {
    let key_ptr = &key as *const _ as *const c_void;
    let res =
        // SAFETY:
        // - `handle` us guaranteed by the caller to be a valid pointer.
        // - `key_ptr` is a valid pointer to `K`, and outlives the call.
        unsafe { bpfMapDeleteElem(handle, key_ptr) };

    if res == -libc::ENOENT {
        return Ok(false);
    }
    ensure!(res == 0, "Failed to delete BPF map element. Error code: {}", res);
    Ok(true)
}
