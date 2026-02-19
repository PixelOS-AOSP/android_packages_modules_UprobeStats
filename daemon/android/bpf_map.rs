//! Abstraction for userspace to access BPF maps.
use anyhow::Result;
use std::marker::PhantomData;
use uprobestats_bpf::{
    bpf_map_close, bpf_map_delete_elem, bpf_map_get_first_key, bpf_map_lookup_elem,
    bpf_map_open_exclusive_rw, bpf_map_update_elem, UpdateMapElemFlags,
};
use uprobestats_bpf_bindgen::BpfMapHandle;
use uprobestats_core::bpf_map::BpfMap;

pub mod binder_transaction;

/// Provides safe access to a BPF map.
///
/// This struct holds a handle to the BPF map, ensuring that it is
/// properly closed when the accessor goes out of scope.
pub struct BpfMapAccessor<M> {
    handle: *mut BpfMapHandle,
    _map: PhantomData<M>,
}

impl<M: BpfMap> BpfMapAccessor<M> {
    /// Creates a new `BpfMapAccessor`.
    ///
    /// This function opens the BPF map at the path specified by `M::MAP_PATH`
    /// and returns a new `BpfMapAccessor` that can be used to interact with it.
    pub fn new() -> Result<Self> {
        let handle = bpf_map_open_exclusive_rw(M::MAP_PATH)?;
        Ok(Self { handle, _map: PhantomData })
    }

    /// Puts a key-value pair into the map.
    ///
    /// Insert/Update/Upsert behavior determined by `UpdateMapElemFlags`.
    pub fn put(&self, key: &M::K, value: &M::V, flags: UpdateMapElemFlags) -> Result<()> {
        // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
        unsafe {
            bpf_map_update_elem::<M::CKey, M::CValue>(
                self.handle,
                M::to_c_key(key),
                M::to_c_value(value),
                flags,
            )
        }
    }

    /// Gets a value from the map for a given key.
    ///
    /// Returns `Ok(Some(value))` if the key exists, and `Ok(None)` if it does not.
    pub fn get(&self, key: &M::K) -> Result<Option<M::V>> {
        let found =
            // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
            unsafe { bpf_map_lookup_elem::<M::CKey, M::CValue>(self.handle, M::to_c_key(key)) }?;
        Ok(found.map(|v| M::from_c_value(&v)))
    }

    /// Gets the first key in the map.
    ///
    /// This is useful for iterating over the map's contents.
    ///
    /// Returns `Ok(Some(key))` if the map is not empty, and `Ok(None)` if it is.
    pub fn get_first_key(&self) -> Result<Option<M::K>> {
        // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
        let found = unsafe { bpf_map_get_first_key::<M::CKey>(self.handle) }?;
        Ok(found.map(|k| M::from_c_key(&k)))
    }

    /// Deletes a key-value pair from the map.
    ///
    /// Returns `Ok(true)` if the element was deleted, `Ok(false)` if it did not exist.
    pub fn delete(&self, key: &M::K) -> Result<bool> {
        // SAFETY: safe by the constraints guaranteed by the implementor of `BpfMap`.
        unsafe { bpf_map_delete_elem::<M::CKey>(self.handle, M::to_c_key(key)) }
    }
}

impl<M> Drop for BpfMapAccessor<M> {
    fn drop(&mut self) {
        // SAFETY: The handle is guaranteed to be valid and is not used after this.
        unsafe { bpf_map_close(self.handle) };
    }
}
