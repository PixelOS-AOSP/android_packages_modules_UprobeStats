//! Abstraction for userspace to read/write BPF maps.
use std::fmt::Debug;

/// Defines the static properties of a BPF map.
/// # Safety
///   - There must exist a BPF map at the path represented by `MAP_PATH`
///   - It must hold items with keys of type `CKey` and values of type `CValue`.
pub unsafe trait BpfMap {
    /// The path to the BPF map in the BPF file system.
    const MAP_PATH: &'static str;
    /// The Rust type for the map key.
    type K: Debug;
    /// The Rust type for the map value.
    type V: Debug;
    /// The C-compatible representation of the key.
    type CKey: Debug + Copy;
    /// The C-compatible representation of the value.
    type CValue: Debug + Copy;

    /// Converts a Rust key to its C representation.
    fn to_c_key(key: &Self::K) -> Self::CKey;
    /// Converts a Rust value to its C representation.
    fn to_c_value(value: &Self::V) -> Self::CValue;
    /// Converts a C value back to its Rust representation.
    fn from_c_value(value: &Self::CValue) -> Self::V;
    /// Converts a C key back to its Rust representation.
    fn from_c_key(key: &Self::CKey) -> Self::K;
}
