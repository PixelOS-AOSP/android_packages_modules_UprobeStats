//! Utils for working with foreign strings.
use anyhow::Result;
use std::ffi::CStr;
use zerocopy::{Immutable, IntoBytes};

/// Create a `&str` from a `&[u8]` of bytes, returning an `anyhow::Result` on failure.
pub fn bytes_as_str(bytes: &(impl IntoBytes + Immutable)) -> Result<&str> {
    let string = CStr::from_bytes_until_nul(bytes.as_bytes())?;
    Ok(string.to_str()?)
}

/// Identical to `bytes_as_str`, but returns an error if the string is empty.
pub fn bytes_as_nonempty_str(bytes: &(impl IntoBytes + Immutable)) -> Result<&str> {
    let string = bytes_as_str(bytes)?;
    if string.is_empty() {
        Err(anyhow::anyhow!("bytes_as_str returned an unexpected empty string"))
    } else {
        Ok(string)
    }
}
