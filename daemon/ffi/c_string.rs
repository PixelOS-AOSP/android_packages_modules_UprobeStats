//! Utils for working with C strings, returning `anyhow::Result` on failure.
use anyhow::{Context, Result};
use std::ffi::CString;

/// Create a `CString` from a `&str`, returning an `anyhow::Result` on failure.
pub fn c_string(string: &str) -> Result<CString> {
    CString::new(string.as_bytes()).context("Failed to create CString")
}
