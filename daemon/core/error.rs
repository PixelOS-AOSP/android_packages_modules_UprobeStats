/*
 * Copyright (C) 2026 The Android Open Source Project
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

//! Specific errors for UprobeStats.

/// Specific error variants for UprobeStats.
#[derive(thiserror::Error, Debug)]
pub enum UprobeStatsError {
    /// The BPF program itself reported an error state.
    /// The value is a hint from the BPF program itself about what went wrong.
    #[error("BPF program error: {0}")]
    BpfProgramError(i64),

    /// Data received from BPF is malformed or logically invalid.
    /// The value is a hint from the BPF handler about what went wrong.
    #[error("BPF data invalid: {0}")]
    BpfDataInvalid(i64),
}
