
// Copyright (C) 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.android.uprobestats;

/**
 * Service for managing UprobeStats tasks.
 */
interface IUprobeStatsService {
    const int FAILURE_CONFIG_RESOLUTION = 1;
    const int FAILURE_CONFLICT = 2;

    /**
     * Starts uprobestats with the given config.
     */
    void startTasks(in byte[] config);
}
