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

package com.android.uprobestats;

import android.cts.statsdatom.lib.AtomTestUtils;

import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.util.RunUtil;

import java.util.function.Supplier;

public class UprobeStatsTestRule extends AbstractUprobeStatsTestRule {
    public UprobeStatsTestRule(Supplier<ITestDevice> deviceSupplier) {
        super(deviceSupplier);
    }

    @Override
    void initializeUprobeStats(ITestDevice device) throws Exception {
        device.deleteFile(CONFIG_DIR + CONFIG_NAME);
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
        device.executeShellCommand("killall uprobestats");
    }
}
