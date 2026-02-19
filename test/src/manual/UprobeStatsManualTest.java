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

import static com.android.uprobestats.UprobeStatsTestSetup.configureStatsDAndStartUprobeStats;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.DeviceUtils;
import android.cts.statsdatom.lib.ReportUtils;

import android.platform.test.annotations.RequiresFlagsDisabled;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.host.HostFlagsValueProvider;

import com.android.compatibility.common.util.CpuFeatures;
import com.android.os.StatsLog;
import com.android.os.framework.FrameworkExtensionAtoms;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.RunUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class UprobeStatsManualTest extends BaseHostJUnit4Test {
    @Rule
    public final UprobeStatsTestRule mUprobeStatsTestRule =
            new UprobeStatsTestRule(this::getDevice);

    @Test
    public void runConfig() throws Exception {
        String configName = System.getenv("UPROBESTATS_TEST_CONFIG");
        if (configName == null) {
            throw new AssertionError(
                    "UPROBESTATS_TEST_CONFIG is not set. Should be set to the name of the config"
                            + " file in the res/ directory, without the .textproto extension.");
        }
        int atomId = UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER;
        boolean expectAtom = false;
        String atomIdStr = System.getenv("UPROBESTATS_TEST_ATOM_ID");
        if (atomIdStr != null) {
            expectAtom = true;
            atomId = Integer.parseInt(atomIdStr);
        }
        configureStatsDAndStartUprobeStats(
                getClass(), getDevice(), configName + ".textproto", atomId);

        if (expectAtom) {
            String timeout = System.getenv("UPROBESTATS_TEST_TIMEOUT");
            long timeoutMillis = 30 * 1000;
            if (timeout != null) {
                timeoutMillis = Long.parseLong(timeout) * 1000;
            }
            RunUtil.getDefault().sleep(timeoutMillis);
            // See if the atom made it
            List<StatsLog.EventMetricData> data =
                    ReportUtils.getEventMetricDataList(
                            getDevice(), mUprobeStatsTestRule.getRegistry());
            assertThat(data.size()).isGreaterThan(0);
        }
    }

    private static final List<String> TEST_CONFIG_NAMES =
            Arrays.asList(
                    "binder",
                    "disruptive_app",
                    "runtime_permission",
                    "test_bss_setBatteryState_artApi",
                    "test_updateDeviceIdleTempAllowlist",
                    "bitmap_snapshot");

    // TODO(b/454898357): Replace with tests that actually assert that uprobestats handles
    // concurrent configs per requirements.
    @Test
    public void runAllConfigsInParralel() throws Exception {
        List<Thread> threads = new ArrayList<>();
        for (String configName : TEST_CONFIG_NAMES) {
            System.out.println("uprobestats: Starting config: " + configName);
            configureStatsDAndStartUprobeStats(
                    getClass(), getDevice(), configName + ".textproto", 1217);
        }
    }
}
