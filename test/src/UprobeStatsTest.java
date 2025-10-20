/*
 * Copyright (C) 2024 The Android Open Source Project
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

import static android.uprobestats.flags.Flags.FLAG_ENABLE_UPROBESTATS;
import static android.uprobestats.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS;

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

import java.util.List;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class UprobeStatsTest extends BaseHostJUnit4Test {

    private static final String BATTERY_STATS_CONFIG_OATDUMP =
            "test_bss_setBatteryState_oatdump.textproto";
    private static final String BATTERY_STATS_CONFIG_ART =
            "test_bss_setBatteryState_artApi.textproto";
    private static final String TEMP_ALLOWLIST_CONFIG =
            "test_updateDeviceIdleTempAllowlist.textproto";
    private static final String SET_TEMP_ALLOWLIST_STATE_CONFIG =
            "test_setUidTempAllowlistStateLSP.textproto";
    private static final String CONFIG_NAME = "config";
    private static final String CMD_SETPROP_UPROBESTATS = "setprop ctl.start uprobestats";
    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";

    @Rule(order = 0)
    public final CheckFlagsRule mCheckFlagsRule =
            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);

    @Rule(order = 1)
    public final UprobeStatsTestRule mUprobeStatsTestRule = new UprobeStatsTestRule(this::getDevice);

    @Test
    @RequiresFlagsDisabled(FLAG_EXECUTABLE_METHOD_FILE_OFFSETS)
    @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
    public void batteryStats_oatdump() throws Exception {
        batteryStats(BATTERY_STATS_CONFIG_OATDUMP);
    }

    @Test
    @RequiresFlagsEnabled({
        FLAG_ENABLE_UPROBESTATS,
        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS
    })
    public void batteryStats_artApi() throws Exception {
        batteryStats(BATTERY_STATS_CONFIG_ART);
    }

    @Test
    @Ignore
    @RequiresFlagsEnabled({
        FLAG_ENABLE_UPROBESTATS,
        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS
    })
    public void batteryStats_oatdump_fallback() throws Exception {
        batteryStats(BATTERY_STATS_CONFIG_OATDUMP);
    }

    private void batteryStats(String config) throws Exception {
        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                config,
                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);

        // Set charging state, which should invoke BatteryStatsService#setBatteryState.
        // Assumptions:
        //   - uprobestats flag is enabled
        //   - userdebug build
        //   - said method is precompiled (specified in frameworks/base/services/art-profile)
        // If this test fails, check those assumptions first.
        DeviceUtils.setChargingState(getDevice(), 2);
        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), mUprobeStatsTestRule.getRegistry());
        assertThat(data.size()).isEqualTo(1);
        TestUprobeStatsAtomReported reported =
                data.get(0)
                        .getAtom()
                        .getExtension(UprobestatsExtensionAtoms.testUprobestatsAtomReported);
        assertThat(reported.getFirstField()).isEqualTo(1);
        assertThat(reported.getSecondField()).isGreaterThan(0);
        assertThat(reported.getThirdField()).isEqualTo(0);
    }

    @Test
    @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
    public void updateDeviceIdleTempAllowlist() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                TEMP_ALLOWLIST_CONFIG,
                FrameworkExtensionAtoms.DEVICE_IDLE_TEMP_ALLOWLIST_UPDATED_FIELD_NUMBER);

        // Set tempallowlist
        getDevice().executeShellCommand("cmd deviceidle tempwhitelist com.google.android.tts");
        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), mUprobeStatsTestRule.getRegistry());
        assertThat(data.size()).isGreaterThan(0);
        boolean anyMatch =
                data.stream()
                        .map(StatsLog.EventMetricData::getAtom)
                        .filter(
                                atom ->
                                        atom.hasExtension(
                                                FrameworkExtensionAtoms
                                                        .deviceIdleTempAllowlistUpdated))
                        .map(
                                atom ->
                                        atom.getExtension(
                                                FrameworkExtensionAtoms
                                                        .deviceIdleTempAllowlistUpdated))
                        .anyMatch(reported -> reported.getReason().equals("shell"));
        assertThat(anyMatch).isTrue();
    }

    @Test
    @Ignore
    @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
    public void setUidTempAllowlistState() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                SET_TEMP_ALLOWLIST_STATE_CONFIG,
                FrameworkExtensionAtoms.POWER_SAVE_TEMP_ALLOWLIST_CHANGED_FIELD_NUMBER);

        // Set tempallowlist
        getDevice().executeShellCommand("cmd deviceidle tempwhitelist com.google.android.tts");
        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), mUprobeStatsTestRule.getRegistry());
        assertThat(data.size()).isGreaterThan(0);
        boolean anyMatch =
                data.stream()
                        .map(StatsLog.EventMetricData::getAtom)
                        .filter(
                                atom ->
                                        atom.hasExtension(
                                                FrameworkExtensionAtoms
                                                        .powerSaveTempAllowlistChanged))
                        .map(
                                atom ->
                                        atom.getExtension(
                                                FrameworkExtensionAtoms
                                                        .powerSaveTempAllowlistChanged))
                        .anyMatch(
                                reported -> reported.getUid() > 0 && reported.getAddToAllowlist());
        assertThat(anyMatch).isTrue();
    }
}
