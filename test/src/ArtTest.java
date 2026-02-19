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

import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BINDER_TRANSACTION;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_INSTRUMENTATION;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_SNAPSHOT;
import static android.uprobestats.mainline.flags.Flags.FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import static com.android.uprobestats.UprobeStatsTestSetup.configureStatsDAndStartUprobeStats;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.DeviceUtils;
import android.cts.statsdatom.lib.ReportUtils;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.host.HostFlagsValueProvider;

import com.android.compatibility.common.util.CpuFeatures;
import com.android.os.StatsLog;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.RunUtil;
import com.android.uprobestats.TestUprobeStatsAtomReported;
import com.android.uprobestats.UprobestatsExtensionAtoms;

import com.google.protobuf.ExtensionRegistry;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Tests that UprobeStats can instrument both AOT and JIT compiled java code via integration with
 * ART. This test is currently only run on userdebug devices, as it relies on code that is only
 * included in userdebug builds, as we conditionally include code that is exclusively used for this
 * test.
 */
@RunWith(DeviceJUnit4ClassRunner.class)
public class ArtTest extends BaseHostJUnit4Test {
    private static final String JIT_CONFIG = "atms_startActivityAsUser.textproto";
    private static final String AOT_CONFIG = "ams_updateDeviceIdletempAllowlist.textproto";

    @Rule(order = 0)
    public final CheckFlagsRule mCheckFlagsRule =
            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);

    @Rule(order = 1)
    public final UprobeStatsTestRule mUprobeStatsTestRule = new UprobeStatsTestRule(this::getDevice);


    // hash of the string "com.android.uprobestats.disruptive", which gets sent as a long to statsd
    static long COM_ANDROID_UPROBESTATS_DISRUPTIVE_PACKAGE_NAME_HASH = -576996686495794312L;

    @Test
    @RequiresFlagsEnabled({
        com.android.art.rw.flags.Flags.FLAG_DYNAMIC_INSTRUMENTATION_METHOD_ENTRY_HOOK,
    })
    public void fetchValuesFromRegistersAndStack_jit() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                JIT_CONFIG,
                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);

        // Should trigger ActivityTaskManagerService#startActivityAsUser
        getDevice()
                .executeShellCommand(
                        "am start -n" + " com.android.uprobestats.disruptive/.TestActivity");

        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), mUprobeStatsTestRule.getRegistry());
        assertThat(data.size()).isGreaterThan(0);

        TestUprobeStatsAtomReported reported =
                data.get(0)
                        .getAtom()
                        .getExtension(UprobestatsExtensionAtoms.testUprobestatsAtomReported);
        assertThat(reported.getFirstField()).isEqualTo(1);
        assertThat(reported.getSecondField()).isEqualTo(-2);
        assertThat(reported.getThirdField())
                .isEqualTo(COM_ANDROID_UPROBESTATS_DISRUPTIVE_PACKAGE_NAME_HASH);
    }

    // hash of the string "shell", which gets sent as a long to statsd
    static long SHELL_HASH = -5667491721050574174L;
    static int REASON_CODE = 316;

    @Test
    public void fetchValuesFromRegistersAndStack_aot() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                AOT_CONFIG,
                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);

        // Set tempallowlist
        getDevice().executeShellCommand("cmd deviceidle tempwhitelist com.google.android.tts");
        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), mUprobeStatsTestRule.getRegistry());
        assertThat(data.size()).isGreaterThan(0);
        TestUprobeStatsAtomReported match =
                data.stream()
                        .map(StatsLog.EventMetricData::getAtom)
                        .filter(
                                atom ->
                                        atom.hasExtension(
                                                UprobestatsExtensionAtoms
                                                        .testUprobestatsAtomReported))
                        .map(
                                atom ->
                                        atom.getExtension(
                                                UprobestatsExtensionAtoms
                                                        .testUprobestatsAtomReported))
                        .findFirst()
                        .get();
        assertThat(match.getFirstField()).isEqualTo(1); // boolean true
        assertThat(match.getSecondField()).isEqualTo(REASON_CODE);
        assertThat(match.getThirdField()).isEqualTo(SHELL_HASH);
    }

    // TODO: b/445930395 - add tests for static methods and floating point arguments
}
