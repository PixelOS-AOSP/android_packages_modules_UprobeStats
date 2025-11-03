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
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_SCALED_INSTRUMENTATION;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_SNAPSHOT;

import static com.android.uprobestats.UprobeStatsTestSetup.configureStatsDAndStartUprobeStats;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

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

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class UprobeStatsTestRust extends BaseHostJUnit4Test {
    private static final String BITMAP_ALLOCATION_CONFIG = "bitmap.textproto";
    private static final String BITMAP_ALLOCATION_SNAPSHOT_CONFIG = "bitmap_snapshot.textproto";
    private static final String BITMAP_TESTAPP_PACKAGE_NAME = "com.android.uprobestats.bitmap";
    private static final String BINDER_TRANSACTION_CONFIG = "binder.textproto";

    @Rule(order = 0)
    public final CheckFlagsRule mCheckFlagsRule =
            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);

    @Rule(order = 1)
    public final UprobeStatsTestRule mUprobeStatsTestRule =
            new UprobeStatsTestRule(this::getDevice);

    @Test
    @RequiresFlagsEnabled({
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2,
        FLAG_ENABLE_BITMAP_INSTRUMENTATION,
    })
    public void bitmapAllocation() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        final int uid = DeviceUtils.getAppUid(getDevice(), BITMAP_TESTAPP_PACKAGE_NAME);

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                BITMAP_ALLOCATION_CONFIG,
                UprobestatsExtensionAtoms.ANDROID_GRAPHICS_BITMAP_ALLOCATED_FIELD_NUMBER);

        try (AutoCloseable a =
                DeviceUtils.withActivity(
                        getDevice(),
                        BITMAP_TESTAPP_PACKAGE_NAME,
                        "BitmapTestActivity",
                        "action",
                        "action.lmk")) {

            // Allow UprobeStats/StatsD time to collect metric
            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

            // Wait until the uprobestats process exits.
            waitForUprobeStatsToExit(95);

            // See if the atom made it
            List<StatsLog.EventMetricData> data =
                    ReportUtils.getEventMetricDataList(
                            getDevice(), mUprobeStatsTestRule.getRegistry());
            assertThat(data.size()).isGreaterThan(0);
            boolean anyMatch =
                    data.stream()
                            .map(StatsLog.EventMetricData::getAtom)
                            .filter(
                                    atom ->
                                            atom.hasExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocated))
                            .map(
                                    atom ->
                                            atom.getExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocated))
                            .anyMatch(
                                    reported ->
                                            reported.getWidth() == 100
                                                    && reported.getHeight() == 100
                                                    && reported.getUid() == uid);
            assertThat(anyMatch).isTrue();
        }
    }

    private void waitForUprobeStatsToExit(int timeoutSeconds)
            throws TimeoutException, DeviceNotAvailableException {
        long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() - startTime < TimeUnit.SECONDS.toMillis(timeoutSeconds)) {
            String pid = getDevice().executeShellCommand("pidof uprobestats");
            if (pid.isEmpty() || !pid.trim().matches("\\d+")) {
                return;
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TimeoutException("Interrupted while waiting for uprobestats to exit");
            }
        }
        throw new TimeoutException("Timeout waiting for uprobestats to exit");
    }

    @Test
    @RequiresFlagsEnabled({
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2,
        FLAG_ENABLE_BITMAP_INSTRUMENTATION,
        FLAG_ENABLE_BITMAP_SNAPSHOT,
    })
    public void bitmapAllocationSnapshot() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        final int uid = DeviceUtils.getAppUid(getDevice(), BITMAP_TESTAPP_PACKAGE_NAME);

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                BITMAP_ALLOCATION_SNAPSHOT_CONFIG,
                UprobestatsExtensionAtoms.ANDROID_GRAPHICS_BITMAP_ALLOCATION_SNAPSHOT_FIELD_NUMBER);

        try (AutoCloseable a =
                DeviceUtils.withActivity(
                        getDevice(),
                        BITMAP_TESTAPP_PACKAGE_NAME,
                        "BitmapTestActivity",
                        "action",
                        "action.lmk")) {

            // Allow UprobeStats/StatsD time to collect metric
            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

            getDevice().executeShellCommand("dumpsys meminfo " + "com.android.uprobestats.bitmap");

            // Wait until the uprobestats process exits.
            waitForUprobeStatsToExit(95);

            // See if the atom made it
            List<StatsLog.EventMetricData> data =
                    ReportUtils.getEventMetricDataList(
                            getDevice(), mUprobeStatsTestRule.getRegistry());
            assertThat(data.size()).isGreaterThan(0);
            Stream<AndroidGraphicsBitmapAllocationSnapshot> randomSampleSnapshot =
                    data.stream()
                            .map(StatsLog.EventMetricData::getAtom)
                            .filter(
                                    atom ->
                                            atom.hasExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocationSnapshot))
                            .map(
                                    atom ->
                                            atom.getExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocationSnapshot))
                            .filter(
                                    reported ->
                                            reported.getSnapshotType()
                                                    == AndroidGraphicsBitmapAllocationSnapshot
                                                            .SnapshotType
                                                            .SNAPSHOT_TYPE_RANDOM_SAMPLE);
            assertThat(
                            randomSampleSnapshot
                                    .filter(
                                            reported ->
                                                    reported.getWidth() == 48
                                                            && reported.getHeight() == 48
                                                            && reported.getUid() == uid)
                                    .count())
                    .isEqualTo(1);
            List<AndroidGraphicsBitmapAllocationSnapshot> maxAllocationSizeSnapshot =
                    data.stream()
                            .map(StatsLog.EventMetricData::getAtom)
                            .filter(
                                    atom ->
                                            atom.hasExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocationSnapshot))
                            .map(
                                    atom ->
                                            atom.getExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocationSnapshot))
                            .filter(
                                    reported ->
                                            reported.getSnapshotType()
                                                    == AndroidGraphicsBitmapAllocationSnapshot
                                                            .SnapshotType
                                                            .SNAPSHOT_TYPE_MAX_ALLOCATION_SIZE)
                            .filter(
                                    reported ->
                                            reported.getWidth() == 48
                                                    && reported.getHeight() == 48
                                                    && reported.getUid() == uid)
                            .collect(Collectors.toList());

            assertThat(maxAllocationSizeSnapshot.size()).isEqualTo(2);
            assertThat(maxAllocationSizeSnapshot.get(0).getActivityName())
                    .isEqualTo("com.android.uprobestats.bitmap.BitmapTestActivity");
        }
    }

    @Test
    @RequiresFlagsEnabled({
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2,
        FLAG_ENABLE_BITMAP_INSTRUMENTATION,
        FLAG_ENABLE_BITMAP_SNAPSHOT,
        FLAG_ENABLE_BITMAP_SCALED_INSTRUMENTATION,
    })
    public void bitmapAllocationScaled() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        final int uid = DeviceUtils.getAppUid(getDevice(), BITMAP_TESTAPP_PACKAGE_NAME);

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                BITMAP_ALLOCATION_SNAPSHOT_CONFIG,
                UprobestatsExtensionAtoms.ANDROID_GRAPHICS_BITMAP_SCALED_FIELD_NUMBER);

        try (AutoCloseable a =
                DeviceUtils.withActivity(
                        getDevice(),
                        BITMAP_TESTAPP_PACKAGE_NAME,
                        "BitmapTestActivity",
                        "action",
                        "action.lmk")) {

            // Allow UprobeStats/StatsD time to collect metric
            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

            getDevice().executeShellCommand("dumpsys meminfo " + "com.android.uprobestats.bitmap");

            // Wait until the uprobestats process exits.
            waitForUprobeStatsToExit(95);

            // See if the atom made it
            List<StatsLog.EventMetricData> data =
                    ReportUtils.getEventMetricDataList(
                            getDevice(), mUprobeStatsTestRule.getRegistry());
            assertThat(data.size()).isGreaterThan(0);
            boolean anyMatch =
                    data.stream()
                            .map(StatsLog.EventMetricData::getAtom)
                            .filter(
                                    atom ->
                                            atom.hasExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapScaled))
                            .map(
                                    atom ->
                                            atom.getExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapScaled))
                            .anyMatch(
                                    reported ->
                                            reported.getScaledWidth() == 321
                                                    && reported.getScaledHeight() == 321
                                                    && reported.getOriginalWidth() == 48
                                                    && reported.getOriginalHeight() == 48
                                                    && reported.getUid() == uid);
            assertThat(anyMatch).isTrue();
        }
    }

    @Test
    @RequiresFlagsEnabled(FLAG_ENABLE_BINDER_TRANSACTION)
    public void binderTransaction() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                BINDER_TRANSACTION_CONFIG,
                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);

        // Should trigger IBatteryStats#noteStartSensor
        DeviceUtils.turnScreenOff(getDevice());
        DeviceUtils.turnScreenOn(getDevice());

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
        assertThat(reported.getFirstField()).isGreaterThan(0);
    }
}
