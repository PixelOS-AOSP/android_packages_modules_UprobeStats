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

import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BINDER_TRANSACTION;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_INSTRUMENTATION;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_SCALED_INSTRUMENTATION;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_SNAPSHOT;
import static android.uprobestats.mainline.flags.Flags.FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.DeviceUtils;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.host.HostFlagsValueProvider;

import com.android.compatibility.common.util.CpuFeatures;
import com.android.os.framework.FrameworkExtensionAtoms;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.RunUtil;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RunWith(DeviceJUnit4ClassRunner.class)
public class UprobeStatsTest extends BaseHostJUnit4Test {

    private static final int CINNAMON_BUN = 37; // android.os.Build.VERSION_CODES.CINNAMON_BUN

    private static final String BATTERY_STATS_CONFIG_ART =
            "test_bss_setBatteryState_artApi.textproto";
    private static final String TEMP_ALLOWLIST_CONFIG =
            "test_updateDeviceIdleTempAllowlist.textproto";
    private static final String SET_TEMP_ALLOWLIST_STATE_CONFIG =
            "test_setUidTempAllowlistStateLSP.textproto";
    private static final String CONFIG_NAME = "config";
    private static final String CMD_SETPROP_UPROBESTATS = "setprop ctl.start uprobestats";
    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";

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
    public void batteryStats_artApi() throws Exception {
        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
                BATTERY_STATS_CONFIG_ART,
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
        TestUprobeStatsAtomReported reported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(UprobestatsExtensionAtoms.testUprobestatsAtomReported)
                        .findFirst()
                        .get();
        assertThat(reported.getFirstField()).isEqualTo(0);
        assertThat(reported.getSecondField()).isGreaterThan(0);
        assertThat(reported.getThirdField()).isEqualTo(0);
    }

    @Test
    public void updateDeviceIdleTempAllowlist() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
                TEMP_ALLOWLIST_CONFIG,
                FrameworkExtensionAtoms.DEVICE_IDLE_TEMP_ALLOWLIST_UPDATED_FIELD_NUMBER);

        // Set tempallowlist
        getDevice().executeShellCommand("cmd deviceidle tempwhitelist com.google.android.tts");
        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        boolean anyMatch =
                mUprobeStatsTestRule
                        .getExtensionAtoms(FrameworkExtensionAtoms.deviceIdleTempAllowlistUpdated)
                        .anyMatch(reported -> reported.getReason().equals("shell"));
        assertThat(anyMatch).isTrue();
    }

    @Test
    @RequiresFlagsEnabled({
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2,
        FLAG_ENABLE_BITMAP_INSTRUMENTATION,
    })
    public void bitmapAllocation() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        final int uid = DeviceUtils.getAppUid(getDevice(), BITMAP_TESTAPP_PACKAGE_NAME);

        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
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
            mUprobeStatsTestRule.waitForUprobeStatsToExit(95, TimeUnit.SECONDS);

            // See if the atom made it
            boolean anyMatch =
                    mUprobeStatsTestRule
                            .getExtensionAtoms(
                                    UprobestatsExtensionAtoms.androidGraphicsBitmapAllocated)
                            .anyMatch(
                                    reported ->
                                            reported.getWidth() == 100
                                                    && reported.getHeight() == 100
                                                    && reported.getUid() == uid);
            assertThat(anyMatch).isTrue();
        }

        mUprobeStatsTestRule.assertSelfMetricsReported(
                UprobeStatsBpfProgram.PROG_BITMAP_ALLOCATION_UPROBE_BITMAP_CREATION_FOR_SNAPSHOT,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_BITMAP_ALLOCATION_OUTPUT);
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

        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
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
            mUprobeStatsTestRule.waitForUprobeStatsToExit(95, TimeUnit.SECONDS);

            // See if the atom made it
            Stream<AndroidGraphicsBitmapAllocationSnapshot> randomSampleSnapshot =
                    mUprobeStatsTestRule
                            .getExtensionAtoms(
                                    UprobestatsExtensionAtoms
                                            .androidGraphicsBitmapAllocationSnapshot)
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
                    mUprobeStatsTestRule
                            .getExtensionAtoms(
                                    UprobestatsExtensionAtoms
                                            .androidGraphicsBitmapAllocationSnapshot)
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

        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
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
            mUprobeStatsTestRule.waitForUprobeStatsToExit(95, TimeUnit.SECONDS);

            // See if the atom made it
            boolean anyMatch =
                    mUprobeStatsTestRule
                            .getExtensionAtoms(
                                    UprobestatsExtensionAtoms.androidGraphicsBitmapScaled)
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

        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
                BINDER_TRANSACTION_CONFIG,
                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);

        // Should trigger IBatteryStats#noteStartSensor
        DeviceUtils.turnScreenOff(getDevice());
        DeviceUtils.turnScreenOn(getDevice());

        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        TestUprobeStatsAtomReported reported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(UprobestatsExtensionAtoms.testUprobestatsAtomReported)
                        .filter(atom -> atom.getSecondField() == 1) // Code == 1 (noteStartSensor)
                        .findFirst()
                        .orElseThrow(() -> new AssertionError("Atom 915 not found"));

        assertThat(reported.getFirstField()).isGreaterThan(0); // Calling UID
        assertThat(reported.getSecondField()).isEqualTo(1); // Code
        assertThat(reported.getThirdField()).isGreaterThan(0); // KTIME_NS

        mUprobeStatsTestRule.assertSelfMetricsReported(
                UprobeStatsBpfProgram.PROG_BINDER_UPROBE_EXEC_TRANSACT_INTERNAL,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_BINDER_OUTPUT_BUF);

        // TODO(b/413078491): use the test infra from UprobeStats/test/cts to assert that the
        // correct events were enqueued to the event service (although a unit test does already
        // check this, and the self metrics test that the bpf was successfully attached and produced
        // events).
    }

    private static final String TEST_MALWARE_SIGNAL_CONFIG = "disruptive_app.textproto";
    private static final String RESOLVE_PROCESS_FRAMEWORK_CONFIG =
            "resolve_process_framework.textproto";
    private static final String RESOLVE_PROCESS_CUSTOM_CONFIG = "resolve_process_custom.textproto";
    private static final String GENERIC_INSTRUMENTATION_PRIMITIVE_ARGS_CONFIG =
            "generic_instrumentation_primitive_args.textproto";
    private static final String GENERIC_INSTRUMENTATION_PRIMITIVE_ARGS_AOT_CONFIG =
            "generic_instrumentation_primitive_args_aot.textproto";
    private static final String TEST_APK_PACKAGE_NAME = "com.android.uprobestats.testapk";
    private static final String TEST_APK_ACTIVITY_NAME = "InstrumentationTestActivity";
    private static final String TEST_APK_COMPONENT_NAME =
            TEST_APK_PACKAGE_NAME + "/." + TEST_APK_ACTIVITY_NAME;
    private static final String ACTION_TRIGGER_FRAMEWORK =
            TEST_APK_PACKAGE_NAME + ".TRIGGER_FRAMEWORK";
    private static final String ACTION_TRIGGER_CUSTOM = TEST_APK_PACKAGE_NAME + ".TRIGGER_CUSTOM";
    private static final String ACTION_TRIGGER_PRIMITIVES =
            TEST_APK_PACKAGE_NAME + ".TRIGGER_PRIMITIVES";
    private static final String ACTION_TRIGGER_PRIMITIVES_AOT =
            TEST_APK_PACKAGE_NAME + ".TRIGGER_PRIMITIVES_AOT";
    private static final String EXTRA_INT_VAL = "intVal";
    private static final String EXTRA_BOOL_VAL = "boolVal";
    private static final String EXTRA_LONG_VAL = "longVal";

    @Test
    @RequiresFlagsEnabled(FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES)
    public void disruptiveAppActivity() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        assumeTrue(getDevice().getApiLevel() >= CINNAMON_BUN);

        mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                getClass(),
                TEST_MALWARE_SIGNAL_CONFIG,
                UprobestatsExtensionAtoms.SET_COMPONENT_ENABLED_SETTING_REPORTED_FIELD_NUMBER,
                UprobestatsExtensionAtoms.BIND_SERVICE_LOCKED_WITH_BAL_FLAGS_REPORTED_FIELD_NUMBER,
                UprobestatsExtensionAtoms.DISABLED_LAUNCHER_ACTIVITY_UIDS_REPORTED_FIELD_NUMBER,
                UprobestatsExtensionAtoms
                        .BIND_SERVICE_LOCKED_WITH_BAL_FLAGS_UIDS_REPORTED_FIELD_NUMBER);

        // enable and disable a non-launcher component
        getDevice()
                .executeShellCommand(
                        "pm disable" + " com.android.uprobestats.disruptive/.TestActivity");
        getDevice()
                .executeShellCommand(
                        "pm enable" + " com.android.uprobestats.disruptive/.TestActivity");

        // enable and disable a launcher component
        getDevice()
                .executeShellCommand(
                        "pm disable" + " com.android.uprobestats.disruptive/.TestLauncherActivity");
        getDevice()
                .executeShellCommand(
                        "pm enable" + " com.android.uprobestats.disruptive/.TestLauncherActivity");

        getDevice()
                .executeShellCommand(
                        "am start -n" + " com.android.uprobestats.disruptive/.TestActivity");

        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        SetComponentEnabledSettingReported reported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(
                                UprobestatsExtensionAtoms.setComponentEnabledSettingReported)
                        .findFirst()
                        .get();
        assertThat(reported.getNewState())
                .isEqualTo(2); // PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
        assertThat(reported.getPackageName()).isEqualTo("com.android.uprobestats.disruptive");
        assertThat(reported.getClassName())
                .isEqualTo("com.android.uprobestats.disruptive.TestActivity");
        assertThat(reported.getCallingPackageName()).isEqualTo("shell");
        assertThat(reported.getIsLauncherActivity()).isFalse();

        SetComponentEnabledSettingReported launcherReported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(
                                UprobestatsExtensionAtoms.setComponentEnabledSettingReported)
                        .skip(1)
                        .findFirst()
                        .get();
        assertThat(launcherReported.getNewState())
                .isEqualTo(2); // PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
        assertThat(launcherReported.getPackageName())
                .isEqualTo("com.android.uprobestats.disruptive");
        assertThat(launcherReported.getClassName())
                .isEqualTo("com.android.uprobestats.disruptive.TestLauncherActivity");
        assertThat(launcherReported.getCallingPackageName()).isEqualTo("shell");
        assertThat(launcherReported.getIsLauncherActivity()).isTrue();

        DisabledLauncherActivityUidsReported disabledLauncherActivityUidsReported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(
                                UprobestatsExtensionAtoms.disabledLauncherActivityUidsReported)
                        .findFirst()
                        .get();
        assertThat(disabledLauncherActivityUidsReported.getCallingUid()).isEqualTo(2000); // shell
        assertThat(disabledLauncherActivityUidsReported.getDisabledActivityUid()).isGreaterThan(0);

        BindServiceLockedWithBalFlagsReported balReported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(
                                UprobestatsExtensionAtoms.bindServiceLockedWithBalFlagsReported)
                        .findFirst()
                        .get();
        assertThat(balReported.getCallingPackageName())
                .isEqualTo("com.android.uprobestats.disruptive");
        assertThat(balReported.getFlags())
                .isEqualTo(1048576); // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS
        assertThat(balReported.getIntentPackageName()).isEqualTo("");
        assertThat(balReported.getIntentAction()).isEqualTo("");
        assertThat(balReported.getIntentComponentNamePackage()).isNotEmpty();
        assertThat(balReported.getIntentComponentNameClass()).isNotEmpty();

        BindServiceLockedWithBalFlagsUidsReported balUidsReported =
                mUprobeStatsTestRule
                        .getExtensionAtoms(
                                UprobestatsExtensionAtoms.bindServiceLockedWithBalFlagsUidsReported)
                        .findFirst()
                        .get();
        assertThat(balUidsReported.getBinderUid()).isGreaterThan(0);
        assertThat(balUidsReported.getBindeeUid()).isGreaterThan(0);

        mUprobeStatsTestRule.assertSelfMetricsReported(
                UprobeStatsBpfProgram.PROG_DISRUPTIVE_APP_UPROBE_SET_COMPONENT_ENABLED_SETTING,
                UprobeStatsBpfMapPath
                        .BPF_MAP_PATH_DISRUPTIVE_APP_COMPONENT_ENABLED_SETTING_OUTPUT_BUF);

        mUprobeStatsTestRule.assertSelfMetricsReported(
                UprobeStatsBpfProgram.PROG_DISRUPTIVE_APP_UPROBE_BIND_SERVICE_LOCKED,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_DISRUPTIVE_APP_BIND_SERVICE_LOCKED_OUTPUT_BUF);
    }

    @Test
    public void apkProcess_frameworkMethod() throws Exception {
        genericInstrumentationTest(
                RESOLVE_PROCESS_FRAMEWORK_CONFIG,
                ACTION_TRIGGER_FRAMEWORK,
                UprobeStatsBpfProgram.PROG_GENERIC_INSTRUMENTATION_UPROBE_CALL_TIMESTAMP,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_GENERIC_INSTRUMENTATION_CALL_TIMESTAMP_BUF,
                null);
    }

    @Test
    public void apkProcess_apkMethod() throws Exception {
        genericInstrumentationTest(
                RESOLVE_PROCESS_CUSTOM_CONFIG,
                ACTION_TRIGGER_CUSTOM,
                UprobeStatsBpfProgram.PROG_GENERIC_INSTRUMENTATION_UPROBE_CALL_TIMESTAMP,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_GENERIC_INSTRUMENTATION_CALL_TIMESTAMP_BUF,
                null);
    }

    @Test
    public void apkProcess_genericInstrumentation_primitiveArgs() throws Exception {
        genericInstrumentationTest(
                GENERIC_INSTRUMENTATION_PRIMITIVE_ARGS_CONFIG,
                ACTION_TRIGGER_PRIMITIVES,
                UprobeStatsBpfProgram.PROG_GENERIC_INSTRUMENTATION_UPROBE_CALL_DETAIL,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_GENERIC_INSTRUMENTATION_CALL_DETAIL_BUF,
                new ExpectedValues(123, true, 456L));
    }

    @Test
    public void apkProcess_genericInstrumentation_primitiveArgsAot() throws Exception {
        genericInstrumentationTest(
                GENERIC_INSTRUMENTATION_PRIMITIVE_ARGS_AOT_CONFIG,
                ACTION_TRIGGER_PRIMITIVES_AOT,
                UprobeStatsBpfProgram.PROG_GENERIC_INSTRUMENTATION_UPROBE_CALL_DETAIL,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_GENERIC_INSTRUMENTATION_CALL_DETAIL_BUF,
                new ExpectedValues(123, true, 456L));
    }

    @Test
    public void apkProcess_genericInstrumentation_primitiveArgs_negative() throws Exception {
        genericInstrumentationTest(
                GENERIC_INSTRUMENTATION_PRIMITIVE_ARGS_CONFIG,
                ACTION_TRIGGER_PRIMITIVES,
                UprobeStatsBpfProgram.PROG_GENERIC_INSTRUMENTATION_UPROBE_CALL_DETAIL,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_GENERIC_INSTRUMENTATION_CALL_DETAIL_BUF,
                new ExpectedValues(-123, false, -456L));
    }

    @Test
    public void apkProcess_genericInstrumentation_primitiveArgsAot_negative() throws Exception {
        genericInstrumentationTest(
                GENERIC_INSTRUMENTATION_PRIMITIVE_ARGS_AOT_CONFIG,
                ACTION_TRIGGER_PRIMITIVES_AOT,
                UprobeStatsBpfProgram.PROG_GENERIC_INSTRUMENTATION_UPROBE_CALL_DETAIL,
                UprobeStatsBpfMapPath.BPF_MAP_PATH_GENERIC_INSTRUMENTATION_CALL_DETAIL_BUF,
                new ExpectedValues(-123, false, -456L));
    }

    private void genericInstrumentationTest(
            String config,
            String action,
            UprobeStatsBpfProgram bpfProgram,
            UprobeStatsBpfMapPath bpfMapPath,
            ExpectedValues expectedValues)
            throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        getDevice().executeShellCommand("pm compile -m speed-profile -f " + TEST_APK_PACKAGE_NAME);

        try (AutoCloseable a =
                DeviceUtils.withActivity(
                        getDevice(), TEST_APK_PACKAGE_NAME, TEST_APK_ACTIVITY_NAME, null, null)) {

            mUprobeStatsTestRule.configureStatsDAndStartUprobeStats(
                    getClass(),
                    config,
                    UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);

            // Allow UprobeStats/StatsD time to get set up and listening
            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

            StringBuilder command =
                    new StringBuilder("am start -n ")
                            .append(TEST_APK_COMPONENT_NAME)
                            .append(" -e action ")
                            .append(action);
            if (expectedValues != null) {
                command.append(" --ei ")
                        .append(EXTRA_INT_VAL)
                        .append(" ")
                        .append(expectedValues.intVal)
                        .append(" --ez ")
                        .append(EXTRA_BOOL_VAL)
                        .append(" ")
                        .append(expectedValues.boolVal)
                        .append(" --el ")
                        .append(EXTRA_LONG_VAL)
                        .append(" ")
                        .append(expectedValues.longVal);
            }

            getDevice().executeShellCommand(command.toString());

            if (expectedValues != null) {
                // See if the atom made it
                TestUprobeStatsAtomReported reported =
                        mUprobeStatsTestRule
                                .getExtensionAtoms(
                                        UprobestatsExtensionAtoms.testUprobestatsAtomReported)
                                .findFirst()
                                .get();
                assertThat(reported.getFirstField())
                        .isEqualTo(Integer.toUnsignedLong(expectedValues.intVal));
                assertThat(reported.getSecondField()).isEqualTo(expectedValues.boolVal ? 1 : 0);
                assertThat(reported.getThirdField()).isEqualTo(expectedValues.longVal);
            }

            mUprobeStatsTestRule.assertSelfMetricsReported(
                    bpfProgram, bpfMapPath, atom -> assertThat(atom.getEventsCount()).isEqualTo(1));
        }
    }

    private static final class ExpectedValues {
        final int intVal;
        final boolean boolVal;
        final long longVal;

        ExpectedValues(int intVal, boolean boolVal, long longVal) {
            this.intVal = intVal;
            this.boolVal = boolVal;
            this.longVal = longVal;
        }
    }
}
