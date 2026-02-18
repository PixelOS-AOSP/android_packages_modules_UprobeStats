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

import static android.uprobestats.mainline.flags.Flags.FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES;
import static com.android.uprobestats.UprobeStatsBpfAttached.BpfProgram;
import static com.android.uprobestats.UprobeStatsBpfMapPolled.BpfMapPath;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assume.assumeTrue;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.host.HostFlagsValueProvider;
import com.android.compatibility.common.util.CpuFeatures;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.RunUtil;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class UprobeStatsTestBridgeService extends BaseHostJUnit4Test {
    private static final String TEST_MALWARE_SIGNAL_CONFIG = "disruptive_app.textproto";

    @Rule(order = 0)
    public final CheckFlagsRule mCheckFlagsRule =
            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);

    @Rule(order = 1)
    public final UprobeStatsTestRule mUprobeStatsTestRule =
            new UprobeStatsTestRule(this::getDevice);

    @Test
    @RequiresFlagsEnabled(FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES)
    public void disruptiveAppActivity() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));

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
                BpfProgram.PROG_DISRUPTIVE_APP_UPROBE_SET_COMPONENT_ENABLED_SETTING,
                BpfMapPath.BPF_MAP_PATH_DISRUPTIVE_APP_COMPONENT_ENABLED_SETTING_OUTPUT_BUF);

        mUprobeStatsTestRule.assertSelfMetricsReported(
                BpfProgram.PROG_DISRUPTIVE_APP_UPROBE_BIND_SERVICE_LOCKED,
                BpfMapPath.BPF_MAP_PATH_DISRUPTIVE_APP_BIND_SERVICE_LOCKED_OUTPUT_BUF);
    }
}
