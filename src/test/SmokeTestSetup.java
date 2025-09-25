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

package test;

import static com.google.common.truth.Truth.assertThat;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.ConfigUtils;
import android.cts.statsdatom.lib.ReportUtils;

import com.android.internal.os.StatsdConfigProto;
import com.android.os.framework.FrameworkExtensionAtoms;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.util.RunUtil;
import com.android.uprobestats.UprobestatsExtensionAtoms;

import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.TextFormat;

import uprobestats.protos.Config.UprobestatsConfig;

import java.io.File;
import java.nio.file.Files;
import java.util.Scanner;

/** Collection of utilities to set up statsd and start uprobestats for a test. */
public class SmokeTestSetup {
    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
    private static final String CONFIG_NAME = "config";
    private static final String CMD_SETPROP_UPROBESTATS = "setprop ctl.start uprobestats";

    /** Initializes and then sets up the statsd extension registry */
    public static ExtensionRegistry initializeStatsD(ITestDevice device) throws Exception {
        ConfigUtils.removeConfig(device);
        ReportUtils.clearReports(device);
        ExtensionRegistry registry = ExtensionRegistry.newInstance();
        UprobestatsExtensionAtoms.registerAllExtensions(registry);
        FrameworkExtensionAtoms.registerAllExtensions(registry);
        return registry;
    }

    /** Cleans up any pre-existing uprobestats execution. */
    public static void initializeUprobeStats(ITestDevice device) throws Exception {
        device.deleteFile(CONFIG_DIR + CONFIG_NAME);
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
        device.executeShellCommand("killall uprobestats");
    }

    /**
     * Starts UprobeStats with the given config and configures statsd to collect the given atomIds.
     */
    public static void configureStatsDAndStartUprobeStats(
            Class clazz, ITestDevice device, String textprotoFilename, int... atomIds)
            throws Exception {
        // 1. Parse config from resources
        String textProto =
                new Scanner(clazz.getResourceAsStream(textprotoFilename))
                        .useDelimiter("\\A")
                        .next();
        UprobestatsConfig.Builder builder = UprobestatsConfig.newBuilder();
        TextFormat.getParser().merge(textProto, builder);
        UprobestatsConfig config = builder.build();

        // 2. Write config to a file and drop it on the device
        File tmp = File.createTempFile("uprobestats", CONFIG_NAME);
        assertThat(tmp.setWritable(true)).isTrue();
        Files.write(tmp.toPath(), config.toByteArray());
        assertThat(device.enableAdbRoot()).isTrue();
        assertThat(device.pushFile(tmp, CONFIG_DIR + CONFIG_NAME)).isTrue();

        // 3. Configure StatsD
        StatsdConfigProto.StatsdConfig.Builder configBuilder =
                ConfigUtils.createConfigBuilder("AID_UPROBESTATS");
        for (int atomId : atomIds) {
            ConfigUtils.addEventMetric(configBuilder, atomId);
        }
        ConfigUtils.uploadConfig(device, configBuilder);

        // 4. Start UprobeStats
        device.executeShellCommand(CMD_SETPROP_UPROBESTATS);
        // Allow UprobeStats time to attach probe
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
    }
}
