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

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.ConfigUtils;

import com.android.internal.os.StatsdConfigProto;
import com.android.internal.os.StatsdConfigProto.Alert;
import com.android.internal.os.StatsdConfigProto.FieldMatcher;
import com.android.internal.os.StatsdConfigProto.StatsdConfig;
import com.android.internal.os.StatsdConfigProto.Subscription;
import com.android.internal.os.StatsdConfigProto.UprobestatsDetails;
import com.android.internal.os.StatsdConfigProto.ValueMetric;
import com.android.os.AtomsProto.AppBreadcrumbReported;
import com.android.os.AtomsProto.Atom;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.util.RunUtil;

import com.google.protobuf.TextFormat;

import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import uprobestats.protos.Config.UprobestatsConfig;

/** Collection of utilities to set up statsd and start uprobestats for a test. */
public class UprobeStatsTestSetup {
    private static final int APP_BREADCRUMB_REPORTED_MATCH_START_ID = 1;
    private static final int METRIC_ID = 8;
    private static final int ALERT_ID = 29754810;
    private static final int SUBSCRIPTION_ID = 29796753;

    /**
     * Starts UprobeStats with the given config and configures statsd to collect the given atomIds.
     */
    public static void configureStatsDAndStartUprobeStats(
            Class clazz, ITestDevice device, String textprotoFilename, int... atomIds)
            throws Exception {
        // 1. Parse config from resources
        String textProto =
                new Scanner(clazz.getResourceAsStream("/" + textprotoFilename), "UTF-8")
                        .useDelimiter("\\A")
                        .next();
        UprobestatsConfig.Builder configBuilder = UprobestatsConfig.newBuilder();
        TextFormat.getParser().merge(textProto, configBuilder);
        UprobestatsConfig uprobeStatsConfig = configBuilder.build();

        // 2. Configure StatsD
        StatsdConfig.Builder config =
                ConfigUtils.createConfigBuilder("com.android.uprobestats.test");
        for (int atomId : atomIds) {
            ConfigUtils.addEventMetric(config, atomId);
        }
        config.addSubscription(
                        Subscription.newBuilder()
                                .setId(SUBSCRIPTION_ID)
                                .setRuleType(Subscription.RuleType.ALERT)
                                .setRuleId(ALERT_ID)
                                .setUprobestatsDetails(
                                        UprobestatsDetails.newBuilder()
                                                .setConfig(uprobeStatsConfig.toByteString())))
                .addValueMetric(
                        ValueMetric.newBuilder()
                                .setId(METRIC_ID)
                                .setWhat(APP_BREADCRUMB_REPORTED_MATCH_START_ID)
                                .setBucket(StatsdConfigProto.TimeUnit.ONE_MINUTE)
                                // Get the label field's value:
                                .setValueField(
                                        FieldMatcher.newBuilder()
                                                .setField(Atom.APP_BREADCRUMB_REPORTED_FIELD_NUMBER)
                                                .addChild(
                                                        FieldMatcher.newBuilder()
                                                                .setField(
                                                                        AppBreadcrumbReported
                                                                                .LABEL_FIELD_NUMBER))))
                .addAtomMatcher(
                        StatsdConfigProto.AtomMatcher.newBuilder()
                                .setId(APP_BREADCRUMB_REPORTED_MATCH_START_ID)
                                .setSimpleAtomMatcher(
                                        StatsdConfigProto.SimpleAtomMatcher.newBuilder()
                                                .setAtomId(
                                                        Atom.APP_BREADCRUMB_REPORTED_FIELD_NUMBER)
                                                .addFieldValueMatcher(
                                                        ConfigUtils.createFvm(
                                                                        AppBreadcrumbReported
                                                                                .STATE_FIELD_NUMBER)
                                                                .setEqInt(
                                                                        AppBreadcrumbReported.State
                                                                                .START
                                                                                .getNumber()))))
                .addAlert(
                        Alert.newBuilder()
                                .setId(ALERT_ID)
                                .setMetricId(METRIC_ID)
                                .setNumBuckets(4)
                                .setRefractoryPeriodSecs(0)
                                .setTriggerIfSumGt(0))
                .addNoReportMetric(METRIC_ID);

        ConfigUtils.uploadConfig(device, config);

        // 3. Start UprobeStats by triggering the alert
        AtomTestUtils.sendAppBreadcrumbReportedAtom(device);
        waitForUprobeStats(20, TimeUnit.SECONDS, device);
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
    }

    /** Waits for the uprobestats process to start */
    public static void waitForUprobeStats(long timeout, TimeUnit unit, ITestDevice device)
            throws TimeoutException, DeviceNotAvailableException {
        waitForCondition(
                () -> {
                    try {
                        return device.executeShellCommand("pidof uprobestats").length() > 0;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                },
                timeout,
                unit);
    }

    /** Waits for the uprobestats process to exit */
    public static void waitForUprobeStatsToExit(long timeout, TimeUnit unit, ITestDevice device)
            throws TimeoutException, DeviceNotAvailableException {
        waitForCondition(
                () -> {
                    try {
                        String pid = device.executeShellCommand("pidof uprobestats");
                        return pid.isEmpty() || !pid.trim().matches("\\d+");
                    } catch (DeviceNotAvailableException e) {
                        throw new RuntimeException(e);
                    }
                },
                timeout,
                unit);
    }

    /** Waits for a certain condition to become true. */
    public static void waitForCondition(Supplier<Boolean> condition, long timeout, TimeUnit unit)
            throws TimeoutException {
        long startTime = System.currentTimeMillis();
        long timeoutMillis = unit.toMillis(timeout);

        while (true) {
            // Calculate remaining time
            long elapsedTime = System.currentTimeMillis() - startTime;
            long remainingTime = timeoutMillis - elapsedTime;

            if (remainingTime <= 0) {
                throw new TimeoutException();
            }

            if (condition.get()) {
                break;
            }

            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
        }
    }
}
