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
import android.cts.statsdatom.lib.ConfigUtils;
import android.cts.statsdatom.lib.DeviceUtils;
import android.cts.statsdatom.lib.ReportUtils;

import com.android.os.framework.FrameworkExtensionAtoms;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.util.RunUtil;
import com.google.protobuf.ExtensionRegistry;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

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
import com.android.os.StatsLog;
import com.android.tradefed.device.ITestDevice;
import com.google.protobuf.ExtensionRegistry;

import com.google.common.collect.ImmutableList;
import com.google.protobuf.TextFormat;
import com.google.protobuf.Extension;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import uprobestats.protos.Config.UprobestatsConfig;

import java.util.function.Supplier;

import static com.google.common.truth.Truth.assertThat;

public class UprobeStatsTestRule implements TestRule {
    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
    private static final String CONFIG_NAME = "config";
    private static final int APP_BREADCRUMB_REPORTED_MATCH_START_ID = 1;
    private static final int METRIC_ID = 8;
    private static final int ALERT_ID = 29754810;
    private static final int SUBSCRIPTION_ID = 29796753;

    private static final List<Integer> SELF_METRICS_ATOM_IDS =
            ImmutableList.of(
                    UprobestatsExtensionAtoms.UPROBE_STATS_INVOCATION_FIELD_NUMBER,
                    UprobestatsExtensionAtoms.UPROBE_STATS_INTERNAL_ERROR_FIELD_NUMBER,
                    UprobestatsExtensionAtoms.UPROBE_STATS_BPF_ATTACHED_FIELD_NUMBER,
                    UprobestatsExtensionAtoms.UPROBE_STATS_BPF_MAP_POLLED_FIELD_NUMBER);

    private Supplier<ITestDevice> mDeviceSupplier;
    private ExtensionRegistry mRegistry;
    private List<Atom> mReportedAtoms = new ArrayList<>();

    public UprobeStatsTestRule(Supplier<ITestDevice> deviceSupplier) {
        mDeviceSupplier = deviceSupplier;
    }

    public ExtensionRegistry getRegistry() {
        return mRegistry;
    }

    public ITestDevice getDevice() {
        return mDeviceSupplier.get();
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                initializeRegistry();
                initializeUprobeStats();
                base.evaluate();
            }
        };
    }

    /**
     * Starts UprobeStats with the given config and configures statsd to collect the given atomIds.
     */
    public void configureStatsDAndStartUprobeStats(
            Class clazz, String textprotoFilename, int... atomIds) throws Exception {
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
        for (int atomId : SELF_METRICS_ATOM_IDS) {
            ConfigUtils.addEventMetric(config, atomId);
        }
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

        ConfigUtils.uploadConfig(getDevice(), config);

        // 3. Start UprobeStats by triggering the alert
        AtomTestUtils.sendAppBreadcrumbReportedAtom(getDevice());
        waitForUprobeStats(20, TimeUnit.SECONDS);
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
    }

    /**
     * Asserts that the given BPF program and map path have been executed and polled by UprobeStats,
     * as evidenced by the presence of the corresponding self-metrics atoms.
     */
    public void assertSelfMetricsReported(
            UprobeStatsBpfAttached.BpfProgram bpfProgram,
            UprobeStatsBpfMapPolled.BpfMapPath bpfMapPath)
            throws Exception {

        long countServiceStarted =
                getExtensionAtoms(UprobestatsExtensionAtoms.uprobeStatsInvocation)
                        .filter(
                                atom ->
                                        atom.getInvocationType()
                                                == UprobeStatsInvocation.InvocationType
                                                        .INVOCATION_TYPE_SERVICE_STARTED)
                        .count();
        assertThat(countServiceStarted).isEqualTo(1);

        long countBpfAttached =
                getExtensionAtoms(UprobestatsExtensionAtoms.uprobeStatsBpfAttached)
                        .filter(atom -> atom.getBpfProgram() == bpfProgram)
                        .count();
        assertThat(countBpfAttached).isEqualTo(1);

        // BPF map path stats are not reported until uprobestats is done polling.
        waitForUprobeStatsToExit(60, TimeUnit.SECONDS);

        Stream<UprobeStatsBpfMapPolled> afterTaskCompleteData =
                getExtensionAtoms(UprobestatsExtensionAtoms.uprobeStatsBpfMapPolled);
        long hasExpectedEvents =
                afterTaskCompleteData
                        .filter(
                                atom ->
                                        atom.getMapPath() == bpfMapPath
                                                && atom.getEventsCount() > 0)
                        .count();
        assertThat(hasExpectedEvents).isEqualTo(1);
    }

    /**
     * Returns a stream of atoms that have the given extension. This method will also query
     * statsd for any new atoms that have been reported since the last time this method was called.
     */
    public <T> Stream<T> getExtensionAtoms(Extension<Atom, T> extension) throws Exception {
        mReportedAtoms.addAll(getReportedAtomsAndDeleteReport());
        return mReportedAtoms.stream()
                .filter(atom -> atom.hasExtension(extension))
                .map(atom -> atom.getExtension(extension));
    }

    /** Waits for the uprobestats process to start */
    public void waitForUprobeStats(long timeout, TimeUnit unit)
            throws TimeoutException, DeviceNotAvailableException {
        waitForCondition(
                () -> {
                    try {
                        return mDeviceSupplier
                                        .get()
                                        .executeShellCommand("pidof uprobestats")
                                        .length()
                                > 0;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                },
                timeout,
                unit);
    }

    /** Waits for the uprobestats process to exit */
    public void waitForUprobeStatsToExit(long timeout, TimeUnit unit)
            throws TimeoutException, DeviceNotAvailableException {
        waitForCondition(
                () -> {
                    try {
                        String pid = getDevice().executeShellCommand("pidof uprobestats");
                        return pid.isEmpty() || !pid.trim().matches("\\d+");
                    } catch (DeviceNotAvailableException e) {
                        throw new RuntimeException(e);
                    }
                },
                timeout,
                unit);
    }

    /** Waits for a certain condition to become true. */
    public void waitForCondition(Supplier<Boolean> condition, long timeout, TimeUnit unit)
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

    /**
     * Returns all the atoms reported to statsd in the test. Note the footgun in
     * `ReportUtils.getEventMetricDataList`. Once you call it, the report is deleted.
     */
    private List<Atom> getReportedAtomsAndDeleteReport() throws Exception {
        return ReportUtils.getEventMetricDataList(mDeviceSupplier.get(), mRegistry).stream()
                .map(StatsLog.EventMetricData::getAtom)
                .collect(Collectors.toList());
    }

    /** Initializes and then sets up the statsd extension registry */
    private void initializeRegistry() throws Exception {
        ConfigUtils.removeConfig(getDevice());
        ReportUtils.clearReports(getDevice());
        ExtensionRegistry registry = ExtensionRegistry.newInstance();
        UprobestatsExtensionAtoms.registerAllExtensions(registry);
        FrameworkExtensionAtoms.registerAllExtensions(registry);
        mRegistry = registry;
    }

    /** Initializes UprobeStats by deleting the config file and killing any existing process. */
    private void initializeUprobeStats() throws Exception {
        getDevice().deleteFile(CONFIG_DIR + CONFIG_NAME);
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
        getDevice().executeShellCommand("killall uprobestats");
    }
}
