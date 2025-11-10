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
package com.android.uprobestats.cts;

import static android.Manifest.permission.DYNAMIC_INSTRUMENTATION;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import static androidx.test.InstrumentationRegistry.getInstrumentation;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.DeviceFlagsValueProvider;
import android.service.uprobestats.DynamicInstrumentationEvent;
import android.service.uprobestats.DynamicInstrumentationEventSender;

import com.android.bedstead.harrier.BedsteadJUnit4;
import com.android.bedstead.harrier.DeviceState;
import com.android.bedstead.permissions.annotations.EnsureHasPermission;
import com.android.uprobestats.consumer.ITestService;

import com.google.common.truth.Correspondence;

import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

@RunWith(BedsteadJUnit4.class)
public class DynamicInstrumentationEventServiceTest {

    private static final long TEST_SERVICE_SETUP_TIMEOUT_MS = Duration.ofSeconds(20).toMillis();
    public static final String CONSUMER_PACKAGE = "com.android.uprobestats.consumer";
    private static final ComponentName CONSUMER_COMPONENT_NAME =
            ComponentName.createRelative(
                    CONSUMER_PACKAGE, ".DynamicInstrumentationEventServiceImpl");
    private static final ComponentName TEST_SERVICE_COMPONENT_NAME =
            ComponentName.createRelative(CONSUMER_PACKAGE, ".TestService");
    private static final ComponentName ACTIVITY_COMPONENT_NAME =
            ComponentName.createRelative(CONSUMER_PACKAGE, ".MainActivity");

    protected final Instrumentation mInstrumentation = getInstrumentation();
    protected final Context mContext = getInstrumentation().getContext();

    @ClassRule public static final DeviceState sDeviceState = new DeviceState();

    @Rule
    public final TestRule chain =
            RuleChain.outerRule(DeviceFlagsValueProvider.createCheckFlagsRule())
                    .around(sDeviceState);

    @Rule
    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();

    /**
     * Get a {@link ITestService} instance.
     *
     * <p>Also cleans any residual events before returning the service.
     */
    private ITestService getTestService() throws Exception {
        FutureConnection<ITestService> futureConnection;
        // need to setup new test service connection for the component
        Intent bindIntent = new Intent();
        bindIntent.setComponent(TEST_SERVICE_COMPONENT_NAME);
        futureConnection = new FutureConnection<>(ITestService.Stub::asInterface);
        boolean success =
                mContext.bindService(bindIntent, futureConnection, Context.BIND_AUTO_CREATE);
        assertTrue("Failed to setup " + TEST_SERVICE_COMPONENT_NAME, success);
        return futureConnection.get(TEST_SERVICE_SETUP_TIMEOUT_MS);
    }

    @After
    public void disableTestMode() throws Exception {
        if (mContext.checkSelfPermission(DYNAMIC_INSTRUMENTATION) == PERMISSION_GRANTED) {
            DynamicInstrumentationEventSender sender =
                    mContext.getSystemService(DynamicInstrumentationEventSender.class);
            sender.disableTestMode();
        }
    }

    @Test
    public void testLaunchConsumer() throws Exception {
        mContext.startActivity(
                new Intent()
                        .setComponent(ACTIVITY_COMPONENT_NAME)
                        .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
    }

    @Test
    @EnsureHasPermission(DYNAMIC_INSTRUMENTATION)
    public void testReceiveEventWithFlush() throws Exception {
        DynamicInstrumentationEventSender sender =
                mContext.getSystemService(DynamicInstrumentationEventSender.class);
        assertNotNull("Failed to get DynamicInstrumentationEventSender", sender);
        sender.enableTestMode(CONSUMER_COMPONENT_NAME);
        sender.waitQueueFlushed(); // make sure no events in the server side queue

        ITestService testService = getTestService();
        testService.getReceivedEvents(); // make sure no events in the client side queue

        sender.sendEvent(createTestDynamicInstrumentationEvent(0), false);
        sender.sendEvent(createTestDynamicInstrumentationEvent(1), false);
        sender.sendEvent(createTestDynamicInstrumentationEvent(2), true);

        sender.waitQueueFlushed();

        Correspondence<Bundle, Bundle> bundleCorrespondence =
                Correspondence.from(
                        (actual, expected) -> {
                            if (!actual.keySet().equals(expected.keySet())) {
                                return false;
                            }
                            for (String key : actual.keySet()) {
                                if (!Objects.equals(actual.get(key), expected.get(key))) {
                                    return false;
                                }
                            }
                            return true;
                        },
                        "bundleCorrespondence");

        List<Bundle> events = testService.getReceivedEvents();
        assertThat(events)
                .comparingElementsUsing(bundleCorrespondence)
                .containsExactly(createTestResult(0), createTestResult(1), createTestResult(2));
    }

    @Test
    @EnsureHasPermission(DYNAMIC_INSTRUMENTATION)
    public void testReceiveEventWithoutFlush() throws Exception {
        DynamicInstrumentationEventSender sender =
                mContext.getSystemService(DynamicInstrumentationEventSender.class);
        assertNotNull("Failed to get DynamicInstrumentationEventSender", sender);
        sender.enableTestMode(CONSUMER_COMPONENT_NAME);
        sender.waitQueueFlushed(); // make sure no events in the server side queue

        ITestService testService = getTestService();
        testService.getReceivedEvents(); // make sure no events in the client side queue

        sender.sendEvent(createTestDynamicInstrumentationEvent(0), false);
        sender.sendEvent(createTestDynamicInstrumentationEvent(1), false);
        sender.sendEvent(createTestDynamicInstrumentationEvent(2), false);

        sender.waitQueueFlushed();

        Correspondence<Bundle, Bundle> bundleCorrespondence =
                Correspondence.from(
                        (actual, expected) -> {
                            if (!actual.keySet().equals(expected.keySet())) {
                                return false;
                            }
                            for (String key : actual.keySet()) {
                                if (!Objects.equals(actual.get(key), expected.get(key))) {
                                    return false;
                                }
                            }
                            return true;
                        },
                        "bundleCorrespondence");

        List<Bundle> events = testService.getReceivedEvents();
        assertThat(events)
                .comparingElementsUsing(bundleCorrespondence)
                .containsExactly(createTestResult(0), createTestResult(1), createTestResult(2));
    }

    DynamicInstrumentationEvent createTestDynamicInstrumentationEvent(int seed) {
        return new DynamicInstrumentationEvent(
                seed, Instant.ofEpochSecond(seed + 1), seed + 2, createTestBundle(seed));
    }

    Bundle createTestResult(int seed) {
        Bundle result = createTestBundle(seed);
        result.putInt("uid", seed);
        result.putLong("timestampMillis", Instant.ofEpochSecond(seed + 1).toEpochMilli());
        result.putInt("payloadId", seed + 2);
        return result;
    }

    Bundle createTestBundle(int seed) {
        Bundle result = new Bundle();
        result.putInt("someInteger", seed + 37);
        result.putString("someClassName", getClass().getName());
        return result;
    }
}
