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
import android.cts.statsdatom.lib.ReportUtils;

import com.android.os.framework.FrameworkExtensionAtoms;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.util.RunUtil;
import com.google.protobuf.ExtensionRegistry;

import java.util.function.Supplier;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public abstract class AbstractUprobeStatsTestRule implements TestRule {
    static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
    static final String CONFIG_NAME = "config";

    public AbstractUprobeStatsTestRule(Supplier<ITestDevice> deviceSupplier) {
        mDeviceSupplier = deviceSupplier;
    }

    private Supplier<ITestDevice> mDeviceSupplier;
    private ExtensionRegistry mRegistry;

    public ExtensionRegistry getRegistry() {
        return mRegistry;
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                mRegistry = initializeStatsD(mDeviceSupplier.get());
                initializeUprobeStats(mDeviceSupplier.get());

                base.evaluate();
            }
        };
    }

    /** Initializes and then sets up the statsd extension registry */
    private static ExtensionRegistry initializeStatsD(ITestDevice device) throws Exception {
        ConfigUtils.removeConfig(device);
        ReportUtils.clearReports(device);
        ExtensionRegistry registry = ExtensionRegistry.newInstance();
        UprobestatsExtensionAtoms.registerAllExtensions(registry);
        FrameworkExtensionAtoms.registerAllExtensions(registry);
        return registry;
    }

    /** Cleans up any pre-existing uprobestats execution. */
    abstract void initializeUprobeStats(ITestDevice device) throws Exception;
}
