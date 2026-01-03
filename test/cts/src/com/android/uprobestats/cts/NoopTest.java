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

import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.DeviceFlagsValueProvider;

import com.android.bedstead.harrier.BedsteadJUnit4;
import com.android.compatibility.common.util.NonApiTest;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** This test class exists only to make the test suite valid if the module is not enabled. */
@RunWith(BedsteadJUnit4.class)
public class NoopTest {

    @Rule
    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();

    @Test
    @RequiresFlagsEnabled(android.security.Flags.FLAG_DYNAMIC_INSTRUMENTATION_API)
    @NonApiTest(
            exemptionReasons = {},
            justification =
                    "Required for technical reasons. "
                            + "Actual test class is included conditionally")
    public void testNothing() {}
}
