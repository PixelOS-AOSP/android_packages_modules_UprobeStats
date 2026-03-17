/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.android.uprobestats.testapk;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;

public class InstrumentationTestActivity extends Activity {
    private static final String TAG = "InstrumentationTestActivity";
    public static final String ACTION_TRIGGER_FRAMEWORK =
            "com.android.uprobestats.testapk.TRIGGER_FRAMEWORK";
    public static final String ACTION_TRIGGER_CUSTOM =
            "com.android.uprobestats.testapk.TRIGGER_CUSTOM";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate called");
    }

    @Override
    protected void onStart() {
        super.onStart();
        Log.i(TAG, "onStart called");
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.i(
                TAG,
                "onNewIntent called with action: "
                        + (intent != null ? intent.getAction() : "null"));
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        String actionToTake = intent.getStringExtra("action");
        if (actionToTake == null) {
            return;
        }

        switch (actionToTake) {
            case ACTION_TRIGGER_FRAMEWORK:
                Log.i(TAG, "Triggering framework method");
                ActivityManager.isUserAMonkey();
                break;
            case ACTION_TRIGGER_CUSTOM:
                Log.i(TAG, "Triggering custom method");
                customMethodToTrace();
                break;
        }
    }

    public void customMethodToTrace() {
        Log.i(TAG, "customMethodToTrace called");
    }
}
