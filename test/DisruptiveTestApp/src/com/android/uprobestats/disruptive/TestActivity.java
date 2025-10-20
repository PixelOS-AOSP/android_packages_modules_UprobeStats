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

package com.android.uprobestats.disruptive;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

public class TestActivity extends Activity {
    private static String TAG = "DisruptiveTestActivity";

    @Override
    public void onCreate(Bundle bundle) {
        Log.i(TAG, "onCreate");
        super.onCreate(bundle);
        Intent intent = new Intent(this, TestService.class);
        int flags = Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS;
        boolean bound = bindService(intent, new Fake(), flags);
        Log.i(TAG, "bound: " + bound);
    }

    private static class Fake implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName component, IBinder _svc) {
            Log.i(TAG, "onServiceConnected: " + component.toString());
        }

        @Override
        public void onServiceDisconnected(ComponentName component) {
            Log.i(TAG, "onServiceDisconnected: " + component.toString());
        }
    }
}
