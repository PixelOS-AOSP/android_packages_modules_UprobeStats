/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.uprobestats.consumer;

import android.annotation.RequiresNoPermission;
import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

/** Test service to extract data from the test app. */
public class TestService extends Service {

    static final String TAG = TestService.class.getName();
    private final ITestService mBinder = new MyBinder();

    static BlockingQueue<Bundle> sStoredEvents = new LinkedBlockingDeque<>();

    /** Add an event to be picked up by a test. */
    public static void addEvent(Bundle event) {
        sStoredEvents.add(event);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder.asBinder();
    }

    private class MyBinder extends ITestService.Stub {
        @Override
        @RequiresNoPermission
        public List<Bundle> getReceivedEvents() {
            ArrayList<Bundle> result = new ArrayList<>(sStoredEvents.size());
            sStoredEvents.drainTo(result);
            return result;
        }
    }
}
