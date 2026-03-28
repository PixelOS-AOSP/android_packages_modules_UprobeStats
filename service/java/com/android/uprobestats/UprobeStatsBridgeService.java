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

import android.annotation.NonNull;
import android.content.Context;
import android.os.Build;
import androidx.annotation.RequiresApi;
import android.util.Slog;

import com.android.server.SystemService;

/**
 * UprobeStats service.
 *
 * @hide
 */
@RequiresApi(Build.VERSION_CODES.CINNAMON_BUN)
public class UprobeStatsBridgeService extends SystemService {
    private static final String SERVICE_NAME = "uprobestats_bridge";
    private static final String TAG = "UprobeStatsBridgeService";

    private final UprobeStatsBridgeServiceImpl mUprobeStatsBridgeServiceImpl;

    public UprobeStatsBridgeService(@NonNull Context context) {
        super(context);
        mUprobeStatsBridgeServiceImpl = new UprobeStatsBridgeServiceImpl(context);
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mUprobeStatsBridgeServiceImpl);
    }
}
