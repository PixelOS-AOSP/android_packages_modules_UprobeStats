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

import static android.Manifest.permission.DYNAMIC_INSTRUMENTATION;

import android.annotation.PermissionManuallyEnforced;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.util.Log;

import java.util.List;

/**
 * Implementation of {@link IUprobeStatsService} binder service.
 *
 * @hide
 */
public final class UprobeStatsBridgeServiceImpl extends IUprobeStatsBridgeService.Stub {
    private static final String TAG = "UprobeStatsBridgeService";
    private final Context mContext;

    public UprobeStatsBridgeServiceImpl(Context context) {
        super();
        mContext = context;
    }

    @Override
    @PermissionManuallyEnforced
    public boolean isLauncherActivity(String packageName, String className, boolean matchDisabled) {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        final Intent intent = new Intent(Intent.ACTION_MAIN);
        intent.addCategory(Intent.CATEGORY_LAUNCHER);
        intent.setPackage(packageName);

        int flags = matchDisabled ? PackageManager.MATCH_DISABLED_COMPONENTS : 0;

        PackageManager pm = mContext.getPackageManager();
        List<ResolveInfo> activities = pm.queryIntentActivities(intent, flags);

        for (ResolveInfo resolveInfo : activities) {
            if (resolveInfo.activityInfo.name.equals(className)) {
                return true;
            }
        }

        return false;
    }

    @Override
    @PermissionManuallyEnforced
    public int getUidForPackage(String packageName) {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        try {
            return mContext.getPackageManager().getPackageUid(packageName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Package not found: " + packageName);
            return -1;
        }
    }
}
