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

import android.accessibilityservice.AccessibilityServiceInfo;
import android.annotation.PermissionManuallyEnforced;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.UserHandle;
import android.service.uprobestats.DynamicInstrumentationManager;
import android.util.Slog;
import android.view.accessibility.AccessibilityManager;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of {@link IUprobeStatsBridgeService} binder service.
 *
 * @hide
 */
public final class UprobeStatsBridgeServiceImpl extends IUprobeStatsBridgeService.Stub {
    private static final String TAG = "UprobeStatsBridgeService";
    private final Context mContext;
    private volatile IUprobeStatsEventListener mEventListener;
    private final HandlerThread mHandlerThread;
    private final Handler mFlushHandler;
    private static final int EVENT_BUFFER_CAPACITY = 32;
    private static final long FLUSH_TIMEOUT = Duration.ofSeconds(60).toMillis();
    private static final long TEST_FLUSH_TIMEOUT = Duration.ofSeconds(10).toMillis();
    private final ArrayDeque<Event> mEventBuffer = new ArrayDeque<>(EVENT_BUFFER_CAPACITY);
    private long flushTimeout = FLUSH_TIMEOUT;

    public UprobeStatsBridgeServiceImpl(Context context) {
        super();
        mContext = context;

        mHandlerThread = new HandlerThread(TAG);
        mHandlerThread.start();
        mFlushHandler = new Handler(mHandlerThread.getLooper());

        bindConsumer(); // we are not waiting for the latch to open here. Events created before
        // the binding finishes will simply be discarded as if no consumer was configured.
    }

    private CountDownLatch bindConsumer() {
        CountDownLatch latch = new CountDownLatch(1);
        DynamicInstrumentationManager dynamicInstrumentationManager =
                mContext.getSystemService(DynamicInstrumentationManager.class);
        ComponentName dynamicInstrumentationEventConsumer =
                dynamicInstrumentationManager.getDynamicInstrumentationEventConsumer();

        if (dynamicInstrumentationEventConsumer == null) {
            Slog.w(
                    TAG,
                    "Dynamic instrumentation consumer service not configured. "
                            + "Events will be dropped.");
            latch.countDown();
            return latch; // Do not attempt to bind
        }

        final long callerToken = Binder.clearCallingIdentity();
        try {
            mContext.bindServiceAsUser(
                    new Intent().setComponent(dynamicInstrumentationEventConsumer),
                    new ServiceConnection() {
                        @Override
                        public void onServiceConnected(ComponentName name, IBinder service) {
                            mEventListener = IUprobeStatsEventListener.Stub.asInterface(service);
                            latch.countDown();
                        }

                        @Override
                        public void onServiceDisconnected(ComponentName name) {
                            mEventListener = null;
                            latch.countDown();
                        }

                        @Override
                        public void onNullBinding(ComponentName name) {
                            mEventListener = null;
                            latch.countDown();
                        }
                    },
                    Context.BIND_AUTO_CREATE | Context.BIND_INCLUDE_CAPABILITIES,
                    UserHandle.SYSTEM);
        } finally {
            Binder.restoreCallingIdentity(callerToken);
        }
        return latch;
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
            Slog.e(TAG, "Package not found: " + packageName);
            return -1;
        }
    }

    @Override
    @PermissionManuallyEnforced
    public boolean packageHasEnabledAccessibilityService(String packageName) {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        AccessibilityManager am = mContext.getSystemService(AccessibilityManager.class);
        if (am == null) {
            Slog.e(TAG, "Failed to get AccessibilityManager.");
            return false;
        }

        List<AccessibilityServiceInfo> services =
                am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        for (AccessibilityServiceInfo info : services) {
            if (info.getResolveInfo().serviceInfo.packageName.equals(packageName)) {
                return true;
            }
        }
        return false;
    }

    private Runnable mFlushRunnable =
            new Runnable() {
                @Override
                public void run() {
                    mFlushHandler.removeCallbacks(mFlushRunnable); // Cancel any pending flush
                    List<Event> eventsToSend = new ArrayList<>(EVENT_BUFFER_CAPACITY);
                    synchronized (mEventBuffer) {
                        eventsToSend.addAll(mEventBuffer);
                        mEventBuffer.clear();
                    }
                    if (eventsToSend.isEmpty()) {
                        // buffer was already cleared by another flush
                        return;
                    }
                    try {
                        mEventListener.onEvent(eventsToSend);
                    } catch (RemoteException e) {
                        Slog.w(TAG, "Events may have been lost (" + eventsToSend.size() + ")", e);
                    }
                }
            };

    @Override
    @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
    public void enqueueEvent(Event event, boolean flush) {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        if (mEventListener != null) {
            boolean bufferFull;
            synchronized (mEventBuffer) {
                mEventBuffer.add(event);
                bufferFull = mEventBuffer.size() >= EVENT_BUFFER_CAPACITY;
            }
            if (flush || bufferFull) {
                mFlushHandler.post(mFlushRunnable);
            } else {
                mFlushHandler.postDelayed(mFlushRunnable, flushTimeout);
            }
        }
    }

    @Override
    @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
    public boolean enableTestMode(String packageName, String className) {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        ComponentName componentName = ComponentName.createRelative(packageName, className);
        DynamicInstrumentationManager dynamicInstrumentationManager =
                mContext.getSystemService(DynamicInstrumentationManager.class);
        dynamicInstrumentationManager.setDynamicInstrumentationEventConsumer(componentName);
        try {
            // bind and wait for the binding to complete - since this is only used in test mode
            // consistency is more important than performance
            bindConsumer().await(10, TimeUnit.SECONDS);
            if (mEventListener != null) {
                flushTimeout = TEST_FLUSH_TIMEOUT;
                Slog.i(TAG, "TestMode enabled " + componentName.flattenToShortString());
                return true;
            }
            return false;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
    public boolean disableTestMode() {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        flushTimeout = FLUSH_TIMEOUT;
        DynamicInstrumentationManager dynamicInstrumentationManager =
                mContext.getSystemService(DynamicInstrumentationManager.class);
        dynamicInstrumentationManager.setDynamicInstrumentationEventConsumer(null);
        try {
            // bind and wait for the binding to complete - since this is only used in test mode
            // consistency is more important than performance
            bindConsumer().await(10, TimeUnit.SECONDS);
            if (mEventListener != null) {
                Slog.i(TAG, "TestMode disabled");
                return true;
            }
            return false;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
    public boolean waitQueueFlushed() {
        mContext.enforceCallingPermission(
                DYNAMIC_INSTRUMENTATION, "Caller must have DYNAMIC_INSTRUMENTATION permission");
        synchronized (mEventBuffer) {
            if (mEventBuffer.isEmpty()) {
                return true;
            }
            try {
                mEventBuffer.wait(flushTimeout * 2);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
        return mEventBuffer.isEmpty();
    }
}
