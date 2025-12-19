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
#pragma once

#include <android/activity_manager.h>
#include <android/binder_status.h>
#include <stdbool.h>

__BEGIN_DECLS

binder_status_t ffi_AActivityManager_getRunningAppProcesses(
        ARunningAppProcessInfoList* _Nullable* _Nonnull outProcessInfoList);

AActivityManager_ProcessObserver* _Nullable ffi_AActivityManager_createProcessObserver(
        void* _Nonnull cookie);

void ffi_AActivityManager_destroyProcessObserver(
        AActivityManager_ProcessObserver* _Nonnull observer);

void ffi_AActivityManager_ProcessObserver_setOnProcessStarted(
        AActivityManager_ProcessObserver* _Nonnull observer,
        AActivityManager_onProcessStarted _Nullable callback);

void ffi_AActivityManager_ProcessObserver_setOnForegroundActivitiesChanged(
        AActivityManager_ProcessObserver* _Nonnull observer,
        AActivityManager_onForegroundActivitiesChanged _Nullable callback);

void ffi_AActivityManager_ProcessObserver_setOnForegroundServicesChanged(
        AActivityManager_ProcessObserver* _Nonnull observer,
        AActivityManager_onForegroundServicesChanged _Nullable callback);

void ffi_AActivityManager_ProcessObserver_setOnProcessDied(
        AActivityManager_ProcessObserver* _Nonnull observer,
        AActivityManager_onProcessDied _Nullable callback);

binder_status_t ffi_AActivityManager_registerProcessObserver(
        AActivityManager_ProcessObserver* _Nonnull observer);

void ffi_AActivityManager_unregisterProcessObserver(
        AActivityManager_ProcessObserver* _Nonnull observer);

void ffi_AActivityManager_RunningAppProcessInfoList_destroy(
        const ARunningAppProcessInfoList* _Nullable list);

const ARunningAppProcessInfo* _Nullable ffi_AActivityManager_RunningAppProcessInfoList_get(
        const ARunningAppProcessInfoList* _Nonnull list, size_t index);

size_t ffi_AActivityManager_RunningAppProcessInfoList_getSize(
        const ARunningAppProcessInfoList* _Nonnull list);

int32_t ffi_ARunningAppProcessInfo_getImportance(const ARunningAppProcessInfo* _Nonnull info);

const char* _Nonnull const* _Nullable ffi_ARunningAppProcessInfo_getPackageList(
        const ARunningAppProcessInfo* _Nonnull info, size_t* _Nonnull outNumPackages);

pid_t ffi_ARunningAppProcessInfo_getPid(const ARunningAppProcessInfo* _Nonnull info);

const char* _Nonnull ffi_ARunningAppProcessInfo_getProcessName(
        const ARunningAppProcessInfo* _Nonnull info);

uid_t ffi_ARunningAppProcessInfo_getUid(const ARunningAppProcessInfo* _Nonnull info);

__END_DECLS
