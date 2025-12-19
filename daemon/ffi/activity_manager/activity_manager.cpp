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

#include "activity_manager.h"

#include <dlfcn.h>
#include <log/log.h>

#include <mutex>

namespace {
std::once_flag gApiCheckOnceFlag;
bool gApisAreAvailable = false;

void CheckApiAvailability() {
  void* handle = dlopen("libandroid.so", RTLD_LAZY);
  if (handle) {
    gApisAreAvailable =
        dlsym(handle, "AActivityManager_getRunningAppProcesses") != nullptr;
    dlclose(handle);
  } else {
    gApisAreAvailable = false;
  }
}

bool AreApisAvailable() {
  std::call_once(gApiCheckOnceFlag, CheckApiAvailability);
  return gApisAreAvailable;
}
}  // namespace

binder_status_t ffi_AActivityManager_getRunningAppProcesses(
    ARunningAppProcessInfoList** outProcessInfoList) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::AActivityManager_getRunningAppProcesses(outProcessInfoList);
    }
  }
  return -1;
}

AActivityManager_ProcessObserver* ffi_AActivityManager_createProcessObserver(
    void* cookie) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::AActivityManager_createProcessObserver(cookie);
    }
  }
  return nullptr;
}

void ffi_AActivityManager_destroyProcessObserver(
    AActivityManager_ProcessObserver* observer) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_destroyProcessObserver(observer);
    }
  }
}

void ffi_AActivityManager_ProcessObserver_setOnProcessStarted(
    AActivityManager_ProcessObserver* observer,
    AActivityManager_onProcessStarted callback) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_ProcessObserver_setOnProcessStarted(observer, callback);
    }
  }
}

void ffi_AActivityManager_ProcessObserver_setOnForegroundActivitiesChanged(
    AActivityManager_ProcessObserver* observer,
    AActivityManager_onForegroundActivitiesChanged callback) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_ProcessObserver_setOnForegroundActivitiesChanged(
          observer, callback);
    }
  }
}

void ffi_AActivityManager_ProcessObserver_setOnForegroundServicesChanged(
    AActivityManager_ProcessObserver* observer,
    AActivityManager_onForegroundServicesChanged callback) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_ProcessObserver_setOnForegroundServicesChanged(
          observer, callback);
    }
  }
}

void ffi_AActivityManager_ProcessObserver_setOnProcessDied(
    AActivityManager_ProcessObserver* observer,
    AActivityManager_onProcessDied callback) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_ProcessObserver_setOnProcessDied(observer, callback);
    }
  }
}

binder_status_t ffi_AActivityManager_registerProcessObserver(
    AActivityManager_ProcessObserver* observer) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::AActivityManager_registerProcessObserver(observer);
    }
  }
  return -1;
}

void ffi_AActivityManager_unregisterProcessObserver(
    AActivityManager_ProcessObserver* observer) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_unregisterProcessObserver(observer);
    }
  }
}

void ffi_AActivityManager_RunningAppProcessInfoList_destroy(
    const ARunningAppProcessInfoList* list) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      ::AActivityManager_RunningAppProcessInfoList_destroy(list);
    }
  }
}

const ARunningAppProcessInfo*
ffi_AActivityManager_RunningAppProcessInfoList_get(
    const ARunningAppProcessInfoList* list, size_t index) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::AActivityManager_RunningAppProcessInfoList_get(list, index);
    }
  }
  return nullptr;
}

size_t ffi_AActivityManager_RunningAppProcessInfoList_getSize(
    const ARunningAppProcessInfoList* list) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::AActivityManager_RunningAppProcessInfoList_getSize(list);
    }
  }
  return 0;
}

int32_t ffi_ARunningAppProcessInfo_getImportance(
    const ARunningAppProcessInfo* info) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::ARunningAppProcessInfo_getImportance(info);
    }
  }
  // Corresponds to IMPORTANCE_GONE.
  return 1000;
}

const char* const* ffi_ARunningAppProcessInfo_getPackageList(
    const ARunningAppProcessInfo* info, size_t* outNumPackages) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::ARunningAppProcessInfo_getPackageList(info, outNumPackages);
    }
  }
  if (outNumPackages) {
    *outNumPackages = 0;
  }
  return nullptr;
}

pid_t ffi_ARunningAppProcessInfo_getPid(const ARunningAppProcessInfo* info) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::ARunningAppProcessInfo_getPid(info);
    }
  }
  return -1;
}

const char* ffi_ARunningAppProcessInfo_getProcessName(
    const ARunningAppProcessInfo* info) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::ARunningAppProcessInfo_getProcessName(info);
    }
  }
  return nullptr;
}

uid_t ffi_ARunningAppProcessInfo_getUid(const ARunningAppProcessInfo* info) {
  if (AreApisAvailable()) {
    if (__builtin_available(android 37, *)) {
      return ::ARunningAppProcessInfo_getUid(info);
    }
  }
  return -1;
}