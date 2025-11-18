/*
 * Copyright (c) 2025, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 package com.android.uprobestats;

import com.android.uprobestats.Event;

/**
 * Binder interface to communicate with the UprobeStatsBridgeService.
 *
 * @hide
 */
interface IUprobeStatsBridgeService {
  /**
   * Returns true if the given package name and class name represent a launcher activity.
   *
   * @param packageName The package name of the activity.
   * @param className The class name of the activity.
   * @param matchDisabled Whether to match disabled components.
   * @return True if the given package name and class name represent a launcher activity.
   */
  @PermissionManuallyEnforced
  boolean isLauncherActivity(in String packageName, in String className, boolean matchDisabled);
  /**
   * Returns the uid for the given package name. If the package name is not found
   * (e.g. a system package like "shell" is passed), returns -1.
   *
   * @param packageName The package name of the package.
   * @return The uid for the given package name.
   */
  @PermissionManuallyEnforced
  int getUidForPackage(in String packageName);
  /**
   * Returns true if the given package name has an accessibility service.
   *
   * @param packageName The package name of the package.
   * @return True if the given package name has an accessibility service.
   */
  @PermissionManuallyEnforced
  boolean packageHasEnabledAccessibilityService(in String packageName);
  /** Share a protection log event */
  @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
  void enqueueEvent(in Event data, in boolean flush);
  /** Enable test mode - only used for testing */
  @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
  boolean enableTestMode(in String packageName, in String className);
  /** Disable test mode - only used for testing */
  @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
  boolean disableTestMode();
  /** Wait until queue is flushed - only used for testing */
  @PermissionManuallyEnforced // @EnforcePermission("DYNAMIC_INSTRUMENTATION")
  boolean waitQueueFlushed();
}
