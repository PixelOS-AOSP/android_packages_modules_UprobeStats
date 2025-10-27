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

#define LOG_TAG "uprobestats"

#include <android_uprobestats_mainline_flags.h>

#include "FlagSelector.h"

namespace android {
namespace uprobestats {
namespace flag_selector {

bool enable_uprobestats() {
#ifdef UPROBESTATS_IN_MAINLINE
  return android::uprobestats::mainline::flags::enable_uprobestats();
#else
  return true;
#endif
}

bool uprobestats_support_update_device_idle_temp_allowlist() {
#ifdef UPROBESTATS_IN_MAINLINE
  return android::uprobestats::mainline::flags::
      uprobestats_support_update_device_idle_temp_allowlist();
#else
  return true;
#endif
}

bool executable_method_file_offsets() {
#ifdef UPROBESTATS_IN_MAINLINE
  return android::uprobestats::mainline::flags::
      executable_method_file_offsets();
#else
  return true;
#endif
}

} // namespace flag_selector
} // namespace uprobestats
} // namespace android
