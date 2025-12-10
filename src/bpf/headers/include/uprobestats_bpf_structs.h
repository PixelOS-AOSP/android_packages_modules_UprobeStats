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

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#define MAX_STRING_LENGTH 128

__BEGIN_DECLS

// TODO(b/408763304): use libbpf instead of redefining pt_regs, which is defined
// by the kernel and architecture specific.
// We don't use `#ifdef` here because there are bpf programs that depend on
// a field (`sp`), which isn't defined on the x86 version, and I'm not even sure
// where in the struct that field should be (or if it just has a different
// name). Thus, we have limited test coverage on x86 (one test, at time of
// writing). This is really unforunate, and also liable to break on future
// kernels. We should probably prioritize migrating to libbpf sooner than later.
struct pt_regs { // really, specific to arm64, but named for the struct we
                 // should be getting from elsewhere.
  unsigned long regs[31];
  unsigned long sp;
  unsigned long pc;
  unsigned long pr;
  unsigned long sr;
  unsigned long gbr;
  unsigned long mach;
  unsigned long macl;
  long tra;
};
struct pt_regs_x86_supported { // used only in bpf programs that need to compile
                               // on x86 for the sake of tests.
  unsigned long regs[16];
  unsigned long pc;
  unsigned long pr;
  unsigned long sr;
  unsigned long gbr;
  unsigned long mach;
  unsigned long macl;
  long tra;
};

struct CallTimestamp {
  unsigned int event;
  unsigned long timestampNs;
};

struct CallResult {
  unsigned long pc;
  unsigned long regs[10];
};

struct SetUidTempAllowlistStateRecord {
  uint64_t uid;
  bool onAllowlist;
};

struct UpdateDeviceIdleTempAllowlistRecord {
  unsigned long method_identifier;
  int changing_uid;
  bool adding;
  long duration_ms;
  int type;
  int reason_code;
  char reason[256];
  int calling_uid;
};

struct BindServiceLocked {
  char intent_action[MAX_STRING_LENGTH];
  char intent_package[MAX_STRING_LENGTH];
  char intent_component_name_package[MAX_STRING_LENGTH];
  char intent_component_name_class[MAX_STRING_LENGTH];
  long bind_flags;
  char calling_package[MAX_STRING_LENGTH];
};

struct ComponentEnabledSetting {
  char package_name[MAX_STRING_LENGTH];
  char class_name[MAX_STRING_LENGTH];
  int new_state;
  char calling_package_name[MAX_STRING_LENGTH];
};

struct ProcessChange {
  int pid;
  int uid;
  char process_name[256];
};

const uint32_t K_BITMAP_EVENT_TYPE_ALLOCATION = 0;
const uint32_t K_BITMAP_EVENT_TYPE_DEALLOCATION = 1;
const uint32_t K_BITMAP_EVENT_TYPE_ACTIVITY_START = 2;
const uint32_t K_BITMAP_EVENT_TYPE_BITMAP_SCALED = 3;

struct BitmapEvent {
  uint32_t type;
  uint32_t width;
  uint32_t height;
  uint32_t scaled_width;
  uint32_t scaled_height;
  uint32_t pixel_storage_type;
  uint32_t bitmap_size;
  void *native_ptr;
  char activity_name[128];
};

struct BinderTransaction {
  char interface_descriptor[MAX_STRING_LENGTH];
  unsigned long code;
  int calling_uid;
  unsigned long timestamp_ns;
};

struct BinderInterfaceBpfMapKey {
  char interface_descriptor[MAX_STRING_LENGTH];
};

struct BinderCodesBpfMapValue {
  unsigned long codes[10];
};

struct StartActivityAsUser {
  unsigned long method_identifier;
  char calling_package[MAX_STRING_LENGTH];
  int request_code;
  int start_flags;
  int user_id;
  int validate_incoming_user;
  unsigned long x0;
};

struct AccessibilityEvent {
  unsigned long timestamp_ns;
  int variant; // 1 == runtime permission grant, 2 == a11y service connection
  char package_name[MAX_STRING_LENGTH]; // runtime permission grant
  char permission_name[MAX_STRING_LENGTH]; // runtime permission grant
  int uid; // a11y service connection
  int code; // a11y service connection
};

__END_DECLS
