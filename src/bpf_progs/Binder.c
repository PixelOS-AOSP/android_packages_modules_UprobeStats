/*
 * Copyright 2025 The Android Open Source Project
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

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <uprobestats_bpf_fns.h>
#include <uprobestats_bpf_structs.h>

const int kBinderDescriptorOffset = 8;
const char kTargetInterfaceDescriptor[MAX_STRING_LENGTH] =
    "com.android.internal.app.IBatteryStats";
const int kTargetCode = 1; // noteStartSensor

DEFINE_BPF_MAP_EXT(interfaces, HASH, struct BinderInterfaceBpfMapKey,
                   struct BinderCodesBpfMapValue, 5000, AID_UPROBESTATS,
                   AID_UPROBESTATS, 0600, "", "", PRIVATE, BPFLOADER_MIN_VER,
                   BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER,
                   LOAD_ON_USERDEBUG);

DEFINE_BPF_RINGBUF_EXT(output_buf, struct BinderTransaction, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/exec_transact_internal", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE11)
(struct pt_regs *ctx) {
  void *this_binder_ptr = (void *)ctx->regs[1];
  void *descriptor_ptr = NULL;
  struct BinderInterfaceBpfMapKey key = {};
  bpf_probe_read_user(&descriptor_ptr, 4,
                      this_binder_ptr + kBinderDescriptorOffset);
  recordString(descriptor_ptr, MAX_STRING_LENGTH, key.interface_descriptor);

  struct BinderCodesBpfMapValue *value = bpf_interfaces_lookup_elem(&key);
  if (value == NULL)
    return 0;

  for (int i = 0; i < 10; ++i) {
    if (value->codes[i] == 0)
      break;
    if (value->codes[i] != ctx->regs[2])
      continue;

    struct BinderTransaction *output = bpf_output_buf_reserve();
    if (output == NULL)
      return 1;

    memcpy(output->interface_descriptor, key.interface_descriptor,
           sizeof(key.interface_descriptor));
    output->calling_uid = ctx->regs[6];
    output->code = ctx->regs[2];
    output->timestamp_ns = bpf_ktime_get_ns();
    bpf_output_buf_submit(output);
    return 0;
  }

  return 0;
}

LICENSE("GPL");
