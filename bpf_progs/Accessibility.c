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
#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <uprobestats_bpf_fns.h>
#include <uprobestats_bpf_structs.h>

DEFINE_BPF_RINGBUF_EXT(output_buf, struct AccessibilityEvent, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/grant_runtime_permission", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE)
(struct pt_regs* ctx) {
  // Permission grants are rare events. We prioritize robust error handling and
  // buffer reservation here to ensure any read failures are reported and the
  // daemon is safely shut down.
  struct AccessibilityEvent* output = bpf_output_buf_reserve();
  if (output == NULL) return 1;

  output->error_code = 0;
  output->variant = 1;
  output->timestamp_ns = bpf_ktime_get_ns();

  int ret = 0;
  ret = recordStringArg(ctx, MAX_STRING_LENGTH, 0, output->package_name);
  if (ret < 0)
    goto out;

  ret = recordStringArg(ctx, MAX_STRING_LENGTH, 1, output->permission_name);

out:
  output->error_code = ret;
  bpf_output_buf_submit(output);
  return 0;
}

const int kBinderDescriptorOffset = 8;
const char kTargetInterfaceDescriptor[MAX_STRING_LENGTH] =
    "android.accessibilityservice.IAccessibilityServiceConnection";

DEFINE_BPF_PROG("uprobe/dispatch_gesture", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE2)
(struct pt_regs* ctx) {
  // This probe is triggered for every Binder transaction served by a Java
  // implementation in system server. To keep overhead to a minimum, we want to
  // avoid calling `bpf_output_buf_reserve` if we don't have to. The only
  // way to communicate an error to userspace is by doing so (and putting an
  // error into the `error_code` field). Therefore, we ignore errors up until we
  // know that we are dealing with the `IAccessibilityServiceConnection`
  // interface, since all we could do is `return 0;` in that case anyway.
  void* this_binder_ptr = (void*)ctx->regs[1];
  void* descriptor_ptr = NULL;
  int ret = bpf_probe_read_user(&descriptor_ptr, 4,
                                this_binder_ptr + kBinderDescriptorOffset);
  (void)ret; // As described above, all we could do is `return 0;` anyway,
             // which is not helpful, so we avoid a branch.
  char interface_descriptor[MAX_STRING_LENGTH] = {0};
  ret = recordString(descriptor_ptr, MAX_STRING_LENGTH, interface_descriptor);
  (void)ret; // As described above, all we could do is `return 0;` anyway,
             // which is not helpful, so we avoid a branch.
  if (strcmp(interface_descriptor, kTargetInterfaceDescriptor) != 0) return 0;

  struct AccessibilityEvent* output = bpf_output_buf_reserve();
  if (output == NULL) return 1;

  output->error_code = 0;
  output->variant = 2;
  output->timestamp_ns = bpf_ktime_get_ns();
  output->uid = ctx->regs[6];
  output->code = ctx->regs[2];

  bpf_output_buf_submit(output);
  return 0;
}

LICENSE("GPL");
