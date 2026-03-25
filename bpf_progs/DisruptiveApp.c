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

DEFINE_BPF_RINGBUF_EXT(BindServiceLocked_output_buf, struct BindServiceLocked,
                       4096, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "",
                       PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_RINGBUF_EXT(ComponentEnabledSetting_output_buf,
                       struct ComponentEnabledSetting, 4096, AID_UPROBESTATS,
                       AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

// Offsets of fields in Intent: kIntent<FieldName>Offset
const int kIntentPackageOffset = 48;
const int kIntentComponentNameOffset = 20;
const int kIntentActionOffset = 8;
// Offsets of fields in ComponentName: kComponentName<FieldName>Offset
const int kComponentNameClassOffset = 8;
const int kComponentNamePackageOffset = 12;
// The <callingPackage> argument is located at offset=60 in stack frame. This
// is calculated as 12 + sizeof(previous arguments). There are 11 preceding
// arguments all of which is 4 bytes each except for <long flags> which
// is 8 bytes. Therefore the offset is:
// 12 + (4 * 10) + 8 = 60
const int kCallingPackageStackFrameOffset = 60;

const long kBindAllowBackgroundActivityStartsFlag =
    0x00100000;  // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS

DEFINE_BPF_PROG("uprobe/bind_service_locked", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE2)
(struct pt_regs *ctx) {
  long bind_flags = ctx->regs[7];
  bool has_bal_flag = (bind_flags & kBindAllowBackgroundActivityStartsFlag) != 0;
  if (!has_bal_flag) {
    return 0;
  }

  struct BindServiceLocked *output = bpf_BindServiceLocked_output_buf_reserve();
  if (output == NULL)
    return 1;

  output->error_code = 0;
  output->bind_flags = bind_flags;

  int ret = 0;
  void *intent_ptr = (void *)ctx->regs[4];
  if (intent_ptr == NULL) {
    ret = -EFAULT;
    goto out;
  }

  void *intent_package_name_ptr = NULL;
  ret = bpf_probe_read_user(&intent_package_name_ptr, 4,
                            intent_ptr + kIntentPackageOffset);
  if (ret < 0)
    goto out;

  ret = recordString(intent_package_name_ptr, MAX_STRING_LENGTH,
                     output->intent_package);
  if (ret < 0)
    goto out;

  void *intent_action_ptr = NULL;
  ret = bpf_probe_read_user(&intent_action_ptr, 4,
                            intent_ptr + kIntentActionOffset);
  if (ret < 0)
    goto out;

  ret =
      recordString(intent_action_ptr, MAX_STRING_LENGTH, output->intent_action);
  if (ret < 0)
    goto out;

  void *component_name_ptr = NULL;
  ret = bpf_probe_read_user(&component_name_ptr, 4,
                            intent_ptr + kIntentComponentNameOffset);
  if (ret < 0)
    goto out;
  if (component_name_ptr == NULL) {
    ret = -EFAULT;
    goto out;
  }

  void *intent_component_name_package_ptr = NULL;
  ret = bpf_probe_read_user(&intent_component_name_package_ptr, 4,
                            component_name_ptr + kComponentNamePackageOffset);
  if (ret < 0)
    goto out;

  ret = recordString(intent_component_name_package_ptr, MAX_STRING_LENGTH,
                     output->intent_component_name_package);
  if (ret < 0)
    goto out;

  void *intent_component_name_class_ptr = NULL;
  ret = bpf_probe_read_user(&intent_component_name_class_ptr, 4,
                            component_name_ptr + kComponentNameClassOffset);
  if (ret < 0)
    goto out;

  ret = recordString(intent_component_name_class_ptr, MAX_STRING_LENGTH,
                     output->intent_component_name_class);
  if (ret < 0)
    goto out;

  ret = recordStringArgFromSp(ctx, MAX_STRING_LENGTH,
                              kCallingPackageStackFrameOffset,
                              output->calling_package);

out:
  output->error_code = ret;
  bpf_BindServiceLocked_output_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/set_component_enabled_setting", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE3)
(struct pt_regs *ctx) {
  struct ComponentEnabledSetting *output =
      bpf_ComponentEnabledSetting_output_buf_reserve();
  if (output == NULL)
    return 1;

  output->error_code = 0;
  int ret = 0;
  void *component_name_ptr = (void *)ctx->regs[2];
  if (component_name_ptr == NULL) {
    ret = -EFAULT;
    goto out;
  }

  void *class_name = NULL;
  void *package_name = NULL;

  ret = bpf_probe_read_user(&class_name, 4,
                            component_name_ptr + kComponentNameClassOffset);
  if (ret < 0)
    goto out;

  ret = recordString(class_name, 64, output->class_name);
  if (ret < 0)
    goto out;

  ret = bpf_probe_read_user(&package_name, 4,
                            component_name_ptr + kComponentNamePackageOffset);
  if (ret < 0)
    goto out;

  ret = recordString(package_name, 64, output->package_name);
  if (ret < 0)
    goto out;

  void *calling_package_name = (void *)ctx->regs[6];
  ret = recordString(calling_package_name, 64, output->calling_package_name);
  if (ret < 0)
    goto out;

  output->new_state = ctx->regs[3];

out:
  output->error_code = ret;
  bpf_ComponentEnabledSetting_output_buf_submit(output);
  return 0;
}

LICENSE("GPL");
