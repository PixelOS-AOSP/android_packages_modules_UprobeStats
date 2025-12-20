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

DEFINE_BPF_RINGBUF_EXT(output_buf_aot,
                       struct UpdateDeviceIdleTempAllowlistRecord, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/update_device_idle_temp_allowlist", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE3)
(struct pt_regs* ctx) {
  struct UpdateDeviceIdleTempAllowlistRecord* output =
      bpf_output_buf_aot_reserve();
  if (output == NULL) return 1;

  // For AOT code we're instrumentiong the method directly.
  // Identifier is just the pc.
  output->method_identifier = ctx->pc;

  output->changing_uid = ctx->regs[3];
  output->adding = ctx->regs[4];
  output->duration_ms = ctx->regs[5];
  output->type = ctx->regs[6];
  output->reason_code = ctx->regs[7];

  // The <reason> argument is located at offset=40 in stack frame. This is
  // calculated as 12 + sizeof(previous arguments). There are 6 preceding
  // arguments all of which is 4 bytes each except for <long durationMs> which
  // is 8 bytes. Therefore the offset is 12 + 5 * 4 + 8 = 40
  recordStringArgFromSp(ctx, 256, 40, output->reason);

  // The <calling_uid> argument follows <reason> immediately and therefore has
  // an offset that's 4 more bytes larger.
  bpf_probe_read_user(&output->calling_uid, 4, (void*)ctx->sp + 44);

  bpf_output_buf_aot_submit(output);
  return 0;
}

DEFINE_BPF_RINGBUF_EXT(output_buf_jit, struct StartActivityAsUser, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/start_activity_as_user", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE11)
(struct pt_regs* ctx) {
  struct StartActivityAsUser* output = bpf_output_buf_jit_reserve();
  if (output == NULL) return 1;

  // The first entry in the stack frame is the method identifier.
  bpf_probe_read_user(&output->method_identifier,
                      sizeof(output->method_identifier), (void*)ctx->sp);

  bpf_probe_read_user(&output->x0, sizeof(output->x0), (void*)ctx->regs[0]);

  /// Calling package is the 2nd argument.
  recordStringArg(ctx, MAX_STRING_LENGTH, 1, output->calling_package);

  uint8_t* sf = getJitMethodStackFrame(ctx);

  // The request_code is the 8th argument, which will be:
  // 12 + sizeof(preceding arguments):
  //
  // 1. android.app.IApplicationThread (+4 = 16) +
  // 2. java.lang.String (+4 = 20) +
  // 3. java.lang.String (+4 = 24) +
  // 4. android.content.Intent (+4 = 28)
  // 5. java.lang.String (+4 = 32)
  // 6. android.os.IBinder (+4 = 36)
  // 7. java.lang.String (+4 = 40)
  //
  // + the frame offset, since this method is JIT compiled.
  bpf_probe_read_user(&output->request_code, sizeof(output->request_code),
                      sf + 40);
  // The start_flags is the 9th argument, which will be:
  // 12 + sizeof(preceding arguments):
  //
  // 1. android.app.IApplicationThread (+4 = 16) +
  // 2. java.lang.String (+4 = 20) +
  // 3. java.lang.String (+4 = 24) +
  // 4. android.content.Intent (+4 = 28)
  // 5. java.lang.String (+4 = 32)
  // 6. android.os.IBinder (+4 = 36)
  // 7. java.lang.String (+4 = 40)
  // 8. int (+4 = 44)
  //
  // + the frame offset, since this method is JIT compiled.
  bpf_probe_read_user(&output->start_flags, sizeof(output->start_flags),
                      sf + 44);
  // The user_id is the 12th argument, which will be:
  // 12 + sizeof(preceding arguments):
  //
  // 1. android.app.IApplicationThread (+4 = 16) +
  // 2. java.lang.String (+4 = 20) +
  // 3. java.lang.String (+4 = 24) +
  // 4. android.content.Intent (+4 = 28)
  // 5. java.lang.String (+4 = 32)
  // 6. android.os.IBinder (+4 = 36)
  // 7. java.lang.String (+4 = 40)
  // 8. int (+4 = 44)
  // 9. int (+4 = 48)
  // 10. android.app.ProfilerInfo (+4 = 52)
  // 11. android.os.Bundle (+4 = 56)
  //
  // + the frame offset, since this method is JIT compiled.
  bpf_probe_read_user(&output->user_id, sizeof(output->user_id), sf + 56);
  // The validate_incoming_user is the 13th argument, which will be:
  // 12 + sizeof(preceding arguments):
  //
  // 1. android.app.IApplicationThread (+4 = 16) +
  // 2. java.lang.String (+4 = 20) +
  // 3. java.lang.String (+4 = 24) +
  // 4. android.content.Intent (+4 = 28)
  // 5. java.lang.String (+4 = 32)
  // 6. android.os.IBinder (+4 = 36)
  // 7. java.lang.String (+4 = 40)
  // 8. int (+4 = 44)
  // 9. int (+4 = 48)
  // 10. android.app.ProfilerInfo (+4 = 52)
  // 11. android.os.Bundle (+4 = 56)
  // 12. int (+4 = 60)
  //
  // + the frame offset, since this method is JIT compiled.
  bpf_probe_read_user(&output->validate_incoming_user,
                      sizeof(output->validate_incoming_user), sf + 60);

  bpf_output_buf_jit_submit(output);
  return 0;
}

LICENSE("GPL");
