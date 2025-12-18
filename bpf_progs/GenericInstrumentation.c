/*
 * Copyright 2023 The Android Open Source Project
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
#include <uprobestats_bpf_structs.h>

DEFINE_BPF_RINGBUF_EXT(call_detail_buf, struct CallResult, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_RINGBUF_EXT(call_timestamp_buf, struct CallTimestamp, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/call_detail", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE11)
(struct pt_regs_x86_supported *ctx) {
  struct CallResult result;
  // for whatever reason, reading past register 10 causes bpf verifier to fail
  for (int i = 0; i < 11; i++) {
    result.regs[i] = ctx->regs[i];
  }
  result.pc = ctx->pc;
  struct CallResult *output = bpf_call_detail_buf_reserve();
  if (output == NULL)
    return 1;
  (*output) = result;
  bpf_call_detail_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/call_timestamp_1", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE1)
() {
  struct CallTimestamp result;
  result.event = 1;
  result.timestampNs = bpf_ktime_get_ns();
  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
  if (output == NULL) {
    return 1;
  }
  (*output) = result;
  bpf_call_timestamp_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/call_timestamp_2", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE2)
() {
  struct CallTimestamp result;
  result.event = 2;
  result.timestampNs = bpf_ktime_get_ns();
  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
  if (output == NULL) {
    return 1;
  }
  (*output) = result;
  bpf_call_timestamp_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/call_timestamp_3", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE3)
() {
  struct CallTimestamp result;
  result.event = 3;
  result.timestampNs = bpf_ktime_get_ns();
  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
  if (output == NULL) {
    return 1;
  }
  (*output) = result;
  bpf_call_timestamp_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/call_timestamp_4", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE4)
() {
  struct CallTimestamp result;
  result.event = 4;
  result.timestampNs = bpf_ktime_get_ns();
  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
  if (output == NULL) {
    return 1;
  }
  (*output) = result;
  bpf_call_timestamp_buf_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/call_timestamp_5", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE5)
() {
  struct CallTimestamp result;
  result.event = 5;
  result.timestampNs = bpf_ktime_get_ns();
  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
  if (output == NULL) {
    return 1;
  }
  (*output) = result;
  bpf_call_timestamp_buf_submit(output);
  return 0;
}

LICENSE("GPL");
