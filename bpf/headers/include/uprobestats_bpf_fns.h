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

__BEGIN_DECLS

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <uprobestats_bpf_structs.h>

/**
 * Copies the content of a Java String object to <dest>.
 *
 * Assumes the following memory layout of a Java String object:
 * byte offset 8-11: count (this is the length of the string * 2)
 * byte offset 12-15: hash_code
 * byte offset 16 and beyond: string content
 */
static __always_inline __attribute__((unused)) int
recordString(uint8_t *jstring, unsigned int max_length, char *dest) {
  if (jstring == NULL) {
    dest[0] = '\0';
    return 0;
  }
  __u32 count;
  int ret = bpf_probe_read_user(&count, sizeof(count), jstring + 8);
  if (ret < 0)
    return ret;
  count /= 2;
  return bpf_probe_read_user_str(
      dest, max_length < count + 1 ? max_length : count + 1, jstring + 16);
}

/**
 * Copies the content of a Java String object to <dest>, where the Java String
 * is located at <position> in the method invocation argument list (0-based).
 * This only works for the 0th - the 5th arguments. Rest of the arguments need
 * to be accessed via stack pointer using the recordStringArgFromSp() function.
 */
static __always_inline __attribute__((unused)) int
recordStringArg(struct pt_regs *ctx, unsigned int max_length, int position,
                char *dest) {
  uint8_t *jstring = (uint8_t *)ctx->regs[2 + position];
  return recordString(jstring, max_length, dest);
}

/**
 * Copies the content of a Java String object to <dest>, where the Java String
 * address is located in stack frame.
 */
static __always_inline __attribute__((unused)) int
recordStringArgFromSp(struct pt_regs *ctx, unsigned int max_length,
                      int sp_offset, char *dest) {
  void *jstring = NULL;
  int ret = bpf_probe_read_user(&jstring, 4, (void *)ctx->sp + sp_offset);
  if (ret < 0)
    return ret;
  return recordString(jstring, max_length, dest);
}

static __always_inline __attribute__((unused)) uint8_t *
getJitMethodStackFrame(struct pt_regs *ctx) {
  // The first argument of a JIT compiled method is the size of the "stub"
  // method in the stack frame. The next frame is the actual method under
  // instrumentation.
  return (uint8_t*) ctx->sp + ctx->regs[0];
}

/**
 * Loads the content of <length> bytes from the user space address
 * <user_space_address> to <dest> at offset <offset>.
 * TODO(yutingtseng): double check this description is correct.
 */
static __always_inline __attribute__((unused)) int
load(void *dest, int offset, int length, void *user_space_address) {
  long canonical_address = (long)user_space_address & 0x00FFFFFFFFFFFFFF;
  return bpf_probe_read_user(dest, length,
                             (void *)(canonical_address + offset));
}

__END_DECLS
