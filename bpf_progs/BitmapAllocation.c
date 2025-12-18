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
#include <uprobestats_bpf_fns.h>
#include <uprobestats_bpf_structs.h>

DEFINE_BPF_RINGBUF_EXT(output_buf, __u64, 4096, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "",
                       PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER,
                       LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/bitmap_constructor_heap", AID_UPROBESTATS, AID_UPROBESTATS, BPF_KPROBE2)
(__unused void* this_ptr, __unused void* buffer_address, __unused __u32 size) {
    __u64* output = bpf_output_buf_reserve();
    if (output == NULL) return 1;
    (*output) = 123;
    bpf_output_buf_submit(output);
    return 0;
}

struct BitmapKey {
  __u64 tgid;
  void* native_ptr;
};

DEFINE_BPF_MAP_EXT(active_bitmaps, HASH, struct BitmapKey, bool, 5000,
                   AID_UPROBESTATS, AID_UPROBESTATS, 0060, "", "", PRIVATE,
                   BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                   LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_RINGBUF_EXT(output, struct BitmapEvent, 16 * 1024,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/bitmap_creation", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE3)
(struct pt_regs *ctx) {

  struct BitmapEvent *output = bpf_output_reserve();
  if (output == NULL)
    return 1;
  output->width = ctx->regs[4];
  output->height = ctx->regs[5];

  uint8_t *bitmap_wrapper_ptr = (uint8_t *)(ctx->regs[3]);
  uint8_t *bitmap_ptr;
  // The first 8 bytes of a BitmapWrapper object is the pointer to the
  // underlying Bitmap.
  load(&bitmap_ptr, 0, 8, bitmap_wrapper_ptr);
  // 0x78 is the offset of pixel_storage_type into a Bitmap object.
  load(&output->pixel_storage_type, 0x78, 4, bitmap_ptr);

  bpf_output_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/bitmap_creation_for_snapshot", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE4)
(struct pt_regs *ctx) {

  struct BitmapEvent *output = bpf_output_reserve();
  if (output == NULL)
    return 1;
  output->width = ctx->regs[4];
  output->height = ctx->regs[5];

  uint8_t *bitmap_wrapper_ptr = (uint8_t *)(ctx->regs[3]);
  uint8_t *bitmap_ptr;
  // The first 8 bytes of a BitmapWrapper object is the pointer to the
  // underlying Bitmap.
  load(&bitmap_ptr, 0, 8, bitmap_wrapper_ptr);
  // 0x78 is the offset of pixel_storage_type into a Bitmap object.
  load(&output->pixel_storage_type, 0x78, 4, bitmap_ptr);

  int heap_size;
  load(&heap_size, 152, 4, bitmap_ptr);
  output->bitmap_size = heap_size;

  output->type = K_BITMAP_EVENT_TYPE_ALLOCATION;
  output->native_ptr = (void*)bitmap_wrapper_ptr;

  bool active = true;
  struct BitmapKey bitmap_key;
  bitmap_key.tgid = bpf_get_current_pid_tgid() >> 32;
  bitmap_key.native_ptr = bitmap_wrapper_ptr;
  bpf_active_bitmaps_update_elem(&bitmap_key, &active, BPF_NOEXIST);

  bpf_output_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/apply_free_function", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE5)
(struct pt_regs *ctx) {
  uint8_t *native_ptr;
  bpf_probe_read_user(&native_ptr, 8, (void *)(ctx->regs[1] + 16));

  struct BitmapKey bitmap_key;
  bitmap_key.tgid = bpf_get_current_pid_tgid() >> 32;
  bitmap_key.native_ptr = native_ptr;
  if (!bpf_active_bitmaps_lookup_elem(&bitmap_key)) {
    return 0;
  }
  bpf_active_bitmaps_delete_elem(&bitmap_key);

  struct BitmapEvent *output = bpf_output_reserve();
  if (output == NULL)
    return 1;
  output->type = K_BITMAP_EVENT_TYPE_DEALLOCATION;
  output->native_ptr = (void*)native_ptr;
  bpf_output_submit(output);
  return 0;
}

const int kComponentNameClassOffset = 8;

DEFINE_BPF_PROG("uprobe/activity_perform_start", AID_UPROBESTATS,
                AID_UPROBESTATS, BPF_KPROBE6)
(struct pt_regs *ctx) {
  struct BitmapEvent *output = bpf_output_reserve();
  if (output == NULL)
    return 1;
  output->type = K_BITMAP_EVENT_TYPE_ACTIVITY_START;

  uint8_t *component_name_ptr = 0;
  bpf_probe_read_user(&component_name_ptr, 4, (void *)(ctx->regs[1] + 76));

  void *intent_component_name_class_ptr = NULL;
  bpf_probe_read_user(&intent_component_name_class_ptr, 4,
                      component_name_ptr + kComponentNameClassOffset);
  recordString(intent_component_name_class_ptr, MAX_STRING_LENGTH,
               output->activity_name);

  bpf_output_submit(output);
  return 0;
}

DEFINE_BPF_PROG("uprobe/create_scaled_bitmap", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE7)
(struct pt_regs *ctx) {

  struct BitmapEvent *output = bpf_output_reserve();
  if (output == NULL)
    return 1;
  output->scaled_width = ctx->regs[2];
  output->scaled_height = ctx->regs[3];

  uint8_t *bitmap_java_object_ptr = (uint8_t *)(ctx->regs[1]);
  load(&output->width, 64, 4, bitmap_java_object_ptr);
  load(&output->height, 60, 4, bitmap_java_object_ptr);

  uint8_t *bitmap_wrapper_ptr = 0;
  load(&bitmap_wrapper_ptr, 40, 4, bitmap_java_object_ptr);
  uint8_t *bitmap_ptr;
  // The first 8 bytes of a BitmapWrapper object is the pointer to the
  // underlying Bitmap.
  load(&bitmap_ptr, 0, 8, bitmap_wrapper_ptr);
  // 0x78 is the offset of pixel_storage_type into a Bitmap object.
  load(&output->pixel_storage_type, 0x78, 4, bitmap_ptr);

  int heap_size;
  load(&heap_size, 152, 4, bitmap_ptr);
  output->bitmap_size = heap_size;

  output->type = K_BITMAP_EVENT_TYPE_BITMAP_SCALED;
  output->native_ptr = (void*)bitmap_wrapper_ptr;

  bpf_output_submit(output);
  return 0;
}

LICENSE("GPL");
