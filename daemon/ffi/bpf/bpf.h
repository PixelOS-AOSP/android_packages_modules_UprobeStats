
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

#include <sys/types.h>

__BEGIN_DECLS

typedef struct BpfMapHandle BpfMapHandle;

int pollRingBuf(const char *mapPath, int timeoutMs, size_t valueSize,
                void (*callback)(const void *, void *), void *cookie);
int bpfPerfEventOpen(const char *filename, int offset, int pid,
                     const char *bpfProgramPath);

int bpfMapOpenExclusiveRW(const char *path, BpfMapHandle **handle_out);
void bpfMapClose(BpfMapHandle *handle);
int bpfMapUpdateElem(BpfMapHandle *handle, const void *key, const void *value,
                     uint64_t flags);
int bpfMapLookupElem(BpfMapHandle *handle, const void *key, void *value);
int bpfMapDeleteElem(BpfMapHandle *handle, const void *key);
int bpfMapGetFirstKey(BpfMapHandle *handle, void *firstKey);

__END_DECLS
