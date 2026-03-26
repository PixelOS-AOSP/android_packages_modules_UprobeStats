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

#define LOG_TAG "uprobestats"

#include "bpf.h"

#include <BpfSyscallWrappers.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <linux/perf_event.h>

#include <string>

#include "bpf/BpfRingbuf.h"

struct BpfRingBufHandle {
  std::unique_ptr<android::bpf::BpfRingbufSized> ringbuf;
};

BpfRingBufHandle* bpfRingBufCreate(const char* mapPath, size_t valueSize) {
  auto result = android::bpf::BpfRingbufSized::Create(mapPath, valueSize);
  if (!result.ok()) {
    LOG(ERROR) << "Failed to create BpfRingbufSized: "
               << result.error().message();
    return nullptr;
  }
  return new BpfRingBufHandle{std::move(result.value())};
}

void bpfRingBufDestroy(BpfRingBufHandle* handle) { delete handle; }

int bpfRingBufDiscard(const char *mapPath) {
  auto result = android::bpf::BpfRingbufSized::Create(mapPath, 1);
  if (!result.ok()) {
    if (result.error().code() == ENOENT) {
      return 0;
    }
    LOG(ERROR) << "Failed to open ring buffer " << mapPath << " for discard"
               << ". Error: " << result.error().message();
    return -1;
  }
  return result.value()->discard();
}

int bpfRingBufPoll(BpfRingBufHandle* handle, int timeoutMs,
                   void (*callback)(const void*, void*), void* cookie) {
  if (!handle) {
    return -1;
  }
  if (!handle->ringbuf->wait(timeoutMs)) {
    return 0;
  }
  auto count = handle->ringbuf->ConsumeAll(
      [&](const void* value) { callback(value, cookie); });
  if (!count.ok()) {
    LOG(ERROR) << "Failed to consume events from ring buffer. Error: "
               << count.error().message();
    return -2;
  }
  return count.value();
}

const char *PMU_TYPE_FILE = "/sys/bus/event_source/devices/uprobe/type";

int bpfPerfEventOpen(const char *filename, int offset, int pid,
                     const char *bpfProgramPath) {
  android::base::unique_fd bpfProgramFd(
      android::bpf::retrieveProgram(bpfProgramPath));
  if (bpfProgramFd < 0) {
    LOG(ERROR) << "retrieveProgram failed";
    return -1;
  }
  std::string typeStr;
  if (!android::base::ReadFileToString(PMU_TYPE_FILE, &typeStr)) {
    LOG(ERROR) << "Failed to open pmu type file";
    return -1;
  }
  int pmu_type = (int)strtol(typeStr.c_str(), NULL, 10);
  struct perf_event_attr attr = {};
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  attr.config2 = offset;
  attr.size = sizeof(attr);
  attr.type = pmu_type;
  attr.config1 = android::bpf::ptr_to_u64((void *)filename);
  attr.exclude_kernel = true;
  android::base::unique_fd perfEventFd(syscall(__NR_perf_event_open, &attr, pid,
                                                 /*cpu=*/-1,
                                                 /* group_fd=*/-1, PERF_FLAG_FD_CLOEXEC));
  if (perfEventFd < 0) {
    LOG(ERROR) << "syscall(__NR_perf_event_open) failed. "
               << "perfEventFd: " << perfEventFd.get() << " "
               << "error: " << strerror(errno);
    return -1;
  }
  if (ioctl(perfEventFd.get(), PERF_EVENT_IOC_SET_BPF, int(bpfProgramFd)) < 0) {
    LOG(ERROR) << "PERF_EVENT_IOC_SET_BPF failed. " << strerror(errno);
    return -1;
  }
  if (ioctl(perfEventFd.get(), PERF_EVENT_IOC_ENABLE, 0) < 0) {
    LOG(ERROR) << "PERF_EVENT_IOC_ENABLE failed. " << strerror(errno);
    return -1;
  }
  return perfEventFd.release();
}

struct BpfMapHandle {
  android::base::unique_fd map_fd;
};

int bpfMapOpenExclusiveRW(const char *path, BpfMapHandle **handle_out) {
  android::base::unique_fd map_fd(android::bpf::mapRetrieveExclusiveRW(path));
  if (map_fd < 0) {
    PLOG(ERROR) << "failed to open bpf map " << path;
    return -errno;
  }
  *handle_out = new BpfMapHandle{std::move(map_fd)};
  return 0;
}

void bpfMapClose(BpfMapHandle *handle) { delete handle; }

int bpfMapUpdateElem(BpfMapHandle *handle, const void *key, const void *value,
                     uint64_t flags) {
  if (!handle)
    return -EINVAL;
  int res = android::bpf::writeToMapEntry(handle->map_fd, key, value, flags);
  if (res < 0)
    return -errno;
  return res;
}

int bpfMapLookupElem(BpfMapHandle *handle, const void *key, void *value) {
  if (!handle)
    return -EINVAL;
  // NOTE: this is not ideal, as we hold an exclusive lock for a read operation.
  // A more complex implementation could store the lock type in the handle and
  // conditionally use mapRetrieveRW vs mapRetrieveExclusiveRW.
  // For now, we accept this limitation as the primary use case is write-only
  // during setup, followed by read-only during teardown, and we have no
  // existing use case where concurrent threads would need to access
  // the same map.
  int res = android::bpf::findMapEntry(handle->map_fd, key, value);
  if (res < 0)
    return -errno;
  return res;
}

int bpfMapDeleteElem(BpfMapHandle *handle, const void *key) {
  if (!handle)
    return -EINVAL;
  int res = android::bpf::deleteMapEntry(handle->map_fd, key);
  if (res < 0)
    return -errno;
  return res;
}

int bpfMapGetFirstKey(BpfMapHandle *handle, void *firstKey) {
  if (!handle)
    return -EINVAL;
  // NOTE: this is not ideal, as we hold an exclusive lock for a read operation.
  // A more complex implementation could store the lock type in the handle and
  // conditionally use mapRetrieveRW vs mapRetrieveExclusiveRW.
  // For now, we accept this limitation as the primary use case is write-only
  // during setup, followed by read-only during teardown, and we have no
  // existing use case where concurrent threads would need to access
  // the same map.
  int res = android::bpf::getFirstMapKey(handle->map_fd, firstKey);
  if (res < 0)
    return -errno;
  return res;
}
