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

#include <aidl/com/android/uprobestats/IUprobeStatsService.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <android/uprobestats_client.h>
#include <com_android_uprobestats_flags.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <statslog_uprobestats.h>

#include <thread>

using aidl::com::android::uprobestats::IUprobeStatsService;

const char* kUprobeStatsServiceName = "uprobestats_service";

void AUprobestatsClient_startUprobestats(const uint8_t* config, int64_t size) {
  std::vector<uint8_t> config_vec(config, config + size);

  std::thread([config_vec = std::move(config_vec)]() {
    auto log_startup_error = []() {
      android::uprobestats::stats::stats_write(
          android::uprobestats::stats::UPROBE_STATS_INTERNAL_ERROR,
          android::uprobestats::stats::
              UPROBE_STATS_INTERNAL_ERROR__ERROR_TYPE__ERROR_TYPE_SERVICE_STARTUP_FAILED,
          0 /* task_id - not applicable here */
        );
    };

    ndk::SpAIBinder binder =
        ndk::SpAIBinder(AServiceManager_waitForService(kUprobeStatsServiceName));
    // TODO(b/480959242): Remove this fallback once SDK 37 is available.
    if (binder == nullptr) {
      LOG(WARNING) << "Failed to get uprobestats service, falling back to file "
                      "based config";
      const char* filename = "/data/misc/uprobestats-configs/config";
      android::base::WriteStringToFile(
          std::string(reinterpret_cast<const char*>(config_vec.data()),
                      config_vec.size()),
          filename);
      chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      android::base::SetProperty("ctl.start", "uprobestats");
      log_startup_error();
      return;
    }

    auto service = IUprobeStatsService::fromBinder(binder);
    if (!service) {
      LOG(ERROR) << "Failed to get uprobestats service from binder";
      log_startup_error();
      return;
    }

    auto status = service->startTasks(config_vec);
    if (!status.isOk()) {
      LOG(ERROR) << "Failed to start uprobestats: " << status.getMessage();
      log_startup_error();
    }
  }).detach();
}
