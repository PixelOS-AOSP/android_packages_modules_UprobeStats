/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <filesystem>
#include <iostream>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <config.pb.h>
#include <json/json.h>

#include "Art.h"
#include "ConfigResolver.h"
#include "DebugLog.h"
#include "DynamicInstrumentationManager.h"
#include "Process.h"

namespace android {
namespace uprobestats {
namespace config_resolver {

std::ostream &operator<<(std::ostream &os, const ResolvedTask &c) {
  os << "pid: " << c.pid << " taskConfig: " << c.taskConfig.DebugString();
  return os;
}

std::ostream &operator<<(std::ostream &os, const ResolvedProbe &c) {
  os << "filename: " << c.filename << " offset: " << c.offset
     << " probeConfig: " << c.probeConfig.DebugString();
  return os;
}

// Reads probing configuration from a file, which should be the serialized
// bytes of a UprobestatsConfig proto.
std::optional<::uprobestats::protos::UprobestatsConfig>
readConfig(std::string configFilePath) {
  std::string config_str;
  if (!android::base::ReadFileToString(configFilePath, &config_str)) {
    LOG(ERROR) << "Failed to open config file " << configFilePath;
    return {};
  }

  ::uprobestats::protos::UprobestatsConfig config;
  bool success = config.ParseFromString(config_str);
  if (!success) {
    LOG(ERROR) << "Failed to parse file " << configFilePath
               << " to UprobestatsConfig";
    return {};
  }

  return config;
}

std::optional<ResolvedTask>
resolveSingleTask(::uprobestats::protos::UprobestatsConfig config) {
  auto task_count = config.tasks().size();
  if (task_count == 0) {
    LOG(ERROR) << "config has no tasks";
    return {};
  }
  if (task_count > 1) {
    LOG(ERROR) << "config has " << task_count
               << " tasks. Only 1 is supported. The first task is read and the "
                  "rest are ignored.";
  }
  auto taskConfig = config.tasks().Get(0);
  if (!taskConfig.has_duration_seconds()) {
    LOG(ERROR) << "config task has no duration";
    return {};
  }
  if (taskConfig.duration_seconds() <= 0) {
    LOG(ERROR) << "config task cannot have zero or negative duration";
  }
  if (!taskConfig.has_target_process_name()) {
    LOG(ERROR) << "task.target_process_name is required.";
    return {};
  }
  if (taskConfig.target_process_name() != "system_server") {
    LOG(ERROR)
        << "system_server is the only target process currently supported";
    return {};
  }
  auto process_name = taskConfig.target_process_name();
  int pid = process::getPid(process_name);
  if (pid < 0) {
    LOG(ERROR) << "Unable to find pid of " << process_name;
    return {};
  }
  ResolvedTask task;
  task.taskConfig = taskConfig;
  task.pid = pid;
  return task;
}

std::optional<std::vector<ResolvedProbe>>
resolveProbes(::uprobestats::protos::UprobestatsConfig::Task &taskConfig) {
  if (taskConfig.probe_configs().size() == 0) {
    LOG(ERROR) << "task has no probe configs";
    return {};
  }
  std::vector<ResolvedProbe> result;
  for (auto &probeConfig : taskConfig.probe_configs()) {
    if (probeConfig.has_fully_qualified_class_name()) {
      LOG_IF_DEBUG("using getExecutableMethodFileOffsets to retrieve offsets");
      std::vector<std::string> fqParameters(
          probeConfig.fully_qualified_parameters().begin(),
          probeConfig.fully_qualified_parameters().end());
      std::string processName(taskConfig.target_process_name());
      std::string fqcn(probeConfig.fully_qualified_class_name());
      std::string methodName(probeConfig.method_name());
      std::optional<
          dynamic_instrumentation_manager::ExecutableMethodFileOffsets>
          offsets =
              dynamic_instrumentation_manager::getExecutableMethodFileOffsets(
                  processName, fqcn, methodName, fqParameters);
      if (!offsets.has_value()) {
        LOG(ERROR) << "Unable to find method offset for "
                   << probeConfig.fully_qualified_class_name() << "#"
                   << probeConfig.method_name();
        return {};
      }

      ResolvedProbe probe;
      probe.filename = offsets->containerPath;
      probe.offset = offsets->methodOffset;
      probe.probeConfig = probeConfig;
      result.push_back(probe);
      continue;
    }

    LOG_IF_DEBUG("using oatdump to retrieve offsets");
    int offset = 0;
    std::string matched_file_path;
    for (auto &file_path : probeConfig.file_paths()) {
      offset = art::getMethodOffsetFromOatdump(file_path,
                                               probeConfig.method_signature());
      if (offset > 0) {
        matched_file_path = file_path;
        break;
      } else {
        LOG(WARNING) << "File " << file_path << " has no offset for "
                     << probeConfig.method_signature();
      }
    }
    if (offset == 0) {
      LOG(ERROR) << "Unable to find method offset for "
                 << probeConfig.method_signature();
      return {};
    }

    ResolvedProbe probe;
    probe.filename = matched_file_path;
    probe.offset = offset;
    probe.probeConfig = probeConfig;
    result.push_back(probe);
  }

  return result;
}

} // namespace config_resolver
} // namespace uprobestats
} // namespace android
