/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android/binder_process.h>
#include <android/trace.h>
#include <android_uprobestats_mainline_flags.h>
#include <config.pb.h>
#include <stats_event.h>
#include <stdio.h>

#include <iostream>
#include <string>
#include <thread>

#include "Bpf.h"
#include "ConfigResolver.h"
#include "DebugLog.h"
#include "FlagSelector.h"
#include "Guardrail.h"

using namespace android::uprobestats;

const std::string kGenericBpfMapDetail =
    std::string("GenericInstrumentation_call_detail");
const std::string kGenericBpfMapTimestamp =
    std::string("GenericInstrumentation_call_timestamp");
const std::string kUpdateDeviceIdleTempAllowlistMap =
    std::string("ProcessManagement_update_device_idle_temp_allowlist_records");
const std::string kProcessManagementMap =
    std::string("ProcessManagement_output_buf");
const std::string kMalwareSignalMap = std::string("MalwareSignal_output_buf");
const int kJavaArgumentRegisterOffset = 2;

const std::string kBpfPath = std::string("/sys/fs/bpf/uprobestats/");
std::string prefixBpf(std::string value) { return kBpfPath + value.c_str(); }

struct PollArgs {
  std::string mapPath;
  ::uprobestats::protos::UprobestatsConfig::Task taskConfig;
};

bool startsWith(const std::string& str, const std::string& prefix) {
  return str.length() >= prefix.length() &&
         std::equal(prefix.begin(), prefix.end(), str.begin());
}

void doPoll(PollArgs args) {
  auto mapPath = args.mapPath;
  auto durationSeconds = args.taskConfig.duration_seconds();
  auto duration = std::chrono::seconds(durationSeconds);
  auto startTime = std::chrono::steady_clock::now();
  auto now = startTime;
  while (now - startTime < duration) {
    auto remaining = duration - (std::chrono::steady_clock::now() - startTime);
    auto timeoutMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
            .count());
    if (mapPath.find(kGenericBpfMapDetail) != std::string::npos) {
      LOG_IF_DEBUG("polling for GenericDetail result");
      auto result =
          bpf::pollRingBuf<bpf::CallResult>(mapPath.c_str(), timeoutMs);
      for (auto value : result) {
        LOG_IF_DEBUG("GenericDetail result...");
        LOG_IF_DEBUG("register: pc = " << value.pc);
        for (int i = 0; i < 10; i++) {
          auto reg = value.regs[i];
          LOG_IF_DEBUG("register: " << i << " = " << reg);
        }
        if (!args.taskConfig.has_statsd_logging_config()) {
          LOG_IF_DEBUG("no statsd logging config");
          continue;
        }

        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
        int atom_id = statsd_logging_config.atom_id();
        LOG_IF_DEBUG("attempting to write atom id: " << atom_id);
        AStatsEvent* event = AStatsEvent_obtain();
        AStatsEvent_setAtomId(event, atom_id);
        for (int primitiveArgumentPosition :
             statsd_logging_config.primitive_argument_positions()) {
          int primitiveArgument = value.regs[primitiveArgumentPosition +
                                             kJavaArgumentRegisterOffset];
          LOG_IF_DEBUG("writing argument value: " << primitiveArgument
                                                  << " from position: "
                                                  << primitiveArgumentPosition);
          AStatsEvent_writeInt32(event, primitiveArgument);
        }
        AStatsEvent_write(event);
        AStatsEvent_release(event);
        LOG_IF_DEBUG("successfully wrote atom id: " << atom_id);
      }
    } else if (mapPath.find(kGenericBpfMapTimestamp) != std::string::npos) {
      LOG_IF_DEBUG("polling for GenericTimestamp result");
      auto result =
          bpf::pollRingBuf<bpf::CallTimestamp>(mapPath.c_str(), timeoutMs);
      for (auto value : result) {
        LOG_IF_DEBUG("GenericTimestamp result: event "
                     << value.event << " timestampNs: " << value.timestampNs);
        if (!args.taskConfig.has_statsd_logging_config()) {
          LOG_IF_DEBUG("no statsd logging config");
          continue;
        }
        // TODO: for now, we assume an atom structure of event, then timestamp.
        // We will build a cleaner abstraction for handling "just give me
        // timestamps when X API is called", but we're just trying ot get things
        // working for now.
        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
        int atom_id = statsd_logging_config.atom_id();
        LOG_IF_DEBUG("attempting to write atom id: " << atom_id);
        AStatsEvent* event = AStatsEvent_obtain();
        AStatsEvent_setAtomId(event, atom_id);
        AStatsEvent_writeInt32(event, value.event);
        AStatsEvent_writeInt64(event, value.timestampNs);
        AStatsEvent_write(event);
        AStatsEvent_release(event);
        LOG_IF_DEBUG("successfully wrote atom id: " << atom_id);
      }
    } else if (mapPath.find(kUpdateDeviceIdleTempAllowlistMap) !=
               std::string::npos) {
      LOG_IF_DEBUG("Polling for UpdateDeviceIdleTempAllowlistRecord result");
      auto result = bpf::pollRingBuf<bpf::UpdateDeviceIdleTempAllowlistRecord>(
          mapPath.c_str(), timeoutMs);
      for (auto value : result) {
        LOG_IF_DEBUG("UpdateDeviceIdleTempAllowlistRecord result... "
                     << " changing_uid: " << value.changing_uid
                     << " reason_code: " << value.reason_code << " reason: "
                     << value.reason << " calling_uid: " << value.calling_uid
                     << " mapPath: " << mapPath);
        if (!args.taskConfig.has_statsd_logging_config()) {
          LOG_IF_DEBUG("no statsd logging config");
          continue;
        }
        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
        int atom_id = statsd_logging_config.atom_id();
        AStatsEvent* event = AStatsEvent_obtain();
        AStatsEvent_setAtomId(event, atom_id);
        AStatsEvent_writeInt32(event, value.changing_uid);
        AStatsEvent_writeBool(event, value.adding);
        AStatsEvent_writeInt64(event, value.duration_ms);
        AStatsEvent_writeInt32(event, value.type);
        AStatsEvent_writeInt32(event, value.reason_code);
        AStatsEvent_writeString(event, value.reason);
        AStatsEvent_writeInt32(event, value.calling_uid);
        AStatsEvent_write(event);
        AStatsEvent_release(event);
      }
    } else if (mapPath.find(kProcessManagementMap) != std::string::npos) {
      LOG_IF_DEBUG("Polling for SetUidTempAllowlistStateRecord result");
      auto result = bpf::pollRingBuf<bpf::SetUidTempAllowlistStateRecord>(
          mapPath.c_str(), timeoutMs);
      for (auto value : result) {
        LOG_IF_DEBUG("SetUidTempAllowlistStateRecord result... uid: "
                     << value.uid << " onAllowlist: " << value.onAllowlist
                     << " mapPath: " << mapPath);
        if (!args.taskConfig.has_statsd_logging_config()) {
          LOG_IF_DEBUG("no statsd logging config");
          continue;
        }
        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
        int atom_id = statsd_logging_config.atom_id();
        AStatsEvent* event = AStatsEvent_obtain();
        AStatsEvent_setAtomId(event, atom_id);
        AStatsEvent_writeInt32(event, value.uid);
        AStatsEvent_writeBool(event, value.onAllowlist);
        AStatsEvent_write(event);
        AStatsEvent_release(event);
      }
    } else {
      LOG(ERROR) << "unsupported mapPath: " << mapPath;
      break;
    }
    now = std::chrono::steady_clock::now();
  }
  LOG_IF_DEBUG("finished polling for mapPath: " << mapPath);
}

int main() {
  ATrace_beginSection("uprobestats_cpp::main");
  ABinderProcess_startThreadPool();
  auto config =
      config_resolver::readConfig("/data/misc/uprobestats-configs/config");
  if (!config.has_value()) {
    LOG(ERROR) << "Failed to parse uprobestats config.";
    return 1;
  }
  if (!guardrail::isAllowed(
          config.value(),
          android::base::GetProperty("ro.build.type", "unknown"), true)) {
    LOG(ERROR) << "uprobestats probing config disallowed on this device.";
    return 1;
  }
  auto resolvedTask = config_resolver::resolveSingleTask(config.value());
  if (!resolvedTask.has_value()) {
    LOG(ERROR) << "Failed to parse task";
    return 1;
  }

  LOG_IF_DEBUG("Found task config: " << resolvedTask.value());
  auto resolvedProbeConfigs =
      config_resolver::resolveProbes(resolvedTask.value().taskConfig);
  if (!resolvedProbeConfigs.has_value()) {
    LOG(ERROR) << "Failed to resolve a probe config from task";
    return 1;
  }
  for (auto& resolvedProbe : resolvedProbeConfigs.value()) {
    LOG_IF_DEBUG("Opening bpf perf event from probe: " << resolvedProbe);
    if (resolvedProbe.filename ==
            "prog_MalwareSignal_uprobe_add_bound_client_uid" &&
        !android::uprobestats::mainline::flags::
            uprobestats_monitor_disruptive_app_activities()) {
      LOG(ERROR)
          << "uprobestats_monitor_disruptive_app_activities disabled by flag";
      continue;
    }
    if (resolvedProbe.filename ==
            "prog_MalwareSignal_uprobe_set_component_enabled_setting" &&
        !android::uprobestats::mainline::flags::
            uprobestats_monitor_disruptive_app_activities()) {
      LOG(ERROR)
          << "uprobestats_monitor_disruptive_app_activities disabled by flag";
      continue;
    }
    auto openResult = bpf::bpfPerfEventOpen(
        resolvedProbe.filename.c_str(), resolvedProbe.offset,
        resolvedTask.value().pid,
        prefixBpf(resolvedProbe.probeConfig.bpf_name()).c_str());
    if (openResult != 0) {
      LOG(ERROR) << "Failed to open bpf "
                 << resolvedProbe.probeConfig.bpf_name();
      return 1;
    }
  }

  std::vector<std::thread> threads;
  for (auto mapPath : resolvedTask.value().taskConfig.bpf_maps()) {
    if (mapPath == "map_MalwareSignal_output_buf" &&
        !android::uprobestats::mainline::flags::
            uprobestats_monitor_disruptive_app_activities()) {
      LOG(ERROR)
          << "uprobestats_monitor_disruptive_app_activities disabled by flag";
      continue;
    }
    auto pollArgs =
        PollArgs{prefixBpf(mapPath), resolvedTask.value().taskConfig};
    LOG_IF_DEBUG(
        "Starting thread to collect results from mapPath: " << mapPath);
    threads.emplace_back(doPoll, pollArgs);
  }
  for (auto& thread : threads) {
    thread.join();
  }

  LOG_IF_DEBUG("done.");

  ATrace_endSection();

  return 0;
}
