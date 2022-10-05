/*
 * Copyright (c) 2021 Morpheus Authors
 *
 * Author: Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MorpheusCompiler.h"
#include "macro_logger.h"
#include "bpf_module.h"
#include "api/BPF.h"
#include <fstream>
#include <iostream>

#include <yaml-cpp/node/node.h>
#define CONFIGFILEDIR "/etc/morpheus"
#define CONFIGFILENAME "morpheus.yaml"
#define CONFIGFILE (CONFIGFILEDIR "/" CONFIGFILENAME)

namespace ebpf {

    MorpheusCompiler::MorpheusCompiler() : trace_guard_prog(new ebpf::BPF()), quit_thread_(false),
                                               initialized_(false), engine_(time(nullptr)) {
      init();
      max_offloaded_entries_ = config_.max_offloaded_entries;
      dynamic_compiler_enabled_ = false;

      if (config_.enable_guard && !config_.enable_guards_update) {
        assert(false && "You cannot enable the guard update without enabling the guards");
      }
    }

    int MorpheusCompiler::init() {
      initlogger();
      read_config_file(CONFIGFILE);

      logger->info("Configuration file loaded");

      logger->set_level(get_config().log_level);

      initialized_ = true;
      return 0;
    }

    MorpheusCompiler::~MorpheusCompiler() {}

    void MorpheusCompiler::create_config_file(std::string path) {
      mkdir(CONFIGFILEDIR, 0755);
      std::ofstream file(path);
      if (!file.good()) {
        throw std::runtime_error("Error creating configuration file");
      }

      struct MorpheusConfigStruct defaultConfig;
      YAML::Node node;  // starts out as null
      node["Morpheus"] = defaultConfig;

      file << node;
      file.flush();
      file.close();
    }

    void MorpheusCompiler::read_config_file(std::string path) {
      logger->info("loading configuration from {}", path);
      std::ifstream file(path);
      if (!file.good()) {
        logger->warn("Default configuration file ({}) for Morpheus not found, " 
                      "creating a new file with default parameters", CONFIGFILE);
        create_config_file(CONFIGFILE);
      }
      file.close();

      YAML::Node config = YAML::LoadFile(path);
      struct MorpheusConfigStruct readConfig = config["Morpheus"].as<MorpheusConfigStruct>();
      config_ = readConfig;
    }

    const struct ebpf::MorpheusConfigStruct &MorpheusCompiler::get_config() {
      return config_;
    }

    void MorpheusCompiler::initlogger() {
      console = std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>();
      std::vector<spdlog::sink_ptr> sinks {console};
      logger = std::make_shared<spdlog::logger>("Morpheus", sinks.begin(), sinks.end());
      logger->flush_on(spdlog::level::trace);
      spdlog::register_logger(logger);
    }

    unsigned int MorpheusCompiler::getMaxOffloadedEntries() {
      return max_offloaded_entries_;
    }

    void MorpheusCompiler::setMaxOffloadedEntries(unsigned int entries) {
      max_offloaded_entries_ = entries;
    }

    bool MorpheusCompiler::dynamicCompilerEnabled() {
      return dynamic_compiler_enabled_;
    }

    void MorpheusCompiler::setDynamicCompiler(bool enable) {
      dynamic_compiler_enabled_ = enable;
    }

    void MorpheusCompiler::poll_guard_program() {
      while (!quit_thread_) {
        trace_guard_prog->poll_perf_buffer("map_change", 1000);
      }
    }

    void MorpheusCompiler::update_bpf_map(int fd) {
      if (!config_.enable_guards_update) {
        return;
      }
      auto filteredIDsTable = trace_guard_prog->get_percpu_hash_table<int, uint64_t>("filtered_ids");
      std::vector<uint64_t> values(BPFTable::get_possible_cpu_count(), 0);
      filteredIDsTable.update_value(fd, values);
    }

    void MorpheusCompiler::add_entries_to_bpf_map(const std::map<int, TableDesc> *pMap) {
      if (!config_.enable_guards_update) {
        return;
      }
      auto filteredIDsTable = trace_guard_prog->get_percpu_hash_table<int, uint64_t>("filtered_ids");
      std::vector<uint64_t> values(BPFTable::get_possible_cpu_count(), 0);
      for (const auto &e : *pMap) {
        filteredIDsTable.update_value(e.first, values);
      }
    }

    void MorpheusCompiler::remove_entries_from_bpf_map(const std::map<int, TableDesc> *pMap) {
      if (!config_.enable_guards_update) {
        return;
      }
      auto filteredIDsTable = trace_guard_prog->get_percpu_hash_table<int, uint64_t>("filtered_ids");
      for (const auto &e : *pMap) {
        filteredIDsTable.remove_value(e.first);
      }
    }

    void MorpheusCompiler::update_filtered_map_ids(int callback_id) {
      if (!config_.enable_guards_update) {
        return;
      }
      if (map_to_guards_list_.find(callback_id) != map_to_guards_list_.end()) {
        add_entries_to_bpf_map(map_to_guards_list_[callback_id]);
      }
    }

    void MorpheusCompiler::addOrUpdateMapInfo(int map_fd, struct MapInfo info) {
      std::map<int, struct MapInfo>::iterator it;
      bool value_inserted;
      std::tie(it, value_inserted) = map_info_.emplace(std::make_pair(map_fd, info));

      // If the value is not inserted using emplace, then the map already contains that value
      if (!value_inserted) {
        it->second = info;
      }
    }

    bool MorpheusCompiler::isMapROAcrossModules(int map_fd) {
      auto it = map_info_.find(map_fd);
      
      if (it != map_info_.end())
        return it->second.is_read_only;
      
      return true;
    }

    int MorpheusCompiler::registerCallback(callbackFunc &&func, std::map<int, TableDesc> *map_to_guards) {
      assert(config_.enable_guards_update && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);

      int random_key = uniform_distribution_(engine_);
      callback_functions_[random_key] = std::forward<callbackFunc>(func);
      map_to_guards_list_[random_key] = map_to_guards;

      add_entries_to_bpf_map(map_to_guards);
      return random_key;
    }


    void MorpheusCompiler::unregisterAllCallbacks() {
      assert(config_.enable_guards_update && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);
      for (const auto &it : callback_functions_) {
        remove_entries_from_bpf_map(map_to_guards_list_[it.first]);
        map_to_guards_list_.erase(it.first);
      }
      callback_functions_.clear();
    }

    void MorpheusCompiler::unregisterCallback(int callback_id) {
      assert(config_.enable_guards_update && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);

      if (callback_functions_.count(callback_id) > 0) {
        callback_functions_.erase(callback_id);
        remove_entries_from_bpf_map(map_to_guards_list_[callback_id]);
        map_to_guards_list_.erase(callback_id);
      }
    }

    void MorpheusCompiler::notify(map_event event, int fd) {
      assert(config_.enable_guards_update && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);

      for (const auto &it : callback_functions_) {
        auto cb = it.second;
        if (map_to_guards_list_[it.first]->count(fd) > 0) {
          cb(event, fd);
          update_bpf_map(fd);
        }
      }
    }
}