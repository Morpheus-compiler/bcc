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

#pragma once

#include <mutex>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <random>
#include <map>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>
#include "MorpheusCompilerConfig.h"

namespace ebpf {
    class BPF;
    class TableDesc;

    struct MapInfo {
        bool is_read_only;
    };
    
    class MorpheusCompiler {
    public:
        static MorpheusCompiler& getInstance() {
          // Guaranteed to be destroyed and instantiated on first use.
          static MorpheusCompiler instance;
          return instance;
        }

        MorpheusCompiler(MorpheusCompiler const&) = delete;
        void operator=(MorpheusCompiler const&)     = delete;

        typedef enum {
            UPDATE,	// update
            DELETE  // delete
        } map_event;

        typedef std::function<void(map_event, int)> callbackFunc;

        //int init();
        void update_filtered_map_ids(int callback_id);
        int registerCallback(callbackFunc &&func, std::map<int, TableDesc> *map_to_guards);
        void unregisterCallback(int callback_id);
        unsigned int getMaxOffloadedEntries();
        void setMaxOffloadedEntries(unsigned int entries);

        bool dynamicCompilerEnabled();
        void setDynamicCompiler(bool enable);
        void addOrUpdateMapInfo(int map_fd, struct MapInfo info);
        bool isMapROAcrossModules(int map_fd);

        std::shared_ptr<spdlog::logger> logger;

        const struct ebpf::MorpheusConfigStruct &get_config();
    private:
        MorpheusCompiler();
        ~MorpheusCompiler();

        int init();
        void poll_guard_program();
        void notify(map_event event, int fd);
        void update_bpf_map(int fd);
        void add_entries_to_bpf_map(const std::map<int, TableDesc> *pMap);
        void remove_entries_from_bpf_map(const std::map<int, TableDesc> *pMap);
        void unregisterAllCallbacks();

        void initlogger();
        void read_config_file(std::string path);
        void create_config_file(std::string path);
    private:
        std::mutex dyn_mutex;
        std::unique_ptr<ebpf::BPF> trace_guard_prog;
        std::atomic<bool> quit_thread_{};
        std::atomic<bool> initialized_{};
        std::thread polling_thread_;
        std::mutex notify_mutex;
        std::map<int, std::map<int, TableDesc> *> map_to_guards_list_;
        std::map<int, struct MapInfo> map_info_;
        unsigned int max_offloaded_entries_;
        bool dynamic_compiler_enabled_;
        std::shared_ptr<spdlog::sinks::ansicolor_stdout_sink_mt> console;

        std::map<int, callbackFunc> callback_functions_;

        std::uniform_int_distribution<int> uniform_distribution_;
        std::mt19937 engine_;  // Mersenne twister MT19937

        struct ebpf::MorpheusConfigStruct config_;

        struct data_def {
            map_event event;
            uint32_t fd;
            //uint32_t key[10];
            //uint32_t key_len;
        };
    };
}

