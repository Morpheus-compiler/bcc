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

// This flag is use to enable or disable the runtime optimization.
// If set to 0 no optimization is applied to the programs.
#define DYN_COMPILER_ENABLE_RUNTIME_OPTS 1

// This parameter is used to enable/disable the instrumentation.
// A map is instrumented when the max number of entries is greater than
// the current value of MAX_OFFLOADED_ENTRIES. Otherwise, since we are going
// to offload all the entries we do not need to instrument it.
// The instrumentation is carried out by another PERCPU_HASH map, which
// is inserted at runtime in the dataplane and save all the keys that are
// used before a given lookup.
#ifndef DYN_COMPILER_ENABLE_INSTRUMENTATION
#define DYN_COMPILER_ENABLE_INSTRUMENTATION 1

// This parameter is used to control the percentage of sampled packets
// that are saved into the instrumented map.
// This is implemented by generating a random number in the dataplane;
// if the number is in a given range, which depends on this percentage value
// it is inserted into the instrumented map. Otherwise the packet
// is not instrumented.
#define DYN_COMPILER_INSTRUMENTATION_PERCENTAGE 5
#endif

// This parameter is used to enable/disable guards in the maps
// that are not read-only in the data plane. This is needed because
// if an update of the map happens then we need to retrieve the actual values
// of the map and not the optimized ones, which may be different.
#ifndef DYN_COMPILER_ENABLE_GUARDS
#define DYN_COMPILER_ENABLE_GUARDS    0
#endif

// This parameter is used to enable/disable the update of the
// guards when an update of the map happens in the data plane.
// This is implemented by an additional thread that is attached to the
// kprobe corresponding to the map_update_elem. When the new event is reached,
// the corresponding guard map is updated.
#ifndef DYN_COMPILER_ENABLE_GUARDS_UPDATE
#define DYN_COMPILER_ENABLE_GUARDS_UPDATE    0
#endif

// This HAS TO BE DISABLED at runtime because it can reduce
// a lot the performance. Use this flag only for DEBUG purposes
#ifndef DYN_OPT_DEBUG_LLVM_IR_TRACE_PRINTK
#define DYN_OPT_DEBUG_LLVM_IR_TRACE_PRINTK    0
#endif

// If this parameter is set to 0 then the compiler removes
// the instrumentation after some optimization cycles in order to reduce
// its overhead. Of course, in the future this parameter should be dynamic
// and should be decided depending on the runtime performance
// of the application
#define DYN_OPT_ALWAYS_INSTRUMENT       	1

// This parameter is used when the DYN_OPT_ALWAYS_INSTRUMENT
// is set to 0. In this case, the instrumentation is removed every
// after N cycles, with N set as the value of this parameter.
// Then after 10-N cycles executed without the instrumentation,
// it is inserted again and lasts for N cycles.
#define STOP_INTRUMENTATION_AFTER_CYCLES	5

// This is the maximum number of entries that are offloaded
// in the JITRuntimePass. This includes either the instrumented
// entries and the map entries; if no instrumented entries are found,
// the pass retrieves the entry from the map in an unspecified order.
#define MAX_OFFLOADED_ENTRIES           	50

// When this flag is set of 1 we replace the program anyway, even if
// the compiler recognizes that there is no need to update it
// By default it should be set to 0
#define ALWAYS_SWAP_PROGRAM           	0

// This flag should be turned always off by default.
// It is used for testing the overhead of the instrumentation when
// we instrument everything, even small tables
#define INSTRUMENT_EVERYTHING         0

// This parameter indicates the time between two different
// optimization cycles. Every thread waits for this timer
// by sleeping only the time indicated by DYNAMIC_OPTIMIZER_TIMEOUT_STEPS.
// When the counter reaches the value of DYNAMIC_OPTIMIZER_TIMEOUT the opts
// are executed for the current module.
#define DYNAMIC_OPTIMIZER_TIMEOUT       	2
#define DYNAMIC_OPTIMIZED_TIMEOUT_INIT      10
#define DYNAMIC_OPTIMIZER_TIMEOUT_STEPS 	1

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
    private:
        MorpheusCompiler();
        ~MorpheusCompiler();

        int init();
        void poll_guard_program();
        void notify(map_event event, int fd);
        void update_bpf_map(int fd);
        void add_entries_to_bpf_map(const std::map<int, TableDesc> *pMap);
        void remove_entries_from_bpf_map(const std::map<int, TableDesc> *pMap);
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

        std::map<int, callbackFunc> callback_functions_;

        std::uniform_int_distribution<int> uniform_distribution_;
        std::mt19937 engine_;  // Mersenne twister MT19937

        static const std::string BPF_GUARD_PROG;

        struct data_def {
            map_event event;
            uint32_t fd;
            //uint32_t key[10];
            //uint32_t key_len;
        };

        void unregisterAllCallbacks();
    };
}

