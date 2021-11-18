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

namespace ebpf {

    MorpheusCompiler::MorpheusCompiler() : trace_guard_prog(new ebpf::BPF()), quit_thread_(false),
                                               initialized_(false), engine_(time(nullptr)) {
      init();
      max_offloaded_entries_ = MAX_OFFLOADED_ENTRIES;
      dynamic_compiler_enabled_ = false;

      if (DYN_COMPILER_ENABLE_GUARDS_UPDATE && !DYN_COMPILER_ENABLE_GUARDS) {
        assert(false && "You cannot enable the guard update without enabling the guards");
      }
    }

    int MorpheusCompiler::init() {
      std::vector<std::string> cflags = {};
      std::unique_lock<std::mutex> dyn_guard(dyn_mutex);

      if (DYN_COMPILER_ENABLE_GUARDS && DYN_COMPILER_ENABLE_GUARDS_UPDATE) {

        auto init_res = trace_guard_prog->init(BPF_GUARD_PROG, cflags, {});

        if (init_res.code() != 0) {
          LOG_ERROR("[MorpheusCompiler] Error while initializing map guard tracing program: %s",
                    init_res.msg().c_str());
          return -1;
        }

        //LOG_DEBUG("Function name: %s", fnname.c_str());
        auto attach_res = trace_guard_prog->attach_kprobe("htab_map_update_elem", "on_map_update_elem2");

        // attach_res = bpf->attach_tracepoint("bpf:bpf_map_delete_elem", "on_bpf_map_delete_elem");
        if (attach_res.code() != 0) {
          LOG_ERROR("[MorpheusCompiler] Error while attaching map guard tracing program: %s", init_res.msg().c_str());
          return -2;
        }

        attach_res = trace_guard_prog->attach_kprobe("__htab_map_lookup_elem", "on_map_lookup_elem");

        if (attach_res.code() != 0) {
          LOG_ERROR("[MorpheusCompiler] Error while attaching map guard tracing program: %s", init_res.msg().c_str());
          return -2;
        }

        // attach_res = trace_guard_prog->attach_kprobe("trie_lookup_elem", "on_map_trie_lookup_elem");

        // if (attach_res.code() != 0) {
        //   LOG_ERROR("[MorpheusCompiler] Error while attaching map guard tracing program: %s", init_res.msg().c_str());
        //   return -2;
        // }

        auto open_res = trace_guard_prog->open_perf_buffer("map_change",
                                                          [](void *cb_cookie, void *p_data, int data_size) {
                                                              auto *data = static_cast<struct data_def *>(p_data);
                                                              struct bpf_map_info info = {};
                                                              uint32_t info_len = sizeof(info);
                                                              bpf_obj_get_info(data->fd, &info, &info_len);

                                                              auto *c = static_cast<MorpheusCompiler *>(cb_cookie);
                                                              if (c == nullptr)
                                                                throw std::runtime_error("Bad controller");

                                                              if (c->quit_thread_) return;

                                                              c->notify(data->event, data->fd);

                                                              //LOG_DEBUG("[MorpheusCompiler] New map event: %d, fd: %d", data->event, data->fd);
                                                              //LOG_DEBUG("[MorpheusCompiler] New map change: %d, info.id: %d, data.key: %d", info.id, info.max_entries, info.key_size);
                                                              //std::cout<<data->event<<","<<info.id<<","<<data->key[0]<<std::endl;
                                                          }, nullptr, this);

        quit_thread_ = false;
        polling_thread_ = std::thread(&MorpheusCompiler::poll_guard_program, this);
      }
      initialized_ = true;
      return 0;
    }

    MorpheusCompiler::~MorpheusCompiler() {
      if (DYN_COMPILER_ENABLE_GUARDS && DYN_COMPILER_ENABLE_GUARDS_UPDATE) {
        unregisterAllCallbacks();

        if (initialized_) {
          quit_thread_ = true;
          polling_thread_.join();
        }

        auto detach_res = trace_guard_prog->detach_kprobe("map_update_elem");
        if (detach_res.code() != 0) {
          LOG_ERROR("[MorpheusCompiler] Error while detaching kprobe: %s", detach_res.msg().c_str());
        }

        detach_res = trace_guard_prog->detach_kprobe("map_lookup_elem");
        if (detach_res.code() != 0) {
          LOG_ERROR("[MorpheusCompiler] Error while detaching kprobe: %s", detach_res.msg().c_str());
        }

        // detach_res = trace_guard_prog->detach_kprobe("trie_lookup_elem");
        // if (detach_res.code() != 0) {
        //   LOG_ERROR("[MorpheusCompiler] Error while detaching kprobe: %s", detach_res.msg().c_str());
        // }
      }
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
      if (!DYN_COMPILER_ENABLE_GUARDS_UPDATE) {
        return;
      }
      auto filteredIDsTable = trace_guard_prog->get_percpu_hash_table<int, uint64_t>("filtered_ids");
      std::vector<uint64_t> values(BPFTable::get_possible_cpu_count(), 0);
      filteredIDsTable.update_value(fd, values);
    }

    void MorpheusCompiler::add_entries_to_bpf_map(const std::map<int, TableDesc> *pMap) {
      if (!DYN_COMPILER_ENABLE_GUARDS_UPDATE) {
        return;
      }
      auto filteredIDsTable = trace_guard_prog->get_percpu_hash_table<int, uint64_t>("filtered_ids");
      std::vector<uint64_t> values(BPFTable::get_possible_cpu_count(), 0);
      for (const auto &e : *pMap) {
        filteredIDsTable.update_value(e.first, values);
      }
    }

    void MorpheusCompiler::remove_entries_from_bpf_map(const std::map<int, TableDesc> *pMap) {
      if (!DYN_COMPILER_ENABLE_GUARDS_UPDATE) {
        return;
      }
      auto filteredIDsTable = trace_guard_prog->get_percpu_hash_table<int, uint64_t>("filtered_ids");
      for (const auto &e : *pMap) {
        filteredIDsTable.remove_value(e.first);
      }
    }

    void MorpheusCompiler::update_filtered_map_ids(int callback_id) {
      if (!DYN_COMPILER_ENABLE_GUARDS_UPDATE) {
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
      assert(DYN_COMPILER_ENABLE_GUARDS_UPDATE && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);

      int random_key = uniform_distribution_(engine_);
      callback_functions_[random_key] = std::forward<callbackFunc>(func);
      map_to_guards_list_[random_key] = map_to_guards;

      add_entries_to_bpf_map(map_to_guards);
      return random_key;
    }


    void MorpheusCompiler::unregisterAllCallbacks() {
      assert(DYN_COMPILER_ENABLE_GUARDS_UPDATE && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);
      for (const auto &it : callback_functions_) {
        remove_entries_from_bpf_map(map_to_guards_list_[it.first]);
        map_to_guards_list_.erase(it.first);
      }
      callback_functions_.clear();
    }

    void MorpheusCompiler::unregisterCallback(int callback_id) {
      assert(DYN_COMPILER_ENABLE_GUARDS_UPDATE && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);

      if (callback_functions_.count(callback_id) > 0) {
        callback_functions_.erase(callback_id);
        remove_entries_from_bpf_map(map_to_guards_list_[callback_id]);
        map_to_guards_list_.erase(callback_id);
      }
    }

    void MorpheusCompiler::notify(map_event event, int fd) {
      assert(DYN_COMPILER_ENABLE_GUARDS_UPDATE && "This function should be never called if DYN_COMPILER_ENABLE_GUARDS_UPDATE is disabled");
      std::lock_guard<std::mutex> lock(notify_mutex);

      for (const auto &it : callback_functions_) {
        auto cb = it.second;
        if (map_to_guards_list_[it.first]->count(fd) > 0) {
          cb(event, fd);
          update_bpf_map(fd);
        }
      }
    }

    const std::string MorpheusCompiler::BPF_GUARD_PROG = R"(
        #include <linux/sched.h>
        #include <linux/file.h>
        #include <linux/bpf.h>
        #include <linux/fdtable.h>
        #include <linux/fs.h>
        #include <uapi/linux/ptrace.h>

        BPF_TABLE("percpu_hash", int, uint64_t, filtered_ids, 1024);
        BPF_PERF_OUTPUT(map_change);

        typedef enum {
            UPDATE,	// update
            DELETE	// delete
        } map_event;

        struct data_def {
            map_event event;
            u32 fd;
            //u32 key[10];
            //u32 key_len;
            //u32 val[10];
            //u32 val_len;
        };

        int on_map_update_elem(struct pt_regs *ctx, union bpf_attr *attr)
        {
            struct data_def data = {};

            data.event = UPDATE;
            data.fd = attr->map_fd;

            uint64_t *present = filtered_ids.lookup(&data.fd);
            if (!present) {
              //bpf_trace_printk("Skipping this map. We are not interested to it!\n");
              return 0;
            }

            bpf_trace_printk("Map update for %d\n", data.fd);

            // I can do the update directly into this code; this will be executed
            // before the actual map update and will avoid the inconsistency between
            // the map update and the guard update.

            map_change.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        int on_map_update_elem2(struct pt_regs *ctx, struct bpf_map *map)
        {
            bpf_trace_printk("Map update for %d\n", map->id);

            return 0;
        }

        int on_map_lookup_elem(struct pt_regs *ctx, struct bpf_map *map)
        {
            bpf_trace_printk("Map looukp for %d\n", map->id);

            return 0;
        }

        int on_map_trie_lookup_elem(struct pt_regs *ctx, struct bpf_map *map)
        {
            bpf_trace_printk("Map looukp for %d\n", map->id);

            return 0;
        }
    )";
}