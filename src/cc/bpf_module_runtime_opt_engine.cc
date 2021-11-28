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

#include "common.h"
#include "bpf_module.h"
#include "table_storage.h"

#include <string>
#include <utility>
#include <iomanip>
#include <iostream>
#include <regex>
#include <linux/bpf.h>
#include "macro_logger.h"
#include "libbpf/src/bpf.h"

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include "llvm/IR/IntrinsicInst.h"
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include "llvm/Transforms/Utils/FunctionComparator.h"
#include <llvm/Linker/Linker.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Analysis/MemorySSA.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <cc/passes/utils.h>

#include <spdlog/spdlog.h>

#include "passes/JITTableRuntimePass.h"
#include "passes/DynamicMapOptAnalysisPass.h"
#include "passes/BPFMapInstrumentationPass.h"
#include "libbpf.h"

namespace ebpf {
    using std::get;
    using std::make_tuple;
    using std::map;
    using std::move;
    using std::string;
    using std::tuple;
    using std::unique_ptr;
    using std::vector;
    using namespace llvm;

    const int BPFModule::NO_MODULE_CHANGES;

    int BPFModule::run_dynamic_opt_pass_manager(const std::string &func_name) {
      spdlog::get("Morpheus")->trace("[bpf_module] Running dynamic optimization pass manager");
      if (mod_original_ == nullptr) {
        spdlog::get("Morpheus")->error("[bpf_module] Error while accessing module at runtime");
        return -1;
      }

      // The first time the module is only instrumented with additional instructions.
      // Later, it is optimized at runtime based on the information retrieved at runtime
      if (first_time_dyn_pass_) {
        dyn_opt_runs = 0;
        // In this prototype I will always work starting from the original module
        // Every execution of the thread the original module is cloned and the optimizations
        // are applied to the new cloned module, while the previous one is removed from the
        // execution engine.
        assert(engine_ != nullptr && "Engine is NULL, did you enable the rw_engine in the BPF call?");
        engine_->removeModule(mod_runtime_ptr_);
        mod_runtime_ = CloneModule(*mod_original_);
        mod_runtime_ptr_ = &*mod_runtime_;

        engine_->addModule(move(mod_runtime_));
        
        current_func = engine_->FindFunctionNamed(func_name);

        if (!current_func) {
          spdlog::get("Morpheus")->error("[bpf_module] I was not able to get function pointer");
          return -1;
        }

        first_time_dyn_pass_ = false;
        if (MorpheusCompiler::getInstance().get_config().enable_instrumentation) {
          if (int rc = run_dyn_instrumentation_manager(*mod_runtime_ptr_, func_name)) {
            return rc;
          }
        } else {
          finalize_runtime_module();
          return BPFModule::NO_MODULE_CHANGES;
        }

        int rc = finalize_runtime_module();
        dyn_opt_runs++;
        return rc;
      } else {
        std::vector<std::string> offloaded_entries;
//        mod_runtime_ = CloneModule(*mod_runtime_ptr_);
//        engine_->removeModule(mod_runtime_ptr_);
//        mod_runtime_ptr_ = &*mod_runtime_;
//
//        engine_->addModule(move(mod_runtime_));
//        pfn = engine_->FindFunctionNamed(func_name);

        // TODO: Check here is the module should be optimized or not based on runtime statistics
        engine_->removeModule(mod_runtime_ptr_);
        mod_runtime_ = CloneModule(*mod_original_);
        mod_runtime_ptr_ = &*mod_runtime_;

        engine_->addModule(move(mod_runtime_));

        auto compiler_start = std::chrono::high_resolution_clock::now();
        if (int rc = run_dyn_pass_manager(*mod_runtime_ptr_, func_name, offloaded_entries)) {
          return rc;
        }

        // Record end time
        auto compiler_finish = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> compiler_elapsed = compiler_finish - compiler_start;
        spdlog::get("Morpheus")->info("[bpf_module]Time to execute run_dyn_pass_manager: {} ms", compiler_elapsed.count());

        compiler_start = std::chrono::high_resolution_clock::now();
        int final_res = finalize_runtime_module();
        compiler_finish = std::chrono::high_resolution_clock::now();
        compiler_elapsed = compiler_finish - compiler_start;
        spdlog::get("Morpheus")->info("[bpf_module]Time to execute finalize_runtime_module: {} ms", compiler_elapsed.count());

        Function *new_func = engine_->FindFunctionNamed(func_name);
        auto hash1 = FunctionComparator::functionHash(*new_func);
        auto hash2 = FunctionComparator::functionHash(*current_func);

        dyn_opt_runs++;
        if ((hash1 == hash2) && (saved_offloaded_entries_ == offloaded_entries) && !MorpheusCompiler::getInstance().get_config().always_swap_program) {
          spdlog::get("Morpheus")->info("[bpf_module] No changes detected, skipping reloading");
          return BPFModule::NO_MODULE_CHANGES;
        } else {
          current_func = new_func;
          saved_offloaded_entries_ = offloaded_entries;
          spdlog::get("Morpheus")->info("[bpf_module] Changes detected, reloading!");
        }
        return final_res;
      }

      return BPFModule::NO_MODULE_CHANGES;
    }

    int BPFModule::finalize_runtime_module() {
      sections_.clear();

      if (rw_engine_enabled_ && MorpheusCompiler::getInstance().get_config().enable_instrumentation) {
        if (int rc = annotate_runtime_module())
          return rc;
      }

      if (int rc = run_pass_manager(*mod_runtime_ptr_))
        return rc;

      engine_->finalizeObject();

      if (update_maps(sections_))
        return -1;

      // give functions an id
      for (const auto &section : sections_)
        if (!strncmp(FN_PREFIX.c_str(), section.first.c_str(), FN_PREFIX.size()))
          function_names_.push_back(section.first);    
      
      return 0;
    }

    int BPFModule::annotate_runtime_module() {
      // I need to do this only for the newly added instrumented maps otherwise I cannot read them
      // bool create_new_module = false;
      // separate module to hold the reader functions
      auto m = ebpf::make_unique<Module>("sscanf_instr", *ctx_);

      for (auto &value : original_maps_to_instrumented_maps_) {
        // Get the original map from which I can extract the needed information
        auto *fd_value = ConstantInt::get(Type::getInt64Ty(*ctx_), value.first, true);
        auto *original_table = dyn_opt::utils::getTableByFD(*fd_value, id_, ts_, fake_fd_map_, tables_);
        assert(original_table != nullptr && "Unable to find original table associated with the instrumented map");

        TableDesc &table = value.second;
        GlobalValue *gvar = mod_runtime_ptr_->getNamedValue(original_table->name);
        assert(gvar && "Error while trying to annotate the runtime module for the instrumented maps");
        if (!gvar) continue;
        if (auto *pt = dyn_cast<PointerType>(gvar->getType())) {
          if (auto *st = dyn_cast<StructType>(pt->getElementType())) {
            if (st->getNumElements() < 2) continue;
            Type *key_type = st->elements()[0];
            Type *leaf_type = Type::getInt64Ty(m->getContext());

            using std::placeholders::_1;
            using std::placeholders::_2;
            using std::placeholders::_3;

            table.key_sscanf = std::bind(&BPFModule::sscanf_instrumentation, this,
                                         make_reader(&*m, key_type), _1, _2);
            table.leaf_sscanf = std::bind(&BPFModule::sscanf_instrumentation, this,
                                          make_reader(&*m, leaf_type), _1, _2);
            table.key_snprintf = std::bind(&BPFModule::snprintf_instrumentation, this,
                                           make_writer(&*m, key_type), _1, _2, _3);
            table.leaf_snprintf =
                    std::bind(&BPFModule::snprintf_instrumentation, this, make_writer(&*m, leaf_type),
                              _1, _2, _3);
            int instrumented_map_fd = table.fd;
            spdlog::get("Morpheus")->debug("Annotating runtime module for instrumented map with fd: %d", instrumented_map_fd);
          }
        }
      }

      spdlog::get("Morpheus")->trace("There is a need to re-create all readers and writers");
      make_all_readers_and_writers(&*m);
      rw_instr_engine_.reset();
      rw_instr_engine_ = finalize_rw(move(m));
      if (!rw_instr_engine_)
        return -1;

      return 0;
    }

    void BPFModule::cleanup_rw_instr_engine() {
      if (rw_instr_engine_)
        rw_instr_engine_.release();
    }

    int BPFModule::run_dyn_instrumentation_manager(Module &mod, const std::string &func_name) {
      legacy::PassManager PM;
      PassManagerBuilder PMB;
      PMB.OptLevel = 3;

      PM.add(DynamicMapOptAnalysisPass::createDynamicMapOptAnalysisPass(id_, func_name, ts_, fake_fd_map_, tables_));
      PM.add(BPFMapInstrumentationPass::createBPFMapInstrumentationPass(id_, func_name, ts_, fake_fd_map_, tables_,
                                                                        original_maps_to_instrumented_maps_));
      PMB.populateModulePassManager(PM);
      PM.run(mod);

      if (verifyModule(mod, &errs())) {
        if (flags_ & DEBUG_LLVM_IR)
          dump_ir(mod);
        return -1;
      }

      return 0;
    }

    int BPFModule::run_dyn_pass_manager(Module &mod, const std::string &func_name, std::vector<std::string> &offloaded_entries) {
      legacy::PassManager PM;
      PassManagerBuilder PMB;
      PMB.OptLevel = 3;

      auto &morpheusConfig = MorpheusCompiler::getInstance().get_config();
      PM.add(DynamicMapOptAnalysisPass::createDynamicMapOptAnalysisPass(id_, func_name, ts_, fake_fd_map_, tables_));
      if (morpheusConfig.enable_instrumentation && (morpheusConfig.always_instrument || ((dyn_opt_runs % 10) <= morpheusConfig.stop_instrumentation_after_cycles))) {
        PM.add(BPFMapInstrumentationPass::createBPFMapInstrumentationPass(id_, func_name, ts_, fake_fd_map_, tables_,
                                                                          original_maps_to_instrumented_maps_));
      }
      PM.add(JITTableRuntimePass::createJITTableRuntimePass(id_, func_name, ts_, fake_fd_map_, tables_,
                                                            original_maps_to_guards_,
                                                            original_maps_to_instrumented_maps_, offloaded_entries));
      PM.add(createGlobalDCEPass());
      PM.add(createFunctionInliningPass());
      PM.add(createGlobalOptimizerPass());

      PMB.populateModulePassManager(PM);
      PM.run(mod);

//      dump_ir(mod);
      if (verifyModule(mod, &errs())) {
        if (flags_ & DEBUG_LLVM_IR)
          dump_ir(mod);
        return -1;
      }

      return 0;
    }

    std::map<int, TableDesc> *BPFModule::getRuntimeMapToGuards() {
      return &original_maps_to_guards_;
    }

    void BPFModule::update_guard(MorpheusCompiler::map_event event, int map_fd) {
      if (original_maps_to_guards_.count(map_fd) > 0) {
        auto guard_table = BPFPercpuArrayTable<uint64_t>(original_maps_to_guards_[map_fd]);
        std::vector<uint64_t> guard_map_value(BPFTable::get_possible_cpu_count());
        auto res = guard_table.get_value(0, guard_map_value);
        assert(res.code() == 0 && "[BPFModule] Unable to get current value from guard map");

        // I take the first value since it is the same among the various CPU cores
        uint64_t value = guard_map_value[0];
        value++;

        //Update guard map with the new value
        std::vector<uint64_t> new_guard_value(BPFTable::get_possible_cpu_count(), value);
        res = guard_table.update_value(0, new_guard_value);
        assert(res.code() == 0 && "[BPFModule] Unable to update value inside guard map");

        spdlog::get("Morpheus")->debug("Guard map with fd: {} (original: {}) updated", guard_table.fd(), map_fd);
      } else {
        spdlog::get("Morpheus")->debug("Unable to find guard map associated with map: {}", map_fd);
      }
    }

    int BPFModule::update_maps(sec_map_def &sections) {
      // update instructions in the different sections with
      // the real FDs of the maps
      for (auto section : sections) {
        auto sec_name = section.first;
        if (strncmp(".bpf.fn.", sec_name.c_str(), 8) == 0) {
          uint8_t *addr = get<0>(section.second);
          uintptr_t size = get<1>(section.second);
          auto *insns = (struct bpf_insn *) addr;
          int i, num_insns;

          num_insns = size / sizeof(struct bpf_insn);
          for (i = 0; i < num_insns; i++) {
            if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM)) {
              // change map_fd is it is a ld_pseudo */
              if (insns[i].src_reg == BPF_PSEUDO_MAP_FD &&
                  fake_fds_to_real_fds_.find(insns[i].imm) != fake_fds_to_real_fds_.end())
                insns[i].imm = fake_fds_to_real_fds_[insns[i].imm];
              i++;
            }
          }
        }
      }

      maps_loaded_ = true;
      return 0;
    }

    StatusTuple BPFModule::sscanf_instrumentation(string fn_name, const char *str, void *val) {
      if (!rw_engine_enabled_)
        return StatusTuple(-1, "rw_engine not enabled");
      auto fn =
          (int (*)(const char *, void *))rw_instr_engine_->getFunctionAddress(fn_name);
      if (!fn) {
        fn =  (int (*)(const char *, void *))rw_engine_->getFunctionAddress(fn_name);
        if (!fn) {
          return StatusTuple(-1, "sscanf not available: %s", fn_name.c_str());
        }
      }
      int rc = fn(str, val);
      if (rc < 0)
        return StatusTuple(rc, "error in sscanf: %s", std::strerror(errno));
      return StatusTuple(rc);
    }

    StatusTuple BPFModule::snprintf_instrumentation(string fn_name, char *str, size_t sz,
                                    const void *val) {
      if (!rw_engine_enabled_)
        return StatusTuple(-1, "rw_engine not enabled");

      auto fn = (int (*)(char *, size_t,
                        const void *))rw_instr_engine_->getFunctionAddress(fn_name);
      if (!fn) {
        fn = (int (*)(char *, size_t, const void *))rw_engine_->getFunctionAddress(fn_name);
        if (!fn) {
          return StatusTuple(-1, "snprintf not available: %s", fn_name.c_str());
        }
      }
      int rc = fn(str, sz, val);
      if (rc < 0)
        return StatusTuple(rc, "error in snprintf: %s", std::strerror(errno));
      if ((size_t)rc == sz)
        return StatusTuple(-1, "buffer of size %zd too small", sz);
      return StatusTuple::OK();
    }

} // namespace ebpf
