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

#include "DynamicMapOptAnalysisPass.h"

#include <llvm/Analysis/MemorySSA.h>
#include <llvm/Analysis/GlobalsModRef.h>

#include "utils.h"
#include "cc/macro_logger.h"

using namespace llvm;

namespace ebpf {

    char DynamicMapOptAnalysisPass::ID;

    DynamicMapOptAnalysisPass::DynamicMapOptAnalysisPass(std::string id, std::string func_name, TableStorage *ts,
                                                         fake_fd_map_def &fake_fd_map,
                                                         std::vector<TableDesc *> &tables)
            : FunctionPass(ID), bpf_module_id_(std::move(id)), func_name_(std::move(func_name)), ts_(ts),
              fake_fd_map_(fake_fd_map), tables_(tables), has_array_of_maps_(false) {}

    DynamicMapOptAnalysisPass::~DynamicMapOptAnalysisPass() = default;

    void DynamicMapOptAnalysisPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
      AU.setPreservesCFG();
      AU.addRequired<AAResultsWrapperPass>();
      AU.addRequired<MemorySSAWrapperPass>();
      AU.addPreserved<GlobalsAAWrapperPass>();
      AU.addPreserved<MemorySSAWrapperPass>();
    }


// We use this function to check if the map lookup value is later used to modifiy the value "inline".
// I know, eBPF is cool but this can cause us a lot of trouble!
bool DynamicMapOptAnalysisPass::helperInstructionCanBeOptimized(llvm::Function &F, llvm::AliasAnalysis &AA,
                                                                llvm::MemorySSA &MSSA,
                                                                llvm::CallInst *helperInstruction) {
  for (auto &bb : F) {
    for (auto &inst : bb) {
      if (isa<StoreInst>(&inst) &&
          MSSA.dominates(MSSA.getMemoryAccess(helperInstruction), MSSA.getMemoryAccess(&inst)) &&
          &inst != helperInstruction) {
        auto *storeInst = dyn_cast<StoreInst>(&inst);
        // TODO: Check if this should be Partial or May Alias
        if (AA.isMustAlias(helperInstruction, storeInst->getPointerOperand())) {
          return false;
        }
      }
    }
  }
  return true;
}

bool DynamicMapOptAnalysisPass::mapIsReadOnly(llvm::Function &F, llvm::AliasAnalysis &AA, llvm::MemorySSA &MSSA,
                          llvm::CallInst &mapLookupInstruction) {
  for (auto &bb : F) {
    for (auto &inst : bb) {
      auto mapUpdateInstruction = dyn_opt::utils::getCompleteBPFMapUpdateCallInst(inst);
      if (mapUpdateInstruction == nullptr) {
        continue;
      } else {
        auto lookup_pseudo = dyn_opt::utils::findPseudoFromHelperInstr(mapLookupInstruction);
        auto update_pseudo = dyn_opt::utils::findPseudoFromHelperInstr(*mapUpdateInstruction);

        if (lookup_pseudo != nullptr && update_pseudo != nullptr) {
          auto &lookupPseudoInt = dyn_opt::utils::getBPFPseudoTableFd(*lookup_pseudo)->getValue();
          auto &updatePseudoInt = dyn_opt::utils::getBPFPseudoTableFd(*update_pseudo)->getValue();

          if (lookupPseudoInt == updatePseudoInt) {
            spdlog::get("Morpheus")->trace("Lookup and update instruction have the same FD");
            return false;
          }
        } else {
          // Let's rely only on the alias analysis, which is a bit weaker than checking the fd directly
          // Found map update instruction, let's check if it uses the same map fd as argument
          Value *map_update_fd = mapUpdateInstruction->getOperand(0);
          Value *map_lookup_fd = mapLookupInstruction.getOperand(0);
          auto alias_result = AA.alias(map_lookup_fd, map_update_fd);

          if (alias_result > AliasResult::PartialAlias) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

void DynamicMapOptAnalysisPass::findAssociatedArrayOfMaps(LLVMContext &ctx, CallInst &instruction, llvm::AliasAnalysis &AA,
                                                          llvm::MemorySSA &MSSA, std::vector<std::pair<CallInst *, ebpf::TableDesc *>> &array_of_maps) {
  Value *map_fd = instruction.getArgOperand(0);

  for (auto &value : array_of_maps) {
    if (value.first != &instruction) {
      // Return value of the ArrayOfMaps is alias of the first operand of the
      // lookup instruction?
      auto alias_result = AA.alias(value.first, map_fd);

      if (alias_result > 0) {
        // The map pointer used in this lookup instruction may come from the array of maps table
        // I will add this information in the debug instructions
        llvm::MDNode *N = llvm::MDNode::get(ctx, MDString::get(ctx, std::to_string(value.second->fd)));
        instruction.setMetadata("opt.arrayOfMapFD", N);
      }
    }
  }
}

bool DynamicMapOptAnalysisPass::runOnFunction(Function &pfn) {
  AliasAnalysis *AA = &getAnalysis<AAResultsWrapperPass>().getAAResults();
  MemorySSA *MSSA = &getAnalysis<MemorySSAWrapperPass>().getMSSA();

  auto &dynamic_opt_compiler = MorpheusCompiler::getInstance();

  if (pfn.getName() != func_name_) {
    // I will skip all the functions that I am not interested in
    return false;
  }

  LLVMContext &ctx_ = pfn.getContext();
  for (auto bb = pfn.begin(); bb != pfn.end(); bb++) {
    for (auto &instruction : *bb) {
      // The getBPFMapLookup call will return the pointer to the instruction containing the real
      // helper call, but only if the call is a bpf_map_lookup_elem. Otherwise the call
      // will return nullptr.
      // In addition, this function will check if the input instruction is a llvm.bpf.pseudo
      // call, and then it will go two instructions after to find the helper call.

      auto helperInstruction = dyn_opt::utils::getCompleteBPFMapLookupCallInst(instruction);
      if (helperInstruction == nullptr) {
        continue;
      }

      if (!helperInstructionCanBeOptimized(pfn, *AA, *MSSA, helperInstruction)) {
        spdlog::get("Morpheus")->trace("[AnalysisPass] Map cannot be optimized!");

        // Before we finish, I want to mark the current helper so that we cannot apply the
        // optimization on it.
        // This happens when the value returned by the map_lookup function is later modified
        // "inline", which mean by directly accessing the returned pointer.
        // TODO: In the future, this may be avoided by adding an additional level of caching
        llvm::MDNode *N = llvm::MDNode::get(ctx_, MDString::get(ctx_, "true"));
        helperInstruction->setMetadata("opt.cannotBeOptimized", N);
      } else {
        struct ebpf::MapInfo map_info;

        auto bpfPseudoCallInst = dyn_opt::utils::findPseudoFromHelperInstr(*helperInstruction);

        if (bpfPseudoCallInst == nullptr) {
          findAssociatedArrayOfMaps(ctx_, *helperInstruction, *AA, *MSSA, per_cpu_map_values_array);
          // Now its time to check if the map is read only or not
          if (!mapIsReadOnly(pfn, *AA, *MSSA, *helperInstruction)) {
            llvm::MDNode *N = llvm::MDNode::get(ctx_, MDString::get(ctx_, "false"));
            helperInstruction->setMetadata("opt.isReadOnly", N);
          } else {
            llvm::MDNode *N = llvm::MDNode::get(ctx_, MDString::get(ctx_, "true"));
            helperInstruction->setMetadata("opt.isReadOnly", N);
          }
          continue;
        } else {
          auto *ci = dyn_opt::utils::getBPFPseudoTableFd(*bpfPseudoCallInst);

          ebpf::TableDesc *table = dyn_opt::utils::getTableByFD(*ci, bpf_module_id_, ts_, fake_fd_map_, tables_);
          if (table == nullptr) continue;

          int map_fd = table->fd;

          // Now its time to check if the map is read only or not
          // This function will return the result of the alias analysis
          // that checks if the map_fd value of the helper instruction
          // is contained into a map_update helper call
          if (!mapIsReadOnly(pfn, *AA, *MSSA, *helperInstruction)) {
            spdlog::get("Morpheus")->debug("[AnalysisPass] Map with fd: {} is NOT read only! It should be guarded!", map_fd);
            llvm::MDNode *N = llvm::MDNode::get(ctx_, MDString::get(ctx_, "false"));
            helperInstruction->setMetadata("opt.isReadOnly", N);
            table->is_read_only = false;
            map_info.is_read_only = false;
            // TODO: This can be a problem when multiple programs update this value
            dynamic_opt_compiler.addOrUpdateMapInfo(map_fd, map_info);
          } else {
            spdlog::get("Morpheus")->trace("[AnalysisPass] Map with fd: {} is read only! Yeah!", map_fd);
            llvm::MDNode *N = llvm::MDNode::get(ctx_, MDString::get(ctx_, "true"));
            helperInstruction->setMetadata("opt.isReadOnly", N);
            table->is_read_only = true;
            map_info.is_read_only = true;
            dynamic_opt_compiler.addOrUpdateMapInfo(map_fd, map_info);
          }

          // Map can be optimized. However, I want to check if we have seen an ARRAY_OF_MAPS.
          // In this case, I will save this information, which is useful to later associate the lookup in
          // the inner map with the corresponding parent map.
          if (table->type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
            bool value_already_in_vect = false;
            for (auto &value : per_cpu_map_values_array) {
              if (table->fd == value.second->fd) {
                value_already_in_vect = true;
              }
            }
            if (!value_already_in_vect) {
              per_cpu_map_values_array.push_back(std::make_pair(helperInstruction, table));
            }
          }
        }   
      }
    }
  }
  return false;
}

Pass *
DynamicMapOptAnalysisPass::createDynamicMapOptAnalysisPass(std::string id, std::string func_name, TableStorage *ts,
                                                            fake_fd_map_def &fake_fd_map,
                                                            std::vector<TableDesc *> &tables) {
  return new DynamicMapOptAnalysisPass(std::move(id), std::move(func_name), ts, fake_fd_map, tables);
}
}