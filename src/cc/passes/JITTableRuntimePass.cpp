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

#include "JITTableRuntimePass.h"

#include <map>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <algorithm>
#include <regex>
#include <iostream>
#include <map>
#include <set>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <functional>
#include <linux/bpf.h>
#include <cc/api/BPFTable.h>
#include <cc/libbpf/src/bpf.h>

#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/IR/DebugInfo.h>
#include "llvm/IR/InstrTypes.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRPrintingPasses.h>

#include "nlohmann/json.hpp"
#include "bpf_module.h"
#include "table_storage.h"
#include "jhash.h"
#include "utils.h"
#include "DynamicMapOptAnalysisPass.h"
#include "BPFMapInstrumentationPass.h"
#include "builder/irbuilderbpf.h"


/*****************************************
 * Pass implementation
 *****************************************/

/* An arbitrary initial parameter */
#define JHASH_FUNC_NAME          "jhash_"

#ifndef JHASH_INITVAL
#define JHASH_INITVAL            0xdeadbeef
#endif

#define JHASH_INITVAL_INT       3735928559

// We should put a limit on the size of entries that can be offloaded
// into the eBPF code. Otherwise the stack grows and we risk our optimized
// program to be rejected
#define DYN_OPT_KEY_SIZE_LIMIT  1024
#define DYN_OPT_LEAF_SIZE_LIMIT  512

using namespace llvm;

namespace ebpf {

char JITTableRuntimePass::ID;

JITTableRuntimePass::JITTableRuntimePass(std::string id, std::string func_name, ebpf::TableStorage *ts,
                                          ebpf::fake_fd_map_def &fake_fd_map,
                                          std::vector<ebpf::TableDesc *> &tables,
                                          std::map<int, TableDesc> &original_maps_to_guards,
                                          std::map<int, TableDesc> &original_maps_to_instrumented_maps,
                                          std::vector<std::string> &offloaded_entries_list)
        : FunctionPass(ID), bpf_module_id_(std::move(id)), func_name_(std::move(func_name)), ts_(ts),
          fake_fd_map_(fake_fd_map), tables_(tables), original_maps_to_guards_(original_maps_to_guards),
          original_maps_to_instrumented_maps_(original_maps_to_instrumented_maps),
          offloaded_entries_list_(offloaded_entries_list) {}

JITTableRuntimePass::~JITTableRuntimePass() = default;

// Called once for each module, before the calls on the basic blocks.
// We could use doFinalization to clear RNG, but that's not needed.
bool JITTableRuntimePass::doInitialization(Module &M) {
  // I want the same seed to better debugability. In the future it should be changed with time(NULL)
  srand(5678); 
  // srand(time(NULL));
  return false;
}

// Called for each basic block of the module
bool JITTableRuntimePass::runOnFunction(Function &pfn) {

  auto &dynamic_opt_compiler = MorpheusCompiler::getInstance();
  bool modified = false;
  if (pfn.getName() != func_name_) {
    // I will skip all the functions that I am not interested in
    return false;
  }

  spdlog::get("Morpheus")->trace("[JIT Pass] Processing function: {}", pfn.getName().str());

  LLVMContext &ctx_ = pfn.getContext();
  for (auto bb = pfn.begin(); bb != pfn.end(); bb++) {
    for (auto instruction = bb->begin(); instruction != bb->end(); instruction++) {
      bool is_map_in_map_lookup = false;
      int map_in_map_fd = -1;
      // The getBPFMapLookup call will return the pointer to the instruction containing the real
      // helper call, but only if the call is a bpf_map_lookup_elem. Otherwise the call
      // will return nullptr.
      // In addition, this function will check if the input instruction is a llvm.bpf.pseudo
      // call, and then it will go two instructions after to find the helper call.
      auto helperInstruction = dyn_opt::utils::getCompleteBPFMapLookupCallInst(*instruction);
      if (helperInstruction == nullptr) {
        continue;
      }

      auto bpfPseudoCallInst = dyn_opt::utils::findPseudoFromHelperInstr(*helperInstruction);
      if (bpfPseudoCallInst == nullptr) {
        spdlog::get("Morpheus")->trace("[JIT Pass] Is this maybe a map in map instruction?");
        // There is still a case that we have to consider here.
        // When the lookup is a reference to an map obtained from the ARRAY_OF_MAPS.
        // In this case, I read the debug information where I can find the ARRAY_OF_MAP table FD associated
        // and read the corresponding entries.
        map_in_map_fd = dyn_opt::utils::getMapInMapFDFromDebugInfo(*helperInstruction);
        if (map_in_map_fd > 0) {
          is_map_in_map_lookup = true;
          spdlog::get("Morpheus")->trace("[JIT Pass] This lookup is referring to a BPF_MAP_IN_MAP with fd: {}", map_in_map_fd);
          bpfPseudoCallInst = helperInstruction;
        } else {
          spdlog::get("Morpheus")->trace("[JIT Pass] Not a map in map instruction. Continue!");
          continue;
        }
      }

      // auto bpfPseudoCallInst = dyn_cast_or_null<CallInst>(&(*instruction));
      // assert(bpfPseudoCallInst != nullptr && "Detected BPF call instruction is NULL");
      ebpf::TableDesc *table = nullptr;
      std::vector<int> nested_map_fds;
      if (is_map_in_map_lookup && map_in_map_fd > 0) {
        std::tie(nested_map_fds, table) = dyn_opt::utils::getNestedMapInMapTable(ctx_, map_in_map_fd, bpf_module_id_, ts_, fake_fd_map_, tables_);

        if (dyn_opt::utils::nestedMapIsReadOnly(*helperInstruction)) {
          table->is_read_only = true;
        } else {
          table->is_read_only = false;
        }
      } else {
        auto *ci = dyn_opt::utils::getBPFPseudoTableFd(*bpfPseudoCallInst);
        table = getTableByFD(*ci);
      }

      if (table == nullptr) continue;
      //assert(table != nullptr && "Trying to get a table that does not exist!");

      spdlog::get("Morpheus")->debug("[JIT Pass] Reading runtime values of the map: {} (fd: {}), type: {}",
                table->name, (int) table->fd,
                dyn_opt::utils::table_type_id_to_string_name(table->type));

      // First of all I need to understand the type of map that it is using,
      // in order to apply different type of optimizations.
      if (table->type == BPF_MAP_TYPE_HASH || table->type == BPF_MAP_TYPE_LRU_HASH ||
          table->type == BPF_MAP_TYPE_ARRAY || table->type == BPF_MAP_TYPE_LPM_TRIE || table->type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        auto genericTable = ebpf::BPFTable(*table);
        spdlog::get("Morpheus")->debug("[JIT Pass] We are dealing with a {}", dyn_opt::utils::table_type_id_to_string_name(table->type));
        spdlog::get("Morpheus")->trace("[JIT Pass] Key desc: {}", table->key_desc);
        spdlog::get("Morpheus")->trace("[JIT Pass] Leaf desc: {}", table->leaf_desc);

        if (table->leaf_size >= DYN_OPT_LEAF_SIZE_LIMIT || table->key_size >= DYN_OPT_KEY_SIZE_LIMIT) {
          continue;
        }

        auto &config = MorpheusCompiler::getInstance().get_config();
        if (std::find(config.tables_to_skip.begin(), config.tables_to_skip.end(), table->name) != config.tables_to_skip.end()) {
          spdlog::get("Morpheus")->debug("[JIT Pass] Skip table {}", table->name);
          continue;
        }

        // if (table->name == "index64" || table->name == "ctl_array" || table->name == "dp_rules") continue;  
        
        std::vector<std::pair<std::string, std::string>> values;

        // This should read all the entries, but for very large map it will take a lot of time
        // TODO: improve with batch reading!
        if (is_map_in_map_lookup && nested_map_fds.size() > 0) {
          dyn_opt::utils::readEntriesFromNestedTables(values, nested_map_fds, *table, dynamic_opt_compiler.getMaxOffloadedEntries()*50);
          if (values.size() == 0) {
            spdlog::get("Morpheus")->trace("[JIT Pass] Skip offloading if all values are null in the nested array of maps");
            continue;
          }
        } else if (table->type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
          spdlog::get("Morpheus")->trace("[JIT Pass] Read entries from array of maps");
          BPFArrayOfMapTable arrayOfMapTable(*table);
          std::vector<int> array_of_map_values = arrayOfMapTable.get_table_offline();

          for (uint i = 0; i < array_of_map_values.size(); i++) {
            // We are not interested on empty values
            if (array_of_map_values[i] == 0) continue;
            std::string string_key = int_to_hex(static_cast<uint32_t>(i));
            std::string string_value = int_to_hex(static_cast<uint32_t>(array_of_map_values[i]));
            values.push_back(std::make_pair(string_key, string_value));
          }
        } else {
          genericTable.get_table_offline(values, dynamic_opt_compiler.getMaxOffloadedEntries()*50);
        }

        spdlog::get("Morpheus")->debug("[JIT Pass] Size of runtime value is {}", values.size());

        // Here we are gonna optimize the map based on runtime values.
        // To avoid inconsistency problems I am going to insert a guard that checks the version
        // of the offloaded value.
        // If the version does not match, fall back to the "normal" (and slower) path.

        // There are two options here when the map is empty. The first one is to insert a guard; in this
        // case, the inconsistency is reduced since there is always the right path in the program
        // The other option is to substitute the value directly; in this case, we could exploit the DCE
        // to eliminate some checks/paths into the code.
        // In my opinion, it is better to distinguish the type of map used in the data plane.
        // Configurations map could use the DCE while other maps, which can be potentially written by the
        // data plane, should be always optimized with a guard.
        // I leave here the old code for reference.

        // I am splitting the block before the call to the llvm.bpf.pseudo call
        // The new created block will be the default block of the switch-case statement
        // But all the instructions after the helper call will be moved to another block that will be
        // the continuation of the original one.
        // What is happening here is the following:
        // Before:
        //   BeforePseudo
        //   llvm.bpf.pseudo(1, map_fd);
        //   bitcastInstruction
        //   helperCallInstruction
        //   Tail
        // After:
        //   BeforePseudo
        //   LoadInstruction(key)
        //   Switch(key):
        //     Case value: CaseNBlock
        //   Default:
        //     llvm.bpf.pseudo(1, map_fd);
        //     bitcastInstruction
        //     helperCallInstruction
        //   PhiInstruction(Default, CaseNBlock...)
        //   Tail
        BasicBlock *Default = SplitBlock(bpfPseudoCallInst->getParent(), bpfPseudoCallInst);

        auto afterHelperInst = helperInstruction->getNextNode();
        BasicBlock *Tail = SplitBlock(afterHelperInst->getParent(), afterHelperInst);

        if (dynamic_opt_compiler.get_config().enable_debug_printk) {
          builder::IRBuilderBPF IRB(Default->getFirstNonPHI());
          IRB.CreateTracePrintk("Map: " + table->name + " -> Default branch hit!\n");
        }

        std::vector<std::pair<Value *, BasicBlock *> > CaseValues;
        SwitchInst *switchInst = nullptr;

        if (values.empty()) {
          spdlog::get("Morpheus")->debug("[JIT Pass] Map is empty, replacing with null value!!!");
          BasicBlock *successGuardBB;

          if (dynamic_opt_compiler.get_config().enable_guard && (!table->is_read_only || !dynamic_opt_compiler.isMapROAcrossModules(table->fd))) {
            spdlog::get("Morpheus")->debug("[JIT Pass] Creating guard for this map since it is not real-only!!!");
            successGuardBB = createGuardForTable(ctx_, *table, bb->getTerminator(), Tail, Default);
            auto final_value = std::make_pair(ConstantPointerNull::get(Type::getInt8PtrTy(ctx_)), successGuardBB);
            CaseValues.emplace_back(std::move(final_value));
          } else {
            spdlog::get("Morpheus")->info("[JIT Pass] Performing DCE for empty table {}", table->name);
            /*
              * This is for the dead code elimination.
              * I remove all the instructions (that are already dead)
              * referencing that table, which is empty.
              */
            while (Default->getFirstNonPHI() != helperInstruction) {
              Default->getFirstNonPHI()->eraseFromParent();
            }
            BasicBlock::iterator ii(helperInstruction);
            ReplaceInstWithValue(helperInstruction->getParent()->getInstList(), ii,
                                  ConstantPointerNull::get(llvm::Type::getInt8PtrTy(ctx_)));

            instruction = bb->begin();
            continue;
          }
        } else {
          spdlog::get("Morpheus")->debug("[JIT Pass] Map is NOT empty, offloading the existing values!!!");
          auto leaf_desc = nlohmann::json::parse(table->leaf_desc);
          nlohmann::json struct_desc;
          AllocaInst *alloca_struct = nullptr;
          if (!leaf_desc.is_array()) {
            // The leaf of this map is a simple element
            struct_desc = leaf_desc;

            alloca_struct = createAllocaForSimpleLeafValues(ctx_, pfn, table->leaf_desc, table->leaf_size);
          } else {
            // The leaf contained in this map is a struct, let's extract the needed information
            struct_desc = leaf_desc[1];

            // An allocaInstruction is placed on top of the main block of the current function
            // This is IMPORTANT because if the instruction is not placed on top of this block
            // the compiler crashes (and it is damn hard to understand why)
            alloca_struct = createAllocaForStructLeafValues(ctx_, pfn, table->leaf_desc, table->leaf_size);
          }

          // What I am gonna do before JIT compiling the entries into the code is to insert the
          // guards to protect the values when the corresponding maps are updated
          // What I do now is to insert a guard for the entire map, then every time the map
          // is update the guards is also updated. However, another possibility is to
          // insert a guard for each value of the map. E.g., if we have a map whose update
          // rate is high but the most used entries (i.e., the one offloaded) are not updated
          // then it makes sense to have a per-value guard.
          // This may be achieved by using a per-CPU map equals to the optimized map and use the guard
          // as the value for each key of this map (that is accessed using the original key).
          // What is happening here is the following:
          // Before:
          //   BeforePseudo
          //   llvm.bpf.pseudo(1, map_fd);
          //   bitcastInstruction
          //   helperCallInstruction
          //   Tail
          // After:
          //   BeforePseudo
          //   guard = BPFLookupGuardMap()
          //   if (guard == vN) goto OptBB;
          //   else goto Default;
          //   OptBB:
          //     LoadInstruction(key)
          //     Switch(key):
          //       Case value: CaseNBlock
          //   Default:
          //     llvm.bpf.pseudo(1, map_fd);
          //     bitcastInstruction
          //     helperCallInstruction
          //   PhiInstruction(Default, CaseNBlock...)
          //   Tail
          BasicBlock *OptBB = bb->splitBasicBlock(bb->getTerminator());
          if (dynamic_opt_compiler.get_config().enable_guard && (!table->is_read_only || !dynamic_opt_compiler.isMapROAcrossModules(table->fd))) {
            spdlog::get("Morpheus")->debug("[JIT Pass] Creating guard for this map since it is not real-only!!!");
            createGuardForTable(ctx_, *table, bb->getTerminator(), OptBB, Default);
          }

          //Let's start building before the terminator of the original basic block
          builder::IRBuilderBPF IRB(OptBB->getTerminator());
          Value *key_value = nullptr;

          auto key_desc = nlohmann::json::parse(table->key_desc);
          nlohmann::json key_struct_desc;

          if (!key_desc.is_array()) {
            key_struct_desc = key_desc;
            // First of all, let me extract the key value from the lookup call
            auto real_key_value = dyn_opt::utils::getKeyValueFromLookupHelperCall(*helperInstruction);
            assert(real_key_value != nullptr);

            // First, let's load the key into a variable and then create the switch comparison
            key_value = IRB.CreateLoad(real_key_value, "key_value");
          } else {
            // The leaf contained in this map is a struct, let's extract the needed information
            key_struct_desc = key_desc[1];

            // We are dealing with a complex key, composed of different elements
            // The solution that I want to apply now is to perform the jhash of the key
            // and compare it with the pre-computed values, so that they can be injected
            Function *jhash_func = pfn.getParent()->getFunction(JHASH_FUNC_NAME);
            assert(jhash_func != nullptr && "Unable to find function 'jhash_' into the module");

            std::vector<Value *> args;
            // First argument is the pointer to the key (struct)
            args.push_back(dyn_opt::utils::getKeyPtrFromLookupHelperCall(*helperInstruction));
            args.push_back(ConstantInt::get(Type::getInt32Ty(ctx_), table->key_size));
            args.push_back(ConstantInt::get(Type::getInt32Ty(ctx_), JHASH_INITVAL_INT));

            key_value = IRB.CreateCall(jhash_func, args);
          }

          if (dynamic_opt_compiler.get_config().enable_debug_printk) {
            IRB.CreateTracePrintkOneArg("Map: " + table->name + " -> Key value: %u!\n", key_value);
          }

          switchInst = SwitchInst::Create(key_value, Default, 0);
          ReplaceInstWithInst(OptBB->getTerminator(), switchInst);

          // If the table is not empty, I will go through the map values
          // and I will modify the code accordingly in order to JIT compile the
          // values directly into the code.
          std::vector<std::string> topEntries;
          unsigned int num_cases = 0;

          // If the size of the current values in the map is less than the maximum number of
          // entries that can be offloaded we can skip the instrumentation step.
          // However, if the map is an LPM it is better to keep the result of the instrumentation
          // since with the last one we can get the real most accessed entries that can be
          // for instance the /32 addresses, while in the map we may have less specific entries (e.g., /24).
          if (values.size() > dynamic_opt_compiler.getMaxOffloadedEntries() || table->type == BPF_MAP_TYPE_LPM_TRIE) {
            // topEntries = getEntriesFromInstrumentedMap(table->fd, dynamic_opt_compiler.getMaxOffloadedEntries());
            topEntries = getEntriesFromInstrumentedMap(table->fd, table->max_entries);

            if (topEntries.empty()) {
              spdlog::get("Morpheus")->trace("No runtime entries found in the instrumented map for map: {}", table->name);
              goto createPhi;
            } else {
              spdlog::get("Morpheus")->debug("Found {} TOP Entries", topEntries.size());
            }

            for (auto &topKey : topEntries) {
              // First of all, let's find the corresponding entries in the list of values
              auto it = std::find_if(values.begin(), values.end(),
                                      [&](const std::pair<std::string, std::string> &val) {
                                          return (topKey == val.first);
                                      });

              std::pair<std::string, std::string> entry;
              if (it == values.end()) {
                  // Try to lookup the value in the map with the one included in the instrumented
                  // map. This is possible if in the LPM we store a value that is less specific
                  // than the one used to perform the lookup
                  spdlog::get("Morpheus")->debug("[JIT Pass] Top entry not found in the values. Try to lookup in the map");
                  std::string map_value;
                  ebpf::StatusTuple res(-1);
                  if (is_map_in_map_lookup && nested_map_fds.size() > 0) {
                    for (auto &fd : nested_map_fds) {
                      res = dyn_opt::utils::get_value_from_map(fd, topKey, map_value, *table);
                      if (res.code() == 0) {
                        break;
                      }
                    }
                  } else {
                    res = genericTable.get_value(topKey, map_value);
                  }
                  if (res.code() != 0) {
                    spdlog::get("Morpheus")->trace("[JIT Pass] Map does not contain a value for key: {}", topKey);
                    map_value.erase();
                    entry = std::make_pair(topKey, map_value);
                  } else {
                    entry = std::make_pair(topKey, map_value);
                  }
              } else {
                entry = *it;
              }

              spdlog::get("Morpheus")->trace("[JIT Pass] Top entry key from map: {}", entry.first);
              spdlog::get("Morpheus")->trace("[JIT Pass] Top entry leaf from map: {}", entry.second);

              auto key_constant = getKeyConstantValue(ctx_, key_struct_desc, table->key_size, entry.first);
              auto final_value = createCaseBlockForEntry(bb->getContext(), bb->getParent(), Tail, table->name,
                                                          alloca_struct,
                                                          entry, struct_desc, table->leaf_size, table->type);

              // Now I should add the new block as case to the switch instruction
              switchInst->addCase(key_constant, std::get<1>(final_value));
              CaseValues.emplace_back(std::move(final_value));
              num_cases++;
              offloaded_entries_list_.push_back(entry.first);

              if (num_cases == dynamic_opt_compiler.getMaxOffloadedEntries()) {
                break;
              }
            }
          }

          for (auto &entry : values) {
            /*
              * Now I do not want to JIT all the values. We should put an upper-bound that
              * now is fixed but maybe in a second moment it is decided at runtime.
              */
            // TODO: This value of dynamic_opt_compiler.getMaxOffloadedEntries() could be dynamic depending on various conditions
            if (num_cases >= dynamic_opt_compiler.getMaxOffloadedEntries() || topEntries.size() > 0) break;

            if (std::find(topEntries.begin(), topEntries.end(), entry.first) != topEntries.end())
              continue;

            spdlog::get("Morpheus")->trace("[JIT Pass] Key from map: {}", entry.first);
            spdlog::get("Morpheus")->trace("[JIT Pass] Leaf from map: {}", entry.second);

            auto key_constant = getKeyConstantValue(ctx_, key_struct_desc, table->key_size, entry.first);
            auto final_value = createCaseBlockForEntry(bb->getContext(), bb->getParent(), Tail, table->name,
                                                        alloca_struct,
                                                        entry, struct_desc, table->leaf_size, table->type);


            // Now I should add the new block as case to the switch instruction
            switchInst->addCase(key_constant, std::get<1>(final_value));
            CaseValues.emplace_back(std::move(final_value));
            num_cases++;
            offloaded_entries_list_.push_back(entry.first);
          }
        }

createPhi:
        createAndAddPhiNode(pfn, *Tail, CaseValues, helperInstruction);

        // Before we finish, I want to mark the current helper as optimized so that we cannot apply the
        // manipulation again
        MDNode *N = MDNode::get(ctx_, MDString::get(ctx_, "true"));
        helperInstruction->setMetadata("opt.hasBeenProcessed", N);

        if (values.size() <= CaseValues.size() && table->is_read_only && dynamic_opt_compiler.isMapROAcrossModules(table->fd) && table->type != BPF_MAP_TYPE_LPM_TRIE) {
          spdlog::get("Morpheus")->info("[JIT Pass] Performing DCE for JITed table {}, since the entries are small.", table->name);
          /*
            * This is for the dead code elimination.
            * I remove all the instructions (that are already dead)
            * referencing that table.
            * In this case, if we do not match the entries we should substitute
            * the map result with null, in order to simulate the entry not found.
            */
          while (Default->getFirstNonPHI() != helperInstruction) {
            Default->getFirstNonPHI()->eraseFromParent();
          }

          //TODO: What I want to do here is to replace the instruction with the key value
          //that is shared among all the entries
          BasicBlock::iterator ii(helperInstruction);
          // helperInstruction->replaceAllUsesWith(ConstantPointerNull::get(llvm::Type::getInt8PtrTy(ctx_)));
          ReplaceInstWithValue(helperInstruction->getParent()->getInstList(), ii,
                                ConstantPointerNull::get(llvm::Type::getInt8PtrTy(ctx_)));
        } 

        modified = true;

        /* Since I made some modifications on the function I update the iterator with the position of
          * the last block generated (Tail)
          */
        bb = Tail->getIterator();
        instruction = bb->begin();
      } else {
        spdlog::get("Morpheus")->debug("[JIT Pass] This type of map is currently not supported");
      }
    }
  }

#if LLVM_VERSION_MAJOR >= 9
  EliminateUnreachableBlocks(pfn);
#endif
  return modified;
}

void JITTableRuntimePass::deleteAllInstructionsInRange(llvm::LLVMContext &context, Instruction* startInst, Instruction* endInst) {
    BasicBlock::iterator it(startInst);
    BasicBlock::iterator it_end(endInst);
    it_end--;

    Instruction* currentInst ;

    while (it != it_end ) {
        currentInst = &*it;

       // this cannot be done at the end of the while loop.
       // has to be incremented before "erasing" the instruction
        ++it;
        if (it == it_end) continue;

        if (!currentInst->use_empty()) {   
          if (currentInst == endInst) {
            currentInst->replaceAllUsesWith(ConstantPointerNull::get(llvm::Type::getInt8PtrTy(context)));
          } else {
            currentInst->replaceAllUsesWith(UndefValue::get(currentInst->getType()));
          }
        }

        currentInst->eraseFromParent();
    }

}

std::vector<std::string> JITTableRuntimePass::getEntriesFromInstrumentedMap(int originalMapFd, uint max_entries) {
  spdlog::get("Morpheus")->trace("[JIT Pass] getEntriesFromInstrumentedMap called with fd: {}", originalMapFd);

  if (original_maps_to_instrumented_maps_.find(originalMapFd) == original_maps_to_instrumented_maps_.end())
    return std::vector<std::string>();

  std::vector<std::string> entries;

  TableDesc &instMapDesc = original_maps_to_instrumented_maps_[originalMapFd];
  assert(instMapDesc.leaf_size == sizeof(uint64_t) && "Undefined format of instrumented map!");
//      if (instMapDesc.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
//        auto table = BPFPercpuArrayTable<uint64_t>(instMapDesc);
//        auto values = table.get_table_offline();
//
//        std::sort(values.begin(), values.end(), [](const std::vector<uint64_t> &lhs, const std::vector<uint64_t> &rhs) {
//            return std::accumulate(lhs.begin(), lhs.end(), 0) > std::accumulate(rhs.begin(), rhs.end(), 0);
//        });
//
//        for (size_t i = 0; i < values.size(); i++) {
//          if (i > max_entries) break;
//          entries.push_back(std::to_string(std::accumulate(values[i].begin(), values[i].end(), 0)));
//        }
//
//      } else
//      if (instMapDesc.type == BPF_MAP_TYPE_PERCPU_HASH || instMapDesc.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
  if (instMapDesc.type == BPF_MAP_TYPE_LRU_PERCPU_HASH || instMapDesc.type == BPF_MAP_TYPE_PERCPU_HASH) {
    auto table = BPFTable(instMapDesc);
    std::vector<std::pair<std::string, std::vector<std::string>>> values;

    int instrumented_map_fd = instMapDesc.fd;
    spdlog::get("Morpheus")->trace("[JIT Pass] getEntriesFromInstrumentedMap: Reading values from instrumented map {}", instrumented_map_fd);

    StatusTuple rc = table.get_table_offline_percpu(values);
    if (rc.code() != 0) {
      spdlog::get("Morpheus")->error("[JIT Pass] Error while reading instrumented map: {}", rc.msg());
    }

    if (values.size() == 0) {
      spdlog::get("Morpheus")->trace("[JIT Pass] getEntriesFromInstrumentedMap: Got empty map from instrumented values");
    } else {
      spdlog::get("Morpheus")->trace("[JIT Pass] getEntriesFromInstrumentedMap: Got {} instrumented values", values.size());
    }

    // entries = dyn_opt::utils::getTopEntriesFromInstrumentedEntriesPerCPU(values, max_entries);
    entries = dyn_opt::utils::getTopEntriesFromInstrumentedEntries(values, max_entries);
  } else {
    spdlog::get("Morpheus")->trace("[JIT Pass] Unsupported instrumented map. Skipping!");
    return std::vector<std::string>();
  }


  return entries;
}

BasicBlock *JITTableRuntimePass::createGuardForTable(llvm::LLVMContext &context, TableDesc &table,
                                                      llvm::Instruction *insertBefore, llvm::BasicBlock *IfTrue,
                                                      llvm::BasicBlock *ifFalse) {

  int guard_fd = 0;
  // First of all, we need to create the guard table if it does not exist
  if (original_maps_to_guards_.find(table.fd) != original_maps_to_guards_.end()) {
    // The guard map already exists, we need to extract the fd
    guard_fd = original_maps_to_guards_[table.fd].fd;
  } else {
    // We need to create the guard map and allocate a new FD to it
    guard_fd = createGuardMap(table);
    assert(guard_fd > 0 && "[JIT Pass] Error while creating the guard map");
  }

  struct bpf_map_info info = {};
  uint32_t info_len = sizeof(info);
  bpf_obj_get_info(guard_fd, &info, &info_len);
  spdlog::get("Morpheus")->debug("[JIT Pass] Guard for table: {} has been created with fd: {}/{}", table.name, guard_fd, info.id);

  auto guard_table = BPFPercpuArrayTable<uint64_t>(original_maps_to_guards_[table.fd]);
  std::vector<uint64_t> guard_map_value(BPFTable::get_possible_cpu_count(), 0);
  auto res = guard_table.update_value(0, guard_map_value);
  assert(res.code() == 0 && "[JIT Pass] Unable to get current value from guard map");

  builder::IRBuilderBPF builder(insertBefore);

  // First, let's allocate the fixed key with index 0, which is used to lookup
  // into the per-CPU guard map
  auto alloca_key = builder.CreateAllocaBPF(Type::getInt32Ty(context));
  builder.CreateStore(builder.getInt32(0), alloca_key);

  auto guard_value = builder.CreateGuardMapLookupElem(guard_fd, Type::getInt64Ty(context), alloca_key, ifFalse,
                                                      MorpheusCompiler::getInstance().get_config().enable_debug_printk);
  auto guard_cmp_res = builder.CreateICmpEQ(guard_value, builder.getInt64(guard_map_value[0]));

  builder.CreateCondBr(guard_cmp_res, IfTrue, ifFalse);
  return builder.GetInsertBlock();
}

int JITTableRuntimePass::createGuardMap(TableDesc &original_map) {
  int fd, map_type, key_size, value_size, max_entries, map_flags;
  const char *map_name;

  // The type of the guard map is always a per-cpu array
  map_type = BPF_MAP_TYPE_PERCPU_ARRAY;

  // The name of the guard map is equal to the original name + "_guard"
  // TODO: This should be improved to avoid that the program uses the same name for another map
  // But I do not know if this can be actually a problem
  auto original_map_name = original_map.name;
  original_map_name.resize(5);
  map_name = std::string(original_map_name + "_g").c_str();

  // WARNING: The size of the array map cannot be less than an integer
  // otherwise the map is not loaded
  key_size = sizeof(int);

  // At the same time, the size of the value inside the guard map is
  // just 1B; in this way we are creating maps with up to 256 different
  // versions, which sounds quite reasonable to me.
  // Unfortunately, it is not possible to set values that are not aligned to 8B
  value_size = sizeof(uint64_t);

  // The max number of entries is 1 since this map contains only the guard value
  max_entries = 1;

  // I will copy the same flags as the original maps
  // TODO: Check if this is correct or it is better to put the flags to 0
  // Setting the same flags as the original one can be a problem when we try to
  // optimize maps such as LPM Tries that use different flags and we copy them into a different
  // map type (i.e., LRU_MAP)
  //map_flags = original_map.flags;
  map_flags = 0;

  struct bpf_create_map_attr attr = {};
  attr.map_type = (enum bpf_map_type) map_type;
  attr.name = map_name;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;

  fd = bcc_create_map_xattr(&attr, true);
  if (fd < 0) {
    spdlog::get("Morpheus")->error("[JIT Pass] could not open bpf map: {}, error: {}", map_name, strerror(errno));
    return -1;
  }

  // Let's create the corresponding BPFTable, which is easier to manipulate
  TableDesc desc = TableDesc(std::string(map_name), FileDesc(fd), map_type, key_size, value_size, max_entries,
                              map_flags);
  original_maps_to_guards_.emplace(original_map.fd, std::move(desc));

  auto guard_table = BPFPercpuArrayTable<uint64_t>(original_maps_to_guards_[original_map.fd]);
  std::vector<uint64_t> guard_init_value(BPFTable::get_possible_cpu_count(), 0);

  auto res = guard_table.update_value(0, guard_init_value);
  assert(res.code() == 0 && "[JIT Pass] Unable to initialize guard map");

  return fd;
}

AllocaInst *JITTableRuntimePass::createAllocaForSimpleLeafValues(LLVMContext &ctx, Function &mainFunction,
                                                                  std::string &leafDesc, size_t &leafSize) {
  IRBuilder<> IRB(&mainFunction.front().getInstList().front());

  auto leaf = nlohmann::json::parse(leafDesc);

  assert(!leaf.is_array() && "The leaf values are not in the expected JSON format (not array)");

  // TODO: What is missing here is the proper creation of the alloca struct with the correct types

  auto struct_elem = leaf.get<std::string>();

  Type *type = dyn_opt::utils::getCorrectTypeGivenDescription(ctx, struct_elem, leafSize);

  return IRB.CreateAlloca(type);
}

AllocaInst *JITTableRuntimePass::createAllocaForStructLeafValues(LLVMContext &ctx, Function &mainFunction,
                                                                  std::string &leafDesc, size_t &leafSize) {
  IRBuilder<> IRB(&mainFunction.front().getInstList().front());

  auto leaf = nlohmann::json::parse(leafDesc);

  assert(leaf.is_array() && "The leaf values are not in the expected JSON format (array)");

  // The first element is the name of the struct
  auto struct_name = leaf[0].get<std::string>();
  auto struct_elem = leaf[1];

  Type *struct_type = nullptr;

  auto final_str_name = "struct." + struct_name;

  if (struct_type == nullptr) {
    struct_type = StructType::create(ctx, struct_name);
    std::vector<Type *> members;
    // TODO: What is missing here is the proper creation of the alloca struct with the correct types
    for (auto &elem : struct_elem) {
      std::string value_name = elem[0];
      std::string value_type = elem[1];

      if (value_type.find("bpf_spin_lock") != std::string::npos) {
        assert(false && "Spin lock found in the struct definition");
        continue;
      }

      if (elem.size() == 3 && elem[2].is_array()) {
        // The element is an array, we should allocate the proper type
        unsigned int array_size = elem[2][0];
        auto type = ArrayType::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                    array_size);
        members.push_back(type);
      } else {
        members.push_back(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize));
      }
    }

    dyn_cast<StructType>(struct_type)->setBody(members);
  }

  std::string alloca_name = struct_name + std::to_string(rand() % 255) + "_alloca";
  auto alloca_struct = IRB.CreateAlloca(struct_type, nullptr, alloca_name);
  // IMPORTANT: Without this memset, the system crashes because the value could
  // be used to perform a lookup or update in the map and, if not initialized, can raise an error
  IRB.CREATE_MEMSET(alloca_struct, IRB.getInt8(0), leafSize, 1);
  //IRB.CreateMemSet(alloca_struct, IRB.getInt8(0), leafSize, 1);
  return alloca_struct;
}

bool JITTableRuntimePass::isSimpleKey(std::string &keyDesc) {
  auto key = nlohmann::json::parse(keyDesc);

  // If the description of the key is an array then we are dealing with complex
  // keys that are made of a struct of elements
  return !key.is_array();
}

llvm::ConstantInt *
JITTableRuntimePass::getKeyConstantValue(LLVMContext &ctx, nlohmann::json &keyDesc, size_t &keySize,
                                          std::string &keyValue) {
  uint32_t key = 0;

  IntegerType *key_type = nullptr;
  if (!keyDesc.is_array()) {
    bool signed_int = true;
    auto key_string = keyDesc.get<std::string>();
    if (key_string.find("unsigned") != std::string::npos) signed_int = false;
    if (signed_int) {
      key = std::stoi(keyValue, nullptr, 16);
    } else {
      key = std::stoul(keyValue, nullptr, 16);
    }

    key_type = dyn_opt::utils::getKeyType(ctx, key_string, keySize);
    assert((key_type != nullptr) && "The key in this map is not currently supported!");
  } else {
    auto key_value = nlohmann::json::parse(getJsonFromLeafValues(keyValue));
    assert(key_value.is_array() && "Unexpected format in the key values!");

    unsigned char key_array[keySize];
    unsigned int pos = 0;
    for (unsigned int i = 0; i < keyDesc.size(); i++) {
      assert(keyDesc[i].is_array() && "Wrong format of the element description");
      std::string value_name = keyDesc[i][0];
      std::string value_type = keyDesc[i][1];
      bool is_type_array = false;
      // bool is_type_union = false;
      unsigned int array_size = 1;
      if (keyDesc.size() > 2) {
        auto third_param = keyDesc[i][2];
        if (third_param.is_array()) {
          is_type_array = true;
        } else if (third_param.is_string() && third_param.get<std::string>() == "union") {
          assert(false && "Unions are not supported right now! :(");
        } else {
          assert(false && "Unknown third parameter in the key description");
        }
      }

      // if (is_type_union) {
      //   parseUnionKeyType(value_type);
      // }

      bool signed_int = true;

      if (value_name.find("__pad_end") != std::string::npos) {
        assert(value_type.find("char") != std::string::npos && "Final padding is not a char");

        auto padding_desc = keyDesc[i][2];
        assert(padding_desc.is_array() && "Found __pad_end but I was not able to read the value");
        
        unsigned int padding_size = padding_desc.at(0);
        
        for (unsigned int j = 0; j < padding_size; j++) {
          key_array[pos] = 0;
          pos++;
        }

        continue;
      }

      if (value_type.find("unsigned") != std::string::npos)
        signed_int = false;

      if (is_type_array) {
         array_size = keyDesc[i][2].at(0);
      }

      for (unsigned int j = 0; j < array_size; j++) {
        nlohmann::ordered_json value;
        if (key_value[i].is_string()) {
          value = key_value[i];
        } else if (key_value[i].is_array() && key_value[i][j].is_string()) {
          value = key_value[i][j];
        } else {
          assert(false && "Unexpected value while parsing the key");
        }

        if (value_type.find("long long") != std::string::npos) {
          // It is a 64bit integer
          if (signed_int) {
            int64_t real_value = std::stoll(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          } else {
            uint64_t real_value = std::stoull(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          }
        } else if (value_type.find("long") != std::string::npos || value_type.find("int") != std::string::npos) {
          // It is a 32bit integer
          if (signed_int) {
            int32_t real_value = std::stol(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          } else {
            uint32_t real_value = std::stoul(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          }
        } else if (value_type.find("short") != std::string::npos) {
          // It is a 16bit integer
          if (signed_int) {
            int16_t real_value = std::stoi(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          } else {
            uint16_t real_value = std::stoul(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          }
        } else if (value_type.find("char") != std::string::npos) {
          // It is a 8bit integer
          if (signed_int) {
            int8_t real_value = std::stoi(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          } else {
            uint8_t real_value = std::stoul(value.get<std::string>(), nullptr, 16);
            std::copy(static_cast<const char *>(static_cast<const void *>(&real_value)),
                      static_cast<const char *>(static_cast<const void *>(&real_value)) + sizeof(real_value),
                      key_array + pos);
            pos += sizeof(real_value);
          }
        } else {
          assert(false && "Unable to recognize type of the key");
        }
      }
    } // end for

    assert(pos == keySize && "Error while calculating the correct size of the key structure");
    // Now let's calculate the result of the jhash
    //key = jhash_words(reinterpret_cast<const uint32_t *>(key_array), keySize, JHASH_INITVAL);

    // TODO: Check if there is a collision in the hash of the offloaded entries.
    key = jhash_bytes((void *) key_array, keySize, JHASH_INITVAL);
    spdlog::get("Morpheus")->trace("[JIT Pass] Calculated jhash with value: {}", key);
    key_type = IntegerType::getInt32Ty(ctx);
  }

  return ConstantInt::get(key_type, key, false);
}

std::pair<Value *, BasicBlock *> JITTableRuntimePass::createCaseBlockForEntry(LLVMContext &ctx, Function *parent,
                                                                              BasicBlock *insertBefore,
                                                                              std::string &tableName,
                                                                              AllocaInst *allocaStruct,
                                                                              std::pair<std::string, std::string> &value,
                                                                              nlohmann::json &structDesc,
                                                                              size_t &leafSize, int tableType) {
  BasicBlock *CaseBlock = BasicBlock::Create(ctx, "", parent, insertBefore);
  BranchInst *branchInst = BranchInst::Create(insertBefore, CaseBlock);

  builder::IRBuilderBPF IRBCase(branchInst);
  Value *final_value = nullptr;

  if (MorpheusCompiler::getInstance().get_config().enable_debug_printk) {
    IRBCase.CreateTracePrintk("Map: " + tableName + " -> Optimized branch hit for key " + value.first + "!\n");
  }


  if (tableType == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
    auto map_id = std::stoul(value.second, nullptr, 16);
    auto map_fd = bpf_map_get_fd_by_id(map_id);

    if (map_fd < 0) {
      spdlog::get("Morpheus")->error("[JITTableRuntimePass] Error while retrieving map fd for array of maps");
      assert(false && "Runtime error while retrieving map fd");
    }

    spdlog::get("Morpheus")->trace("[JITTableRuntimePass] Dealing with Array of Maps. Map entry value is: {}, and fd is: {}", map_id, map_fd);

    auto map_fd_value = IRBCase.CreateBpfPseudoCall(map_fd);
    //auto value_ptr = CreateIntToPtr(getInt64(0), getInt8PtrTy());
    final_value = IRBCase.CreateIntToPtr(map_fd_value, IntegerType::getInt8PtrTy(ctx));
    //final_value = IRBCase.CreateBitCast(map_fd_value, IntegerType::getInt8PtrTy(ctx));

    return std::make_pair(final_value, CaseBlock);
  }

  std::string value_copy = value.second;
  value_copy.erase(std::remove(value_copy.begin(), value_copy.end(), '"'), value_copy.end());
  if (value.second.empty() || value_copy.empty()) {
    spdlog::get("Morpheus")->trace("[JIT Pass] Setting value pointer to NULL for entry: {}", value.first);
    // Table for that key is empty
    final_value = ConstantPointerNull::get(llvm::Type::getInt8PtrTy(ctx));
  } else {
    if (structDesc.is_array()) {
      // The leaf is a struct
      std::string tmp_string = getJsonFromLeafValues(value.second);
      spdlog::get("Morpheus")->trace("[JIT Pass] The string returned from getJsonFromLeafValues is: {}", tmp_string);
      auto leaf_value = nlohmann::json::parse(getJsonFromLeafValues(value.second));
      assert(leaf_value.is_array() && "Unexpected format in the leaf values!");

      // We are dealing with a struct, it should be safe to do this cast
      StructType *struct_type = dyn_cast_or_null<StructType>(allocaStruct->getType());
      if (struct_type == nullptr) {
        assert(false && "Error while processing struct in offloaded values");
      }

      for (unsigned int i = 0, j = 0; i < structDesc.size(); i++) {
        assert(structDesc[i].is_array() && "Wrong format of the element description");
        std::string value_name = structDesc[i][0];
        std::string value_type = structDesc[i][1];

        if (value_name.find("__pad") != std::string::npos ||
            value_type.find("bpf_spin_lock") != std::string::npos) {
            spdlog::get("Morpheus")->trace("[JIT Pass] Skip this entry, it is just padding or a bpf_spin_lock");
            continue;
        }

        auto signed_int = true;
        if (value_type.find("unsigned") != std::string::npos || 
            value_type.find("char") != std::string::npos) signed_int = false;

        auto gep_value = IRBCase.CreateStructGEP(allocaStruct, i, value_name);

        if (structDesc[i].size() == 3 && structDesc[i][2].is_array()) {
          spdlog::get("Morpheus")->trace("[JIT Pass] We are inside an array");
          // We have an array in this case as an entry in the struct
          //unsigned int array_size = structDesc[i][2][0];
          std::vector<Constant *> vect;

          // ArrayType *array_type = dyn_cast_or_null<ArrayType>(struct_type->elements()[i]);
          // assert(array_type != nullptr && "This field should be an array type");

          assert(leaf_value[j].is_array() && "Unexpected format for the leaf values!");

          if (value_type == "char" && leaf_value[j].size() == 1) {
            uint32_t string_size = structDesc[i][2].at(0).get<uint32_t>();
            std::string string_to_offload = std::string(string_size, 0);
            std::string original_string = leaf_value[j].get<std::string>();
            string_to_offload.replace(0, original_string.length(), original_string);
            // We have a string to allocate
            spdlog::get("Morpheus")->trace("[JIT Pass] We need to allocate a string of size {} in this case: {}", string_to_offload.length(), string_to_offload);

            std::vector<llvm::Constant *> chars(string_to_offload.size());
            for(unsigned int i = 0; i < string_to_offload.size(); i++) {
              chars[i] = ConstantInt::get(IntegerType::getInt8Ty(ctx), string_to_offload[i]);
            }
            auto init = ConstantArray::get(ArrayType::get(IntegerType::getInt8Ty(ctx), chars.size()), chars);
            IRBCase.CreateStore(init, gep_value);
          } else {
            for (auto &elem : leaf_value[j]) {
              if (value_type.find("long long") != std::string::npos) {
                // It is a 64bit integer
                if (signed_int) {
                  int64_t real_value = std::stoll(elem.get<std::string>(), nullptr, 16);
                  vect.push_back(
                        ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                          real_value));
                } else {
                  uint64_t real_value = std::stoull(elem.get<std::string>(), nullptr, 16);
                  vect.push_back(
                        ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                          real_value));
                }
              } else if (value_type.find("long") != std::string::npos || value_type.find("int") != std::string::npos) {
                // It is a 32bit integer
                if (signed_int) {
                  int32_t real_value = std::stol(elem.get<std::string>(), nullptr, 16);
                  vect.push_back(
                        ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                          real_value));
                } else {
                  uint32_t real_value = std::stoul(elem.get<std::string>(), nullptr, 16);
                  vect.push_back(
                        ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                          real_value));
                }
              } else if (value_type.find("short") != std::string::npos) {
                if (signed_int) {
                  int16_t real_value = std::stoi(elem.get<std::string>(), nullptr, 16);
                  vect.push_back(
                          ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                            real_value));
                  // vect.push_back(ConstantInt::get(array_type->getArrayElementType(), real_value));
                } else {
                  uint16_t real_value = std::stoul(elem.get<std::string>(), nullptr, 16);
                  // vect.push_back(ConstantInt::get(array_type->getArrayElementType(), real_value));
                  vect.push_back(
                          ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                            real_value));
                }
              } else if (value_type.find("char") != std::string::npos) {
                if (signed_int) {
                  int8_t real_value = std::stoi(elem.get<std::string>(), nullptr, 16);
                  vect.push_back(
                          ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                            real_value));
                  // vect.push_back(ConstantInt::get(array_type->getArrayElementType(), real_value));
                } else {
                  uint8_t real_value = std::stoul(elem.get<std::string>(), nullptr, 16);
                  // vect.push_back(ConstantInt::get(array_type->getArrayElementType(), real_value));
                  vect.push_back(
                          ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                            real_value));
                }
              } else {
                assert(false && "Unable to recognize type of the key");
              }
            }

            // Allocate the array with the values
            auto llvm_array = ConstantArray::get(
                    ArrayType::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                    vect.size()), vect);
            // auto llvm_array = ConstantArray::get(array_type, vect);
            IRBCase.CreateStore(llvm_array, gep_value);
          }
        } else {
          if (value_type.find("long long") != std::string::npos) {
            // It is a 64bit integer
            if (signed_int) {
              int64_t real_value = std::stoll(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
            } else {
              uint64_t real_value = std::stoull(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
            }
          } else if (value_type.find("long") != std::string::npos || value_type.find("int") != std::string::npos) {
            // It is a 32bit integer
            if (signed_int) {
              int32_t real_value = std::stol(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
            } else {
              uint32_t real_value = std::stoul(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
            }
          } else if (value_type.find("short") != std::string::npos) {
            if (signed_int) {
              int16_t real_value = std::stoi(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
              // IRBCase.CreateStore(ConstantInt::get(struct_type->elements()[i], real_value), gep_value);
            } else {
              uint16_t real_value = std::stoul(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
              // IRBCase.CreateStore(ConstantInt::get(struct_type->elements()[i], real_value), gep_value);
            }
          } else if (value_type.find("char") != std::string::npos) {
            if (signed_int) {
              int8_t real_value = std::stoi(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
              // IRBCase.CreateStore(ConstantInt::get(struct_type->elements()[i], real_value), gep_value);
            } else {
              uint8_t real_value = std::stoul(leaf_value[j].get<std::string>(), nullptr, 16);
              IRBCase.CreateStore(
                      ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                        real_value),
                      gep_value);
              // IRBCase.CreateStore(ConstantInt::get(struct_type->elements()[i], real_value), gep_value);
            }
          } else {
            assert(false && "Unable to recognize type of the key");
          }
        }
        j++;
      }
    } else {
      //TODO: Fix this with the correct stoul depending on type
      auto value_type = structDesc.get<std::string>();
      auto real_value = std::stoul(value.second, nullptr, 16);
      IRBCase.CreateStore(
              ConstantInt::get(dyn_opt::utils::getCorrectTypeGivenDescription(ctx, value_type, leafSize),
                                real_value),
              allocaStruct);
    }

    final_value = IRBCase.CreateBitCast(allocaStruct, IntegerType::getInt8PtrTy(ctx));
  }

  return std::make_pair(final_value, CaseBlock);
}

std::string JITTableRuntimePass::getJsonFromLeafValues(const std::string &values) {
  const std::regex quotes(R"QUOTES("([^"]*)")QUOTES");
  const std::regex re(R"(([^\[\]\s\{\}]+)(?=\s))");
  const std::regex re1(R"(([^\[\s\{\}]+)(?=\s[^\]|\}]))");
  const std::regex substitution(R"("0xffff")");

  std::smatch m;
  std::string old_string;
  if (std::regex_search(values, m, quotes)) {
    old_string = m[1];
  }

  std::string first_pass = std::regex_replace(values, quotes, R"(0xffff)");
  std::string second_pass = std::regex_replace(first_pass, re, R"("$1")");
  std::string third_pass = std::regex_replace(second_pass, re1, R"($1,)");

  if (old_string.length() > 0) {
    old_string = ebpf::dyn_opt::utils::escape_json(old_string);
    old_string = "\"" + old_string + "\"";
    third_pass = std::regex_replace(third_pass, substitution, old_string);
  }

  std::replace(third_pass.begin(), third_pass.end(), '{', '[');
  std::replace(third_pass.begin(), third_pass.end(), '}', ']');

  return third_pass;
}

void JITTableRuntimePass::createAndAddPhiNode(Function &pFunction, BasicBlock &insertInto,
                                              std::vector<std::pair<Value *, BasicBlock *>> &caseValues,
                                              CallInst *helperInstruction) {
  ValueToValueMapTy vMap;
  DebugInfoFinder DIFinder;

  if (caseValues.empty())
    return;

  PHINode *Phi = nullptr;
  // Finally, I create a PHY node that contains all the results of the previous if-else blocks
  Phi = PHINode::Create(helperInstruction->getType(), 0);

  insertInto.getInstList().insert(insertInto.getFirstInsertionPt(), Phi);

  vMap[helperInstruction] = Phi;
  DIFinder.processInstruction(*pFunction.getParent(), *helperInstruction);
  for (DISubprogram *ISP : DIFinder.subprograms())
    vMap.MD()[ISP].reset(ISP);

  for (DICompileUnit *CU : DIFinder.compile_units())
    vMap.MD()[CU].reset(CU);

  for (DIType *Type : DIFinder.types())
    vMap.MD()[Type].reset(Type);

  dyn_opt::utils::remapInstructionsInFunction(pFunction, vMap);

  for (auto &value : caseValues) {
    Phi->addIncoming(std::get<0>(value), std::get<1>(value));
  }

  //IMPORTANT: If I do not put this instruction here, it may be replaced by the others
  Phi->addIncoming(helperInstruction, helperInstruction->getParent());

}

template< typename T >
std::string JITTableRuntimePass::int_to_hex( T i )
{
  std::stringstream stream;
  stream << "0x" 
         << std::setfill ('0') << std::setw(sizeof(T)*2) 
         << std::hex << i;
  return stream.str();
}

// Called once for each module, before the calls on the basic blocks.
// We could use doFinalization to clear RNG, but that's not needed.
bool JITTableRuntimePass::doFinalization(Module &M) {
  // Let's remove the jhash function from this module, otherwise it raises a compilation error
//      Function *jhash_func = M.getFunction(JHASH_FUNC_NAME);
//
//      if (jhash_func != nullptr) {
//        jhash_func->replaceAllUsesWith(UndefValue::get((Type*)jhash_func->getType()));
//
//        jhash_func->eraseFromParent();
//      }

  return false;
}

TableDesc *JITTableRuntimePass::getTableByFD(llvm::ConstantInt &pInt) {
  return dyn_opt::utils::getTableByFD(pInt, bpf_module_id_, ts_, fake_fd_map_, tables_);
}

Pass *JITTableRuntimePass::createJITTableRuntimePass(std::string id, std::string func_name, ebpf::TableStorage *ts,
                                                      ebpf::fake_fd_map_def &fake_fd_map,
                                                      std::vector<ebpf::TableDesc *> &tables,
                                                      std::map<int, TableDesc> &original_maps_to_guards,
                                                      std::map<int, TableDesc> &original_maps_to_instrumented_maps,
                                                      std::vector<std::string> &offloaded_entries_list) {
  return new JITTableRuntimePass(std::move(id), std::move(func_name), ts, fake_fd_map, tables,
                                  original_maps_to_guards, original_maps_to_instrumented_maps,
                                  offloaded_entries_list);
}

} //namespace ebpf
