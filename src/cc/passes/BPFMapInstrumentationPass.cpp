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

#include "BPFMapInstrumentationPass.h"

#include "utils.h"
#include "cc/macro_logger.h"
#include <cc/api/BPFTable.h>
#include <cc/libbpf/src/bpf.h>
#include "builder/irbuilderbpf.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace ebpf {

char BPFMapInstrumentationPass::ID;

BPFMapInstrumentationPass::BPFMapInstrumentationPass(std::string id, std::string func_name, TableStorage *ts,
                                                      fake_fd_map_def &fake_fd_map,
                                                      std::vector<TableDesc *> &tables,
                                                      std::map<int, TableDesc> &instrum_maps)
        : FunctionPass(ID), bpf_module_id_(std::move(id)), func_name_(std::move(func_name)), ts_(ts),
          fake_fd_map_(fake_fd_map), tables_(tables), original_maps_to_instrumented_maps_(instrum_maps) {}

BPFMapInstrumentationPass::~BPFMapInstrumentationPass() = default;

bool BPFMapInstrumentationPass::doInitialization(Module &M) {
  return false;
}

bool BPFMapInstrumentationPass::runOnFunction(Function &pfn) {
  bool modified = false;

  auto &dynamic_opt_compiler = ebpf::MorpheusCompiler::getInstance();

  if (pfn.getName() != func_name_) {
    // I will skip all the functions that I am not interested in
    return false;
  }

  for (auto bb = pfn.begin(); bb != pfn.end(); bb++) {
    for (auto instruction = bb->begin(); instruction != bb->end(); instruction++) {
      bool is_map_in_map_lookup = false;
      int map_in_map_fd = -1;
      // The getBPFMapLookup call will return the pointer to the instruction containing the real
      // helper call, but only if the call is a bpf_map_lookup_elem. Otherwise the call
      // will return nullptr.
      // In addition, this function will check if the input instruction is a llvm.bpf.pseudo
      // call, and then it will go two instructions after to find the helper call.
      auto helperInstruction = dyn_opt::utils::getCompleteBPFMapLookupCallInst(*instruction, true);
      if (helperInstruction == nullptr) {
        continue;
      }

      if (MDNode *N = helperInstruction->getMetadata("opt.hasBeenInstrumented")) {
        auto processed = cast<MDString>(N->getOperand(0))->getString();
        if (processed.contains("true")) {
          spdlog::get("Morpheus")->trace("[utils] Instruction already instrumented. Skipping!");
          continue;
        }
      }

      auto bpfPseudoCallInst = dyn_opt::utils::findPseudoFromHelperInstr(*helperInstruction);
      if (bpfPseudoCallInst == nullptr) {
        // There is still a case that we have to consider here.
        // When the lookup is a reference to an map obtained from the ARRAY_OF_MAPS.
        // In this case, I read the debug information where I can find the ARRAY_OF_MAP table FD associated
        // and read the corresponding entries.
        map_in_map_fd = dyn_opt::utils::getMapInMapFDFromDebugInfo(*helperInstruction);
        if (map_in_map_fd > 0) {
          is_map_in_map_lookup = true;
          spdlog::get("Morpheus")->trace("[BPFInstr Pass] This lookup is referring to a BPF_MAP_IN_MAP with fd: {}", map_in_map_fd);
          bpfPseudoCallInst = helperInstruction;
        } else {
          continue;
        }
      }

      ebpf::TableDesc *table = nullptr;
      std::vector<int> nested_map_fds;
      if (is_map_in_map_lookup && map_in_map_fd > 0) {
        std::tie(nested_map_fds, table) = dyn_opt::utils::getNestedMapInMapTable(pfn.getContext(), map_in_map_fd, bpf_module_id_, ts_, fake_fd_map_, tables_);
      } else {
        auto *ci = dyn_opt::utils::getBPFPseudoTableFd(*bpfPseudoCallInst);
        table = getTableByFD(*ci);
      }

      auto &config = MorpheusCompiler::getInstance().get_config();
      if (std::find(config.tables_to_skip.begin(), config.tables_to_skip.end(), table->name) != config.tables_to_skip.end()) {
        spdlog::get("Morpheus")->debug("[JIT Pass] Skip table {}", table->name);
        continue;
      }
      // if (table->name == "index64" || table->name == "ctl_array" || table->name == "dp_rules") 
      //   continue;

      if (!dyn_opt::utils::mapCanBeInstrumented(table)) {
        spdlog::get("Morpheus")->debug("[BPFInstr Pass] Skipping map: {} since it cannot be instrumented", table->name);
        continue;
      } else if (table->max_entries <= dynamic_opt_compiler.getMaxOffloadedEntries() && table->type != BPF_MAP_TYPE_LPM_TRIE && !MorpheusCompiler::getInstance().get_config().naive_instrumentation) {
        spdlog::get("Morpheus")->debug("[BPFInstr Pass] No need to instrument map: {}. All entries can be offloaded (max_size <= MAX_OFFLOADED_ENTRIES)", table->name);
        continue;
      }
      
      //TODO: Check if there is another way to avoid reading all the current map values
      std::vector<std::pair<std::string, std::string>> values;
      auto genericTable = ebpf::BPFTable(*table);
      if (is_map_in_map_lookup && nested_map_fds.size() > 0) {
        dyn_opt::utils::readEntriesFromNestedTables(values, nested_map_fds, *table, dynamic_opt_compiler.getMaxOffloadedEntries()*8);
      } else {
        genericTable.get_table_offline(values, dynamic_opt_compiler.getMaxOffloadedEntries()*2);
      }

      if (values.size() <= dynamic_opt_compiler.getMaxOffloadedEntries() && table->type != BPF_MAP_TYPE_LPM_TRIE && !MorpheusCompiler::getInstance().get_config().naive_instrumentation) {
        spdlog::get("Morpheus")->debug("[BPFInstr Pass] No need to instrument map: {}. All entries can be offloaded (runtime_size <= MAX_OFFLOADED_ENTRIES)",
                 table->name);
        continue;
      } else if (values.empty()) {
        spdlog::get("Morpheus")->debug("[BPFInstr Pass] No need to instrument map: {}. The map is empty!", table->name);
        continue;
      }

      spdlog::get("Morpheus")->debug("[BPFInstr Pass] Instrumenting map: {0} (fd: {1}), type: {2}", table->name, (int) table->fd,
                dyn_opt::utils::table_type_id_to_string_name(table->type));

      // First of all, let's create the ancillary per-CPU map equivalent to the normal map that we
      // are going to instrument and let's
      auto &instrumented_map = getOrCreateInstrumentedMap(*table);

      int inst_fd = instrumented_map.fd;

      struct bpf_map_info info = {};
      uint32_t info_len = sizeof(info);
      bpf_obj_get_info(inst_fd, &info, &info_len);
      spdlog::get("Morpheus")->info("[BPFInstr Pass] Instrumented map for original map: {0} has been created with fd: {1}, and id: {2}",
                table->name, inst_fd, info.id);

      // Now that we have the instrumented map, we should create the corresponding call to update the value
      // of the map
      BasicBlock *Default = SplitBlock(bpfPseudoCallInst->getParent(), bpfPseudoCallInst);

      // What I want to do here is to add a random number generator in oder to perform the instrumentation
      // on X packets, so that we can reduce the overhead.
      if (MorpheusCompiler::getInstance().get_config().instrumentation_rate < 100) {
        uint64_t percentage = std::stoul(std::to_string(MorpheusCompiler::getInstance().get_config().instrumentation_rate));
        uint64_t max = std::numeric_limits<uint32_t>::max();
        uint64_t max_range = (max * percentage) / 100;

        createLookupAndUpdateValue(instrumented_map, helperInstruction, bb->getTerminator(), Default, max_range);
      } else {
        createLookupAndUpdateValue(instrumented_map, helperInstruction, bb->getTerminator(), Default);
      }

      modified = true;

      // Before we finish, I want to mark the current helper as optimized so that we cannot apply the
      // manipulation again
      MDNode *N = MDNode::get(pfn.getContext(), MDString::get(pfn.getContext(), "true"));
      helperInstruction->setMetadata("opt.hasBeenInstrumented", N);

      // Since I made some modifications on the function I update the iterator with the position of
      // the last block generated (Tail)
      bb = Default->getIterator();
      instruction = bb->begin();

      spdlog::get("Morpheus")->info("[BPFInstr Pass] Instrumentation completed for map: {}", table->name);
    }
  }

  return modified;
}

bool BPFMapInstrumentationPass::doFinalization(Module &M) {
  return false;
}

void BPFMapInstrumentationPass::createLookupAndUpdateValue(TableDesc &instrumented_map,
                                                            llvm::CallInst *originalHelperCall,
                                                            llvm::Instruction *insertBefore,
                                                            llvm::BasicBlock *defaultBlock, uint32_t max_range) {
  // Let's start building before the call to the bpf.pseudo helper
  builder::IRBuilderBPF builder(insertBefore);

  auto origin_key_ptr = dyn_opt::utils::getKeyPtrFromLookupHelperCall(*originalHelperCall);

  Value *res_value = nullptr;
  if (instrumented_map.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
    res_value = builder.CreateInstrumentedMapLookup(instrumented_map.fd,
                                                    Type::getInt64PtrTy(originalHelperCall->getContext()),
                                                    origin_key_ptr, defaultBlock, max_range,
                                                    MorpheusCompiler::getInstance().get_config().enable_debug_printk);
  } else if (instrumented_map.type == BPF_MAP_TYPE_PERCPU_HASH ||
              instrumented_map.type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
    res_value = builder.CreateInstrumentedMapLookupOrInit(instrumented_map.fd,
                                                          Type::getInt64PtrTy(originalHelperCall->getContext()),
                                                          origin_key_ptr, defaultBlock, max_range,
                                                          MorpheusCompiler::getInstance().get_config().enable_debug_printk);
  } else {
    assert(false && "[BPFInstr Pass] Unsupported instrumented map type");
  }

  if (MorpheusCompiler::getInstance().get_config().enable_debug_printk) {
    builder.CreateTracePrintk(
            "Updating value of instrumented map with fd: " + std::to_string(instrumented_map.fd) + "\n");
  }

  builder.CreateAtomicRMW(AtomicRMWInst::BinOp::Add, res_value, builder.getInt64(1),
                          AtomicOrdering::SequentiallyConsistent);

  builder.CreateBr(defaultBlock);
}

TableDesc *BPFMapInstrumentationPass::getTableByFD(llvm::ConstantInt &pInt) {
  return dyn_opt::utils::getTableByFD(pInt, bpf_module_id_, ts_, fake_fd_map_, tables_);
}

TableDesc &BPFMapInstrumentationPass::getOrCreateInstrumentedMap(TableDesc &bpfTable) {
  // First of all, we need to create the guard table if it does not exist

  if (original_maps_to_instrumented_maps_.find(bpfTable.fd) == original_maps_to_instrumented_maps_.end()) {
    // We need to create the guard map and allocate a new FD to it
    int instrumented_map_fd = createInstrumentedMap(bpfTable);
    if (instrumented_map_fd <= 0) {
      assert(false && "[BPFInstr Pass] Error while creating the instrumented map");
    }
  }

  return original_maps_to_instrumented_maps_[bpfTable.fd];
}

int BPFMapInstrumentationPass::createInstrumentedMap(TableDesc &original_map) {
  int fd, map_type, key_size, value_size, max_entries;
  int map_flags = 0;
  const char *map_name;
  auto &dynamic_opt_compiler = ebpf::MorpheusCompiler::getInstance();

  // The type of the instrumented map depends on the type of the original map (but it is a per-cpu)
  //map_type = dyn_opt::utils::getEquivalentPerCPUMap(original_map.type);
  // map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH;
  map_type = BPF_MAP_TYPE_PERCPU_HASH;

  // The name of the guard map is equal to the original name + "_guard"
  // TODO: This should be improved to avoid that the program uses the same name for another map
  // But I do not know if this can be actually a problem
  auto original_map_name = original_map.name;
  original_map_name.resize(5);
  map_name = std::string(original_map_name + "_in").c_str();

  // The size of the key will be the same as the original key of the map
  key_size = original_map.key_size;

  // The size of the value will be a 64bit integer in order to keep a counter of the entries
  value_size = sizeof(uint64_t);

  // The max number of entries is 1 since this map contains only the guard value
  //max_entries = original_map.max_entries;
  if (dynamic_opt_compiler.getMaxOffloadedEntries() > 50) {
    max_entries = dynamic_opt_compiler.getMaxOffloadedEntries()*100;
  } else {
    max_entries = 50*100;
  }

  struct bpf_create_map_attr attr = {};
  attr.map_type = (enum bpf_map_type) map_type;
  attr.name = map_name;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;

  fd = bcc_create_map_xattr(&attr, true);
  if (fd < 0) {
    spdlog::get("Morpheus")->error("could not open bpf map: {}, error: {}", map_name, strerror(errno));
    return -1;
  }

  // Let's create the corresponding BPFTable, which is easier to manipulate
  TableDesc desc = TableDesc(std::string(map_name), FileDesc(fd), map_type, key_size, value_size, max_entries,
                              map_flags);
  original_maps_to_instrumented_maps_.emplace(original_map.fd, std::move(desc));

  return fd;
}

Pass *
BPFMapInstrumentationPass::createBPFMapInstrumentationPass(std::string id, std::string func_name, TableStorage *ts,
                                                            fake_fd_map_def &fake_fd_map,
                                                            std::vector<TableDesc *> &tables,
                                                            std::map<int, TableDesc> &instrum_maps) {
  return new BPFMapInstrumentationPass(std::move(id), std::move(func_name), ts, fake_fd_map, tables, instrum_maps);
}

} //namespace ebpf
