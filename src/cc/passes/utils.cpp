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

#include "utils.h"
#include "api/BPFTable.h"

#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/Support/raw_ostream.h>

#include "cc/macro_logger.h"
#include "linux/bpf.h"

#include <set>
#include <queue>
#include <sstream>
#include <iomanip>
#include <spdlog/spdlog.h>

namespace ebpf {
namespace dyn_opt {
namespace utils {

using namespace llvm;

CallInst *getCompleteBPFMapLookupCallInst(Instruction &instruction, bool isInstrumentationPass) {
  auto callInst = dyn_cast_or_null<CallInst>(&instruction);

  if (callInst == nullptr) {
    return nullptr;
  }

  // I need to drop all the debug instruction or all the LLVM intrisics
  Function *calledFunction = callInst->getCalledFunction();
  if (calledFunction != nullptr && calledFunction->isIntrinsic())
    return nullptr;

  if (DILocation *Loc = callInst->getDebugLoc()) {
    if (auto scope = Loc->getScope()) {
      if (scope->getName().startswith("bpf_map_lookup_elem_")) {
        spdlog::get("Morpheus")->trace("[utils] Found map lookup call");

        if (MDNode *N = callInst->getMetadata("opt.hasBeenProcessed")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true") && !isInstrumentationPass) {
            spdlog::get("Morpheus")->trace("[utils] Instruction already optimized. Skipping!");
            return nullptr;
          }
        }

        if (MDNode *N = callInst->getMetadata("opt.isInstrumentedMap")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true")) {
            spdlog::get("Morpheus")->trace("[utils] This is a map used for instrumentation. Skipping!");
            return nullptr;
          }
        }

        if (MDNode *N = callInst->getMetadata("opt.isGuardMap")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true")) {
            spdlog::get("Morpheus")->trace("[utils] This is a map used for guards. Skipping!");
            return nullptr;
          }
        }

        if (MDNode *N = callInst->getMetadata("opt.cannotBeOptimized")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true")) {
            spdlog::get("Morpheus")->trace("[utils] Instruction cannot be optimized. Skipping!");
            return nullptr;
          }
        }

        return callInst;
      } else {
        return nullptr;
      }
    }
  }

  return nullptr;
}

CallInst *getCompleteBPFMapUpdateCallInst(Instruction &instruction, bool isInstrumentationPass) {
  auto callInst = dyn_cast_or_null<CallInst>(&instruction);

  if (callInst == nullptr) {
    return nullptr;
  }

  // I need to drop all the debug instruction or all the LLVM intrisics
  Function *calledFunction = callInst->getCalledFunction();
  if (calledFunction != nullptr && calledFunction->isIntrinsic())
    return nullptr;

  if (DILocation *Loc = callInst->getDebugLoc()) {
    if (auto scope = Loc->getScope()) {
      if (scope->getName().startswith("bpf_map_update_elem")) {
        spdlog::get("Morpheus")->trace("[utils] Found map update call");

        return callInst;
      } else {
        return nullptr;
      }
    }
  }

  return nullptr;
}

CallInst *getBPFMapLookupCallInst(Instruction &instruction, bool isInstrumentationPass) {
  auto callInst = dyn_cast_or_null<CallInst>(&instruction);
  CallInst *helperInstruction = nullptr;

  if (callInst == nullptr)
    return nullptr;

  Function *calledFunction = callInst->getCalledFunction();

  if (calledFunction == nullptr)
    return nullptr;

  // First I would like to check if the prototype of the function is the same as the
  // bpf_map_lookup that we already have. In this way, we can recognize the function "easily".
  // if (calledFunction->getFunctionType() )

  StringRef funcName = calledFunction->getName();

  if (funcName.find("llvm.bpf.pseudo") == std::string::npos) {
    return nullptr;
  }

  auto nextInstruction = instruction.getNextNonDebugInstruction();
  if (nextInstruction == nullptr) {
    spdlog::get("Morpheus")->trace("[utils] Strange format in the LLVM IR code. Lookup pattern not found!");
    spdlog::get("Morpheus")->trace("[utils] Not able to find instruction after llvm.bpf.pseudo!");
    return nullptr;
  }

  // Now I should find the call instruction to understand if it is a lookup or not
  auto newInstruction = nextInstruction->getNextNonDebugInstruction();
  helperInstruction = dyn_cast_or_null<CallInst>(newInstruction);

  if (helperInstruction == nullptr) {
    spdlog::get("Morpheus")->trace("[utils] Strange format in the LLVM IR code. Lookup pattern not found!");
    spdlog::get("Morpheus")->trace("[utils] Not able to find helper CallInst!");
    return nullptr;
  }
  //assert(helperInstruction != nullptr && "Detected llvm.bpf.pseudo but not the helper instruction");

  if (DILocation *Loc = helperInstruction->getDebugLoc()) {
    if (auto scope = Loc->getScope()) {
      if (scope->getName().startswith("bpf_map_lookup_elem")) {
        spdlog::get("Morpheus")->trace("[utils] Found map lookup call");

        if (MDNode *N = helperInstruction->getMetadata("opt.hasBeenProcessed")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true") && !isInstrumentationPass) {
            spdlog::get("Morpheus")->trace("[utils] Instruction already optimized. Skipping!");
            return nullptr;
          }
        }

        if (MDNode *N = helperInstruction->getMetadata("opt.isInstrumentedMap")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true")) {
            spdlog::get("Morpheus")->trace("[utils] This is a map used for instrumentation. Skipping!");
            return nullptr;
          }
        }

        if (MDNode *N = helperInstruction->getMetadata("opt.isGuardMap")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true")) {
            spdlog::get("Morpheus")->trace("[utils] This is a map used for guards. Skipping!");
            return nullptr;
          }
        }

        if (MDNode *N = helperInstruction->getMetadata("opt.cannotBeOptimized")) {
          auto processed = cast<MDString>(N->getOperand(0))->getString();
          if (processed.contains("true")) {
            spdlog::get("Morpheus")->trace("[utils] Instruction cannot be optimized. Skipping!");
            return nullptr;
          }
        }

        return helperInstruction;
      } else {
        spdlog::get("Morpheus")->trace("Found map call, but it is not a lookup. Skipping!");
        return nullptr;
      }
    }
  }
  return nullptr;
}

CallInst *findPseudoFromHelperInstr(Instruction &helperInstruction) {
  auto nextInstruction = helperInstruction.getPrevNonDebugInstruction();

  CallInst *pseudoInstruction = nullptr;
  if (nextInstruction == nullptr) {
    std::string str;
    llvm::raw_string_ostream(str) << nextInstruction;
    spdlog::get("Morpheus")->trace("[utils] Strange format in the LLVM IR code. Lookup pattern not found!");
    spdlog::get("Morpheus")->trace("[utils] Not able to find instruction before helper function!");
    // spdlog::get("Morpheus")->trace("[utils] Instruction: {}!", str);
    return nullptr;
  }

  // Now I should find the call instruction to understand if it is a lookup or not
  auto newInstruction = nextInstruction->getPrevNonDebugInstruction();
  pseudoInstruction = dyn_cast_or_null<CallInst>(newInstruction);

  if (pseudoInstruction == nullptr) {
    std::string str;
    llvm::raw_string_ostream(str) << pseudoInstruction;
    spdlog::get("Morpheus")->trace("[utils] Strange format in the LLVM IR code. Lookup pattern not found!");
    spdlog::get("Morpheus")->trace("[utils] Not able to find instruction that is calling bpf.pseudo!");
    // spdlog::get("Morpheus")->trace("[utils] Instruction: {}!", str);
    return nullptr;
  }

  Function *calledFunction = pseudoInstruction->getCalledFunction();

  if (calledFunction == nullptr)
    return nullptr;

  // First I would like to check if the prototype of the function is the same as the
  // bpf_map_lookup that we already have. In this way, we can recognize the function "easily".
  // if (calledFunction->getFunctionType() )
  StringRef funcName = calledFunction->getName();

  if (funcName.find("llvm.bpf.pseudo") == std::string::npos) {
    return nullptr;
  }

  return pseudoInstruction;
}

bool hasMapInMapDebugInfo(Instruction &instruction) {
  if (MDNode *N = instruction.getMetadata("opt.arrayOfMapFD")) {
    llvm::APInt map_fd;
    auto processed = cast<MDString>(N->getOperand(0))->getString();
    if (!processed.getAsInteger(10, map_fd)) {
      spdlog::get("Morpheus")->trace("[utils] Found arrayOfMapFD info!");
      return true;
    }
  }
  return false;
}
  
int getMapInMapFDFromDebugInfo(Instruction &instruction) {
  if (MDNode *N = instruction.getMetadata("opt.arrayOfMapFD")) {
    llvm::APInt map_fd;
    auto processed = cast<MDString>(N->getOperand(0))->getString();
    if (!processed.getAsInteger(10, map_fd)) {
      spdlog::get("Morpheus")->trace("[utils] Found arrayOfMapFD info!");
      return map_fd.getSExtValue();
    }
  }
  return -1;
}

IntegerType *getCorrectTypeGivenDescription(LLVMContext &ctx, std::string &elemType, size_t &elemSize) {
  IntegerType *type = nullptr;
  if (elemType.find("int") != std::string::npos) {
    type = IntegerType::getInt32Ty(ctx);
  } else if (elemType.find("long long") != std::string::npos) {
    type = IntegerType::getInt64Ty(ctx);
  } else if (elemType.find("short") != std::string::npos) {
    type = IntegerType::getInt16Ty(ctx);
  } else if (elemType.find("char") != std::string::npos) {
    type = IntegerType::getInt8Ty(ctx);
  } else if (elemType.find("_Bool") != std::string::npos) {
    type = IntegerType::getInt8Ty(ctx);
  } else {
    assert(false && "Current value in the struct is not supported!");
  }

  return type;
}

IntegerType *getKeyType(LLVMContext &ctx, std::string &keyDesc, size_t &keySize) {
  IntegerType *key_type = nullptr;

  if (keyDesc.find("long long") != std::string::npos && keySize == 8) {
    key_type = IntegerType::getInt64Ty(ctx);
  } else if (keyDesc.find("int") != std::string::npos && keySize == 4) {
    key_type = IntegerType::getInt32Ty(ctx);
  } else if (keyDesc.find("int") != std::string::npos && keySize == 2) {
    key_type = IntegerType::getInt16Ty(ctx);
  } else if (keyDesc.find("short") != std::string::npos && keySize == 2) {
    key_type = IntegerType::getInt16Ty(ctx);
  } else if (keyDesc.find("char") != std::string::npos && keySize == 1) {
    key_type = IntegerType::getInt8Ty(ctx);
  } else if (keyDesc.find("_Bool") != std::string::npos && keySize == 1) {
    key_type = IntegerType::getInt8Ty(ctx);
  } else {
    assert(false && "Current value in the struct is not supported!");
  }

  return key_type;
}

std::string table_type_id_to_string_name(int table_id) {
  switch (table_id) {
    case BPF_MAP_TYPE_HASH:
      return std::string("BPF_MAP_TYPE_HASH");
    case BPF_MAP_TYPE_ARRAY:
      return std::string("BPF_MAP_TYPE_ARRAY");
    case BPF_MAP_TYPE_LPM_TRIE:
      return std::string("BPF_MAP_TYPE_LPM_TRIE");
    case BPF_MAP_TYPE_LRU_HASH:
      return std::string("BPF_MAP_TYPE_LRU_HASH");
    case BPF_MAP_TYPE_PERCPU_ARRAY:
      return std::string("BPF_MAP_TYPE_PERCPU_ARRAY");
    case BPF_MAP_TYPE_PERCPU_HASH:
      return std::string("BPF_MAP_TYPE_PERCPU_HASH");
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
      return std::string("BPF_MAP_TYPE_LRU_PERCPU_HASH");
    case BPF_MAP_TYPE_ARRAY_OF_MAPS:
      return std::string("BPF_MAP_TYPE_ARRAY_OF_MAPS");
    default:
      return std::string("UNKNOWN");
  }
}

ConstantInt *getBPFPseudoTableFd(CallInst &instruction) {
  // Once we detect the start of the BPF helper call, we first extract the
  // file descriptor of the map, which is provided as the second argument in
  // the llvm.bpf.pseudo call.
  auto *ci = dyn_cast<ConstantInt>(instruction.getOperand(1));
  assert(ci != nullptr && "Error in format of bpf.pseudo call");

  return ci;
}

std::tuple<std::vector<int>, ebpf::TableDesc *> getNestedMapInMapTable(LLVMContext &ctx, const int &map_in_map_fd, std::string &bpf_module_id, ebpf::TableStorage *ts,
                                        ebpf::fake_fd_map_def &fake_fd_map, std::vector<ebpf::TableDesc *> &tables) {
  ebpf::TableDesc *mapInMapTable = getTableByFD(map_in_map_fd, bpf_module_id, ts, fake_fd_map, tables);
  spdlog::get("Morpheus")->trace("[utils] getNestedMapInMapTable. Map fd is: {}", map_in_map_fd);
  std::vector<int> runtime_nested_fds;

  if (mapInMapTable != nullptr && mapInMapTable->type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
    BPFArrayOfMapTable arrayTable(*mapInMapTable);
    std::vector<int> table_fds = arrayTable.get_table_offline();
    for (auto &value : table_fds) {
      // Get first non-null value.
      if (value > 0) {
        auto nested_table_fd = bpf_map_get_fd_by_id(value);

        if (nested_table_fd < 0) {
          spdlog::get("Morpheus")->error("[utils] Error while retrieving map fd for array of maps");
          assert(false && "Runtime error while retrieving map fd");
        }

        runtime_nested_fds.push_back(nested_table_fd);
      }
    }

    // Most of the times, the nested tables are created from the control plane. 
    // What I want to do here, is to just take the description of the keys and values of those table
    // I can use the innermap fd for this, which is the map used to create the ARRAY_OF_MAP table in the
    // BCC-compatible data plane.

    spdlog::get("Morpheus")->trace("[utils] Got runtime values of the nested map. The innermap is: {}", mapInMapTable->inner_map_name);

    ebpf::TableDesc *nestedMapTable = getTableByName(mapInMapTable->inner_map_name, bpf_module_id, ts, fake_fd_map, tables);
    if (nestedMapTable != nullptr) {
      spdlog::get("Morpheus")->trace("[utils] Got nested table");
      return std::make_tuple(runtime_nested_fds, nestedMapTable);
    }
  }
  return std::make_tuple(runtime_nested_fds, nullptr);
}

StatusTuple key_to_string(const void* key, std::string& key_str, size_t key_size, snprintf_fn &snprintf) {
  char buf[8 * key_size];
  StatusTuple rc = snprintf(buf, sizeof(buf), key);
  if (!rc.code())
    key_str.assign(buf);
  return rc;
}

StatusTuple leaf_to_string(const void* value, std::string& value_str, size_t leaf_size, snprintf_fn &snprintf) {
  char buf[8 * leaf_size];
  StatusTuple rc = snprintf(buf, sizeof(buf), value);
  if (!rc.code())
    value_str.assign(buf);
  return rc;
}

StatusTuple string_to_key(const std::string& key_str, void* key, sscanf_fn &sscanf) {
  return sscanf(key_str.c_str(), key);
}

bool mapCanBeInstrumented(TableDesc *bpfTable) {
  return (bpfTable->type == BPF_MAP_TYPE_HASH || bpfTable->type == BPF_MAP_TYPE_LRU_HASH ||
          bpfTable->type == BPF_MAP_TYPE_ARRAY || bpfTable->type == BPF_MAP_TYPE_LPM_TRIE);
}

bool nestedMapIsReadOnly(Instruction &helperCall) {
  if (MDNode *N = helperCall.getMetadata("opt.isReadOnly")) {
    auto processed = cast<MDString>(N->getOperand(0))->getString();
    if (processed.contains("false")) {
      return false;
    }
  }
  return true;
}

void readEntriesFromNestedTables(std::vector<std::pair<std::string, std::string>> &res, 
                                 std::vector<int> &nested_map_fds, ebpf::TableDesc &desc,
                                 unsigned int max_entries) {
  auto key = std::unique_ptr<void, decltype(::free)*>(::malloc(desc.key_size), ::free);
  auto value = std::unique_ptr<void, decltype(::free)*>(::malloc(desc.leaf_size), ::free);

  std::string key_str;
  std::string value_str;

  StatusTuple r(0);

  res.clear();

  if (desc.type != BPF_MAP_TYPE_HASH && desc.type != BPF_MAP_TYPE_LRU_HASH) {
    spdlog::get("Morpheus")->error("We currently do not support nested tables different than HASH");
    assert(false && "[utils] We currently do not support nested tables different than HASH");
  }

  unsigned int max_entries_per_map = max_entries / nested_map_fds.size();
  int return_code;
  for (auto &fd : nested_map_fds) {
    spdlog::get("Morpheus")->trace("[utils] Reading values from map: {}", fd);
    if ((return_code = bpf_get_first_key(fd, key.get(), desc.key_size)) < 0) {
      spdlog::get("Morpheus")->error("[utils] First failed while reading map: {0}. Rc: {1}, {2}", fd, return_code, errno);
      continue;
    }

    while(true) {
      if (bpf_lookup_elem(fd, key.get(), value.get()) < 0) {
        break;
      }

      r = dyn_opt::utils::key_to_string(key.get(), key_str, desc.key_size, desc.key_snprintf);
      if (r.code() != 0) {
        spdlog::get("Morpheus")->error("[utils] Error while reading map {} key", fd);
        break;
      }

      r =  dyn_opt::utils::leaf_to_string(value.get(), value_str, desc.leaf_size, desc.leaf_snprintf);
      if (r.code() != 0) {
        spdlog::get("Morpheus")->error("[utils] Error while reading map {} value", fd);
        break;
      }
      res.emplace_back(key_str, value_str);

      if (res.size() == max_entries_per_map)
        break;

      if (bpf_get_next_key(fd, key.get(), key.get()) < 0)
        break;
    }
  }
}

StatusTuple get_value_from_map(int table_fd, const std::string& key_str, std::string& value_str, ebpf::TableDesc &desc) {
  char key[desc.key_size];
  char value[desc.leaf_size];

  StatusTuple r(0);

  r = dyn_opt::utils::string_to_key(key_str, key, desc.key_sscanf);
  if (r.code() != 0)
    return r;

  if (bpf_lookup_elem(table_fd, key, value) < 0) {
    return StatusTuple(-1, "error getting value");
  }

  return dyn_opt::utils::leaf_to_string(value, value_str, desc.leaf_size, desc.leaf_snprintf);
}

// I am using the same type of map for all the instrumented entries
int getEquivalentPerCPUMap(int type) {
  switch (type) {
    case BPF_MAP_TYPE_LPM_TRIE:
    case BPF_MAP_TYPE_HASH:
    case BPF_MAP_TYPE_LRU_HASH:
    case BPF_MAP_TYPE_ARRAY:
//                  return BPF_MAP_TYPE_LRU_PERCPU_HASH;
      return BPF_MAP_TYPE_PERCPU_HASH;
//                case BPF_MAP_TYPE_ARRAY:
//                  return BPF_MAP_TYPE_PERCPU_ARRAY;
    default:
      assert(false && "Unsupported map type for instrumentation");
  }
  return -1;
}

Value *getKeyValueFromLookupHelperCall(CallInst &helperCall) {
  auto key_value = helperCall.getOperand(1);
  auto bitCastInstruction = dyn_cast<BitCastInst>(key_value);
  if (bitCastInstruction != nullptr) {
    auto real_key_value = bitCastInstruction->getOperand(0);
    return real_key_value;
  } else {
    return key_value;
  }
}

Value *getKeyPtrFromLookupHelperCall(CallInst &helperCall) {
  auto key_value = helperCall.getOperand(1);
  auto bitCastInstruction = dyn_cast<BitCastInst>(key_value);
  // This instruction should be a BitCast, otherwise there is something wrong
  if (bitCastInstruction != nullptr) {
    return bitCastInstruction;
  } else {
    return key_value;
  }
}

ebpf::TableDesc *getTableByFD(ConstantInt &pInt, std::string &bpf_module_id, ebpf::TableStorage *ts,
                              ebpf::fake_fd_map_def &fake_fd_map, std::vector<ebpf::TableDesc *> &tables) {
  auto &map_fd = pInt.getValue();
  ebpf::TableDesc *table = nullptr;

  for (const auto &map : fake_fd_map) {
    if (map.first == map_fd) {
      auto &map_name = std::get<1>(map.second);

      ebpf::TableStorage::iterator table_it;
      if (!ts->Find({bpf_module_id, map_name}, table_it))
        return nullptr;

      table = &table_it->second;
      return table;
    }
  }

  for (const auto &map : tables) {
    if (map->fd == map_fd) {
      auto &map_name = map->name;

      ebpf::TableStorage::iterator table_it;
      if (!ts->Find({bpf_module_id, map_name}, table_it))
        return nullptr;

      table = &table_it->second;
      return table;
    }
  }

  return table;
}

ebpf::TableDesc *getTableByFD(const int &pInt, std::string &bpf_module_id, ebpf::TableStorage *ts,
                              ebpf::fake_fd_map_def &fake_fd_map, std::vector<ebpf::TableDesc *> &tables) {
  auto &map_fd = pInt;
  ebpf::TableDesc *table = nullptr;
  for (const auto &map : fake_fd_map) {
    if (map.first == map_fd) {
      auto &map_name = std::get<1>(map.second);

      ebpf::TableStorage::iterator table_it;
      if (!ts->Find({bpf_module_id, map_name}, table_it))
        return nullptr;

      table = &table_it->second;
      return table;
    }
  }

  for (const auto &map : tables) {
    if (map->fd == map_fd) {
      auto &map_name = map->name;

      ebpf::TableStorage::iterator table_it;
      if (!ts->Find({bpf_module_id, map_name}, table_it))
        return nullptr;

      table = &table_it->second;
      return table;
    }
  }

  return table;
}

ebpf::TableDesc *getTableByName(const std::string &map_name, std::string &bpf_module_id, ebpf::TableStorage *ts,
                              ebpf::fake_fd_map_def &fake_fd_map, std::vector<ebpf::TableDesc *> &tables) {
  ebpf::TableDesc *table = nullptr;
  ebpf::TableStorage::iterator table_it;
  if (!ts->Find({bpf_module_id, map_name}, table_it))
    return nullptr;

  table = &table_it->second;
  return table;
}

void remapInstructionsInFunction(llvm::Function &func, llvm::ValueToValueMapTy &vMap) {
  // Loop over all of the instructions in the function, fixing up operand
  // references as we go.  This uses VMap to do all the hard work.
  for (Function::iterator BB = func.front().getIterator(),
                BE = func.end();
        BB != BE; ++BB) {
    // Loop over all instructions, fixing each one as we find it...
    for (Instruction &II : *BB) {
      RemapInstruction(&II, vMap, RF_IgnoreMissingLocals);
    }
  }
}

void remapInstructionsInBB(llvm::BasicBlock &BB, llvm::ValueToValueMapTy &vMap) {
  // Loop over all of the instructions in the function, fixing up operand
  // references as we go.  This uses VMap to do all the hard work.
  // Loop over all instructions, fixing each one as we find it...
  for (Instruction &II : BB) {
    RemapInstruction(&II, vMap, RF_IgnoreMissingLocals);
  }
}

std::vector<std::string> getTopEntriesFromInstrumentedEntries(std::vector<std::pair<std::string, std::vector<std::string>>> &instrValues, uint maxEntries) {
  std::map<std::string, uint64_t> values_map;
  std::vector<std::string> entries;

  // Defining a lambda function to compare two pairs. It will compare two pairs using second field
  auto compFunctor =
          [](const std::pair<std::string, uint64_t> &lhs, const std::pair<std::string, uint64_t> &rhs) {
              return lhs.second > rhs.second;
          };

  for (auto &entry : instrValues) {
    uint64_t sum = 0;
    for (auto &v : entry.second) {
      sum += std::stoul(v, nullptr, 16);
    }

    if (values_map.find(entry.first) != values_map.end()) {
      values_map[entry.first] += sum;
    } else {
      values_map[entry.first] = sum;
    }
  }

  std::set<std::pair<std::string, uint64_t>, decltype(compFunctor)> values_int(values_map.begin(), values_map.end(), compFunctor);

  unsigned int i = 0;
  for (auto &entry : values_int) {
    if (i >= maxEntries) break;
    entries.push_back(entry.first);
    i++;
  }

  return entries;
}

std::vector<std::string> getTopEntriesFromInstrumentedEntriesPerCPU(std::vector<std::pair<std::string, std::vector<std::string>>> &instrValues, uint maxEntries) {
  auto compFunctor = [](const std::pair<std::string, uint64_t> &lhs, const std::pair<std::string, uint64_t> &rhs) {
                          return lhs.second < rhs.second;
                        };

  if (instrValues.empty())
    return std::vector<std::string>();

  uint perCPUSize = instrValues[0].second.size();

  std::vector<std::priority_queue<std::pair<std::string, uint64_t>, std::vector<std::pair<std::string, uint64_t>>, decltype(compFunctor)>> valuesPerCPU(perCPUSize);

  for (auto &value : instrValues) {
    for (uint i = 0; i < value.second.size(); i++) {
      uint64_t count = std::stoull(value.second[i], nullptr, 16);
      valuesPerCPU[i].push(std::make_pair(value.first, count));
    }
  }

  uint finalSize = std::min(instrValues.size(), static_cast<size_t>(maxEntries));

  std::set<std::string> topEntries;

  uint pickFromCPU = 0;
  while (topEntries.size() != finalSize) {
    if (!valuesPerCPU[pickFromCPU].empty()) {
      auto value = valuesPerCPU[pickFromCPU].top();
      if (value.second > 0) {
        topEntries.insert(value.first);
      }
      valuesPerCPU[pickFromCPU].pop();
    }
    pickFromCPU++;
    pickFromCPU %= perCPUSize;
  }

  std::vector<std::string> topEntriesVect(topEntries.begin(), topEntries.end());

  return topEntriesVect;

}

std::string escape_json(const std::string &s) {
    std::ostringstream o;
    for (auto c = s.cbegin(); c != s.cend(); c++) {
        if (*c == '"' || *c == '\\' || ('\x00' <= *c && *c <= '\x1f')) {
            o << "\\u"
              << std::hex << std::setw(4) << std::setfill('0') << (int)*c;
        } else {
            o << *c;
        }
    }
    return o.str();
}

} //utils
} //dyn_opt
} //ebpf
