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

#include <string>
#include <llvm/IR/Instructions.h>
#include <cc/api/BPFTable.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/IR/LLVMContext.h>

namespace ebpf {
namespace dyn_opt {
namespace utils {
    using namespace llvm;

    CallInst *getBPFMapLookupCallInst(Instruction &instruction, bool isInstrumentationPass=false);
    CallInst *getCompleteBPFMapLookupCallInst(Instruction &instruction, bool isInstrumentationPass=false);
    CallInst *getCompleteBPFMapUpdateCallInst(Instruction &instruction, bool isInstrumentationPass=false);
    CallInst *findPseudoFromHelperInstr(Instruction &instruction);
    bool hasMapInMapDebugInfo(Instruction &instruction);
    int getMapInMapFDFromDebugInfo(Instruction &instruction);
    std::tuple<std::vector<int>, ebpf::TableDesc *> getNestedMapInMapTable(LLVMContext &ctx, const int &map_in_map_fd, std::string &bpf_module_id, ebpf::TableStorage *ts,
                                    ebpf::fake_fd_map_def &fake_fd_map, std::vector<ebpf::TableDesc *> &tables);
    IntegerType *getCorrectTypeGivenDescription(LLVMContext &ctx, std::string &elemType, size_t &elemSize);
    IntegerType *getKeyType(LLVMContext &ctx, std::string &keyDesc, size_t &keySize);
    ConstantInt *getBPFPseudoTableFd(CallInst &instruction);
    ebpf::TableDesc *getTableByFD(ConstantInt &pInt, std::string &bpf_module_id, ebpf::TableStorage *ts_,
                                    ebpf::fake_fd_map_def &fake_fd_map_, std::vector<ebpf::TableDesc *> &tables_);
    ebpf::TableDesc *getTableByFD(const int &pInt, std::string &bpf_module_id, ebpf::TableStorage *ts_,
                                    ebpf::fake_fd_map_def &fake_fd_map_, std::vector<ebpf::TableDesc *> &tables_);
    ebpf::TableDesc *getTableByName(const std::string &map_name, std::string &bpf_module_id, ebpf::TableStorage *ts_,
                                    ebpf::fake_fd_map_def &fake_fd_map_, std::vector<ebpf::TableDesc *> &tables_);  

    std::string table_type_id_to_string_name(int table_id);
    StatusTuple get_value_from_map(int table_fd, const std::string& key_str, std::string& value_str, ebpf::TableDesc &desc);

    bool mapCanBeInstrumented(TableDesc *bpfTable);
    bool nestedMapIsReadOnly(Instruction &helperCall);

    int getEquivalentPerCPUMap(int type);
    Value *getKeyValueFromLookupHelperCall(CallInst &helperCall);
    Value *getKeyPtrFromLookupHelperCall(CallInst &helperCall);
    void remapInstructionsInFunction(llvm::Function &func, ValueToValueMapTy &vMap);
    void remapInstructionsInBB(llvm::BasicBlock &func, ValueToValueMapTy &vMap);

    StatusTuple key_to_string(const void* key, std::string& key_str, size_t key_size, snprintf_fn &snprintf);
    StatusTuple leaf_to_string(const void* value, std::string& value_str, size_t leaf_size, snprintf_fn &snprintf);
    StatusTuple string_to_key(const std::string& key_str, void* key, sscanf_fn &sscanf);

    void readEntriesFromNestedTables(std::vector<std::pair<std::string, std::string>> &res, std::vector<int> &nested_map_fds, 
                                        ebpf::TableDesc &table, unsigned int max_entries);

    std::vector<std::string> getTopEntriesFromInstrumentedEntries(std::vector<std::pair<std::string, std::vector<std::string>>> &instrValues, uint maxEntries);

    std::vector<std::string> getTopEntriesFromInstrumentedEntriesPerCPU(std::vector<std::pair<std::string, std::vector<std::string>>> &instrValues, uint maxEntries);

    std::string escape_json(const std::string &s);

} //utils
} //dyn_opt
} //ebpf
