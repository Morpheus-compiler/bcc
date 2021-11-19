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

#include "bcc_exception.h"
#include "table_storage.h"
#include "MorpheusCompiler.h"

#include "nlohmann/json.hpp"

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/Analysis/MemorySSA.h>

namespace ebpf {

    class JITTableRuntimePass : public llvm::FunctionPass {
    public:
        JITTableRuntimePass(std::string id, std::string func_name, TableStorage *ts, fake_fd_map_def &fake_fd_map,
                            std::vector<TableDesc *> &tables, std::map<int, TableDesc> &original_maps_to_guards,
                            std::map<int, TableDesc> &original_maps_to_instrumented_maps,
                            std::vector<std::string> &offloaded_entries_list);

        ~JITTableRuntimePass() override;

        bool doInitialization(llvm::Module &M) override;
        bool runOnFunction(llvm::Function &pfn) override;
        bool doFinalization(llvm::Module &M) override;
        static llvm::Pass *createJITTableRuntimePass(std::string id, std::string func_name, ebpf::TableStorage *ts,
                                                     ebpf::fake_fd_map_def &fake_fd_map,
                                                     std::vector<ebpf::TableDesc *> &tables,
                                                     std::map<int, TableDesc> &original_maps_to_guards,
                                                     std::map<int, TableDesc> &original_maps_to_instrumented_maps,
                                                     std::vector<std::string> &offloaded_entries_list);

        // The address of this static is used to uniquely identify this pass in the
        // pass registry. The PassManager relies on this address to find instance of
        // analyses passes and build dependencies on demand.
        // The value does not matter.
        static char ID;

    private:
        std::string bpf_module_id_;
        std::string func_name_;
        ebpf::TableStorage *ts_;
        ebpf::fake_fd_map_def &fake_fd_map_;
        std::vector<ebpf::TableDesc *> &tables_;
        //llvm::Module *jhash_mod_;
        std::map<int, TableDesc> &original_maps_to_guards_;
        std::map<int, TableDesc> &original_maps_to_instrumented_maps_;
        std::vector<std::string> &offloaded_entries_list_;

        TableDesc *getTableByFD(llvm::ConstantInt &pInt);

        static llvm::ConstantInt *
        getKeyConstantValue(llvm::LLVMContext &ctx, nlohmann::json &keyDesc, size_t &keySize, std::string &keyValue);
        static llvm::AllocaInst *createAllocaForStructLeafValues(llvm::LLVMContext &ctx, llvm::Function &mainFunction,
                                                                 std::string &leafDesc, size_t &leafSize);
        static llvm::AllocaInst *createAllocaForSimpleLeafValues(llvm::LLVMContext &ctx, llvm::Function &mainFunction,
                                                                 std::string &leafDesc, size_t &leafSize);
        static std::pair<llvm::Value *, llvm::BasicBlock *> createCaseBlockForEntry(llvm::LLVMContext &ctx,
                                                                                    llvm::Function *parent,
                                                                                    llvm::BasicBlock *insertBefore,
                                                                                    std::string &tableName,
                                                                                    llvm::AllocaInst *allocaStruct,
                                                                                    std::pair<std::string, std::string> &value,
                                                                                    nlohmann::json &structDesc,
                                                                                    size_t &leafSize, int tableType);
        static void createAndAddPhiNode(llvm::Function &pFunction, llvm::BasicBlock &insertInto,
                                        std::vector<std::pair<llvm::Value *, llvm::BasicBlock *>> &caseValues,
                                        llvm::CallInst *helperInstruction);
        static std::string getJsonFromLeafValues(const std::string &values);
        static bool isSimpleKey(std::string &basicString);

        llvm::BasicBlock *
        createGuardForTable(llvm::LLVMContext &context, TableDesc &table, llvm::Instruction *insertBefore,
                            llvm::BasicBlock *IfTrue, llvm::BasicBlock *ifFalse);
        int createGuardMap(TableDesc &original_map);

        template< typename T >
        std::string int_to_hex( T i );

        std::vector<std::string> getEntriesFromInstrumentedMap(int originalMapFd, uint max_entries);
        // std::tuple<bool, std::string> parseUnionKeyType(nlohmann::json &keyDesc);
    };
}