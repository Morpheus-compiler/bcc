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

#include <llvm/Pass.h>
#include "table_storage.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/Analysis/MemorySSA.h>

#pragma once

namespace ebpf {

    class BPFMapInstrumentationPass : public llvm::FunctionPass {
    public:
        BPFMapInstrumentationPass(std::string id, std::string func_name, TableStorage *ts, fake_fd_map_def &fake_fd_map,
                                  std::vector<TableDesc *> &tables, std::map<int, TableDesc> &instrum_maps);

        ~BPFMapInstrumentationPass() override;

        bool doInitialization(llvm::Module &M) override;
        bool runOnFunction(llvm::Function &pfn) override;
        bool doFinalization(llvm::Module &M) override;
        static llvm::Pass *createBPFMapInstrumentationPass(std::string id, std::string func_name, TableStorage *ts,
                                                           fake_fd_map_def &fake_fd_map,
                                                           std::vector<TableDesc *> &tables,
                                                           std::map<int, TableDesc> &instrum_maps);

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
        std::map<int, TableDesc> &original_maps_to_instrumented_maps_;

        TableDesc &getOrCreateInstrumentedMap(TableDesc &bpfTable);
        int createInstrumentedMap(TableDesc &original_map);
        TableDesc *getTableByFD(llvm::ConstantInt &pInt);
        static void createLookupAndUpdateValue(TableDesc &instrumented_map, llvm::CallInst *originalBPFPseudoInstr,
                                        llvm::Instruction *insertBefore,
                                        llvm::BasicBlock *defaultBlock, uint32_t max_range = 0);
    };

}