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
#include <llvm/Analysis/MemorySSA.h>

#include "table_storage.h"
#include "table_desc.h"

#pragma once

namespace ebpf {

    class DynamicMapOptAnalysisPass : public llvm::FunctionPass {
    public:
        DynamicMapOptAnalysisPass(std::string id, std::string func_name, TableStorage *ts, fake_fd_map_def &fake_fd_map,
                                  std::vector<TableDesc *> &tables);
        ~DynamicMapOptAnalysisPass() override;

        bool runOnFunction(llvm::Function &pfn) override;
        void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
        static llvm::Pass *createDynamicMapOptAnalysisPass(std::string id, std::string func_name, TableStorage *ts,
                                                           fake_fd_map_def &fake_fd_map,
                                                           std::vector<TableDesc *> &tables);

        void findAssociatedArrayOfMaps(llvm::LLVMContext &ctx, llvm::CallInst &instruction, llvm::AliasAnalysis &AA,
                                       llvm::MemorySSA &MSSA, std::vector<std::pair<llvm::CallInst *, ebpf::TableDesc *>> &array_of_maps); 

        // The address of this static is used to uniquely identify this pass in the
        // pass registry. The PassManager relies on this address to find instance of
        // analyses passes and build dependencies on demand.
        // The value does not matter.
        static char ID;

    private:
        std::string bpf_module_id_;
        std::string func_name_;
        ebpf::TableStorage *ts_{};
        ebpf::fake_fd_map_def &fake_fd_map_;
        std::vector<ebpf::TableDesc *> &tables_;
        bool has_array_of_maps_;
        std::vector<std::pair<llvm::CallInst *, ebpf::TableDesc *>> per_cpu_map_values_array;

        static bool helperInstructionCanBeOptimized(llvm::Function &F, llvm::AliasAnalysis &AA, llvm::MemorySSA &MSSA,
                                             llvm::CallInst *helperInstruction);
        bool mapIsReadOnly(llvm::Function &F, llvm::AliasAnalysis &AA, llvm::MemorySSA &MSSA,
                                         llvm::CallInst &mapLookupInstruction);
    };

}