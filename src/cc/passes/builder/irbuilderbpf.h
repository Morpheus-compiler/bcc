// File entirely taken from
// https://github.com/iovisor/bpftrace/blob/master/src/ast/irbuilderbpf.h

#pragma once

#include "bcc_usdt.h"
#include "table_desc.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/Config/llvm-config.h>

#if LLVM_VERSION_MAJOR >= 5 && LLVM_VERSION_MAJOR < 7
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), (src), (size), (algn))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), (src), (size), (algn), true)
#elif LLVM_VERSION_MAJOR >= 7 && LLVM_VERSION_MAJOR < 10
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), (algn), (src), (algn), (size))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), (algn), (src), (algn), (size), true)
#elif LLVM_VERSION_MAJOR >= 10
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), MaybeAlign(algn), (src), MaybeAlign(algn), (size))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), MaybeAlign(algn), (src), MaybeAlign(algn), (size), true)
#else
#error Unsupported LLVM version
#endif

#if LLVM_VERSION_MAJOR >= 10
#define CREATE_MEMSET(ptr, val, size, align)                                   \
  CreateMemSet((ptr), (val), (size), MaybeAlign((align)))
#else
#define CREATE_MEMSET(ptr, val, size, align)                                   \
  CreateMemSet((ptr), (val), (size), (align))
#endif

namespace ebpf {
namespace builder {

using namespace llvm;

class IRBuilderBPF : public IRBuilder<>
{
public:
    IRBuilderBPF(Instruction *IP);

    AllocaInst *CreateAllocaBPF(llvm::Type *ty, const std::string &name="");
    AllocaInst *CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, const std::string &name="");
    AllocaInst *CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, unsigned align, const std::string &name="");
    AllocaInst *CreateAllocaBPF(int bytes, const std::string &name="");
    llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Value *expr);
    CallInst   *CreateBpfPseudoCall(int mapfd);
    Value      *CreateMapLookupElem(int map_fd, Type *value_type, AllocaInst *key);
    Value      *CreateGuardMapLookupElem(int map_fd, Type *value_type, Value *key, BasicBlock *ifFail, bool insertTracePrintk = false);
    Value      *CreateInstrumentedMapLookup(int map_fd, Type *value_type, Value *key, BasicBlock *ifFail, uint32_t maxRange = 0, uint8_t enablePrintk = 0);
    Value      *CreateInstrumentedMapLookupOrInit(int map_fd, Type *value_type, Value *key, BasicBlock *ifFail, uint32_t maxRange = 0, uint8_t enablePrintk = 0);
    CallInst   *CreateProbeReadStr(AllocaInst *dst, llvm::Value *size, Value *src);
    CallInst   *CreateGetNs();
    CallInst   *CreateGetPidTgid();
    CallInst   *CreateGetUidGid();
    CallInst   *CreateGetCpuId();
    CallInst   *CreateGetCurrentTask();
    CallInst   *CreateGetRandom();
    CallInst   *CreateTracePrintk(const std::string& str);
    CallInst   *CreateTracePrintkOneArg(const std::string& str, Value *arg);
    CallInst   *createCall(Value *callee, ArrayRef<Value *> args, const Twine &Name);
private:
    Module &module_;

};

} // namespace builder
} // namespace ebpf