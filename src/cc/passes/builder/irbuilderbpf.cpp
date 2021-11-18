// File entirely taken from
// https://github.com/iovisor/bpftrace/blob/master/src/ast/irbuilderbpf.cpp

#include <iostream>

#include "irbuilderbpf.h"
#include "libbpf.h"
#include "bcc_usdt.h"
#include "cc/macro_logger.h"

#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/IntrinsicInst.h>

#if LLVM_VERSION_MAJOR >= 10
#include <llvm/Support/Alignment.h>
#endif

namespace ebpf {
namespace builder {

IRBuilderBPF::IRBuilderBPF(llvm::Instruction *IP)
        : IRBuilder<>(IP), module_(*(IP->getModule())) {
  // Declare external LLVM function
  FunctionType *pseudo_func_type = FunctionType::get(
          getInt64Ty(),
          {getInt64Ty(), getInt64Ty()},
          false);
  Function::Create(
          pseudo_func_type,
          GlobalValue::ExternalLinkage,
          "llvm.bpf.pseudo",
          IP->getModule());
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, const std::string &name) {
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();

  auto ip = saveIP();
  if (entry_block.empty())
    SetInsertPoint(&entry_block);
  else
    SetInsertPoint(&entry_block.front());
  AllocaInst *alloca = CreateAlloca(ty, arraysize, name);
  restoreIP(ip);

  CreateLifetimeStart(alloca);
  return alloca;
}

AllocaInst *
IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, unsigned align, const std::string &name) {
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock &entry_block = parent->getEntryBlock();

  auto ip = saveIP();
  if (entry_block.empty())
    SetInsertPoint(&entry_block);
  else
    SetInsertPoint(&entry_block.front());

  AllocaInst *alloca = CreateAlloca(ty, arraysize, name);
#if LLVM_VERSION_MAJOR >= 10
  MaybeAlign alignment(align);
  alloca->setAlignment(alignment);
#else
  alloca->setAlignment(align);
#endif
  restoreIP(ip);

  CreateLifetimeStart(alloca);
  return alloca;
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(llvm::Type *ty, const std::string &name) {
  return CreateAllocaBPF(ty, nullptr, name);
}

AllocaInst *IRBuilderBPF::CreateAllocaBPF(int bytes, const std::string &name) {
  llvm::Type *ty = ArrayType::get(getInt8Ty(), bytes);
  return CreateAllocaBPF(ty, name);
}

llvm::ConstantInt *IRBuilderBPF::GetIntSameSize(uint64_t C, llvm::Value *expr) {
  unsigned size = expr->getType()->getIntegerBitWidth();
  return getIntN(size, C);
}

//        llvm::Type *IRBuilderBPF::GetType(const SizedType &stype)
//        {
//          llvm::Type *ty;
//          if (stype.IsArray())
//          {
//            ty = ArrayType::get(getInt8Ty(), stype.size);
//          }
//          else
//          {
//            switch (stype.size)
//            {
//              case 16:
//                ty = getInt128Ty();
//                break;
//              case 8:
//                ty = getInt64Ty();
//                break;
//              case 4:
//                ty = getInt32Ty();
//                break;
//              case 2:
//                ty = getInt16Ty();
//                break;
//              case 1:
//                ty = getInt8Ty();
//                break;
//              default:
//                std::cerr << stype.size << " is not a valid type size for GetType" << std::endl;
//                abort();
//            }
//          }
//          return ty;
//        }

CallInst *IRBuilderBPF::createCall(Value *callee,
                                   ArrayRef<Value *> args,
                                   const Twine &Name)
{
#if LLVM_VERSION_MAJOR >= 11
  auto *calleePtrType = cast<PointerType>(callee->getType());
  auto *calleeType = cast<FunctionType>(calleePtrType->getElementType());
  return CreateCall(calleeType, callee, args, Name);
#else
  return CreateCall(callee, args, Name);
#endif
}

CallInst *IRBuilderBPF::CreateBpfPseudoCall(int mapfd) {
  Function *pseudo_func = module_.getFunction("llvm.bpf.pseudo");
  assert(pseudo_func != nullptr && "Unable to find llvm.bpf.pseudo function inside the module");

  return createCall(pseudo_func, {getInt64(BPF_PSEUDO_MAP_FD), getInt64(mapfd)}, "pseudo");
}

Value *IRBuilderBPF::CreateMapLookupElem(int map_fd, Type *value_type, AllocaInst *key) {
  Value *map_ptr = CreateBpfPseudoCall(map_fd);

  // void *map_lookup_elem(&map, &key)
  // Return: Map value or NULL
  FunctionType *lookup_func_type = FunctionType::get(
          getInt8PtrTy(),
          {getInt8PtrTy(), getInt8PtrTy()},
          false);
  PointerType *lookup_func_ptr_type = PointerType::get(lookup_func_type, 0);
  Constant *lookup_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_map_lookup_elem),
          lookup_func_ptr_type);
  CallInst *call = createCall(lookup_func, {map_ptr, key}, "lookup_elem");

  // Check if result == 0
  Function *parent = GetInsertBlock()->getParent();
  BasicBlock *lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent);
  BasicBlock *lookup_failure_block = BasicBlock::Create(module_.getContext(), "lookup_failure", parent);
  BasicBlock *lookup_merge_block = BasicBlock::Create(module_.getContext(), "lookup_merge", parent);

  AllocaInst *value = CreateAllocaBPF(value_type, "lookup_elem_val");
  Value *condition = CreateICmpNE(
          CreateIntCast(call, getInt8PtrTy(), true),
          ConstantExpr::getCast(Instruction::IntToPtr, getInt64(0), getInt8PtrTy()),
          "map_lookup_cond");
  CreateCondBr(condition, lookup_success_block, lookup_failure_block);

  SetInsertPoint(lookup_success_block);
  CreateStore(CreateLoad(getInt64Ty(), call), value);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_failure_block);
  CreateStore(getInt64(0), value);
  CreateBr(lookup_merge_block);

  SetInsertPoint(lookup_merge_block);

  return CreateLoad(value);
}

Value *IRBuilderBPF::CreateGuardMapLookupElem(int map_fd, llvm::Type *value_type, llvm::Value *key,
                                              BasicBlock *ifFail, bool insertTracePrintk) {
  Value *map_ptr = CreateBpfPseudoCall(map_fd);

  Function *lookup_func = module_.getFunction("bpf_map_lookup_elem_");
  assert(lookup_func != nullptr &&
          "[IRBuilderBPF] Unable to find bpf_map_lookup_elem_ function inside the module");

  assert(key->getType()->isPointerTy() && "[IRBuilderBPF] Key should be a PointerType");

  auto key_ptr = CreatePointerCast(key, getInt8PtrTy());
  CallInst *call = createCall(lookup_func, {map_ptr, key_ptr}, "lookup_elem");

  auto parent = GetInsertBlock()->getParent();
  auto next_block = GetInsertBlock()->getNextNode();
  auto lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent, next_block);
  //auto lookup_failure_block = BasicBlock::Create(module_.getContext(), "lookup_failure", parent, next_block);
//          auto lookup_merge_block = BasicBlock::Create(module_.getContext(), "lookup_merge", parent, next_block);

  Value *condition = CreateICmpNE(call, ConstantPointerNull::get(getInt8PtrTy()));
  auto branchInst = BranchInst::Create(lookup_success_block, ifFail, condition);
  ReplaceInstWithInst(GetInsertBlock()->getTerminator(), branchInst);

  SetInsertPoint(lookup_success_block);
  if (insertTracePrintk) {
    CreateTracePrintk("Guard lookup sucess for table fd: " + std::to_string(map_fd) + "\n");
  }
  AllocaInst *value = CreateAllocaBPF(value_type, "lookup_elem_val");
  CreateStore(CreateLoad(value_type, call), value);

  InlineFunctionInfo ifi;
  #if LLVM_VERSION_MAJOR >= 11
  auto result = InlineFunction(*call, ifi);
  #else
  auto result = InlineFunction(call, ifi);
  #endif

  for (auto new_call : ifi.InlinedCallSites) {
    #if LLVM_VERSION_MAJOR >= 11
    if (new_call->getIntrinsicID() == Intrinsic::not_intrinsic) {
    #else
    if (dyn_cast<IntrinsicInst>(new_call.getInstruction()) == nullptr) {
    #endif
      // TODO: This has to be improved. We should add the metadata only to the call, not to the intrinsic
      MDNode *N = MDNode::get(getContext(), MDString::get(getContext(), "true"));
      new_call->setMetadata("opt.isGuardMap", N);
    }
  }

  #if LLVM_VERSION_MAJOR >= 11
  LOG_IF_ERROR(!result.isSuccess(), "[IRBuilderBPF] Unable to inline function: %s", result.getFailureReason());
  #else
  LOG_IF_ERROR(!result, "[IRBuilderBPF] Unable to inline function: %s", std::string(result).c_str());
  #endif

  return CreateLoad(value);
}

Value *IRBuilderBPF::CreateInstrumentedMapLookup(int map_fd, llvm::Type *value_type, llvm::Value *key,
                                                  BasicBlock *ifFail, uint32_t maxRange, uint8_t enablePrintk) {
  if (maxRange > 0) {
    Value *rand = CreateGetRandom();

    if (enablePrintk) {
      CreateTracePrintkOneArg("Generated random number: %u\n", rand);
    }

    auto random_success_block = BasicBlock::Create(module_.getContext(), "rand_success",
                                                    GetInsertBlock()->getParent(),
                                                    GetInsertBlock()->getNextNode());

    auto condition = CreateICmpULT(rand, getInt32(maxRange));
    auto branchInst = BranchInst::Create(random_success_block, ifFail, condition);
    ReplaceInstWithInst(GetInsertBlock()->getTerminator(), branchInst);

    SetInsertPoint(random_success_block);
    CreateBr(ifFail);
    SetInsertPoint(random_success_block->getTerminator());
  }

  Value *map_ptr = CreateBpfPseudoCall(map_fd);

  Function *lookup_func = module_.getFunction("bpf_map_lookup_elem_");
  assert(lookup_func != nullptr &&
          "[IRBuilderBPF] Unable to find bpf_map_lookup_elem_ function inside the module");

  assert(key->getType()->isPointerTy() && "[IRBuilderBPF] Key should be a PointerType");

  auto key_ptr = CreatePointerCast(key, getInt8PtrTy());
  CallInst *call = createCall(lookup_func, {map_ptr, key_ptr}, "lookup_elem");

  auto parent = GetInsertBlock()->getParent();
  auto next_block = GetInsertBlock()->getNextNode();
  auto lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent, next_block);

  Value *condition = CreateICmpNE(call, ConstantPointerNull::get(getInt8PtrTy()));
  auto branchInst = BranchInst::Create(lookup_success_block, ifFail, condition);
  ReplaceInstWithInst(GetInsertBlock()->getTerminator(), branchInst);

  SetInsertPoint(lookup_success_block);
  // In this case I do not want to store the value since it is later directly updated
  // What I do is to convert the pointer to the value requested and return

//          AllocaInst *value = CreateAllocaBPF(value_type, "lookup_elem_val");
//          CreateStore(CreateLoad(value_type, call), value);
  auto *value = CreatePointerCast(call, value_type, "lookup_elem_val");

  InlineFunctionInfo ifi;
  #if LLVM_VERSION_MAJOR >= 11
  auto result = InlineFunction(*call, ifi);
  #else
  auto result = InlineFunction(call, ifi);
  #endif

  for (auto new_call : ifi.InlinedCallSites) {
    #if LLVM_VERSION_MAJOR >= 11
    if (new_call->getIntrinsicID() == Intrinsic::not_intrinsic) {
    #else
    if (dyn_cast<IntrinsicInst>(new_call.getInstruction()) == nullptr) {
    #endif
      // TODO: This has to be improved. We should add the metadata only to the call, not to the intrinsic
      MDNode *N = MDNode::get(getContext(), MDString::get(getContext(), "true"));
      new_call->setMetadata("opt.isInstrumentedMap", N);
    }
  }

  #if LLVM_VERSION_MAJOR >= 11
  LOG_IF_ERROR(!result.isSuccess(), "[IRBuilderBPF] Unable to inline function: %s", result.getFailureReason());
  #else
  LOG_IF_ERROR(!result, "[IRBuilderBPF] Unable to inline function: %s", std::string(result).c_str());
  #endif

  return value;
}

Value *IRBuilderBPF::CreateInstrumentedMapLookupOrInit(int map_fd, llvm::Type *value_type, llvm::Value *key,
                                                        BasicBlock *ifFail, uint32_t maxRange,
                                                        uint8_t enablePrintk) {
  if (maxRange > 0) {
    Value *rand = CreateGetRandom();

    if (enablePrintk) {
      CreateTracePrintkOneArg("Generated random number: %u\n", rand);
    }

    auto random_success_block = BasicBlock::Create(module_.getContext(), "rand_success",
                                                    GetInsertBlock()->getParent(),
                                                    GetInsertBlock()->getNextNode());

    auto condition = CreateICmpULT(rand, getInt32(maxRange));
    auto branchInst = BranchInst::Create(random_success_block, ifFail, condition);
    ReplaceInstWithInst(GetInsertBlock()->getTerminator(), branchInst);

    SetInsertPoint(random_success_block);
    CreateBr(ifFail);
    SetInsertPoint(random_success_block->getTerminator());
  }

  Value *map_ptr = CreateBpfPseudoCall(map_fd);

  Function *lookup_or_init_func = module_.getFunction("bpf_map_lookup_or_init_elem_");
  assert(lookup_or_init_func != nullptr &&
          "[IRBuilderBPF] Unable to find bpf_map_lookup_or_init_elem_ function inside the module");

  assert(key->getType()->isPointerTy() && "[IRBuilderBPF] Key should be a PointerType");

  auto key_ptr = CreatePointerCast(key, getInt8PtrTy());
  //auto value_ptr = CreatePointerCast(ConstantInt::get(IntegerType::getInt64Ty(getContext()), 0), getInt8PtrTy());
  //auto value_ptr = CreateAllocaBPF(getInt64(0), "value_elem");
  //auto value_ptr = CreateIntToPtr(getInt64(0), getInt8PtrTy());
  CallInst *call = createCall(lookup_or_init_func, {map_ptr, key_ptr}, "lookup_or_init_elem");

  auto parent = GetInsertBlock()->getParent();
  auto next_block = GetInsertBlock()->getNextNode();
  auto lookup_success_block = BasicBlock::Create(module_.getContext(), "lookup_success", parent, next_block);

  Value *condition = CreateICmpNE(call, ConstantPointerNull::get(getInt8PtrTy()));
  auto branchInst = BranchInst::Create(lookup_success_block, ifFail, condition);
  ReplaceInstWithInst(GetInsertBlock()->getTerminator(), branchInst);

  SetInsertPoint(lookup_success_block);
  // In this case I do not want to store the value since it is later directly updated
  // What I do is to convert the pointer to the value requested and return

//          AllocaInst *value = CreateAllocaBPF(value_type, "lookup_elem_val");
//          CreateStore(CreateLoad(value_type, call), value);
  auto *value = CreatePointerCast(call, value_type, "lookup_elem_val");

  InlineFunctionInfo ifi;
  #if LLVM_VERSION_MAJOR >= 11
  auto result = InlineFunction(*call, ifi);
  #else
  auto result = InlineFunction(call, ifi);
  #endif

  for (auto new_call : ifi.InlinedCallSites) {
    #if LLVM_VERSION_MAJOR >= 11
    if (new_call->getIntrinsicID() == Intrinsic::not_intrinsic) {
    #else
    if (dyn_cast<IntrinsicInst>(new_call.getInstruction()) == nullptr) {
    #endif
      // TODO: This has to be improved. We should add the metadata only to the call, not to the intrinsic
      MDNode *N = MDNode::get(getContext(), MDString::get(getContext(), "true"));
      new_call->setMetadata("opt.isInstrumentedMap", N);
    }
  }

  #if LLVM_VERSION_MAJOR >= 11
  LOG_IF_ERROR(!result.isSuccess(), "[IRBuilderBPF] Unable to inline function: %s", result.getFailureReason());
  #else
  LOG_IF_ERROR(!result, "[IRBuilderBPF] Unable to inline function: %s", std::string(result).c_str());
  #endif

  return value;
}


CallInst *IRBuilderBPF::CreateProbeReadStr(AllocaInst *dst, llvm::Value *size, Value *src) {
  // int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
  FunctionType *probereadstr_func_type = FunctionType::get(
          getInt64Ty(),
          {getInt8PtrTy(), getInt64Ty(), getInt8PtrTy()},
          false);
  PointerType *probereadstr_func_ptr_type = PointerType::get(probereadstr_func_type, 0);
  Constant *probereadstr_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_probe_read_str),
          probereadstr_func_ptr_type);
  return createCall(probereadstr_func, {dst, size, src}, "probe_read_str");
}

CallInst *IRBuilderBPF::CreateGetNs() {
  // u64 ktime_get_ns()
  // Return: current ktime
  FunctionType *gettime_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *gettime_func_ptr_type = PointerType::get(gettime_func_type, 0);
  Constant *gettime_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_ktime_get_ns),
          gettime_func_ptr_type);
  return createCall(gettime_func, {}, "get_ns");
}

CallInst *IRBuilderBPF::CreateGetPidTgid() {
  // u64 bpf_get_current_pid_tgid(void)
  // Return: current->tgid << 32 | current->pid
  FunctionType *getpidtgid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getpidtgid_func_ptr_type = PointerType::get(getpidtgid_func_type, 0);
  Constant *getpidtgid_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_get_current_pid_tgid),
          getpidtgid_func_ptr_type);
  return createCall(getpidtgid_func, {}, "get_pid_tgid");
}

CallInst *IRBuilderBPF::CreateTracePrintkOneArg(const std::string &str, Value *arg) {
  auto *stringValue = CreateGlobalStringPtr(str);
  auto *strSize = getInt64(str.size() + 1);

  auto *localStr = CreateAllocaBPF(getInt8Ty(), strSize, 16, "str");
  auto *bitcastStr = CreateBitCast(localStr, getInt8PtrTy());
//          auto *gepValue = CreateInBoundsGEP(ArrayType::get(getInt8Ty(), str.size()), localStr, {getInt64(0), getInt64(0)});
  CreateLifetimeStart(bitcastStr, strSize);

  CREATE_MEMCPY(bitcastStr, stringValue, strSize, 16);
  // u64 bpf_get_current_pid_tgid(void)
  // Return: current->tgid << 32 | current->pid
  FunctionType *traceprintk_func_type = FunctionType::get(getInt32Ty(), {getInt8PtrTy(), getInt64Ty()}, true);
  PointerType *traceprintk_func_ptr_type = PointerType::get(traceprintk_func_type, 0);
  Constant *traceprintk_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_trace_printk),
          traceprintk_func_ptr_type);
  auto *call = createCall(traceprintk_func, {bitcastStr, strSize, arg}, "trace_printk");

  CreateLifetimeEnd(bitcastStr, strSize);
  return call;
}

CallInst *IRBuilderBPF::CreateTracePrintk(const std::string &str) {

  auto *stringValue = CreateGlobalStringPtr(str);
  auto *strSize = getInt64(str.size() + 1);

  auto *localStr = CreateAllocaBPF(getInt8Ty(), strSize, 16, "str");
  auto *bitcastStr = CreateBitCast(localStr, getInt8PtrTy());
//          auto *gepValue = CreateInBoundsGEP(ArrayType::get(getInt8Ty(), str.size()), localStr, {getInt64(0), getInt64(0)});
  CreateLifetimeStart(bitcastStr, strSize);

  CREATE_MEMCPY(bitcastStr, stringValue, strSize, 16);
  // u64 bpf_get_current_pid_tgid(void)
  // Return: current->tgid << 32 | current->pid
  FunctionType *traceprintk_func_type = FunctionType::get(getInt32Ty(), {getInt8PtrTy(), getInt64Ty()}, true);
  PointerType *traceprintk_func_ptr_type = PointerType::get(traceprintk_func_type, 0);
  Constant *traceprintk_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_trace_printk),
          traceprintk_func_ptr_type);
  auto *call = createCall(traceprintk_func, {bitcastStr, strSize}, "trace_printk");

  CreateLifetimeEnd(bitcastStr, strSize);
  return call;
}

CallInst *IRBuilderBPF::CreateGetUidGid() {
  // u64 bpf_get_current_uid_gid(void)
  // Return: current_gid << 32 | current_uid
  FunctionType *getuidgid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getuidgid_func_ptr_type = PointerType::get(getuidgid_func_type, 0);
  Constant *getuidgid_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_get_current_uid_gid),
          getuidgid_func_ptr_type);
  return createCall(getuidgid_func, {}, "get_uid_gid");
}

CallInst *IRBuilderBPF::CreateGetCpuId() {
  // u32 bpf_raw_smp_processor_id(void)
  // Return: SMP processor ID
  FunctionType *getcpuid_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getcpuid_func_ptr_type = PointerType::get(getcpuid_func_type, 0);
  Constant *getcpuid_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_get_smp_processor_id),
          getcpuid_func_ptr_type);
  return createCall(getcpuid_func, {}, "get_cpu_id");
}

CallInst *IRBuilderBPF::CreateGetCurrentTask() {
  // u64 bpf_get_current_task(void)
  // Return: current task_struct
  FunctionType *getcurtask_func_type = FunctionType::get(getInt64Ty(), false);
  PointerType *getcurtask_func_ptr_type = PointerType::get(getcurtask_func_type, 0);
  Constant *getcurtask_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_get_current_task),
          getcurtask_func_ptr_type);
  return createCall(getcurtask_func, {}, "get_cur_task");
}

CallInst *IRBuilderBPF::CreateGetRandom() {
  // u32 bpf_get_prandom_u32(void)
  // Return: random
  FunctionType *getrandom_func_type = FunctionType::get(getInt32Ty(), false);
  PointerType *getrandom_func_ptr_type = PointerType::get(getrandom_func_type, 0);
  Constant *getrandom_func = ConstantExpr::getCast(
          Instruction::IntToPtr,
          getInt64(BPF_FUNC_get_prandom_u32),
          getrandom_func_ptr_type);
  return createCall(getrandom_func, {}, "get_random");
}

} // namespace builder
} // namespace ebpf