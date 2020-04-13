/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019 wcventure Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constant.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

static inline std::string loc_description (const DebugLoc& dd) {
  if(!dd) { return "?"; }
  auto* scope = cast<DIScope>(dd.getScope());
  return scope->getFilename().str() + ":" + std::to_string(dd.getLine()) + ":" + std::to_string(dd.getCol());
}

static inline std::string bb_description(const BasicBlock& bb) {
  return "(" + loc_description(bb.getInstList().begin()->getDebugLoc()) + "-" + loc_description(bb.getTerminator()->getDebugLoc()) + ")";

}


char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  PointerType *CharPtrTy = PointerType::getUnqual(Int8Ty);
  Type *VoidTy = Type::getVoidTy(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "MemLock-stack-fuzzer: afl-llvm-pass " cBRI VERSION cRST " by <wcventure@126.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

    /* 添加函数声明，插桩用途 */
  llvm::LLVMContext& context = M.getContext ();
  llvm::IRBuilder<> builder(context); 
  
  // Function instr_Call()
  llvm::FunctionType *funcCallType = 
      llvm::FunctionType::get(builder.getVoidTy(), false);
  llvm::Function *instr_CallFunc = 
      llvm::Function::Create(funcCallType, llvm::Function::ExternalLinkage, "instr_Call", &M);

  // Function instr_Return()
  llvm::FunctionType *funcReturnType = 
      llvm::FunctionType::get(builder.getVoidTy(), false);
  llvm::Function *instr_ReturnFunc = 
      llvm::Function::Create(funcReturnType, llvm::Function::ExternalLinkage, "instr_Return", &M);

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  
  GlobalVariable *AFLPerfPtr =
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_perf_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  GlobalVariable *AFLPrevLocDesc = new GlobalVariable(
      M, CharPtrTy, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc_desc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  ConstantInt* PerfMask = ConstantInt::get(Int32Ty, PERF_SIZE-1);

  Function* LogLocationsFunc = Function::Create(FunctionType::get(VoidTy, 
      ArrayRef<Type*>({CharPtrTy, CharPtrTy}), true), GlobalVariable::ExternalLinkage,
      "__afl_log_loc", &M);
  

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    bool functionFlag = true;//第一次进函数时flag为true，插桩后改为false

    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (functionFlag == true){

        functionFlag = false;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);
        
        /* Get current source location information */
        std::string cur_loc_desc = bb_description(BB);
        Value* CurLocDesc = IRB.CreateGlobalStringPtr(cur_loc_desc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Get edge ID as XOR */
        Value* EdgeId = IRB.CreateXor(PrevLocCasted, CurLoc);

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, EdgeId);
        
        LoadInst *PerfPtr = IRB.CreateLoad(AFLPerfPtr);
        PerfPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PerfBranchPtr =
            IRB.CreateGEP(PerfPtr, IRB.CreateAnd(EdgeId, PerfMask));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        
        /* Increment performance counter for branch */
        LoadInst *PerfBranchCounter = IRB.CreateLoad(PerfBranchPtr);
        PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PerfBranchIncr = IRB.CreateAdd(PerfBranchCounter, ConstantInt::get(Int32Ty, 1));
        IRB.CreateStore(PerfBranchIncr, PerfBranchPtr)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        
        /* Increment performance counter for total count  */
        LoadInst *PerfTotalCounter = IRB.CreateLoad(PerfPtr); // Index 0 of the perf map
        PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PerfTotalIncr = IRB.CreateAdd(PerfTotalCounter, ConstantInt::get(Int32Ty, 1));
        IRB.CreateStore(PerfTotalIncr, PerfPtr)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Possibly log location */
        LoadInst* PrevLocDesc = IRB.CreateLoad(AFLPrevLocDesc);
        IRB.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));
        

        /* Set prev_loc_desc to cur_loc_desc */
        IRB.CreateStore(CurLocDesc, AFLPrevLocDesc);

        for(BasicBlock::iterator i = BB.begin(), i2 = BB.end(); i!=i2; i++) {

          IRBuilder<> MemFuzzBuilder(&(*i)); //插桩的位置

          if(Instruction *inst = dyn_cast<Instruction>(i)) {
            //return函数插桩
            if(inst->getOpcode() == Instruction::Ret)
            {

              /* Update bitmap */

              LoadInst *Counter = MemFuzzBuilder.CreateLoad(MapPtrIdx);
              Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *Incr = MemFuzzBuilder.CreateSub(Counter, ConstantInt::get(Int8Ty, 1));
              MemFuzzBuilder.CreateStore(Incr, MapPtrIdx)
                  ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              
              /* Decrement performance counter for branch */
              LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
              PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *PerfBranchIncr = MemFuzzBuilder.CreateSub(PerfBranchCounter, ConstantInt::get(Int32Ty, 1));
              MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                  ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              
              /* Decrement performance counter for total count  */
              LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
              PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *PerfTotalIncr = MemFuzzBuilder.CreateSub(PerfTotalCounter, ConstantInt::get(Int32Ty, 1));
              MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                  ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              
              MemFuzzBuilder.CreateCall(instr_ReturnFunc);
            
            }
          }
        }

        IRB.CreateCall(instr_CallFunc);

      } else {

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        for(BasicBlock::iterator i = BB.begin(), i2 = BB.end(); i!=i2; i++) {

          IRBuilder<> MemFuzzBuilder(&(*i)); //插桩的位置

          if(Instruction *inst = dyn_cast<Instruction>(i)) {
            //return函数插桩
            if(inst->getOpcode() == Instruction::Ret)
            {

              /* Get current source location information */
              std::string cur_loc_desc = bb_description(BB);
              Value* CurLocDesc = MemFuzzBuilder.CreateGlobalStringPtr(cur_loc_desc);

              /* Get edge ID as XOR */
              Value* EdgeId = MemFuzzBuilder.CreateXor(PrevLocCasted, CurLoc);

              /* Load SHM pointer */
            
              LoadInst *PerfPtr = MemFuzzBuilder.CreateLoad(AFLPerfPtr);
              PerfPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *PerfBranchPtr =
                  MemFuzzBuilder.CreateGEP(PerfPtr, MemFuzzBuilder.CreateAnd(EdgeId, PerfMask));

              /* Update bitmap */

              LoadInst *Counter = MemFuzzBuilder.CreateLoad(MapPtrIdx);
              Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *Incr = MemFuzzBuilder.CreateSub(Counter, ConstantInt::get(Int8Ty, 1));
              MemFuzzBuilder.CreateStore(Incr, MapPtrIdx)
                  ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              
              /* Increment performance counter for branch */
              LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
              PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *PerfBranchIncr = MemFuzzBuilder.CreateSub(PerfBranchCounter, ConstantInt::get(Int32Ty, 1));
              MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                  ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              
              /* Increment performance counter for total count  */
              LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
              PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
              Value *PerfTotalIncr = MemFuzzBuilder.CreateSub(PerfTotalCounter, ConstantInt::get(Int32Ty, 1));
              MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                  ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

              /* Possibly log location */
              LoadInst* PrevLocDesc = MemFuzzBuilder.CreateLoad(AFLPrevLocDesc);
              MemFuzzBuilder.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));

              /* Set prev_loc_desc to cur_loc_desc */
              MemFuzzBuilder.CreateStore(CurLocDesc, AFLPrevLocDesc);

              MemFuzzBuilder.CreateCall(instr_ReturnFunc);

            }
          }
        }

      }

      inst_blocks++;

    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
