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
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  PointerType *CharPtrTy = PointerType::getUnqual(Int8Ty);
  Type *VoidTy = Type::getVoidTy(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "MemLock-heap-fuzzer: afl-llvm-pass " cBRI VERSION cRST " by <wcventure@126.com>\n");

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
  
  // Function instr_Free()
  std::vector<Type*> argTypesFree;
  argTypesFree.push_back(builder.getInt8PtrTy());
  ArrayRef<Type*> argTypesRefFree(argTypesFree);
  llvm::FunctionType *funcFreeType = FunctionType::get(builder.getVoidTy(), argTypesRefFree, false);
  llvm::Function *instr_FreeFunc = Function::Create(funcFreeType, llvm::Function::ExternalLinkage, "instr_Free", &M);

  // Function instr_MallocAndSize()
  std::vector<Type*> argTypesMalloc;
  argTypesMalloc.push_back(builder.getInt8PtrTy());
  argTypesMalloc.push_back(builder.getInt64Ty());
  ArrayRef<Type*> argTypesRefMalloc(argTypesMalloc);
  llvm::FunctionType *funcMallocAndSizeType = FunctionType::get(builder.getVoidTy(),argTypesRefMalloc,false);
  llvm::Function *instr_MallocAndSizeFunc = Function::Create(funcMallocAndSizeType, llvm::Function::ExternalLinkage, "instr_MallocAndSize", &M);

  // Function instr_CallocAndSize()
  std::vector<Type*> argTypesCalloc;
  argTypesCalloc.push_back(builder.getInt8PtrTy());
  argTypesCalloc.push_back(builder.getInt64Ty());
  argTypesCalloc.push_back(builder.getInt64Ty());
  ArrayRef<Type*> argTypesRefCalloc(argTypesCalloc);
  llvm::FunctionType *funcCallocAndSizeType = FunctionType::get(builder.getVoidTy(),argTypesRefCalloc,false);
  llvm::Function *instr_CallocAndSizeFunc = Function::Create(funcCallocAndSizeType, llvm::Function::ExternalLinkage, "instr_CallocAndSize", &M);

  // Function instr_ReallocAhead()
  std::vector<Type*> argTypesReal;
  argTypesReal.push_back(builder.getInt8PtrTy());
  argTypesReal.push_back(builder.getInt64Ty());
  ArrayRef<Type*> argTypesRefReal(argTypesReal);
  llvm::FunctionType *funcReallocAhead = FunctionType::get(builder.getVoidTy(),argTypesRefReal,false);
  llvm::Function *instr_ReallocAheadFunc = Function::Create(funcReallocAhead, llvm::Function::ExternalLinkage, "instr_ReallocAhead", &M);


  // Function instr_ReallocAndSize()
  std::vector<Type*> argTypesRealloc;
  argTypesRealloc.push_back(builder.getInt8PtrTy());
  argTypesRealloc.push_back(builder.getInt8PtrTy());
  argTypesRealloc.push_back(builder.getInt64Ty());
  ArrayRef<Type*> argTypesRefRealloc(argTypesRealloc);
  llvm::FunctionType *funcReallocAndSizeType = FunctionType::get(builder.getVoidTy(),argTypesRefRealloc,false);
  llvm::Function *instr_ReallocAndSizeFunc = Function::Create(funcReallocAndSizeType, llvm::Function::ExternalLinkage, "instr_ReallocAndSize", &M);

  // Function instr_Exit()
  std::vector<Type*> argTypesExit;
  argTypesExit.push_back(builder.getInt32Ty());
  ArrayRef<Type*> argTypesRefExit(argTypesExit);
  llvm::FunctionType *funcExitType = FunctionType::get(builder.getVoidTy(),argTypesRefExit,false);
  llvm::Function *instr_ExitFunc = Function::Create(funcExitType, llvm::Function::ExternalLinkage, "instr_Exit", &M);

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  
  GlobalVariable *AFLPerfPtr =
      new GlobalVariable(M, PointerType::get(Int64Ty, 0), false,
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

    Function::iterator B_iter = F.begin(); 

    for (auto &BB : F) {

      BasicBlock* BBptr = &*B_iter; //BB的指针
      ++B_iter;

      /*---start: AFL的插桩---*/

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

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


      int insetMallocFlag = 0;
      Value *tmpMallocInst;
      Value *tmpMallocSizeInst;

      int insetCallocFlag = 0;
      Value *tmpCallocInst;
      Value *tmpCallocSizeInst;
      Value *tmpCallocSizeInst2;

      int insetReallocFlag = 0;
      Value *tmpReallocInst;
      Value *tmpReallocp;
      Value *tmpReallocSizeInst;


      for(BasicBlock::iterator i = BB.begin(), i2 = BB.end(); i!=i2; i++) {

        IRBuilder<> MemFuzzBuilder(&(*i)); //插桩的位置

        if(Instruction *inst = dyn_cast<Instruction>(i)) {

          //延迟插的malloc指令
          if (insetMallocFlag == 1){
            insetMallocFlag = 0;
            SmallVector<Value *, 2> AllocArg;
            AllocArg.push_back(tmpMallocInst);
            AllocArg.push_back(tmpMallocSizeInst);
            MemFuzzBuilder.CreateCall(instr_MallocAndSizeFunc, AllocArg);
          }
       
          //延迟插的calloc指令
          if (insetCallocFlag == 1){
            insetCallocFlag = 0;
            SmallVector<Value *, 3> CAllocArg;
            CAllocArg.push_back(tmpCallocInst);
            CAllocArg.push_back(tmpCallocSizeInst);
            CAllocArg.push_back(tmpCallocSizeInst2);
            MemFuzzBuilder.CreateCall(instr_CallocAndSizeFunc, CAllocArg);
          }

          //延迟插的realloc指令
          if (insetReallocFlag == 1){
            insetReallocFlag = 0;
            SmallVector<Value *, 3> ReallocArg;
            ReallocArg.push_back(tmpReallocInst);
            ReallocArg.push_back(tmpReallocp);
            ReallocArg.push_back(tmpReallocSizeInst);
            MemFuzzBuilder.CreateCall(instr_ReallocAndSizeFunc, ReallocArg);
          }

          //在call指令中搜索
          if(inst->getOpcode() == Instruction::Call) {
           
            //malloc函数，插后方
            std::string instr_malloc1 = "malloc";
            //std::string instr_malloc2 = "xmalloc";
            std::string instr_malloc3 = "valloc";
            std::string instr_malloc4 = "safe_malloc";
            std::string instr_malloc5 = "safemalloc";
            std::string instr_malloc6 = "safexmalloc";
            if(inst->getNumOperands() >= 2 ){ //操作数大于二
              if ( instr_malloc1 == std::string(inst->getOperand(1)->getName()) || 
              /*instr_malloc2 == std::string(inst->getOperand(1)->getName()) || */
              instr_malloc3 == std::string(inst->getOperand(1)->getName()) || 
              instr_malloc4 == std::string(inst->getOperand(1)->getName()) || 
              instr_malloc5 == std::string(inst->getOperand(1)->getName()) || 
              instr_malloc6 == std::string(inst->getOperand(1)->getName()) ) {
                //outs() << "malloc: Heap memory allocation. " << "(In Function: " << F.getName() << ")\n";
                //MemFuzzBuilder.CreateCall(instr_MallocAndSizeFunc, inst->getOperand(0) );
                //此处不插，判断返回值后再插
                insetMallocFlag = 1;
                tmpMallocInst = inst;
                tmpMallocSizeInst = inst->getOperand(0);

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
                
                /* Increment performance counter for branch */
                LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
                PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfBranchIncr = MemFuzzBuilder.CreateAdd(PerfBranchCounter, tmpMallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                
                /* Increment performance counter for total count  */
                LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
                PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfTotalIncr = MemFuzzBuilder.CreateAdd(PerfTotalCounter, tmpMallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                /* Possibly log location */
                LoadInst* PrevLocDesc = MemFuzzBuilder.CreateLoad(AFLPrevLocDesc);
                MemFuzzBuilder.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));

                /* Set prev_loc_desc to cur_loc_desc */
                MemFuzzBuilder.CreateStore(CurLocDesc, AFLPrevLocDesc);
              }
            }

            //calloc函数，插后方
            std::string instr_calloc1 = "calloc";
            //std::string instr_calloc2 = "xcalloc";
            std::string instr_calloc3 = "memalign";
            std::string instr_calloc4 = "aligned_alloc";
            std::string instr_calloc5 = "safe_calloc";
            std::string instr_calloc6 = "safecalloc";
            std::string instr_calloc7 = "safexcalloc";
            if(inst->getNumOperands() >= 3 ){ //操作数大于二
              if ( instr_calloc1 == std::string(inst->getOperand(2)->getName()) || 
              /*instr_calloc2 == std::string(inst->getOperand(2)->getName()) || */
              instr_calloc3 == std::string(inst->getOperand(2)->getName()) ||
              instr_calloc4 == std::string(inst->getOperand(2)->getName()) ||
              instr_calloc5 == std::string(inst->getOperand(2)->getName()) ||
              instr_calloc6 == std::string(inst->getOperand(2)->getName()) ||
              instr_calloc7 == std::string(inst->getOperand(2)->getName()) ){
                //outs() << "calloc: Heap memory allocation. " << "(In Function: " << F.getName() << ")\n";
                //SmallVector<Value *, 2> CallocArg;
                //CallocArg.push_back(inst->getOperand(0));
                //CallocArg.push_back(inst->getOperand(1));
                //MemFuzzBuilder.CreateCall(instr_CallocAndSizeFunc, CallocArg);
                //此处不插，判断返回值后再插
                insetCallocFlag = 1;
                tmpCallocInst = inst;
                tmpCallocSizeInst = inst->getOperand(0);
                tmpCallocSizeInst2 = inst->getOperand(1);

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
                
                /* Increment performance counter for branch */
                LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
                PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfBranchIncr = MemFuzzBuilder.CreateAdd(PerfBranchCounter, tmpCallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                
                /* Increment performance counter for total count  */
                LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
                PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfTotalIncr = MemFuzzBuilder.CreateAdd(PerfTotalCounter, tmpCallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                /* Possibly log location */
                LoadInst* PrevLocDesc = MemFuzzBuilder.CreateLoad(AFLPrevLocDesc);
                MemFuzzBuilder.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));

                /* Set prev_loc_desc to cur_loc_desc */
                MemFuzzBuilder.CreateStore(CurLocDesc, AFLPrevLocDesc);
              }
            }

            //realloc函数，插后方,前方插了Ahead
            std::string instr_realloc1 = "realloc"; 
            if(inst->getNumOperands() >= 3 ){ //操作数大于二
              if ( instr_realloc1 == std::string(inst->getOperand(2)->getName()) ){
                //outs() << "realloc: Heap memory reallocation. " << "(In Function: " << F.getName() << ")\n";
                
                //插桩前方
                SmallVector<Value *, 2> RealArg;
                RealArg.push_back(inst->getOperand(0));
                RealArg.push_back(inst->getOperand(1));
                MemFuzzBuilder.CreateCall(instr_ReallocAheadFunc, RealArg );

                //插桩后方
                insetReallocFlag = 1;
                tmpReallocInst = inst;
                tmpReallocp = inst->getOperand(0);
                tmpReallocSizeInst = inst->getOperand(1);

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
                
                /* Increment performance counter for branch */
                LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
                PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfBranchIncr = MemFuzzBuilder.CreateAdd(PerfBranchCounter, tmpReallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                
                /* Increment performance counter for total count  */
                LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
                PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfTotalIncr = MemFuzzBuilder.CreateAdd(PerfTotalCounter, tmpReallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                /* Possibly log location */
                LoadInst* PrevLocDesc = MemFuzzBuilder.CreateLoad(AFLPrevLocDesc);
                MemFuzzBuilder.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));

                /* Set prev_loc_desc to cur_loc_desc */
                MemFuzzBuilder.CreateStore(CurLocDesc, AFLPrevLocDesc);
              }
            }

            //free函数
            std::string instr_free1 = "free";
            //std::string instr_free2 = "xfree";
            std::string instr_free3 = "cfree";
            std::string instr_free4 = "safe_cfree";
            std::string instr_free5 = "safe_free";
            std::string instr_free6 = "safefree";
            std::string instr_free7 = "safexfree";
            if(inst->getNumOperands() >= 2 ){ //操作数大于二
              if ( instr_free1 == std::string(inst->getOperand(1)->getName()) || 
              /*instr_free2 == std::string(inst->getOperand(1)->getName()) ||*/
              instr_free3 == std::string(inst->getOperand(1)->getName()) ||
              instr_free4 == std::string(inst->getOperand(1)->getName()) ||
              instr_free5 == std::string(inst->getOperand(1)->getName()) ||
              instr_free6 == std::string(inst->getOperand(1)->getName()) ||
              instr_free7 == std::string(inst->getOperand(1)->getName()) ) {
                //outs() << "free: Heap memory release. " << "(In Function: " << F.getName() << ")\n";
                MemFuzzBuilder.CreateCall(instr_FreeFunc, inst->getOperand(0));
              }
            }

            //new函数, 插后方
            std::string instr_new1 = "_Znwm";
            std::string instr_new2 = "_Znam";
            std::string instr_new3 = "_Znaj";
            std::string instr_new4 = "_Znwj";
            if(inst->getNumOperands() >= 2 ){ //操作数大于二
              if ( instr_new1 == std::string(inst->getOperand(1)->getName()) || instr_new2 == std::string(inst->getOperand(1)->getName()) || instr_new3 == std::string(inst->getOperand(1)->getName()) || instr_new4 == std::string(inst->getOperand(1)->getName()) ){
                //outs() << "new: Heap memory allocation. " << "(In Function: " << F.getName() << ")\n";
                //MemFuzzBuilder.CreateCall(instr_MallocAndSizeFunc, inst->getOperand(0) );
                insetMallocFlag = 1;
                tmpMallocInst = inst;
                tmpMallocSizeInst = inst->getOperand(0);

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
                
                /* Increment performance counter for branch */
                LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
                PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfBranchIncr = MemFuzzBuilder.CreateAdd(PerfBranchCounter, tmpMallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                
                /* Increment performance counter for total count  */
                LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
                PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfTotalIncr = MemFuzzBuilder.CreateAdd(PerfTotalCounter, tmpMallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                /* Possibly log location */
                LoadInst* PrevLocDesc = MemFuzzBuilder.CreateLoad(AFLPrevLocDesc);
                MemFuzzBuilder.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));

                /* Set prev_loc_desc to cur_loc_desc */
                MemFuzzBuilder.CreateStore(CurLocDesc, AFLPrevLocDesc);
              }
            }

            //delete函数
            std::string instr_delete1 = "_ZdaPv"; 
            std::string instr_delete2 = "_ZdlPv"; 
            if(inst->getNumOperands() >= 2 ){ //操作数大于二
              if ( instr_delete1 == std::string(inst->getOperand(1)->getName()) || instr_delete2 == std::string(inst->getOperand(1)->getName()) ){
                //outs() << "delete: Heap memory release. " << "(In Function: " << F.getName() << ")\n";
                MemFuzzBuilder.CreateCall(instr_FreeFunc, inst->getOperand(0));
              }
            }

            //exit函数,相当于有一个return
            std::string instr_exit="exit"; 
            if(inst->getNumOperands() >= 2 ){ //操作数大于二
              if ( instr_exit == std::string(inst->getOperand(1)->getName()) ){
                //outs() << "exit: Program Exit Point. " << "(In Function: " << F.getName() << ")\n";
                MemFuzzBuilder.CreateCall(instr_ExitFunc, inst->getOperand(0) );
              }
            }
          }

          //针对有些new在invoke指令中搜索
          if(inst->getOpcode() == Instruction::Invoke) {
            std::string instr_malloc1 = "malloc";
            std::string instr_new1 = "_Znwm";
            std::string instr_new2 = "_Znam";
            std::string instr_new3 = "_Znaj";
            std::string instr_new4 = "_Znwj";
            if(inst->getNumOperands() >= 2 ){ //操作数大于二
              if (instr_malloc1 == std::string(inst->getOperand(1)->getName()) || instr_new1 == std::string(inst->getOperand(1)->getName()) || instr_new2 == std::string(inst->getOperand(1)->getName()) || instr_new3 == std::string(inst->getOperand(1)->getName()) || instr_new4 == std::string(inst->getOperand(1)->getName()) ){
                //outs() << "new: Heap memory allocation. " << "(In Function: " << F.getName() << ")\n";          
                insetMallocFlag = 1;
                tmpMallocInst = inst;
                tmpMallocSizeInst = inst->getOperand(0);
                i++;
                if (i == BB.end()){
                  BasicBlock *succ_BBptr = BBptr->getTerminator()->getSuccessor(0);//后继
                  BasicBlock::iterator succ_i = succ_BBptr->begin();
                  IRBuilder<> TmpBuilder(&*succ_i); //插桩的位置,invoke跳转的BLock
                  insetMallocFlag = 0;
                  SmallVector<Value *, 2> AllocArg;
                  AllocArg.push_back(tmpMallocInst);
                  AllocArg.push_back(tmpMallocSizeInst);
                  TmpBuilder.CreateCall(instr_MallocAndSizeFunc, AllocArg);
                }
                i--;

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
                
                /* Increment performance counter for branch */
                LoadInst *PerfBranchCounter = MemFuzzBuilder.CreateLoad(PerfBranchPtr);
                PerfBranchCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfBranchIncr = MemFuzzBuilder.CreateAdd(PerfBranchCounter, tmpMallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfBranchIncr, PerfBranchPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                
                /* Increment performance counter for total count  */
                LoadInst *PerfTotalCounter = MemFuzzBuilder.CreateLoad(PerfPtr); // Index 0 of the perf map
                PerfTotalCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                Value *PerfTotalIncr = MemFuzzBuilder.CreateAdd(PerfTotalCounter, tmpMallocSizeInst);
                MemFuzzBuilder.CreateStore(PerfTotalIncr, PerfPtr)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                /* Possibly log location */
                LoadInst* PrevLocDesc = MemFuzzBuilder.CreateLoad(AFLPrevLocDesc);
                MemFuzzBuilder.CreateCall(LogLocationsFunc, ArrayRef<Value*>({ PrevLocDesc, CurLocDesc }));

                /* Set prev_loc_desc to cur_loc_desc */
                MemFuzzBuilder.CreateStore(CurLocDesc, AFLPrevLocDesc);
              }
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
