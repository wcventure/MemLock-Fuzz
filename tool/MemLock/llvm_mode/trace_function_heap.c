#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ipc.h>//ipc
#include <sys/shm.h>
#include <unistd.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
#define malloc_usable_size malloc_size
#else
#include <malloc.h>
#endif /* ^!__APPLE__ */

struct sys_data
{
  unsigned long long int MaxContinueCMNum;
  unsigned long long int MaxCallNum;
  unsigned long long int MaxAllocNum;
  unsigned long long int TotalMallocSize;
  unsigned long long int MayMemLeak;
  unsigned long long int FailAlloc;
  unsigned long long int LeakSize;
  unsigned long long int TotalMallocNum;
};

static unsigned long long int TotalAllocNum = 0;
static unsigned long long int TotalDeallocNum = 0;
static unsigned long long int TotalCallNum = 0;
//static unsigned long long int TotalMallocSize = 0;
static unsigned long long int memory_peak = 0;
static long long int current_memory = 0;

static unsigned long long int MaxCallNum = 0;
static unsigned long long int MaxAllocNum = 0;

static unsigned long long int ContinueCallNum = (1UL << 20); //防溢出
static unsigned long long int ContinueAllocNum = (1UL << 20); //防溢出

static unsigned long long int MaxContinueCMNum = 0;

static unsigned long long int FailToAllocate = 0; //是否malloc返回值为NULL

void update_mem_peak()
{
	if (current_memory < 0){
    return;
  }
  if (current_memory > memory_peak)
  {
    memory_peak = current_memory;
  }
  if (current_memory >= (15UL << 28) )
  {
    //报错
    FailToAllocate = 1;
    printf("instru: consume too much memory. current memory try to up to %lld bytes.\n", current_memory);
    char *p = (char*)malloc((1ULL << 40));
    printf("%s\n", p);
  }	
}

void __attribute__((constructor)) traceBegin(void) {
  ;
}

void __attribute__((destructor)) traceEnd(void) {

  printf("\n@@@ instru: Finished @@@\n\n");

	//if (current_memory < 0)
    //current_memory = 0;
  
  //if (TotalAllocNum > TotalDeallocNum) {//!= make false positives because of alloca
    //printf("instru: MayMemLeak = 1\n");
  //}else{
    //printf("instru: MayMemLeak = 0\n");
  //}

  //if (current_memory) {
		//printf("instru: WARNING: %lld bytes leaked!\n", current_memory);
	//}

  printf("instru: MemoryPeak = %lld\n", memory_peak);
  //printf("instru: StackLen = %lld\n", MaxCallNum - (1UL << 20));
  //printf("instru: TotalAllocNum = %lld\n", TotalAllocNum);
	//printf("instru: TotalDeallocNum = %lld\n", TotalDeallocNum);
	//printf("instru: FailToAllocate = %lld\n", FailToAllocate);

  unsigned char *mem_str = getenv(MEM_ENV_VAR);

  if (mem_str) {

    unsigned int shm_mem_id = atoi(mem_str);

    struct sys_data *da;

    da = shmat(shm_mem_id, NULL, 0);

    /* Whooooops. */

    if (da == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */
    if(MaxContinueCMNum < (2UL << 20))
      MaxContinueCMNum = (2UL << 20);
    if(MaxAllocNum < (1UL << 20))
      MaxAllocNum = (1UL << 20);
    if(MaxCallNum < (1UL << 20))
      MaxCallNum = (1UL << 20);
    da->MaxContinueCMNum = MaxContinueCMNum - (2UL << 20);
	  da->MaxCallNum = MaxCallNum - (1UL << 20);
    da->MaxAllocNum = MaxAllocNum - (1UL << 20);
    da->TotalMallocSize = memory_peak;
    if (TotalAllocNum > TotalDeallocNum) //!= make false positives because of alloca
      da->MayMemLeak = 1;
    else
      da->MayMemLeak = 0;
    da->FailAlloc = FailToAllocate;
    da->LeakSize = current_memory;
    da->TotalMallocNum = TotalAllocNum;
  }

}

void instr_Call () {
  TotalCallNum++;
  ContinueCallNum++;
  if (ContinueCallNum > MaxCallNum)
    MaxCallNum = ContinueCallNum;
  if (ContinueCallNum + ContinueAllocNum > MaxContinueCMNum)
    MaxContinueCMNum = ContinueCallNum + ContinueAllocNum;
}

void instr_Return () {
  ContinueCallNum--;
}

void instr_Free (void* ptr) {
  if (ptr==NULL)
    return;

  TotalDeallocNum++;
  ContinueAllocNum--;
  current_memory -= malloc_usable_size(ptr);
  //printf("instru: freed %ld bytes for pointer %p\n", malloc_usable_size(ptr), ptr);
}

void instr_MallocAndSize (void* re, unsigned long long int a) {
  if (re == NULL){
    printf("instru: Fail to Allocate in malloc. current memory is %lld bytes, try to allocat %llu bytes.\n", current_memory, a);
    FailToAllocate = 1;
    //报错
    char *p = (char*)malloc((1ULL << 40));
    printf("%s\n", p);
    return;
  }
  
  //if (a < (15UL << 28)){
  if (1){
    TotalAllocNum++;
    ContinueAllocNum++;
    if (ContinueAllocNum > MaxAllocNum)
      MaxAllocNum = ContinueAllocNum;
    if (ContinueCallNum + ContinueAllocNum > MaxContinueCMNum)
      MaxContinueCMNum = ContinueCallNum + ContinueAllocNum;
    
    current_memory += malloc_usable_size(re);
    update_mem_peak();
    //printf("instru: malloced %ld bytes for ptr %p\n", malloc_usable_size(re), re);
  }
  
}

void instr_CallocAndSize (void* re, long long int a, long long int b) {
  if (re == NULL){
    printf("instru: Fail to Allocate in calloc. Current memory is %lld bytes, try to allocat %llu bytes.\n", current_memory, a*b);
    FailToAllocate = 1;
    //报错
    char *p = (char*)malloc((1ULL << 40));
    printf("%s\n", p);
    return;
  }
  
  //if (a*b < (15UL << 28)){
  if (1){
    TotalAllocNum++;
    ContinueAllocNum++;
    if (ContinueAllocNum > MaxAllocNum)
      MaxAllocNum = ContinueAllocNum;
    if (ContinueCallNum + ContinueAllocNum > MaxContinueCMNum)
      MaxContinueCMNum = ContinueCallNum + ContinueAllocNum;

    current_memory += malloc_usable_size(re);
    update_mem_peak();
    //printf("instru: realloced %ld bytes for ptr %p\n", malloc_usable_size(re), re);
  }
  
}

void instr_ReallocAhead (void* p, unsigned long long int a) {
  if (p == NULL && a == 0)
    return;

  if (p == NULL){ //相当于malloc
    ;
  }
  else if ( a==0 ){ //相当于free
    TotalDeallocNum++;
    ContinueAllocNum--;
    current_memory -= malloc_usable_size(p);
    //printf("instru: realloc freed %ld bytes for pointer %p\n", malloc_usable_size(p), p);  
  }
  else{ //realloc, 此处记录p size即可，其他事由插桩后方函数做
    TotalDeallocNum++;
    ContinueAllocNum--;
    current_memory -= malloc_usable_size(p);
    //printf("instru: realloc freed %ld bytes for pointer %p\n", malloc_usable_size(p), p);  
  }
}

void instr_ReallocAndSize (void* re, void* p, unsigned long long int a) {
  if (p == NULL){ //相当于malloc
    if (re == NULL){
      printf("instru: Fail to Allocate in realloc(=malloc). current memory is %lld bytes, try to allocat %llu bytes.\n", current_memory, a);
      FailToAllocate = 1;
      //报错
      char *p = (char*)malloc((1ULL << 40));
      printf("%s\n", p);
      return;
    }

    //if (a < (15UL << 28)){
    if (1){
      TotalAllocNum++;
      ContinueAllocNum++;
      if (ContinueAllocNum > MaxAllocNum)
        MaxAllocNum = ContinueAllocNum;
      if (ContinueCallNum + ContinueAllocNum > MaxContinueCMNum)
        MaxContinueCMNum = ContinueCallNum + ContinueAllocNum;

      current_memory += malloc_usable_size(re);
      update_mem_peak();
      //printf("instru: realloced %ld bytes for ptr %p\n", malloc_usable_size(re), re);
    }
  }
  else if (p != NULL && a != 0){ //realloc
    if (re == NULL){
      FailToAllocate = 1;
      TotalDeallocNum--;
      ContinueAllocNum++;
      current_memory += malloc_usable_size(p);
      printf("instru: realloced Fail, current memory is %lld bytes, try to allocat %llu bytes, still %d bytes for ptr %p\n", current_memory, a, malloc_usable_size(p), p);
      //报错
      char *p = (char*)malloc((1ULL << 40));
      printf("%s\n", p);
      return;
    }

    //if (a < (15UL << 28)){
    if (1){
      TotalAllocNum++;
      ContinueAllocNum++;
      if (ContinueAllocNum > MaxAllocNum)
        MaxAllocNum = ContinueAllocNum;
      if (ContinueCallNum + ContinueAllocNum > MaxContinueCMNum)
        MaxContinueCMNum = ContinueCallNum + ContinueAllocNum;

      current_memory += malloc_usable_size(re);
      update_mem_peak();
      //printf("instru: realloced %ld bytes for ptr %p\n", malloc_usable_size(re), re);
    }
    
  }
}

void instr_Exit(int a){
  ;
}
