#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ipc.h>//ipc
#include <sys/shm.h>
#include <unistd.h>

#ifdef __GNUC__
#define _msize malloc_usable_size
#endif

struct sys_data
{
	unsigned long long int MaxContinueCMNum;
	unsigned long long int MaxCallNum;
};

static unsigned long long int MaxCallNum = 0;
static unsigned long long int ContinueCallNum = 1000000; //防溢出
static unsigned long long int MaxContinueCMNum = 0;

void __attribute__((constructor)) traceBegin(void) {
  ;
}

void __attribute__((destructor)) traceEnd(void) {

  unsigned char *mem_str = getenv(MEM_ENV_VAR);

  if (mem_str) {

    unsigned int shm_mem_id = atoi(mem_str);

    struct sys_data *da;

    da = shmat(shm_mem_id, NULL, 0);

    /* Whooooops. */

    if (da == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */
    if(MaxContinueCMNum < 2000000)
      MaxContinueCMNum = 2000000;
    if(MaxCallNum < 1000000)
      MaxCallNum = 1000000;
    da->MaxContinueCMNum = MaxContinueCMNum-2000000;
	  da->MaxCallNum = MaxCallNum-1000000;
  }
}

void instr_Call () {
  ContinueCallNum++;
  if (ContinueCallNum > MaxCallNum)
    MaxCallNum = ContinueCallNum;
  if (ContinueCallNum > MaxContinueCMNum)
    MaxContinueCMNum = ContinueCallNum;
}

void instr_Return () {
  ContinueCallNum--;
}