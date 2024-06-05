#ifndef _MAIN_H
#define _MAIN_H
#include "common.h"
#include "elf.h"
#include "util.h"
#include "emul.h"

#define LD_BASE 0x00007ffff7fc3000
#define BIN_BASE 0x0000555555554000
#define RANDOM_SEED "AAAAAAAAAAAAAAAA" // 128bit rand
#define STACK_SIZE 0x10000 
#define STACK_BASE 0x00007ffffffde000
#endif