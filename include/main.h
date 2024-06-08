#ifndef _MAIN_H
#define _MAIN_H
#include "common.h"
#include "elf.h"
#include "util.h"
#include "emul.h"

#define MMAP_ADDRESS 0x00007ffff7fc3000ULL
#define BIN_BASE 0x0000555555554000ULL
#define RANDOM_SEED "AAAAAAAAAAAAAAAA" // 128bit rand
#define STACK_SIZE 0x10000 
#define STACK_BASE 0x00007ffffffde000ULL
#define MAPPING_LIMIT 0x8000000
#define FD_LIMIT 0x100 // max limit 3 ~ 0x10000
#endif