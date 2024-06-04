#include <unicorn/unicorn.h>
#include "elf.h"
#include "util.h"
#include "emul.h"

#define LD_BASE 0x00007ffff7fc3000
#define BIN_BASE 0x0000555555554000
#define RANDOM_SEED 0xdeadbeef

