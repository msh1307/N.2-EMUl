#include <unicorn/unicorn.h>
#include <stdint.h>
#include "elf.h"

int emul_load(uc_engine * uc, int fd, uint64_t address);