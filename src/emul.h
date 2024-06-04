#include <unicorn/unicorn.h>
#include <sys/mman.h>
#include <stdint.h>
#include "elf.h"

int emul_load(uc_engine * uc, int fd, uint64_t address);
uc_err emul_map_memory(uc_engine * uc, uint64_t base_address ,Elf64_Phdr * phdrs, uint16_t phnum);
uc_err emul_load_file(uc_engine * uc, uint64_t base_address, uint8_t * data ,Elf64_Phdr * phdrs, uint16_t phnum);