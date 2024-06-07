#ifndef _EMUL_H
#define _EMUL_H
#include "common.h"
#include "util.h"
#include "elf.h"
#include "main.h"

struct bin_meta {
    uint64_t entry;  
    uint64_t phdr;
    uint64_t base;
    uint16_t phnum;
};

struct initial {
    struct bin_meta interpreter;
    struct bin_meta user_bin;
    uint64_t rsp;
};

struct emul_ctx {
    char * prog;
    int argc; 
    char ** argv;
    char ** envp;
    char * platform;
    struct initial init;
    uint64_t program_break; 
    int * fd;
    int fd_cur;
    uint64_t mmap_address;
};

#include "syscalls.h"

int emul_load(uc_engine * uc, int fd, uint64_t address, struct bin_meta * ctx);
void emul_map_memory(uc_engine * uc, uint64_t base_address ,Elf64_Phdr * phdrs, uint16_t phnum);
void emul_load_file(uc_engine * uc, uint64_t base_address, uint8_t * data ,Elf64_Phdr * phdrs, uint16_t phnum);
int emul_setup_emul_ctx(struct emul_ctx ** ctx, int argc, char ** argv);
void push_str(uc_engine * uc, uint64_t stack, char * str, int size);
int interp_load(uc_engine * uc, int fd, struct emul_ctx * ctx);
int bin_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx);
void emul_setup_stack(uc_engine * uc, struct emul_ctx * ctx);
void emul_run(uc_engine * uc, struct emul_ctx * ctx);
void emul_syscall_hook(uc_engine * uc, struct emul_ctx * ctx);
void emul_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void dump_memory_map(uc_engine * uc);
void dump_registers(uc_engine *uc);
#endif