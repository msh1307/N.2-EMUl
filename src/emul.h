#ifndef EMUL_H
#define EMUL_H
#include "libs.h"
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
};

int emul_load(uc_engine * uc, int fd, uint64_t address, struct bin_meta * ctx);
uc_err emul_map_memory(uc_engine * uc, uint64_t base_address ,Elf64_Phdr * phdrs, uint16_t phnum);
uc_err emul_load_file(uc_engine * uc, uint64_t base_address, uint8_t * data ,Elf64_Phdr * phdrs, uint16_t phnum);
int emul_setup_emul_ctx(struct emul_ctx ** ctx, int argc, char ** argv);
uc_err push_str(uc_engine * uc, uint64_t stack, char * str, int size);
int interp_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx);
int bin_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx);
uc_err emul_setup_stack(uc_engine * uc, struct emul_ctx * ctx);
uc_err emul_run(uc_engine * uc, struct emul_ctx * ctx);
#endif