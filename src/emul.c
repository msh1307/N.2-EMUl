#include "emul.h"

int interp_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx){
    ctx -> init.interpreter.base = address;
    return emul_load(uc, fd, address, &ctx -> init.interpreter);
}

int bin_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx){
    ctx -> init.user_bin.base = address;
    return emul_load(uc, fd, address, &ctx -> init.user_bin);
}

int emul_load(uc_engine * uc, int fd, uint64_t address, struct bin_meta * bin){
    size_t size = get_size(fd);
    uint16_t phnum, shnum;
    uint64_t entry;
    Elf64_Phdr * phdrs = NULL;
    Elf64_Shdr * shdrs = NULL;
    Elf64_Shdr * shstrs = NULL;
    uint8_t * data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if ((uint64_t)data == -1){
        failure("emul_load() -> mmap() failed");
        return -1;
    }
    parse_elf(data, &phdrs, &shdrs, &shstrs, &phnum, &shnum, &entry);
    if (!phdrs){
        failure("emul_load() -> phdrs == 0");
        return -1;
    }
    if (!shdrs){
        failure("emul_load() -> shdrs == 0");
        return -1; 
    }
    bin -> phdr = (uint64_t)phdrs - (uint64_t)data + address;
    bin -> entry = address + entry;
    bin -> phnum = phnum;
    success("Entrypoint: %lx", bin -> entry);
    uc_err err = emul_map_memory(uc, address, phdrs, phnum);
    if (err != UC_ERR_OK){
        failure("emul_load() -> emul_map_memory()");
        return -1;
    }
    err = emul_load_file(uc, address, data, phdrs, phnum);
    if (err != UC_ERR_OK){
        failure("emul_load() -> emul_load_file()");
        return -1;
    }

    if (munmap(data, size) == -1)
        return -1;
    return 0;
}

uc_err emul_map_memory(uc_engine * uc, uint64_t base_address ,Elf64_Phdr * phdrs, uint16_t phnum){
    uint64_t vaddr, align, memsz, offset,flags,filesz, sz, addr;
    for (int i=0; i<phnum; i++){
        if (phdrs[i].p_type == PT_LOAD){
            vaddr = phdrs[i].p_vaddr;
            offset = phdrs[i].p_offset;
            align = phdrs[i].p_align;
            memsz = phdrs[i].p_memsz;
            filesz = phdrs[i].p_filesz;
            flags = phdrs[i].p_flags;
            addr = (base_address+vaddr)&0xfffffffffffff000;
            sz = (((base_address+vaddr+memsz - addr-1) / align) + 1) * align;
            success("Mapping Memory [%lx ~ %lx (%lx)] FileOffset=%lx FLAGS=%lx", addr,addr+sz,sz,offset,flags);
            uint32_t uc_flags = 0;
            if (flags & PF_R)
                uc_flags |= UC_PROT_READ;
            if (flags & PF_W)
                uc_flags |= UC_PROT_WRITE;
            if (flags & PF_X)
                uc_flags |= UC_PROT_EXEC;
            uc_err err = uc_mem_map(uc, addr, sz, uc_flags);
            if (err)
                return err;        
        }
    }
    return UC_ERR_OK;
}

uc_err emul_load_file(uc_engine * uc, uint64_t base_address, uint8_t * data ,Elf64_Phdr * phdrs, uint16_t phnum){
    for (int i=0; i<phnum; i++){
        switch (phdrs[i].p_type){
            case PT_LOAD:
                uint64_t address = base_address+phdrs[i].p_vaddr;
                uint64_t sz = phdrs[i].p_memsz;
                uc_err err = uc_mem_write(uc, address, data+phdrs[i].p_offset, sz);
                success("Writing Memory [%lx ~ %lx (%lx)]", address,address+sz,sz);
                if (err)
                    return err;
                break;
            default:
                break;
        }
    }
    return UC_ERR_OK;
}

int emul_setup_emul_ctx(struct emul_ctx ** ctx, int argc, char ** argv){
    int c = 0;
    *ctx = malloc(sizeof(struct emul_ctx));
    (*ctx) -> prog = argv[1];
    int sep = -1;
    for (int i = 2; i < argc; i++) { 
        if (strcmp(argv[i], "--") == 0) {
            sep = i;
            break;
        }
    }
    if (sep == -1){
        sep = argc;
        (*ctx) -> envp = NULL;
    }
    else{
        char **new_envp = (char **)malloc((argc -1 - sep) * sizeof(char *));
        if (new_envp == NULL){
            failure("emul_setup_emul_ctx() -> malloc() failed");
            return -1;
        }
        c = 0;
        for (int i = sep + 1; i < argc; i++){
            new_envp[c++] = argv[i];
        }
        new_envp[c++] = NULL;
        (*ctx) -> envp = new_envp;
    }
    c = 0;
    char **new_argv = (char **)malloc((sep - 1) * sizeof(char *));
    if (new_argv == NULL){
        failure("emul_setup_emul_ctx() -> malloc() failed");
        return -1;
    }
    for (int i = 1; i < sep; i++) {
        new_argv[c++] = argv[i];
    }
    new_argv[c++] = NULL;
    (*ctx) -> argv = new_argv;
    (*ctx) -> argc = c-1;
    (*ctx) -> platform = "x86_64";
    return 0;
}

uc_err emul_setup_stack(uc_engine * uc, struct emul_ctx * ctx){
    char debug[16];
    uint64_t stack_base = STACK_BASE;
    uint64_t stack_size = STACK_SIZE;
    success("Mapping Stack  [%lx ~ %lx (%lx)]", stack_base, stack_base + stack_size, stack_size);
    uc_err err = uc_mem_map(uc, stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE); // FIX ME: if NX bit disabled, stack must be mapped with prot_all
    if (err)
        return err;        
    int c = 0;
    Elf64_auxv_t * auxv = (Elf64_auxv_t * )malloc(sizeof(Elf64_auxv_t) * 20);
    uint64_t stack_top = stack_base + stack_size;
    push_str(uc, stack_top, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    stack_top -= 8;
    int len = strlen(ctx -> platform) + 1;
    push_str(uc, stack_top, ctx -> platform, len);
    stack_top -= len;
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_NULL, .a_un = { .a_val = 0ULL }};
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_PLATFORM, .a_un = { .a_val = stack_top }};
    len = strlen(ctx -> prog) + 1;
    push_str(uc, stack_top, ctx -> prog, len);
    stack_top -= len;
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_EXECFN, .a_un = { .a_val = stack_top }};
    
    push_str(uc, stack_top, RANDOM_SEED, 16);
    stack_top -= 16;
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = { .a_val = stack_top }};
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_SECURE, .a_un = { .a_val = 0ULL }};
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_EGID, .a_un = { .a_val = 0ULL }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_GID, .a_un = { .a_val = 0ULL }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_EUID, .a_un = { .a_val = 0ULL }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_UID, .a_un = { .a_val = 0ULL }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_ENTRY, .a_un = { .a_val = ctx -> init.user_bin.entry }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_FLAGS, .a_un = { .a_val = 0ULL }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_BASE, .a_un = { .a_val = ctx -> init.interpreter.base }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_PHNUM, .a_un = { .a_val = 0ULL }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_PHENT, .a_un = { .a_val = sizeof(Elf64_Phdr) }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_PHDR, .a_un = { .a_val = ctx -> init.user_bin.phdr }}; 
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_CLKTCK, .a_un = { .a_val = 100ULL }};
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_PAGESZ, .a_un = { .a_val = 0x1000ULL }}; // default page size
    auxv[c++] = (Elf64_auxv_t){.a_type = AT_HWCAP, .a_un = { .a_val = 0x078bfbfdULL }}; // x86_64
    // no vdso AT_SYSINFO_EHDR
    uint64_t env_str = stack_top;
    int i = 0;
    if (ctx -> envp){
        while (ctx -> envp[i] != NULL){
            len = strlen(ctx -> envp[i]) + 1;
            push_str(uc, stack_top, ctx -> envp[i], len);
            stack_top -= len;
            i++;
        }
    }
    i = 0;
    uint64_t argv_str = stack_top;
    while (ctx -> argv[i] != NULL){
        len = strlen(ctx -> argv[i]) + 1;
        push_str(uc, stack_top, ctx -> argv[i], len);
        stack_top -= len;
        i++;
    }
    stack_top -= 0x10;
    stack_top = (stack_top) & 0xfffffffffffffff0;
    for (i = 0 ; i < c - 1; i ++){
        push_str(uc, stack_top, (char *)&auxv[i], 0x10);
        stack_top -= 0x10;
    }
    push_str(uc, stack_top, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    stack_top -= 8;

    i = 0;
    if (ctx -> envp){
        while (ctx -> envp[i] != NULL){
            len = strlen(ctx -> envp[i]) + 1;
            env_str -= len;
            push_str(uc, stack_top, (char * )&env_str, 8);
            stack_top -= 8;
            i++;
        }
    }
    push_str(uc, stack_top, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    stack_top -= 8;

    i = 0;
    while (ctx -> argv[i] != NULL){
        len = strlen(ctx -> argv[i]) + 1;
        argv_str -= len;
        push_str(uc, stack_top, (char * )&argv_str, 8);
        stack_top -= 8;
        i++;
    }
    push_str(uc, stack_top, (char *)&ctx -> argc, 4);
    stack_top -= 4;
    push_str(uc, stack_top, "\x00\x00\x00\x00", 4);
    stack_top -= 4;
   
}


uc_err push_str(uc_engine * uc, uint64_t stack, char * str, int size){
    stack -= size;
    uc_err err = uc_mem_write(uc, stack, str, size);
    return err;
}


// 0x7fffffffdf20: 0x0000000000000021      0x00007ffff7fc1000
// 0x7fffffffdf30: 0x0000000000000033      0x00000000000006f0
// 0x7fffffffdf40: 0x0000000000000010      0x000000001f8bfbff
// 0x7fffffffdf50: 0x0000000000000006      0x0000000000001000
// 0x7fffffffdf60: 0x0000000000000011      0x0000000000000064
// 0x7fffffffdf70: 0x0000000000000003      0x0000555555554040
// 0x7fffffffdf80: 0x0000000000000004      0x0000000000000038
// 0x7fffffffdf90: 0x0000000000000005      0x000000000000000d
// 0x7fffffffdfa0: 0x0000000000000007      0x00007ffff7fc3000
// 0x7fffffffdfb0: 0x0000000000000008      0x0000000000000000
// 0x7fffffffdfc0: 0x0000000000000009      0x0000555555555380
// 0x7fffffffdfd0: 0x000000000000000b      0x0000000000000000
// 0x7fffffffdfe0: 0x000000000000000c      0x0000000000000000
// 0x7fffffffdff0: 0x000000000000000d      0x0000000000000000
// 0x7fffffffe000: 0x000000000000000e      0x0000000000000000
// 0x7fffffffe010: 0x0000000000000017      0x0000000000000000
// 0x7fffffffe020: 0x0000000000000019      0x00007fffffffe079
// 0x7fffffffe030: 0x000000000000001a      0x0000000000000002
// 0x7fffffffe040: 0x000000000000001f      0x00007fffffffefd3
// 0x7fffffffe050: 0x000000000000000f      0x00007fffffffe089
// 0x7fffffffe060: 0x0000000000000000      0x0000000000000000