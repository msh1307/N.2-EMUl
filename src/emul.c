#include "../include/emul.h"

int interp_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx){
    ctx -> init.interpreter.base = address;
    return emul_load(uc, fd, address, &ctx -> init.interpreter);
}

int bin_load(uc_engine * uc, int fd, uint64_t address, struct emul_ctx * ctx){
    ctx -> init.user_bin.base = address;
    ctx -> program_break = -1;
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
    success("Entrypoint: 0x%lx", bin -> entry);
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
            success("Mapping Memory [0x%lx ~ 0x%lx (0x%lx)] FileOffset=0x%lx FLAGS=0x%lx", addr,addr+sz,sz,offset,flags);
            uint32_t uc_flags = 0;
            if (flags & PF_R)
                uc_flags |= UC_PROT_READ;
            if (flags & PF_W)
                uc_flags |= UC_PROT_WRITE;
            if (flags & PF_X)
                uc_flags |= UC_PROT_EXEC;
            uc_err err = UC_ERR_CHECK(uc_mem_map(uc, addr, sz, uc_flags));
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
                success("Writing Memory [0x%lx ~ 0x%lx (0x%lx)]", address,address+sz,sz);
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
        char **new_envp = (char **)malloc((argc - sep) * sizeof(char *));
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
    char **new_argv = (char **)malloc((sep) * sizeof(char *));
    if (new_argv == NULL){
        failure("emul_setup_emul_ctx() -> malloc() failed");
        return -1;
    }
    for (int i = 1; i < sep; i++) {
        new_argv[c++] = argv[i];
    }
    new_argv[c++] = NULL;
    
    char * cwd = malloc(0x100);
    if ((*ctx) -> prog[0] != '/' && (*ctx) -> prog[0] != '~'){
        if (getcwd(cwd, 0x100) == NULL) 
            return -1;
        cwd = realloc(cwd, strlen(cwd) + strlen((*ctx) -> prog) + 1);
        strcat(cwd, "/");
        strcat(cwd, (*ctx) -> prog);
        (*ctx) -> prog = cwd;
        puts(cwd);
    }

    (*ctx) -> fd = (int *)malloc(sizeof(int) * FD_LIMIT);
    if ((*ctx) -> fd == NULL){
        failure("emul_setup_emul_ctx() -> malloc() failed");
        return -1;
    }
    memset((void *)(*ctx) -> fd, 0, sizeof(int) * FD_LIMIT);
    (*ctx) -> fd[0] = 0;
    (*ctx) -> fd[0] |= 1 << 16;
    (*ctx) -> fd[1] = 1;
    (*ctx) -> fd[1] |= 1 << 16;
    (*ctx) -> fd[2] = 2;
    (*ctx) -> fd[2] |= 1 << 16;
    (*ctx) -> argv = new_argv;
    (*ctx) -> argc = c-1;
    (*ctx) -> platform = "x86_64";
    return 0;
}

void emul_setup_stack(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t stack_base = STACK_BASE;
    uint64_t stack_size = STACK_SIZE;
    success("Mapping Stack  [0x%lx ~ 0x%lx (0x%lx)]", stack_base, stack_base + stack_size, stack_size);
    UC_ERR_CHECK(uc_mem_map(uc, stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE)); // FIX ME: if NX bit disabled, stack must be mapped with prot_all
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
    for (i = 0 ; i < c; i ++){
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
    push_str(uc, stack_top, "\x00\x00\x00\x00", 4);
    stack_top -= 4;
    push_str(uc, stack_top, (char *)&ctx -> argc, 4);
    stack_top -= 4;
    ctx -> init.rsp = stack_top;

    uint64_t debug[64];
    UC_ERR_CHECK(uc_mem_read(uc, stack_base + stack_size - 64 * 8, debug, 64 * 8));
    hexdump(debug, 64 * 8);
    // char debug_str[40];
    // UC_ERR_CHECK(uc_mem_read(uc, 0x00007ffffffedfc0, debug_str, 40));
    // printf("read: %s\n", debug_str);
}

uc_err push_str(uc_engine * uc, uint64_t stack, char * str, int size){
    stack -= size;
    uc_err err = UC_ERR_CHECK(uc_mem_write(uc, stack, str, size));
    return err;
}

void emul_step_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
        uint8_t code[32];
        memset(code, 0, sizeof(code));
        uc_err err = UC_ERR_CHECK(uc_mem_read(uc, address, &code, size));
        cs_insn *insn;
        size_t count = 0;
        count = cs_disasm(handle, (uint8_t *) &code, sizeof(code)-1, address, 0, &insn);

        uint64_t rip;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        if (0x7ffff7fe27ff == rip){
            char debug[0x20];
            uint64_t rdi;
            uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
            uc_mem_read(uc, rip, debug, 0x20);
            puts("DEBUG");
            puts(debug);
        }
        uint64_t rax, rbx, rcx, rdx, rdi, rsi;
        uc_reg_read(uc, UC_X86_REG_RAX, &rax);
        uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
        uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
        uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
        uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
        uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
        printf("rax=%lx rbx=%lx rcx=%lx rdx=%lx rdi=%lx rsi=%lx\n", rax, rbx, rcx, rdx, rdi, rsi);

        if (count > 0) {
            success("0x%lx:\t%s\t\t%s", insn[0].address, insn[0].mnemonic, insn[0].op_str);
            cs_free(insn, count);
        }
        cs_close(&handle);
    }
}

bool emul_fault_hook(uc_engine *uc, uc_mem_type type, uint64_t address, uint32_t size, void *user_data)
{
    switch(type) {
        case UC_MEM_READ_UNMAPPED:
            failure("SEGV READ");
            return true;
        case UC_MEM_WRITE_UNMAPPED:
            failure("SEGV WRITE");
            return true;
        case UC_MEM_READ_PROT:
            failure("SEGV READ PROT");
            return true;
        case UC_MEM_WRITE_PROT:
            failure("SEGV WRITE PROT");
            return true;
        case UC_MEM_FETCH:
            failure("SEGV FETCH");
            return true;
        case UC_MEM_FETCH_PROT:
            failure("SEGV FETCH PROT");
            return true;
        default:
            failure("SEGV ???");
            return true;
    }
}

void emul_syscall_hook(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t rax, rdi, rsi, rdx, r10, r8, r9;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    handle_syscall(uc, rax, ctx);
}

void emul_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
	success("Tracing basic block at 0x%lx, block size = 0x%x\n", address, size);
} // code coverage

void emul_run(uc_engine * uc, struct emul_ctx * ctx){
    uc_hook step, fault, syscall, block;
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RSP, &ctx -> init.rsp));
    UC_ERR_CHECK(uc_hook_add(uc, &fault, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, (void *)emul_fault_hook, NULL, 1, 0));
    UC_ERR_CHECK(uc_hook_add(uc, &syscall, UC_HOOK_INSN, (void *)emul_syscall_hook, ctx, 1, 0, UC_X86_INS_SYSCALL));
    // UC_ERR_CHECK(uc_hook_add(uc, &block, UC_HOOK_BLOCK, (void *)emul_block_hook, NULL, 1, 0));
    // UC_ERR_CHECK(uc_hook_add(uc, &step, UC_HOOK_CODE, (void *)emul_step_hook, NULL, 1, 0));
    UC_ERR_CHECK(uc_emu_start(uc, ctx -> init.interpreter.entry, -1, 0, 0)); 
    return ;
}