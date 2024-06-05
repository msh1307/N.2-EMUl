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
    (*ctx) -> argv = new_argv;
    (*ctx) -> argc = c-1;
    (*ctx) -> platform = "x86_64";
    return 0;
}

uc_err emul_setup_stack(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t stack_base = STACK_BASE;
    uint64_t stack_size = STACK_SIZE;
    success("Mapping Stack  [0x%lx ~ 0x%lx (0x%lx)]", stack_base, stack_base + stack_size, stack_size);
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

    uint8_t debug[0x200];
    UC_ERR_CHECK(uc_mem_read(uc, stack_base + stack_size - 0x200, debug, 0x200));
    hexdump(debug, 0x200);
    
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

uc_err emul_run(uc_engine * uc, struct emul_ctx * ctx){
    uc_hook step, fault, syscall;
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RSP, &ctx -> init.rsp));
    // uc_hook_add(uc, &step, UC_HOOK_CODE, (void *)emul_step_hook, NULL, 1, 0);
    UC_ERR_CHECK(uc_hook_add(uc, &fault, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, (void *)emul_fault_hook, NULL, 1, 0));
    UC_ERR_CHECK(uc_hook_add(uc, &syscall, UC_HOOK_INSN, (void *)emul_syscall_hook, ctx, 1, 0, UC_X86_INS_SYSCALL));
    uc_err err = UC_ERR_CHECK(uc_emu_start(uc, ctx -> init.interpreter.entry, -1, 0, 0)); 
    
    return err;
}









// execve("./a.out", ["./a.out"], 0x7fff035c98b0 /* 46 vars */) = 0
// brk(NULL)                               = 0x55f63d8af000
// arch_prctl(0x3001 /* ARCH_??? */, 0x7ffd106cacb0) = -1 EINVAL (Invalid argument)
// mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7efdaffb9000
// access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
// openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
// newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=69983, ...}, AT_EMPTY_PATH) = 0
// mmap(NULL, 69983, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7efdaffa7000
// close(3)                                = 0
// openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
// read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
// pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
// pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
// pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0I\17\357\204\3$\f\221\2039x\324\224\323\236S"..., 68, 896) = 68
// newfstatat(3, "", {st_mode=S_IFREG|0755, st_size=2220400, ...}, AT_EMPTY_PATH) = 0
// pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
// mmap(NULL, 2264656, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7efdafd7e000
// mprotect(0x7efdafda6000, 2023424, PROT_NONE) = 0
// mmap(0x7efdafda6000, 1658880, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7efdafda6000
// mmap(0x7efdaff3b000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1bd000) = 0x7efdaff3b000
// mmap(0x7efdaff94000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x215000) = 0x7efdaff94000
// mmap(0x7efdaff9a000, 52816, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7efdaff9a000
// close(3)                                = 0
// mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7efdafd7b000
// arch_prctl(ARCH_SET_FS, 0x7efdafd7b740) = 0
// set_tid_address(0x7efdafd7ba10)         = 31957
// set_robust_list(0x7efdafd7ba20, 24)     = 0
// rseq(0x7efdafd7c0e0, 0x20, 0, 0x53053053) = 0
// mprotect(0x7efdaff94000, 16384, PROT_READ) = 0
// mprotect(0x55f63b92a000, 4096, PROT_READ) = 0
// mprotect(0x7efdafff3000, 8192, PROT_READ) = 0
// prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
// munmap(0x7efdaffa7000, 69983)           = 0
// getrandom("\xec\x22\xe5\x83\x3c\xf7\x46\xd0", 8, GRND_NONBLOCK) = 8
// brk(NULL)                               = 0x55f63d8af000
// brk(0x55f63d8d0000)                     = 0x55f63d8d0000
// newfstatat(0, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x4), ...}, AT_EMPTY_PATH) = 0
// read(0, 0x55f63d8af2d0, 1024)           = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
// --- SIGWINCH {si_signo=SIGWINCH, si_code=SI_KERNEL} ---
// read(0, 




// 55f63b927000-55f63b928000 r--p 00000000 08:20 174919                     /root/Workspace/N.2-EMUl/a.out
// 55f63b928000-55f63b929000 r-xp 00001000 08:20 174919                     /root/Workspace/N.2-EMUl/a.out
// 55f63b929000-55f63b92a000 r--p 00002000 08:20 174919                     /root/Workspace/N.2-EMUl/a.out
// 55f63b92a000-55f63b92b000 r--p 00002000 08:20 174919                     /root/Workspace/N.2-EMUl/a.out
// 55f63b92b000-55f63b92c000 rw-p 00003000 08:20 174919                     /root/Workspace/N.2-EMUl/a.out
// 55f63d8af000-55f63d8d0000 rw-p 00000000 00:00 0                          [heap]
// 7efdafd7b000-7efdafd7e000 rw-p 00000000 00:00 0 
// 7efdafd7e000-7efdafda6000 r--p 00000000 08:20 145440                     /usr/lib/x86_64-linux-gnu/libc.so.6
// 7efdafda6000-7efdaff3b000 r-xp 00028000 08:20 145440                     /usr/lib/x86_64-linux-gnu/libc.so.6
// 7efdaff3b000-7efdaff93000 r--p 001bd000 08:20 145440                     /usr/lib/x86_64-linux-gnu/libc.so.6
// 7efdaff93000-7efdaff94000 ---p 00215000 08:20 145440                     /usr/lib/x86_64-linux-gnu/libc.so.6
// 7efdaff94000-7efdaff98000 r--p 00215000 08:20 145440                     /usr/lib/x86_64-linux-gnu/libc.so.6
// 7efdaff98000-7efdaff9a000 rw-p 00219000 08:20 145440                     /usr/lib/x86_64-linux-gnu/libc.so.6
// 7efdaff9a000-7efdaffa7000 rw-p 00000000 00:00 0 
// 7efdaffb9000-7efdaffbb000 rw-p 00000000 00:00 0 
// 7efdaffbb000-7efdaffbd000 r--p 00000000 08:20 145429                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
// 7efdaffbd000-7efdaffe7000 r-xp 00002000 08:20 145429                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
// 7efdaffe7000-7efdafff2000 r--p 0002c000 08:20 145429                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
// 7efdafff3000-7efdafff5000 r--p 00037000 08:20 145429                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
// 7efdafff5000-7efdafff7000 rw-p 00039000 08:20 145429                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
// 7ffd106ad000-7ffd106ce000 rw-p 00000000 00:00 0                          [stack]
// 7ffd107df000-7ffd107e3000 r--p 00000000 00:00 0                          [vvar]
// 7ffd107e3000-7ffd107e5000 r-xp 00000000 00:00 0                          [vdso]
