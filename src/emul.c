#include "emul.h"

int emul_load(uc_engine * uc, int fd, uint64_t address){
    size_t size = get_size(fd);
    uint16_t phnum, shnum;
    Elf64_Phdr * phdrs = NULL;
    Elf64_Shdr * shdrs;
    Elf64_Shdr * shstrs = NULL;
    uint8_t * data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if ((uint64_t)data == -1){
        failure("emul_load() -> mmap() failed");
        return -1;
    }
    parse_elf(data, &phdrs, &shdrs, &shstrs, &phnum, &shnum);
    if (!phdrs){
        failure("emul_load() -> phdrs == 0");
        return -1;
    }
    if (!shdrs){
        failure("emul_load() -> shdrs == 0");
        return -1; 
    }
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

int emul_setup_user_ctx(struct user_ctx ** ctx, int argc, char ** argv){
    int c = 0;
    *ctx = malloc(sizeof(struct user_ctx));
    (*ctx) -> prog = argv[1];
    int sep = -1;
    for (int i = 2; i < argc; i++) { 
        if (strcmp(argv[i], "--") == 0) {
            sep = i;
            break;
        }
    }
    if (sep == -1){
        sep = argc - 1;
        (*ctx) -> envp = NULL;
    }
    else{
        char **new_envp = (char **)malloc((argc - sep) * sizeof(char *));
        if (new_envp == NULL){
            failure("emul_setup_user_ctx() -> malloc() failed");
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
        failure("emul_setup_user_ctx() -> malloc() failed");
        return -1;
    }
    for (int i = 1; i < (sep-1); i++) {
        new_argv[c++] = argv[i];
    }
    new_argv[c++] = NULL;
    (*ctx) -> argv = new_argv;
    (*ctx) -> platform = "x86_64";
    return 0;
}


    // Elf64_auxv_t * auxv = (Elf64_auxv_t * )malloc(sizeof(Elf64_auxv_t));
    // auxv[c++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = { .a_val = (uint64_t)RANDOM_SEED }};
    // auxv[c++] = (Elf64_auxv_t){.a_type = AT_PLATFORM, .a_un = { .a_val = (uint64_t)"" }};
    // auxv[c++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = { .a_val = (uint64_t)RANDOM_SEED }};
    // auxv[c++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = { .a_val = (uint64_t)RANDOM_SEED }};
    // auxv[c++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = { .a_val = (uint64_t)RANDOM_SEED }};

int emul_setup_stack(uc_engine * uc, user_ctx * ctx){
    // const char *args[] = { "/bin/ls", NULL };
    // char *const env[] = { "HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    Elf64_auxv_t auxv[] = {
        { .a_type = AT_RANDOM, .a_un = { .a_val = (uint64_t)"RANDOM_VALUE" } },
        { .a_type = AT_NULL, .a_un = { .a_val = 0 } }
    };
    char **new_stack;
    int stack_size = 1024;  // 스택 크기 (예시로 1024 사용)

    // 스택 메모리 할당
    new_stack = (char **)malloc(stack_size);
    if (new_stack == NULL) {
        perror("malloc");
        exit(1);
    }

    // 스택에 인자, 환경 변수, aux 벡터 설정
    char **stack_ptr = new_stack + stack_size / sizeof(char *);

    // aux 벡터 설정
    for (int i = sizeof(auxv) / sizeof(auxv[0]) - 1; i >= 0; i--) {
        stack_ptr -= 2;
        *(Elf64_auxv_t *)stack_ptr = auxv[i];
    }
    stack_ptr -= 1;
    *stack_ptr = NULL;

    // 환경 변수 설정
    for (int i = 0; env[i] != NULL; i++) {
        stack_ptr--;
        *stack_ptr = env[i];
    }
    stack_ptr--;
    *stack_ptr = NULL;

    // 인자 설정
    for (int i = argc - 1; i >= 0; i--) {
        stack_ptr--;
        *stack_ptr = argv[i];
    }
    stack_ptr--;
    *stack_ptr = (char *)(intptr_t)argc;

    // 스택 정렬
    stack_ptr = (char **)((uintptr_t)stack_ptr & -16L);

    // execve 시스템 콜 호출
    execve(args[0], args, environ);

    // execve 실패 시 에러 처리
    perror("execve");
    exit(1);
   
}