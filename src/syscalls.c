#include "../include/syscalls.h"

void handle_syscall(uc_engine * uc, uint64_t rax, struct emul_ctx * ctx){
    switch (rax){
        case 0x0:
            emu_sys_read(uc, ctx);
            break;

        case 0x1:
            emu_sys_write(uc, ctx);
            break;
        
        case 0xc:
            emu_sys_brk(uc, ctx);
            break;

        case 0x14:
            emu_sys_writev(uc, ctx);
            break;
        
        case 0x15:
            emu_sys_access(uc);
            break;
            
        case 0x3c:
            success("emul: exit()");
            UC_ERR_CHECK(uc_emu_stop(uc));
            break;

        case 0x3f:
            emu_sys_uname(uc);
            break;

        case 0x9e:
            emu_sys_arch_prctl(uc);
            break;
        
        case 0x101:
            emu_sys_openat(uc, ctx);
            break;
        
        case 0x106:
            emu_sys_newfstatat(uc, ctx);
            break;

        default:
            uint64_t rdi, rsi, rdx;
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
            success("emul: syscall(rax=0x%lx, rdi=0x%lx, rsi=0x%lx, rdx=0x%lx)", rax, rdi, rsi, rdx);
            break;
    }
}

void emu_sys_write(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t rdi, rsi, rdx;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    if (rdi < FD_LIMIT){
        if ((ctx -> fd[rdi]) >> 16){
            char * buf = malloc(rdx+1);
            if (buf){
                UC_ERR_CHECK(uc_mem_read(uc, rsi, buf, rdx));
                success("emul: write(fd=0x%lx, buf=0x%lx, count=0x%lx)", rdi, rsi, rdx);
                uint64_t ret = write(ctx -> fd[rdi]&0xffff, buf, rdx);
                UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ret));
                free(buf);
                return ;
            }
        }
    }
    failure("emul: write(fd=0x%lx, buf=0x%lx, count=0x%lx) == 0xffffffffffffffff", rdi, rsi, rdx);
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
}

void emu_sys_brk(uc_engine * uc, struct emul_ctx * ctx){ // brk implementation with a fixed program break 
    uint64_t rdi;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    if (ctx -> program_break == -1){ 
        uint64_t address = ctx -> init.user_bin.base;
        uc_mem_region *regions;
        int cnt;
        if (UC_ERR_CHECK(uc_mem_regions(uc, &regions, &cnt)) != UC_ERR_OK)
            return ;
        int flag = -1;
        for (int i = 0; i < cnt ; i++){
            if (regions[i].begin == address && flag == -1){
                flag = 1;
                address = regions[i].end + 1;
            }
            else if (flag){
                flag = regions[i].begin == address;
                address = regions[i].end + 1;
            }
        }
        if (flag != -1)
            ctx -> program_break = address;
        else 
            ctx -> program_break = -2;
    }
    else if (ctx -> program_break == -2){
        failure("emul: brk(0x%lx) == 0xffffffffffffffff", rdi);
        return ;
    }
    success("emul: brk(0x%lx)", rdi);
    if (rdi == 0)
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ctx -> program_break));
    else{
        uint64_t exp = rdi - ctx -> program_break;
        if (exp > MAPPING_LIMIT)
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
        else{
            if (UC_ERR_CHECK(uc_mem_map(uc, ctx -> program_break, exp, UC_PROT_READ | UC_PROT_WRITE)) != UC_ERR_OK){
                UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
                return ;
            }
            ctx -> program_break = rdi;
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &rdi));
        }
    }
}

void emu_sys_arch_prctl(uc_engine * uc){
    uint64_t rdi, rsi, tmp;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    success("emul: arch_prctl(0x%lx, 0x%lx)", rdi, rsi);
    switch (rdi){
        case 0x1001: // ARCH_SET_GS
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_GS_BASE, &rsi));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0ULL}));
            break;

        case 0x1002: // ARCH_SET_FS
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &rsi));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0ULL}));
            break;

        case 0x1003: // ARCH_GET_FS
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_FS_BASE, &tmp));
            UC_ERR_CHECK(uc_mem_write(uc, rsi, &tmp, 8));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0ULL}));
            break;

        case 0x1004: // ARCH_GET_GS
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_GS_BASE, &tmp));
            UC_ERR_CHECK(uc_mem_write(uc, rsi, &tmp, 8));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0ULL}));
            break;

        default: 
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
            break;
    }
}

void emu_sys_writev(uc_engine *uc, struct emul_ctx * ctx){
    uint64_t rdi, rsi, rdx;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    if (rdi < FD_LIMIT){
        if ((ctx -> fd[rdi]) >> 16){
            struct iovec * iovec_list = malloc(rdx * sizeof(struct iovec));
            if (iovec_list){
                for (int i = 0; i < rdx; i++){
                    UC_ERR_CHECK(uc_mem_read(uc, rsi + i * sizeof(struct iovec), &iovec_list[i], sizeof(struct iovec)));
                    char * buf = malloc(iovec_list[i].iov_len);
                    if (!buf)
                        goto fail;
                    UC_ERR_CHECK(uc_mem_read(uc, (uint64_t)iovec_list[i].iov_base, buf, iovec_list[i].iov_len));
                    iovec_list[i].iov_base = buf;
                }
                success("emul: writev(fd=0x%lx, iovec=0x%lx, vlen=0x%lx)", rdi, rsi, rdx);
                writev(ctx -> fd[rdi]&0xffff, iovec_list, rdx);
                UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &rdx));
                for (int i = 0; i < rdx; i++)
                    free(iovec_list[i].iov_base);
                free(iovec_list);
                return ;
            }
        }
    }
    fail:
        failure("emul: writev(fd=0x%lx, iovec=0x%lx, vlen=0x%lx) == 0xffffffffffffffff", rdi, rsi, rdx);
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
}

void emu_sys_uname(uc_engine * uc){ // when vdso not supported (emulated) uname syscall used to get kernel info
    struct utsname uname;
    uint64_t rdi;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    strcpy(uname.sysname, "Linux");
    strcpy(uname.nodename, "WIN-XXXXXXXXX");
    strcpy(uname.release, "5.15.146.1-microsoft-standard-WSL2");
    strcpy(uname.version, "#1 SMP Thu Jan 11 04:09:03 UTC 2024");
    strcpy(uname.machine, "x86_64");
    UC_ERR_CHECK(uc_mem_write(uc, rdi, &uname, sizeof(struct utsname)));
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0ULL}));
    success("emul: sys_uname(0x%lx)",rdi);
}

char * get_filename(uc_engine * uc, uint64_t address){
    uint32_t i, len;
    i = 0x30;
    char * filename = malloc(i);
    if (filename){
        while (1){
            UC_ERR_CHECK(uc_mem_read(uc, address, filename, i));
            len = strlen(filename);
            if (len < i - 8)
                return filename;
            filename = realloc(filename, i * 2);
            i *= 2;
        }
    }
    return NULL;
}

void emu_sys_openat(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t rdi, rsi, rdx, r10;
    uint32_t fd;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_R10, &r10));
    char * filename = get_filename(uc, rsi);
    if (filename == NULL)
        goto fail;
    if (rdi != 0xffffff9c && rdi < FD_LIMIT){
        if ((ctx -> fd[rdi]) >> 16)
            fd = openat(ctx -> fd[rdi] & 0xffff, filename, rdx, r10);
        else
            goto fail;
    }
    else
        fd = openat(0xffffff9c, filename, rdx, r10);

    if (fd > 0xffff){
        failure("File descriptor exceed 0xffff");
        goto fail;
    }
    if (ctx -> fd_cur + 1 > FD_LIMIT){
        failure("ctx -> fd_cnt > FD_LIMIT");
        goto fail;
    }
    ctx -> fd[ctx -> fd_cur] = fd;
    ctx -> fd[ctx -> fd_cur] |= 0x1 << 16;
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ctx -> fd_cur));
    ctx -> fd_cur += 1;
    success("emul: sys_openat(0x%lx, \"%s\", 0x%lx, 0x%lx)", rdi, filename, rdx, r10);
    free(filename);
    return ;
    fail:
        free(filename); // file can be null ptr. but fine
        failure("emul: sys_openat(0x%lx, \"%s\", 0x%lx, 0x%lx) == 0xffffffffffffffff", rdi, filename, rdx, r10);
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
}

void emu_sys_read(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t rdi, rsi, rdx;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    if (rdi < FD_LIMIT){
        if ((ctx -> fd[rdi]) >> 16){
            char * buf = malloc(rdx);
            if (buf != NULL){
                uint64_t ret = read(ctx -> fd[rdi], buf, rdx);
                UC_ERR_CHECK(uc_mem_write(uc, rsi, buf, rdx));
                UC_ERR_CHECK(uc_reg_write(uc, X86_REG_RAX, &ret));
                success("emul: sys_read(0x%lx, 0x%lx, 0x%lx)", rdi, rsi, rdx);
                return ;
            }
        }
    }
    failure("emul: sys_read(0x%lx, 0x%lx, 0x%lx) == 0xffffffffffffffff", rdi, rsi, rdx);
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
}

void emu_sys_access(uc_engine * uc){
    uint64_t rdi, rsi;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    char * filename = get_filename(uc, rdi);
    if (filename == NULL)
        goto fail;
    int64_t ret = (int64_t)access(filename, rsi);
    if (ret < 0)
        goto fail;
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ret));
    success("emul: sys_access(\"%s\", 0x%lx)", filename, rsi);
    free(filename);
    return ;
    fail:
        failure("emul: sys_access(\"%s\", 0x%lx) == 0xffffffffffffffff", filename, rsi);
        free(filename); // file can be null ptr. but fine
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
}

void emu_sys_newfstatat(uc_engine * uc, struct emul_ctx * ctx){
    uint64_t rdi, rsi, rdx, r10;
    uint64_t ret;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_R10, &r10));
    char * filename = get_filename(uc, rsi);
    struct stat * st = (struct stat * )malloc(sizeof(struct stat));
    if (filename == NULL)
        goto fail;
    if (rdi != 0xffffff9c && rdi < FD_LIMIT){
        if ((ctx -> fd[rdi]) >> 16)
            ret = fstatat(ctx -> fd[rdi] & 0xffff, filename, st, r10);
        else
            goto fail;
    }
    else
        ret = fstatat(0xffffff9c, filename, st, r10);
    if (ret != 0)
        goto fail;
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ret));
    UC_ERR_CHECK(uc_mem_write(uc, rdx, st, sizeof(struct stat)));
    success("emul: sys_newfstatat(0x%lx, \"%s\", 0x%lx, 0x%lx)", rdi, filename, rdx, r10);
    free(filename);
    free(st);
    return ;
    fail:
        failure("emul: sys_newfstatat(0x%lx, \"%s\", 0x%lx, 0x%lx) == 0xffffffffffffffff", rdi, filename, rdx, r10);
        free(filename); // file can be null ptr. but fine
        free(st);
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffffULL}));
}