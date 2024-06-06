#include "../include/syscalls.h"

void handle_syscall(uc_engine * uc, uint64_t rax, struct emul_ctx * ctx){
    switch (rax){
        case 0x01:
            emu_sys_write(uc, ctx);
            break;
        
        case 0x0c:
            emu_sys_brk(uc, ctx);
            break;

        case 0x14:
            emu_sys_writev(uc, ctx);
            break;
            
        case 0x3c:
            success("emul: exit()");
            UC_ERR_CHECK(uc_emu_stop(uc));
            break;

        case 0x9e:
            emu_arch_prctl(uc);
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
                write(ctx -> fd[rdi]&0xffff, buf, rdx);
                UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &rdx));
                free(buf);
                return ;
            }
        }
    }
    failure("emul: write() == 0xffffffffffffffff");
    UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffff}));
}

void emu_sys_brk(uc_engine * uc, struct emul_ctx * ctx){ // brk implementation with a fixed program break 
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
    else if (ctx -> program_break == -2)
        return ;
    uint64_t rdi;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    success("emul: brk(0x%lx)", rdi);
    if (rdi == 0)
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ctx -> program_break));
    else{
        uint64_t exp = rdi - ctx -> program_break;
        if (exp > MAPPING_LIMIT)
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffff}));
        else{
            if (UC_ERR_CHECK(uc_mem_map(uc, ctx -> program_break, exp, UC_PROT_READ | UC_PROT_WRITE)) != UC_ERR_OK){
                UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffff}));
                return ;
            }
            ctx -> program_break = rdi;
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &rdi));
        }
    }
}

void emu_arch_prctl(uc_engine * uc){
    uint64_t rdi, rsi, tmp;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    success("emul: arch_prctl(0x%lx, 0x%lx)", rdi, rsi);
    switch (rdi){
        case 0x1001: // ARCH_SET_GS
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_GS_BASE, &rsi));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0}));
            break;

        case 0x1002: // ARCH_SET_FS
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &rsi));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0}));
            break;

        case 0x1003: // ARCH_GET_FS
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_FS_BASE, &tmp));
            UC_ERR_CHECK(uc_mem_write(uc, rsi, &tmp, 8));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0}));
            break;

        case 0x1004: // ARCH_GET_GS
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_GS_BASE, &tmp));
            UC_ERR_CHECK(uc_mem_write(uc, rsi, &tmp, 8));
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0x0}));
            break;

        default: 
            UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffea}));
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
        failure("emul: writev() == 0xffffffffffffffff");
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffff}));
}