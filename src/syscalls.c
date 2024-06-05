#include "../include/syscalls.h"
void handle_syscall(uc_engine * uc, uint64_t rax, struct emul_ctx * ctx){
    switch (rax){
        case 0x01:
            emu_sys_write(uc);
            break;
        
        case 0x0c:
            emu_sys_brk(uc, ctx);
            break;
            
        case 0x3c:
            success("emul: exit()");
            UC_ERR_CHECK(uc_emu_stop(uc));
            break;

        default:
            uint64_t rdi, rsi, rdx;
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rsi));
            UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdx));
            success("emul: syscall(rax=0x%lx, rdi=0x%lx, rsi=0x%lx, rdx=0x%lx)", rax, rdi, rsi, rdx);
            break;
    }
}


void emu_sys_write(uc_engine * uc){
    uint64_t rdi, rsi, rdx;
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDI, &rdi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RSI, &rsi));
    UC_ERR_CHECK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    char * buf = malloc(rdx+1);
    if (buf){
        UC_ERR_CHECK(uc_mem_read(uc, rsi, buf, rdx));
        success("emul: write(fd=%ld, buf=\"%s\", count=%ld)", rdi, buf, rdx);
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &rdx));
        free(buf);
    }
    else{
        failure("emul: write() == 0xffffffffffffffff");
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffff}));
    }
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
    if (rdi == 0)
        UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &ctx -> program_break));
    else{
        uint64_t exp = rdi - ctx -> program_break;
        if (exp > MEM_LIMIT)
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

