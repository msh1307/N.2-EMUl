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
            uc_emu_stop(uc);
            break;

        default:
            uint64_t rdi = uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
            uint64_t rsi = uc_reg_read(uc, UC_X86_REG_RDI, &rsi);
            uint64_t rdx = uc_reg_read(uc, UC_X86_REG_RDI, &rdx);
            success("emul: syscall(rax=0x%lx, rdi=0x%lx, rsi=0x%lx, rdx=0x%lx)", rax, rdi, rsi, rdx);
            break;
    }
}


void emu_sys_write(uc_engine * uc){
    uint64_t rdi, rsi, rdx;
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    char * buf = malloc(rdx+1);
    if (buf){
        uc_mem_read(uc, rsi, buf, rdx);
        success("emul: write(fd=%ld, buf=\"%s\", count=%ld)", rdi, buf, rdx);
        uc_reg_write(uc, UC_X86_REG_RAX, &rdx);
        free(buf);
    }
    else{
        failure("emul: write() == 0xffffffffffffffff");
        uc_reg_write(uc, UC_X86_REG_RAX, &(uint64_t){0xffffffffffffffff});
    }
}
void emu_sys_brk(uc_engine * uc, struct emul_ctx * ctx){ // brk implementation with a fixed program break 
    uint64_t rdi;
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    success("program break: 0x%lx", ctx -> program_break);
}

