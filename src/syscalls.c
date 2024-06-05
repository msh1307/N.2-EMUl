#include "../include/syscalls.h"
void handle_syscall(uc_engine * uc, uint64_t rax, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9){
    switch (rax){
        case 0x01:
            emu_sys_write(uc, rdi, rsi, rdx);
            break;
        
        case 0x0c:
            emu_sys_brk(uc, rdi);
            break;
            
        case 0x3c:
            success("emul: exit()");
            uc_emu_stop(uc);
            break;

        default:
            success("emul: syscall(rax=0x%lx, rdi=0x%lx, rsi=0x%lx, rdx=0x%lx)", rax, rdi, rsi, rdx);
            break;
    }
}


void emu_sys_write(uc_engine * uc, uint64_t rdi, uint64_t rsi, uint64_t rdx){
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


void emu_sys_brk(uc_engine * uc, uint64_t rdi){ // brk implementation with a fixed program break
    
}