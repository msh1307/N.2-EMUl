#ifndef SYSCALLS_H
#define SYSCALLS_H
#include "libs.h"
#include "util.h"
void emu_sys_write(uc_engine * uc, uint64_t rdi, uint64_t rsi, uint64_t rdx);
void handle_syscall(uc_engine * uc, uint64_t rax, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9);
#endif