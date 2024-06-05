#ifndef _SYSCALLS_H
#define _SYSCALLS_H
#include "emul.h"
#include "common.h"
#include "util.h"
void emu_sys_write(uc_engine * uc);
void handle_syscall(uc_engine * uc, uint64_t rax, struct emul_ctx * ctx);
void emu_sys_brk(uc_engine * uc, struct emul_ctx * ctx);
#endif