#ifndef _SYSCALLS_H
#define _SYSCALLS_H
#include "emul.h"
#include "common.h"
#include "util.h"
void emu_sys_write(uc_engine * uc, struct emul_ctx * ctx);
void handle_syscall(uc_engine * uc, uint64_t rax, struct emul_ctx * ctx);
void emu_sys_brk(uc_engine * uc, struct emul_ctx * ctx);
void emu_sys_arch_prctl(uc_engine * uc);
void emu_sys_writev(uc_engine *uc, struct emul_ctx * ctx);
void emu_sys_uname(uc_engine * uc);
char * get_filename(uc_engine * uc, uint64_t address);
void emu_sys_openat(uc_engine * uc, struct emul_ctx * ctx);
void emu_sys_read(uc_engine * uc, struct emul_ctx * ctx);
void emu_sys_access(uc_engine * uc);
void emu_sys_newfstatat(uc_engine * uc, struct emul_ctx * ctx);
#endif