#ifndef _COMMON_H
#define _COMMON_H
#include <libelf.h>
#include <gelf.h>
#include <elf.h>
#include <unicorn/unicorn.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <capstone/capstone.h> 
static uc_err _uc_err_check(uc_err err, const char* expr)
{
    if (err) {
        fprintf(stderr, "Failed on %s with error: %s\n", expr, uc_strerror(err)); exit(1);
    }
    return err;
}
#define UC_ERR_CHECK(x) _uc_err_check(x, #x)
#endif 