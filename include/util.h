#ifndef _UTIL_H
#define _UTIL_H
#include "common.h"
void failure(char * s);
char * parse_string_offset(int fd, uint64_t off);
size_t get_size(int fd);
int success(const char *format, ...);
void hexdump(uint64_t * s, int size);
#endif 