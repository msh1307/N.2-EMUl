#ifndef UTIL_H
#define UTIL_H
#include "libs.h"
void failure(char * s);
char * parse_string_offset(int fd, uint64_t off);
size_t get_size(int fd);
int success(const char *format, ...);
#endif 