#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
int error(char * s);
char * parse_string_offset(int fd, uint64_t off);
size_t get_size(int fd);
int success(const char *format, ...);