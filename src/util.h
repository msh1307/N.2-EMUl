#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
int error(char * s);
char * parse_string_offset(int fd, uint64_t off);
int get_size(int fd);