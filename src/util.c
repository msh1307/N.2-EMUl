#include "util.h"
int error(char * s){
    fprintf(stderr, "err: %s", s);
    putchar(0xa);
    exit(1);
}
size_t get_size(int fd){
    size_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    return sz; 
}
char * parse_string_offset (int fd, uint64_t off){
    char c;
    char * buf = malloc(0x50);
    lseek(fd, off, SEEK_SET);
    for (int i=0; i< 0x50; i++){
        if (read(fd, &c, 1) != 1)
            error("parse_string_offset() -> read() failed.");
        if (c != 0x0){
            buf[i] = c;
        }
        else{
            return buf;
        }
    }
    return NULL;
}