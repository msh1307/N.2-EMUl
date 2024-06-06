#include "../include/util.h"
void failure(char * s){
    fprintf(stderr, "[-] %s\n", s);
}

int success(const char *format, ...) {
    int l = strlen(format);
    char * buf = malloc(l+0x10);
    memset(buf, 0,l+0x10);
    strcpy(buf, "[+] ");
    strcat(buf, format);
    buf[l+4] = '\x0a';
    va_list args;
    va_start(args, format);
    int result = vfprintf(stdout, buf, args);
    va_end(args);
    free(buf);
    return result;
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
        if (read(fd, &c, 1) != 1){
            failure("parse_string_offset() -> read() failed");
            return NULL;
        }
        if (c != 0x0){
            buf[i] = c;
        }
        else{
            return buf;
        }
    }
    return NULL;
}

void hexdump(uint64_t * s, int size){
    for (int i = 0; i < size/8; i++){
        if (i % 0x2 == 0){
            putchar(0xa);
            // printf(" %04x | ", i*8);
        }
        printf("0x%016lx ", s[i]);
    }
    putchar(0xa);
    putchar(0xa);
}