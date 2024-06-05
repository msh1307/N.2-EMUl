#ifndef _ELF1_H
#define _ELF1_H
#include "common.h"
#include "util.h"

char * get_interpreter(int fd, void * bin);
void parse_elf(uint8_t *data, Elf64_Phdr **phdrs, Elf64_Shdr ** shdrs, Elf64_Shdr ** shstrs, uint16_t * phnum, uint16_t * shnum, uint64_t * entry);

#endif 