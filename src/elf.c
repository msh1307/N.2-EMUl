#include "elf.h"
int load_elf(char * filename, void * bin){
    int cnt;
    int mode;
    int elfclass = 0;
    Elf_Scn *scn = NULL;
    Elf64_Phdr *phdr = NULL;
    int fd = open(filename, O_RDONLY);
    if (elf_version(EV_CURRENT) == EV_NONE) 
        error("ELF init failed.");
    size_t size = get_size(fd);
    Elf * elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL)
        error("elf_begin() failed.");
    if ((elfclass = gelf_getclass(elf)) == ELFCLASSNONE) 
        error("gelf_getclass() failed.");
    if (elfclass == ELFCLASS32){
        puts("ELF file is 32-bit.");
        mode = MODE_32;
    }
    else if (elfclass == ELFCLASS64){
        puts("ELF file is 64-bit.");
        mode = MODE_64;
    }
    else 
        error("Unknown ELF class.");
    if (elf_getphdrnum(elf,&cnt) != 0)
        error("elf_getphdrnum() failed.");
    if (mode == MODE_64){
        for (int i = 0; i < cnt; i++){
            if((phdr = elf64_getphdr(elf)) == NULL)
                error("elf64_getphdr() failed.");
            if (phdr->p_type == PT_INTERP){
                char * loader_path = parse_string_offset(fd, phdr->p_vaddr);
                if (loader_path == NULL)
                    error("parse_string_offset() failed.");
                puts(loader_path);
            }
        }
    }

}