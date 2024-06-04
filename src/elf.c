#include "elf.h"
char * get_interpreter(int fd, void * bin){
    size_t cnt;
    int elfclass = 0;
    char * loader_path = NULL;
    Elf_Scn *scn = NULL;
    Elf64_Phdr *phdr = NULL;
    if (elf_version(EV_CURRENT) == EV_NONE){
        failure("get_interpreter() -> elf_version() failed");
        return NULL;
    }
    size_t size = get_size(fd);
    Elf * elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL){
        failure("get_interpreter() -> elf_begin() failed");
        return NULL;
    }
    if ((elfclass = gelf_getclass(elf)) == ELFCLASSNONE){
        failure("get_interpreter() -> gelf_getclass() failed");
        return NULL;
    }
    if (elfclass == ELFCLASS64){
        if (elf_getphdrnum(elf,&cnt) != 0){
            failure("get_interpreter() -> elf_getphdrnum() failed");
            return NULL;
        }
        GElf_Phdr Phdr;
        for (int i = 0; i < cnt; i++){
            if((phdr = gelf_getphdr(elf,i,&Phdr)) == NULL){
                failure("get_interpreter() -> elf64_getphdr() failed");
                return NULL;
            }
            if (phdr->p_type == PT_INTERP){
                loader_path = parse_string_offset(fd, phdr->p_vaddr);
                if (loader_path == NULL){
                    failure("get_interpreter() -> parse_string_offset() failed");
                    return NULL;
                }
            }
        }
    }
    else
        failure("unsupported ELF class");
    if (!loader_path)
        return NULL;
    return loader_path;

}

void parse_elf(uint8_t *data, Elf64_Phdr **phdrs, Elf64_Shdr ** shdrs, Elf64_Shdr ** shstrs, uint16_t * phnum, uint16_t * shnum, uint64_t * entry) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    Elf64_Off ph_offset = ehdr->e_phoff;
    if (ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
        *entry = ehdr->e_entry;
        Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ph_offset);
        Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
        Elf64_Shdr *shstr = (Elf64_Shdr *)(data + ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx);
        *shdrs = shdr;
        *phdrs = phdr;
        *shstrs = shstr;
    }
    else{
        failure("unsupported elf class");
        *phnum = 0;
        *shnum = 0;
        return ;
    }
    *phnum = ehdr->e_phnum;
    *shnum = ehdr->e_shnum;
}

