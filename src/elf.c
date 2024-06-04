#include "elf.h"
char * get_interpreter(int fd, void * bin){
    size_t cnt;
    int elfclass = 0;
    char * loader_path = NULL;
    Elf_Scn *scn = NULL;
    Elf64_Phdr *phdr = NULL;
    if (elf_version(EV_CURRENT) == EV_NONE) 
        error("get_interpreter() -> elf_version() failed");
    size_t size = get_size(fd);
    Elf * elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL)
        error("get_interpreter() -> elf_begin() failed");
    if ((elfclass = gelf_getclass(elf)) == ELFCLASSNONE) 
        error("get_interpreter() -> gelf_getclass() failed");
    if (elfclass == ELFCLASS64){
        if (elf_getphdrnum(elf,&cnt) != 0)
            error("get_interpreter() -> elf_getphdrnum() failed");
        GElf_Phdr Phdr;
        for (int i = 0; i < cnt; i++){
            if((phdr = gelf_getphdr(elf,i,&Phdr)) == NULL)
                error("get_interpreter() -> elf64_getphdr() failed");
            if (phdr->p_type == PT_INTERP){
                loader_path = parse_string_offset(fd, phdr->p_vaddr);
                if (loader_path == NULL)
                    error("get_interpreter() -> parse_string_offset() failed");
            }
        }
    }
    else
        error("unsupported ELF class");
    if (!loader_path)
        return NULL;
    return loader_path;

}

void parse_elf(uint8_t *data, Elf64_Phdr **phdrs, Elf64_Shdr ** shdrs, Elf64_Shdr ** shstrs, uint16_t * phnum, uint16_t * shnum) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    Elf64_Off ph_offset = ehdr->e_phoff;
    if (ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
        success("Entry point address:               0x%lx", ehdr->e_entry);
        success("Number of program headers:         %d", ehdr->e_phnum);
        Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ph_offset);
        Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
        Elf64_Shdr *shstr = (Elf64_Shdr *)(data + ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx);
        *shdrs = shdr;
        *phdrs = phdr;
        *shstrs= shstr;
    }
    else 
        error("unsupported elf class");
    *phnum = ehdr->e_phnum;
    *shnum = ehdr->e_shnum;
}
