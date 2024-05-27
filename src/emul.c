#include "emul.h"

int emul_load(uc_engine * uc, int fd, uint64_t address){
    size_t size = get_size(fd);
    uint16_t phnum, shnum;
    Elf64_Phdr * phdrs = NULL;
    Elf64_Shdr * shdrs;
    Elf64_Shdr * shstrs = NULL;
    uint8_t * data = malloc(size);
    if (read(fd, data, size) != size)
        error("emul_load() -> read() failed");
    parse_elf(data, &phdrs, &shdrs, &shstrs, &phnum, &shnum);
    if (!phdrs)
        error("emul_load() -> phdrs == 0");
    if (!shdrs)
        error("emul_load() -> shdrs == 0");
    uc_err err = emul_map_memory(uc, address, phdrs, phnum);
    if (err != UC_ERR_OK)
        error("emul_load() -> emul_map_memory()");
    err = emul_load_file(uc, address, data, phdrs, phnum);
    // if (err != UC_ERR_OK)
    //     error("emul_load() -> emul_load_file()");
    return 0;
}
uc_err emul_map_memory(uc_engine * uc, uint64_t base_address ,Elf64_Phdr * phdrs, uint16_t phnum){
    uint64_t vaddr, align, memsz, offset,flags,filesz, sz, addr;
    for (int i=0; i<phnum; i++){
        if (phdrs[i].p_type == PT_LOAD){
            vaddr = phdrs[i].p_vaddr;
            offset = phdrs[i].p_offset;
            align = phdrs[i].p_align;
            memsz = phdrs[i].p_memsz;
            filesz = phdrs[i].p_filesz;
            flags = phdrs[i].p_flags;
            sz = (((memsz-1) / align) + 1) * align;
            addr = (base_address+vaddr)&0xfffffffffffff000;
            success("Mapping Memory [%lx ~ %lx (%lx)] FileOffset=%lx FLAGS=%lx", addr,addr+sz,sz,offset,flags);
            uint32_t uc_flags = 0;
            if (flags & PF_R)
                uc_flags |= UC_PROT_READ;
            if (flags & PF_W)
                uc_flags |= UC_PROT_WRITE;
            if (flags & PF_X)
                uc_flags |= UC_PROT_EXEC;
            uc_err err = uc_mem_map(uc, addr, sz, uc_flags);
            if (err)
                return err;        
        }
    }
    return UC_ERR_OK;
}


uc_err emul_load_file(uc_engine * uc, uint64_t base_address, uint8_t * data ,Elf64_Phdr * phdrs, uint16_t phnum){
    for (int i=0; i<phnum; i++){
        switch (phdrs[i].p_type){
            case PT_LOAD:
                uint64_t address = base_address+phdrs[i].p_vaddr;
                uint64_t sz = phdrs[i].p_memsz;
                uc_err err = uc_mem_write(uc, address, data+phdrs[i].p_offset, sz);
                success("Writing Memory [%lx ~ %lx (%lx)]", address,address+sz,sz);
                if (err)
                    return err;
                break;
            default:
                break;
        }
    }
    return UC_ERR_OK;
}