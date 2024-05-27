#include "emul.h"

int emul_load(uc_engine * uc, int fd, uint64_t address){
    size_t size = get_size(fd);
    uint64_t vaddr, align, memsz, offset,flags,filesz, sz, addr;
    uint16_t phnum, shnum;
    Elf64_Phdr * phdrs = NULL;
    Elf64_Shdr * shdrs;
    Elf64_Shdr * shstrs = NULL;
    uint8_t * data = malloc(size);
    if (read(fd, data, size) < 0)
        error("emul_load() -> read() failed");
    parse_elf(data, &phdrs, &shdrs, &shstrs, &phnum, &shnum);
    if (!phdrs)
        error("emul_load() -> phdrs == 0");
    if (!shdrs)
        error("emul_load() -> shdrs == 0");
    for (int i=0; i<phnum; i++){
        if (phdrs[i].p_type == PT_LOAD){
            vaddr = phdrs[i].p_vaddr;
            offset = phdrs[i].p_offset;
            align = phdrs[i].p_align;
            memsz = phdrs[i].p_memsz;
            filesz = phdrs[i].p_filesz;
            flags = phdrs[i].p_flags;
            sz = align*(((align/memsz))+1); // fix size
            addr = (address+vaddr);
            success("Mapping Memory [%lx ~ %lx (%lx)] FLAGS=%lx", addr,addr+sz,sz, flags);
            uint32_t uc_flags = 0;
            if (flags & PF_R)
                uc_flags |= UC_PROT_READ;
            if (flags & PF_W)
                uc_flags |= UC_PROT_WRITE;
            if (flags & PF_X)
                uc_flags |= UC_PROT_EXEC;
            uc_err err =uc_mem_map(uc, addr, sz, uc_flags);
            printf("%s\n",uc_strerror(err));
            if (err)
                error("emul_load() -> uc_mem_map()");
        }
    }
}

//   LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
//                  0x0000000000000c48 0x0000000000000c48  R      0x1000
//   LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
//                  0x0000000000000f39 0x0000000000000f39  R E    0x1000
//   LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
//                  0x000000000000053c 0x000000000000053c  R      0x1000
//   LOAD           0x0000000000002ce8 0x0000000000003ce8 0x0000000000003ce8
//                  0x0000000000000328 0x0000000000000368  RW     0x1000
//   DYNAMIC        0x0000000000002cf8 0x0000000000003cf8 0x0000000000003cf8


//    02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
//    03     .init .plt .plt.got .plt.sec .text .fini 
//    04     .rodata .eh_frame_hdr .eh_frame 
//    05     .init_array .fini_array .dynamic .got .data .bss 
//    06     .dynamic 