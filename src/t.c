#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>

void print_segment_info(Elf64_Phdr *program_header) {
    if (program_header->p_type == PT_LOAD){
        

    }

    printf("Segment type: ");
    switch (program_header->p_type) {
        case PT_NULL:    printf("NULL\n"); break;
        case PT_LOAD:    printf("LOAD\n"); break;
        case PT_DYNAMIC: printf("DYNAMIC\n"); break;
        case PT_INTERP:  printf("INTERP\n"); break;
        case PT_NOTE:    printf("NOTE\n"); break;
        case PT_SHLIB:   printf("SHLIB\n"); break;
        case PT_PHDR:    printf("PHDR\n"); break;
        case PT_TLS:     printf("TLS\n"); break;
        default:         printf("Other\n"); break;
    }

    printf("Segment flags: ");
    if (program_header->p_flags & PF_R) printf("Read ");
    if (program_header->p_flags & PF_W) printf("Write ");
    if (program_header->p_flags & PF_X) printf("Execute ");
    printf("\n");

    printf("Segment offset in file: %lu\n", program_header->p_offset);
    printf("Segment virtual address: %lu\n", program_header->p_vaddr);
    printf("Segment size in file: %lu\n", program_header->p_filesz);
    printf("Segment size in memory: %lu\n", program_header->p_memsz);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr elf_header;
    fread(&elf_header, 1, sizeof(Elf64_Ehdr), file);

    // ELF 파일의 Program Header 테이블로 이동
    fseek(file, elf_header.e_phoff, SEEK_SET);

    // Program Header 테이블의 엔트리 개수만큼 반복하여 각 세그먼트 정보 출력
    for (int i = 0; i < elf_header.e_phnum; ++i) {
        Elf64_Phdr program_header;
        fread(&program_header, 1, sizeof(Elf64_Phdr), file);

        // 세그먼트 정보 출력 함수 호출
        printf("Segment %d:\n", i);
        print_segment_info(&program_header);
        printf("\n");
    }

    fclose(file);
    return 0;
}

