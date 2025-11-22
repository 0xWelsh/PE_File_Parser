// pe_parser.c
// Compile: gcc -Wall -O2 pe_parser.c -o pe_parser
// Usage: ./pe_parser target.exe

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PACKED __attribute__((packed))

typedef struct PACKED {
    uint16_t e_magic;      // "MZ"
    uint8_t  e_cblp[58];
    uint32_t e_lfanew;     // Offset to PE header
} IMAGE_DOS_HEADER;

typedef struct PACKED {
    uint32_t Signature;           // "PE\0\0"
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct PACKED {
    uint16_t Magic;
} IMAGE_OPTIONAL_HEADER;

#define IMAGE_NT_SIGNATURE          0x00004550  // "PE\0\0"
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x010b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020b

#define MAX_SECTIONS 96
#define IMAGE_SIZEOF_SECTION_HEADER 40

int parse_pe(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        perror("fstat");
        fclose(f);
        return -1;
    }
    size_t file_size = st.st_size;

    if (file_size == 0) {
        fprintf(stderr, "File is empty\n");
        fclose(f);
        return -1;
    }

    uint8_t* data = malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(f);
        return -1;
    }

    if (fread(data, 1, file_size, f) != file_size) {
        fprintf(stderr, "fread failed\n");
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);

    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "File too small for DOS header\n");
        free(data);
        return -1;
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != 0x5A4D) { // 'M' = 0x4D, 'Z' = 0x5A → little-endian: 0x5A4D
        fprintf(stderr, "Invalid DOS header (not MZ)\n");
        free(data);
        return -1;
    }

    uint32_t pe_offset = dos->e_lfanew;
    if (pe_offset == 0 || pe_offset > file_size - 4) {
        fprintf(stderr, "Invalid e_lfanew offset\n");
        free(data);
        return -1;
    }

    uint32_t sig = *(uint32_t*)(data + pe_offset);
    if (sig != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE signature (expected 'PE\\0\\0')\n");
        free(data);
        return -1;
    }

    if (pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) > file_size) {
        fprintf(stderr, "File too small for PE file header\n");
        free(data);
        return -1;
    }

    IMAGE_FILE_HEADER* file_hdr = (IMAGE_FILE_HEADER*)(data + pe_offset + 4);
    printf("Machine: 0x%04x\n", file_hdr->Machine);
    printf("Sections: %u\n", file_hdr->NumberOfSections);

    if (file_hdr->NumberOfSections > MAX_SECTIONS) {
        fprintf(stderr, "Suspicious number of sections (%u)\n", file_hdr->NumberOfSections);
        free(data);
        return -1;
    }

    uint32_t opt_hdr_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (opt_hdr_offset + 2 > file_size) {
        fprintf(stderr, "Optional header out of bounds\n");
        free(data);
        return -1;
    }

    IMAGE_OPTIONAL_HEADER* opt_hdr = (IMAGE_OPTIONAL_HEADER*)(data + opt_hdr_offset);
    if (opt_hdr->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("PE format: PE32\n");
    } else if (opt_hdr->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("PE format: PE32+\n");
    } else {
        printf("Unknown PE optional header magic: 0x%04x\n", opt_hdr->Magic);
    }

    uint32_t sec_offset = opt_hdr_offset + file_hdr->SizeOfOptionalHeader;
    size_t sec_table_size = (size_t)file_hdr->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

    if (sec_offset > file_size || sec_table_size > file_size - sec_offset) {
        fprintf(stderr, "Section headers exceed file bounds\n");
        free(data);
        return -1;
    }

    printf("\nSections:\n");
    for (int i = 0; i < file_hdr->NumberOfSections; i++) {
        uint8_t* sec = data + sec_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
        char name[9];
        memcpy(name, sec, 8);
        name[8] = '\0';

        // Manually read fields to avoid alignment issues (though PACKED should handle it)
        uint32_t virt_size   = *(uint32_t*)(sec + 8);
        uint32_t virt_addr   = *(uint32_t*)(sec + 12);
        uint32_t raw_size    = *(uint32_t*)(sec + 16);

        printf("  [%02d] %-8s  VA=0x%08x  VSz=0x%08x  RSz=0x%08x\n",
               i, name, virt_addr, virt_size, raw_size);
    }

    free(data);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }
    return parse_pe(argv[1]);
}