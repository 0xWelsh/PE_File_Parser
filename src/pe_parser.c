#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// windows headers
typedef struct {
    uint16_t e_magic;
    uint8_t e_cblp[58];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;


typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

typedef struct {
    uint16_t Magic;
    // we omit the rest for brevity - we only check Magic
} IMAGE_OPTIONAL_HEADER;

int parse_pe(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) { perror("fopen"); return -1; }

    struct stat st;
    if (fstat(fileno(f), &st) != 0) { perror("fstat"); fclose(f); return -1; }
    size_t size = st.st_size;

    uint8_t* data = malloc(size);
    if (!data) { perror("malloc"); fclose(f); return -1; }
    if (fread(data, 1, size, f) != size) { perror("fread"); free(data); fclose(f); return -1; }
    fclose(f);


    // DOS reader
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != 0x5A4D) { // "MZ"
        fprintf(stderr, "Invalid DOS header\n");
        free(data);
        return -1;
    }


    // NT headers
    uint32_t pe_offset = dos->e_lfanew;
    if (pe_offset >= size) { fprintf(stderr, "Invalid PE offset\n"); free(data); return -1; }

    uint32_t* pe_sig = (uint32_t*)(data + pe_offset);
    if (*pe_sig != 0x00004550) {
        fprintf(stderr, "Invalid PE signature\n");
        free(data);
        return -1;
    }

    IMAGE_FILE_HEADER* file_hdr = (IMAGE_FILE_HEADER*)(data + pe_offset + 4);
    printf("Machine: 0x%04x\n", file_hdr->Machine);
    printf("Sections: %u\n", file_hdr->NumberOfSections);

    // optional header (check 32 vs 64)
    IMAGE_OPTIONAL_HEADER* opt_hdr = (IMAGE_OPTIONAL_HEADER*)(data + pe_offset + 4 + sizeof(IMAGE_FILE_HEADER));
    if (opt_hdr->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("PE format: PE32\n");
    } else if (opt_hdr->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("Unknown PE optional header magic: 0x%04x\n", opt_hdr->Magic);
    }

    // section headers
    uint8_t* section_hdr = data + pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) + file_hdr->SizeOfOptionalHeader;
    for (int i = 0; i < file_hdr->NumberOfSections; i++) {
        char name[9];
        memcpy(name, section_hdr + i * 40, 8);
        name[8] = '\0';
        uint32_t va = *(uint32_t*)(section_hdr + i * 40 + 12);
        printf("Section %d: %s (RVA: 0x%08x)\n", i, name, va);
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