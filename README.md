# PE FILE PARSE
A lightweight and educational **Portable Executable file parser** built to
help beginners understand the internal structure of windows executable files
('.exe', '.dll')

This project parses the PE headers, section table, and important data 
directories without requiring windows.

It works fully on Linux


## FEATURES
Parse **MS-DOS Header** ('MZ' header)
Parse **PE Signature** and **NT Headers**
Parse **File Header** (machine type, number of sections, etc)
Parse **Optional Header** (entry point, image base, subsystem)
Parse **Section Table** ('.text', '.data', '.rdata', and more)
Extact:
	Import table (DLLs + Functions)
	Export table
	Data Directories
Works on Ubuntu, Kali, Arch, any linux
no windows environment required


## File loading & validation
```
// reads the entire file into memory
uint8_t* data = malloc(file_size);
fread(data, 1, file_size, f);
```
- loads the entire executable file into memory as raw bytes
- checks if the file exists and is accessible

## DOS header analysis
```
IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
if (dos->e_magic != 0x5A4D) { // 'MZ'
```
- checks for the "MZ" signature (0x5A4D) at the beginning
- this is the legacy DOS header that all PE files start with for backward compatibility
- extracts `e_lfanew` - the offset to the actual PE header

## PE Signature Verification
```
uint32_t sig = read_le32(data + pe_offset);
if (sig != IMAGE_NT_SIGNATURE) {
```
- jumps to the PE header location (specified by e_lfanew)
- verifies the "PE\0\0" signature (0x00004550)
- this confirms it's valid PE file

## PE File Header Parsing
```
uint16_t machine = read_le16(file_hdr_ptr + 0);
uint16_t num_sections = read_le16(file_hdr_ptr + 2);
```
extracts critical information from the COFF file header:
- Machine Type: what CPU architecture the file is for
	0x014C = i386(32-bit x86)
	0x8664 = x64 (64-bit)
	0x01C0 = ARM
	etc
- number of sections: how many code/data sections the file contains
- TimeDateStamp: when the file was compiled
- Characteristics: file attributes (EXE vs DLL, etc.)

## Optional Header Analysis
```
uint16_t opt_magic = read_le16(data + opt_hdr_offset);
```
- determines if it's a **32-bit** (0x010B) or **64-bit**(0x020B) PE file
- the "optional" header is actually required for executables and contains 
crucial loader information

## section table extraction
```
for (int i = 0; i < num_sections; i++) {
	uint8_t* sec = data + sec_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
}
``` 
- iterates through all sections in the file
- each person represents a chunk of code or data with specigic memory permissions

for each section, it displays:
- name (8-character padded name like ".text", ".data")
- virtual address (VA): where this section loads in memory
- virtual size (VSz): how much memory it occupies at runtime
- raw size (RSz): how much space it takes in the file on disk

## Real-World use cases:

**Malware Analysis**
```bash
./pe_parser suspicious_file.exe
```
- check for packed/obfuscated executables
- identify potentially malicious sections
- verify file integrity

## Reverse Engineering
```bash
./pe_parser target.dll
```
- understand the DLL's structure before analyzing
- locate code sections (.text) vs data sections (.data, .rdata)
- find import/export tables


## Software Development
- debug build outputs
- verify compiler/linker settings
- check if 32-bit vs 64-bit was built correctly

## Forensic analysis
- extract compilation timestamps
- identify compiler used
- verify file authenticity

**Example output interpretation**
```text
Machine: 0x014c           ← 32-bit x86 executable
Sections: 5               ← Reasonable number of sections
PE format: PE32           ← Confirmed 32-bit

Sections:
  [00] .text    VA=0x00001000  VSz=0x00005000  ← Code section (executable)
  [01] .data    VA=0x00006000  VSz=0x00001000  ← Data section (read/write)
  [02] .rdata   VA=0x00007000  VSz=0x00002000  ← Read-only data
  [03] .rsrc    VA=0x00009000  VSz=0x00003000  ← Resources (icons, strings)
  [04] .reloc   VA=0x0000c000  VSz=0x00001000  ← Relocation data
```

## Red Flags it can detect:
- **Suspicious Section names**: Names not typical for compilers
- **Too many Sections**: Normal files have 3 - 10 sections, malware often has more
- **Large Raw/Virtual Size Mismatches**: indicates packing
- **Invalid Offsets**: file corruption or manipulation 
