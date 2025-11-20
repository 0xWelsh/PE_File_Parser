## KEY FEATURES
PE Parser can be used to extract features from portable executable files in
one of the following two formats:
1. hexadecimal representation of its binary content. this representation
 represents the machine code as a sequence of hexadecimal values.

the first value indicates the starting address of the machine codes in the
memory, and each hexadecimal value (byte) carries meaningful information
of the Portable Executable file such as instruction codes and data.

there are various tools to obtain the hexadecimal view of a binary file
such as PE explorer, HxD, among others

2. Assembly language source code. the assembly language source code contains
the symbolic machine code of the executable as well as metadata information
such as rudimentary function calls, memory allocation and variable information

there are various tools for disassembling Portable Executable files such as
IDA pro, radare2, ghidra, cutter

---

these file formats are the ones commonly used during static analysis to extract
features from executables without actually running the program.

