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
