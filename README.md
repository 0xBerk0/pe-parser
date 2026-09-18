# pe-parser

A lightweight Windows PE (Portable Executable) file parser written in C. Designed to manually navigate the PE structure without relying on high-level parsing libraries — useful for understanding how Windows loads executables and how offensive tooling interacts with the PE format.

## What it parses

- **DOS Header** — `e_magic` (MZ signature), `e_lfanew` offset to NT Headers
- **NT Headers** — PE signature, Machine type, Timestamp
- **Optional Header** — Image Base, AddressOfEntryPoint, SizeOfImage
- **Section Headers** — name, virtual address, size, and which section contains the EntryPoint
- **Import Table** — all imported DLLs and the number of functions imported from each

## Output example

```
| MAGIC NUMBER          : 0x5A4D        (MZ)
| E_LFANEW              : 0x000000F8
| NT HEADERS LOCATION   : 0x00000...
| NT HEADERS SIGNATURE  : 0x00004550   (PE)
| MACHINE               : 0x8664       (x64)
| NUMBER OF SECTIONS    : 6
| TIMESTAMP             : 0x D4B2C1A
| OPT MAGIC             : 0x020B       (PE32+)
| IMAGE BASE            : 0x00007FF...
| ENTRY POINT           : 0x000219E0
| SIZE OF IMAGE         : 0x00054000

| SECTIONS:
|   [0] .text     VA: 0x00001000  Size: 0x0002A000  <- EntryPoint here
|   [1] .rdata    VA: 0x0002B000  Size: 0x00018000
|   [2] .data     VA: 0x00043000  Size: 0x00001000
|   [3] .pdata    VA: 0x00044000  Size: 0x00003000
|   [4] .rsrc     VA: 0x00047000  Size: 0x00009000
|   [5] .reloc    VA: 0x00050000  Size: 0x00002000

| IMPORTS:
|   ntdll.dll                       14 functions
|   KERNEL32.dll                    42 functions
|   USER32.dll                       8 functions
|   ...
```

## Build

**Requirements:** any C compiler targeting Windows x64.

### MinGW (cross-compile from Linux)
```bash
x86_64-w64-mingw32-gcc pe_parser.c -o pe_parser.exe
```

### MSVC (Windows)
```bash
cl.exe pe_parser.c /Fe:pe_parser.exe
```

### GCC (Windows / MSYS2)
```bash
gcc pe_parser.c -o pe_parser.exe
```

## Usage

```
pe_parser.exe <path_to_executable>
```

```bash
# Examples
pe_parser.exe C:\Windows\System32\cmd.exe
pe_parser.exe C:\Windows\System32\notepad.exe
pe_parser.exe .\target.exe
```

## PE Structure overview

```
+---------------------------+
|      DOS Header           |  e_magic = 0x5A4D ("MZ")
|      e_lfanew = 0xXX      |  offset to NT Headers
+---------------------------+
|      DOS Stub             |  "This program cannot be run in DOS mode"
+---------------------------+
|      NT Headers           |  Signature = 0x00004550 ("PE\0\0")
|        File Header        |  Machine, NumberOfSections, Timestamp
|        Optional Header    |  ImageBase, EntryPoint, SizeOfImage
+---------------------------+
|      Section Headers      |  .text, .rdata, .data, .rsrc, ...
+---------------------------+
|      Section Data         |
|        .text   (code)     |
|        .rdata  (imports,  |
|                 exports,  |
|                 strings)  |
|        .data              |
|        ...                |
+---------------------------+
```

## Relevance to offensive security

Understanding the PE format is fundamental to:
- **Shellcode loaders** — manually mapping a PE into memory (reflective loading)
- **Process injection** — parsing the target PE to find the correct memory regions
- **EDR evasion** — PE stomping, module stomping, and overwriting PE headers post-load
- **Implant development** — writing position-independent code and custom PE loaders
- **Malware analysis** — manually inspecting suspicious binaries without tools

## Roadmap

- [x] DOS Header parsing
- [x] NT Headers parsing
- [x] Section enumeration + EntryPoint location
- [x] Import Table (DLLs + function count)
- [ ] Export Table
- [ ] TLS Callbacks
- [ ] Base Relocations
- [ ] Rich Header
- [ ] Function-level import listing (by name and ordinal)
- [ ] PE32 (x86) support alongside PE32+


## License

For educational and authorised security research purposes only.