# zasm

Multi-target assembler, disassembler, and linker.

This is my experimental playground for a non-LLVM Zig backend.

## Status

This project has only just begun. There is nothing to see here yet.

## Planned Targets

### Architectures

All of them.

No matter how insignificant the architecture, provided it has reached some kind
of stable release that includes a specification, it is in scope.

### Object File Formats

 * ELF
 * COFF
 * MACH-O
 * WebAssembly

### Executable File Formats

 * ELF
 * PE (Portable Executable) (Windows)
 * WebAssembly

### Debug Info Formats

 * DWARF
 * PDB

## Roadmap

 * Hello world aarch64 assembly
 * Hello world x86_64 assembly split across 2 files
 * Hello world i386 assembly
 * Tests
 * Symbol table
 * DWARF Debug Info
 * Support more instructions
 * Build objects
 * Link objects
 * Incremental linking
