// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

typedef UINT64 Elf64_Addr;
typedef UINT16 Elf64_Half;
typedef UINT64 Elf64_Off;
typedef UINT64 Elf64_Sword;
typedef UINT32 Elf64_Word;
typedef UINT64 Elf64_Xword;
typedef UINT64 Elf64_Sxword;
typedef UINT8 Elf_Byte;

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word sh_name;
    Elf64_Word sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word sh_link;
    Elf64_Word sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;

#define SHT_RELA 4

typedef struct {
    Elf64_Addr r_offset;
    Elf64_Xword r_info;
    Elf64_Sxword r_addend;
} Elf64_Rela;

#define R_X86_64_RELATIVE 8

typedef struct {
    Elf64_Word st_name;
    Elf_Byte st_info;
    Elf_Byte st_other;
    Elf64_Half st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
} Elf64_Sym;

#define ELF_ST_TYPE(info)   ((uint32_t)(info) & 0xf)
#define STT_FUNC            2
#define SHN_UNDEF           0
#define SHT_SYMTAB          2
#define SHT_STRTAB          3

static BOOLEAN
RelocateSection(PUINT8 ElfImage, Elf64_Shdr* SectionHeader, UINT64 RelocationAddr)
{
    Elf64_Rela *CurRela;

    if (SectionHeader->sh_entsize == 0) {
        return FALSE;
    }

    for (UINT64 i = 0; i < SectionHeader->sh_size / SectionHeader->sh_entsize; i++) {
        CurRela = (Elf64_Rela*)(ElfImage + SectionHeader->sh_addr + i * SectionHeader->sh_entsize);
        if (CurRela->r_info == R_X86_64_RELATIVE) {
            *(UINT64 *)(ElfImage + CurRela->r_offset) = RelocationAddr + CurRela->r_addend;
        } else {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
RelocateElf(PUINT8 ElfImage, SIZE_T ElfSize, UINT64 RelocationAddr)
{
    Elf64_Ehdr *ElfHeader = (Elf64_Ehdr*)ElfImage;
    Elf64_Shdr *CurSheader;
    BOOLEAN Success;

    if ((UINT8 *)(ElfHeader + 1) > (ElfImage + ElfSize)) {
        FATAL("ELF header goes beyond ELF image");
    }

    for (UINT32 i = 0; i < ElfHeader->e_shnum; i++) {
        CurSheader = (Elf64_Shdr*)(ElfImage + ElfHeader->e_shoff + (UINT64)i * ElfHeader->e_shentsize);

        if ((UINT8 *)(CurSheader + 1) > (ElfImage + ElfSize)) {
            FATAL("ELF section header goes beyond ELF image");
        }

        if (CurSheader->sh_type == SHT_RELA) {
            Success = RelocateSection(ElfImage, CurSheader, RelocationAddr);
            if (!Success) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

UINT64
GetElfEntryPoint(PUINT8 ElfImage, SIZE_T ElfSize)
{
    Elf64_Ehdr *ElfHeader = (Elf64_Ehdr*)ElfImage;

    if ((UINT8 *)(ElfHeader + 1) > (ElfImage + ElfSize)) {
        FATAL("ELF header goes beyond ELF image");
    }

    return ElfHeader->e_entry;
}

UINT64
GetElfSymbolOffset(PUINT8 ElfImage, SIZE_T ElfSize, CHAR *SymbolName)
{
    Elf64_Ehdr *ElfHeader = (Elf64_Ehdr*)ElfImage;
    Elf64_Shdr *Shdr = NULL;
    Elf64_Sym *SymTab;
    Elf64_Sym *Sym;
    SIZE_T SymCount;
    SIZE_T i, j;
    CHAR *StrTab;
    SIZE_T StrSize;
    CHAR *Buf;

    if ((UINT8 *)(ElfHeader + 1) > (ElfImage + ElfSize)) {
        FATAL("ELF header goes beyond ELF image");
    }

    // Locate the symbol table.
    for (i = 0; i < ElfHeader->e_shnum; i++) {
        Shdr = (Elf64_Shdr *)(ElfImage + ElfHeader->e_shoff + (UINT64)i * ElfHeader->e_shentsize);
        if (Shdr->sh_type == SHT_SYMTAB) {
            break;
        }
    }
    if (i == ElfHeader->e_shnum) {
        FATAL("GetElfSymbolOffset: symtab not found");
    }
    if (Shdr->sh_offset == 0) {
        FATAL("GetElfSymbolOffset: symtab not loaded");
    }
    SymTab = (Elf64_Sym *)((uint8_t *)ElfHeader + Shdr->sh_offset);
    SymCount = Shdr->sh_size / sizeof(Elf64_Sym);

    // Also locate the string table
    j = Shdr->sh_link;
    if (j == SHN_UNDEF || j >= ElfHeader->e_shnum) {
        FATAL("GetElfSymbolOffset: wrong strtab index");
    }
    Shdr = (Elf64_Shdr*)(ElfImage + ElfHeader->e_shoff + (UINT64)j * ElfHeader->e_shentsize);
    if (Shdr->sh_type != SHT_STRTAB) {
        FATAL("GetElfSymbolOffset: wrong strtab type");
    }
    if (Shdr->sh_offset == 0) {
        FATAL("GetElfSymbolOffset: strtab not loaded");
    }
    StrTab = (CHAR *)((UINT8 *)ElfHeader + Shdr->sh_offset);
    StrSize = Shdr->sh_size;

    // Look for the symbol.
    for (i = 0; i < SymCount; i++) {
        Sym = &SymTab[i];

        if (Sym->st_name == 0) {
            continue;
        }
        if (Sym->st_shndx == SHN_UNDEF) {
            // Skip external references
            continue;
        }
        Buf = StrTab + Sym->st_name;

        if (!strcmp(Buf, SymbolName)) {
            return (UINT64)Sym->st_value;
        }
    }

    return 0;
}
