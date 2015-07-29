/* multiboot.h - the header for Multiboot */
/* Copyright (C) 1999, 2001  Free Software Foundation, Inc.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; If not, see <http://www.gnu.org/licenses/>.  */

#ifndef __MULTIBOOT_H__
#define __MULTIBOOT_H__

#include "const.h"

/*
 * Multiboot header structure.
 */
#define MULTIBOOT_HEADER_MAGIC         0x1BADB002
#define MULTIBOOT_HEADER_MODS_ALIGNED  0x00000001
#define MULTIBOOT_HEADER_WANT_MEMORY   0x00000002
#define MULTIBOOT_HEADER_HAS_VBE       0x00000004
#define MULTIBOOT_HEADER_HAS_ADDR      0x00010000

/* The magic number passed by a Multiboot-compliant boot loader. */
#define MULTIBOOT_BOOTLOADER_MAGIC     0x2BADB002

#define MBI_MEMLIMITS  (_AC(1,u) << 0)
#define MBI_BOOTDEV    (_AC(1,u) << 1)
#define MBI_CMDLINE    (_AC(1,u) << 2)
#define MBI_MODULES    (_AC(1,u) << 3)
#define MBI_AOUT_SYMS  (_AC(1,u) << 4)
#define MBI_ELF_SYMS   (_AC(1,u) << 5)
#define MBI_MEMMAP     (_AC(1,u) << 6)
#define MBI_DRIVES     (_AC(1,u) << 7)
#define MBI_BIOSCONFIG (_AC(1,u) << 8)
#define MBI_LOADERNAME (_AC(1,u) << 9)
#define MBI_APM        (_AC(1,u) << 10)

#ifndef __ASSEMBLY__

/* The symbol table for a.out.  */
typedef struct {
    u32 tabsize;
    u32 strsize;
    u32 addr;
    u32 reserved;
} aout_symbol_table_t;

/* The section header table for ELF.  */
typedef struct {
    u32 num;
    u32 size;
    u32 addr;
    u32 shndx;
} elf_section_header_table_t;

/* The Multiboot information.  */
typedef struct {
    u32 flags;

    /* Valid if flags sets MBI_MEMLIMITS */
    u32 mem_lower;
    u32 mem_upper;

    /* Valid if flags sets MBI_BOOTDEV */
    u32 boot_device;

    /* Valid if flags sets MBI_CMDLINE */
    u32 cmdline;

    /* Valid if flags sets MBI_MODULES */
    u32 mods_count;
    u32 mods_addr;

    /* Valid if flags sets ... */
    union {
        aout_symbol_table_t aout_sym;        /* ... MBI_AOUT_SYMS */
        elf_section_header_table_t elf_sec;  /* ... MBI_ELF_SYMS */
    } u;

    /* Valid if flags sets MBI_MEMMAP */
    u32 mmap_length;
    u32 mmap_addr;

    /* Valid if flags sets MBI_DRIVES */
    u32 drives_length;
    u32 drives_addr;

    /* Valid if flags sets MBI_BIOSCONFIG */
    u32 config_table;

    /* Valid if flags sets MBI_LOADERNAME */
    u32 boot_loader_name;

    /* Valid if flags sets MBI_APM */
    u32 apm_table;
} multiboot_info_t;

/* The module structure.  */
typedef struct {
    u32 mod_start;
    u32 mod_end;
    u32 string;
    u32 reserved;
} module_t;

/* The memory map. Be careful that the offset 0 is base_addr_low
   but no size.  */
typedef struct {
    u32 size;
    u32 base_addr_low;
    u32 base_addr_high;
    u32 length_low;
    u32 length_high;
    u32 type;
} memory_map_t;


#endif /* __ASSEMBLY__ */

#endif /* __MULTIBOOT_H__ */
