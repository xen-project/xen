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

#include <xen/const.h>

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

#include <xen/stdint.h>

/* The symbol table for a.out.  */
struct aout_symbol_table {
    uint32_t tabsize;
    uint32_t strsize;
    uint32_t addr;
    uint32_t reserved;
};
typedef struct aout_symbol_table aout_symbol_table_t;

/* The section header table for ELF.  */
struct elf_section_header_table {
    uint32_t num;
    uint32_t size;
    uint32_t addr;
    uint32_t shndx;
};
typedef struct elf_section_header_table elf_section_header_table_t;

/* The Multiboot information.  */
struct multiboot_info {
    uint32_t flags;

    /* Valid if flags sets MBI_MEMLIMITS */
    uint32_t mem_lower;
    uint32_t mem_upper;

    /* Valid if flags sets MBI_BOOTDEV */
    uint32_t boot_device;

    /* Valid if flags sets MBI_CMDLINE */
    uint32_t cmdline;

    /* Valid if flags sets MBI_MODULES */
    uint32_t mods_count;
    uint32_t mods_addr;

    /* Valid if flags sets ... */
    union {
        aout_symbol_table_t aout_sym;        /* ... MBI_AOUT_SYMS */
        elf_section_header_table_t elf_sec;  /* ... MBI_ELF_SYMS */
    } u;

    /* Valid if flags sets MBI_MEMMAP */
    uint32_t mmap_length;
    uint32_t mmap_addr;

    /* Valid if flags sets MBI_DRIVES */
    uint32_t drives_length;
    uint32_t drives_addr;

    /* Valid if flags sets MBI_BIOSCONFIG */
    uint32_t config_table;

    /* Valid if flags sets MBI_LOADERNAME */
    uint32_t boot_loader_name;

    /* Valid if flags sets MBI_APM */
    uint32_t apm_table;
};
typedef struct multiboot_info multiboot_info_t;

/* The module structure.  */
struct module {
    uint32_t mod_start;
    uint32_t mod_end;
    uint32_t string;
    uint32_t reserved;
};
typedef struct module module_t;

/* The memory map. Be careful that the offset 0 is base_addr_low
   but no size.  */
struct memory_map {
    uint32_t size;
    uint32_t base_addr_low;
    uint32_t base_addr_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;
};
typedef struct memory_map memory_map_t;


#endif /* __ASSEMBLY__ */

#endif /* __MULTIBOOT_H__ */
