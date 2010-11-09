/******************************************************************************
 * reloc.c
 * 
 * 32-bit flat memory-map routines for relocating Multiboot structures
 * and modules. This is most easily done early with paging disabled.
 * 
 * Copyright (c) 2009, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
 */

asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    mov  $_start,%edi             \n"
    "    call 1f                       \n"
    "1:  pop  %esi                     \n"
    "    sub  $1b-_start,%esi          \n"
    "    mov  $__bss_start-_start,%ecx \n"
    "    rep  movsb                    \n"
    "    xor  %eax,%eax                \n"
    "    mov  $_end,%ecx               \n"
    "    sub  %edi,%ecx                \n"
    "    rep  stosb                    \n"
    "    mov  $reloc,%eax              \n"
    "    jmp  *%eax                    \n"
    );

typedef unsigned int u32;
#include "../../../include/xen/multiboot.h"

extern char _start[];

static void *memcpy(void *dest, const void *src, unsigned int n)
{
    char *s = (char *)src, *d = dest;
    while ( n-- )
        *d++ = *s++;
    return dest;
}

static void *reloc_mbi_struct(void *old, unsigned int bytes)
{
    static void *alloc = &_start;
    alloc = (void *)(((unsigned long)alloc - bytes) & ~15ul);
    return memcpy(alloc, old, bytes);
}

static char *reloc_mbi_string(char *old)
{
    char *p;
    for ( p = old; *p != '\0'; p++ )
        continue;
    return reloc_mbi_struct(old, p - old + 1);
}

multiboot_info_t *reloc(multiboot_info_t *mbi_old)
{
    multiboot_info_t *mbi = reloc_mbi_struct(mbi_old, sizeof(*mbi));
    int i;

    if ( mbi->flags & MBI_CMDLINE )
        mbi->cmdline = (u32)reloc_mbi_string((char *)mbi->cmdline);

    if ( mbi->flags & MBI_MODULES )
    {
        module_t *mods = reloc_mbi_struct(
            (module_t *)mbi->mods_addr, mbi->mods_count * sizeof(module_t));

        mbi->mods_addr = (u32)mods;

        for ( i = 0; i < mbi->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = (u32)reloc_mbi_string((char *)mods[i].string);
        }
    }

    if ( mbi->flags & MBI_MEMMAP )
        mbi->mmap_addr = (u32)reloc_mbi_struct(
            (memory_map_t *)mbi->mmap_addr, mbi->mmap_length);

    if ( mbi->flags & MBI_LOADERNAME )
        mbi->boot_loader_name = (u32)reloc_mbi_string(
            (char *)mbi->boot_loader_name);

    /* Mask features we don't understand or don't relocate. */
    mbi->flags &= (MBI_MEMLIMITS |
                   MBI_BOOTDEV |
                   MBI_CMDLINE |
                   MBI_MODULES |
                   MBI_MEMMAP |
                   MBI_LOADERNAME);

    return mbi;
}
