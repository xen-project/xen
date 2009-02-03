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

multiboot_info_t *reloc(multiboot_info_t *mbi_old)
{
    multiboot_info_t *mbi = reloc_mbi_struct(mbi_old, sizeof(*mbi));

    if ( mbi->flags & MBI_CMDLINE )
    {
        char *cmdline_old, *p;
        cmdline_old = (char *)mbi->cmdline;
        for ( p = cmdline_old; *p != '\0'; p++ )
            continue;
        mbi->cmdline = (u32)reloc_mbi_struct(cmdline_old, p - cmdline_old + 1);
    }

    if ( mbi->flags & MBI_MODULES )
        mbi->mods_addr = (u32)reloc_mbi_struct(
            (module_t *)mbi->mods_addr, mbi->mods_count * sizeof(module_t));

    if ( mbi->flags & MBI_MEMMAP )
        mbi->mmap_addr = (u32)reloc_mbi_struct(
            (memory_map_t *)mbi->mmap_addr, mbi->mmap_length);

    /* Mask features we don't understand or don't relocate. */
    mbi->flags &= (MBI_MEMLIMITS |
                   MBI_DRIVES |
                   MBI_CMDLINE |
                   MBI_MODULES |
                   MBI_MEMMAP);

    return mbi;
}
