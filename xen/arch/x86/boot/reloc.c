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
        u32 max_addr = 0;

        mbi->mods_addr = (u32)mods;

        for ( i = 0; i < mbi->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = (u32)reloc_mbi_string((char *)mods[i].string);
            if ( mods[i].mod_end > max_addr )
                max_addr = mods[i].mod_end;
        }

        /*
         * 32-bit Xen only maps bottom 1GB of memory at boot time. Relocate 
         * modules which extend beyond this (GRUB2 in particular likes to 
         * place modules as high as possible below 4GB).
         */
#define BOOTMAP_END (1ul<<30) /* 1GB */
        if ( (XEN_BITSPERLONG == 32) && (max_addr > BOOTMAP_END) )
        {
            char *mod_alloc = (char *)BOOTMAP_END;
            for ( i = 0; i < mbi->mods_count; i++ )
                mod_alloc -= mods[i].mod_end - mods[i].mod_start;
            for ( i = 0; i < mbi->mods_count; i++ )
            {
                u32 mod_len = mods[i].mod_end - mods[i].mod_start;
                mods[i].mod_start = (u32)memcpy(
                    mod_alloc, (char *)mods[i].mod_start, mod_len);
                mods[i].mod_end = mods[i].mod_start + mod_len;
                mod_alloc += mod_len;
            }
        }
    }

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
