/*
 * reloc.c
 *
 * 32-bit flat memory-map routines for relocating Multiboot structures
 * and modules. This is most easily done early with paging disabled.
 *
 * Copyright (c) 2009, Citrix Systems, Inc.
 *
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

/* entered with %eax = BOOT_TRAMPOLINE */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    call 1f                       \n"
    "1:  pop  %ebx                     \n"
    "    mov  %eax,alloc-1b(%ebx)      \n"
    "    jmp  reloc                    \n"
    );

/*
 * This is our data. Because the code must be relocatable, no BSS is
 * allowed. All data is accessed PC-relative with inline assembly.
 */
asm (
    "alloc:                            \n"
    "    .long 0                       \n"
    );

typedef unsigned int u32;
#include "../../../include/xen/multiboot.h"

static void *reloc_mbi_struct(void *old, unsigned int bytes)
{
    void *new;
    asm(
    "    call 1f                      \n"
    "1:  pop  %%edx                   \n"
    "    mov  alloc-1b(%%edx),%0      \n"
    "    sub  %1,%0                   \n"
    "    and  $~15,%0                 \n"
    "    mov  %0,alloc-1b(%%edx)      \n"
    "    mov  %0,%%edi                \n"
    "    rep  movsb                   \n"
       : "=&r" (new), "+c" (bytes), "+S" (old)
	: : "edx", "edi", "memory");
    return new;
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
                   MBI_CMDLINE |
                   MBI_MODULES |
                   MBI_MEMMAP |
                   MBI_LOADERNAME);

    return mbi;
}
