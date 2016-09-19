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

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with:
 *   - 0x4(%esp) = MULTIBOOT_INFORMATION_ADDRESS,
 *   - 0x8(%esp) = BOOT_TRAMPOLINE_ADDRESS.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  reloc                    \n"
    );

typedef unsigned int u32;
#include "../../../include/xen/multiboot.h"

#define __stdcall	__attribute__((__stdcall__))

#define ALIGN_UP(arg, align) \
                (((arg) + (align) - 1) & ~((typeof(arg))(align) - 1))

#define _p(val)		((void *)(unsigned long)(val))

static u32 alloc;

static u32 alloc_mem(u32 bytes)
{
    return alloc -= ALIGN_UP(bytes, 16);
}

static u32 copy_mem(u32 src, u32 bytes)
{
    u32 dst, dst_ret;

    dst = alloc_mem(bytes);
    dst_ret = dst;

    while ( bytes-- )
        *(char *)dst++ = *(char *)src++;

    return dst_ret;
}

static u32 copy_string(u32 src)
{
    u32 p;

    if ( !src )
        return 0;

    for ( p = src; *(char *)p != '\0'; p++ )
        continue;

    return copy_mem(src, p - src + 1);
}

multiboot_info_t __stdcall *reloc(u32 mbi_old, u32 trampoline)
{
    multiboot_info_t *mbi;
    int i;

    alloc = trampoline;

    mbi = _p(copy_mem(mbi_old, sizeof(*mbi)));

    if ( mbi->flags & MBI_CMDLINE )
        mbi->cmdline = copy_string(mbi->cmdline);

    if ( mbi->flags & MBI_MODULES )
    {
        module_t *mods;

        mbi->mods_addr = copy_mem(mbi->mods_addr,
                                  mbi->mods_count * sizeof(module_t));

        mods = _p(mbi->mods_addr);

        for ( i = 0; i < mbi->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = copy_string(mods[i].string);
        }
    }

    if ( mbi->flags & MBI_MEMMAP )
        mbi->mmap_addr = copy_mem(mbi->mmap_addr, mbi->mmap_length);

    if ( mbi->flags & MBI_LOADERNAME )
        mbi->boot_loader_name = copy_string(mbi->boot_loader_name);

    /* Mask features we don't understand or don't relocate. */
    mbi->flags &= (MBI_MEMLIMITS |
                   MBI_CMDLINE |
                   MBI_MODULES |
                   MBI_MEMMAP |
                   MBI_LOADERNAME);

    return mbi;
}
