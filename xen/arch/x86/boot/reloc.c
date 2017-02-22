/*
 * reloc.c
 *
 * 32-bit flat memory-map routines for relocating Multiboot structures
 * and modules. This is most easily done early with paging disabled.
 *
 * Copyright (c) 2009, Citrix Systems, Inc.
 * Copyright (c) 2013-2016 Oracle and/or its affiliates. All rights reserved.
 *
 * Authors:
 *    Keir Fraser <keir@xen.org>
 *    Daniel Kiper <daniel.kiper@oracle.com>
 */

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with:
 *   - 0x4(%esp) = MULTIBOOT_MAGIC,
 *   - 0x8(%esp) = MULTIBOOT_INFORMATION_ADDRESS,
 *   - 0xc(%esp) = TOPMOST_LOW_MEMORY_STACK_ADDRESS.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  reloc                    \n"
    );

#include "defs.h"
#include "../../../include/xen/multiboot.h"
#include "../../../include/xen/multiboot2.h"

#define get_mb2_data(tag, type, member)   (((multiboot2_tag_##type##_t *)(tag))->member)
#define get_mb2_string(tag, type, member) ((u32)get_mb2_data(tag, type, member))

static u32 alloc;

static u32 alloc_mem(u32 bytes)
{
    return alloc -= ALIGN_UP(bytes, 16);
}

static void zero_mem(u32 s, u32 bytes)
{
    while ( bytes-- )
        *(char *)s++ = 0;
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

static multiboot_info_t *mbi_reloc(u32 mbi_in)
{
    int i;
    multiboot_info_t *mbi_out;

    mbi_out = _p(copy_mem(mbi_in, sizeof(*mbi_out)));

    if ( mbi_out->flags & MBI_CMDLINE )
        mbi_out->cmdline = copy_string(mbi_out->cmdline);

    if ( mbi_out->flags & MBI_MODULES )
    {
        module_t *mods;

        mbi_out->mods_addr = copy_mem(mbi_out->mods_addr,
                                      mbi_out->mods_count * sizeof(module_t));

        mods = _p(mbi_out->mods_addr);

        for ( i = 0; i < mbi_out->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = copy_string(mods[i].string);
        }
    }

    if ( mbi_out->flags & MBI_MEMMAP )
        mbi_out->mmap_addr = copy_mem(mbi_out->mmap_addr, mbi_out->mmap_length);

    if ( mbi_out->flags & MBI_LOADERNAME )
        mbi_out->boot_loader_name = copy_string(mbi_out->boot_loader_name);

    /* Mask features we don't understand or don't relocate. */
    mbi_out->flags &= (MBI_MEMLIMITS |
                       MBI_CMDLINE |
                       MBI_MODULES |
                       MBI_MEMMAP |
                       MBI_LOADERNAME);

    return mbi_out;
}

static multiboot_info_t *mbi2_reloc(u32 mbi_in)
{
    const multiboot2_fixed_t *mbi_fix = _p(mbi_in);
    const multiboot2_memory_map_t *mmap_src;
    const multiboot2_tag_t *tag;
    module_t *mbi_out_mods = NULL;
    memory_map_t *mmap_dst;
    multiboot_info_t *mbi_out;
    u32 ptr;
    unsigned int i, mod_idx = 0;

    ptr = alloc_mem(sizeof(*mbi_out));
    mbi_out = _p(ptr);
    zero_mem(ptr, sizeof(*mbi_out));

    /* Skip Multiboot2 information fixed part. */
    ptr = ALIGN_UP(mbi_in + sizeof(*mbi_fix), MULTIBOOT2_TAG_ALIGN);

    /* Get the number of modules. */
    for ( tag = _p(ptr); (u32)tag - mbi_in < mbi_fix->total_size;
          tag = _p(ALIGN_UP((u32)tag + tag->size, MULTIBOOT2_TAG_ALIGN)) )
    {
        if ( tag->type == MULTIBOOT2_TAG_TYPE_MODULE )
            ++mbi_out->mods_count;
        else if ( tag->type == MULTIBOOT2_TAG_TYPE_END )
            break;
    }

    if ( mbi_out->mods_count )
    {
        mbi_out->flags |= MBI_MODULES;
        mbi_out->mods_addr = alloc_mem(mbi_out->mods_count * sizeof(*mbi_out_mods));
        mbi_out_mods = _p(mbi_out->mods_addr);
    }

    /* Skip Multiboot2 information fixed part. */
    ptr = ALIGN_UP(mbi_in + sizeof(*mbi_fix), MULTIBOOT2_TAG_ALIGN);

    /* Put all needed data into mbi_out. */
    for ( tag = _p(ptr); (u32)tag - mbi_in < mbi_fix->total_size;
          tag = _p(ALIGN_UP((u32)tag + tag->size, MULTIBOOT2_TAG_ALIGN)) )
        switch ( tag->type )
        {
        case MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME:
            mbi_out->flags |= MBI_LOADERNAME;
            ptr = get_mb2_string(tag, string, string);
            mbi_out->boot_loader_name = copy_string(ptr);
            break;

        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            mbi_out->flags |= MBI_CMDLINE;
            ptr = get_mb2_string(tag, string, string);
            mbi_out->cmdline = copy_string(ptr);
            break;

        case MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO:
            mbi_out->flags |= MBI_MEMLIMITS;
            mbi_out->mem_lower = get_mb2_data(tag, basic_meminfo, mem_lower);
            mbi_out->mem_upper = get_mb2_data(tag, basic_meminfo, mem_upper);
            break;

        case MULTIBOOT2_TAG_TYPE_MMAP:
            if ( get_mb2_data(tag, mmap, entry_size) < sizeof(*mmap_src) )
                break;

            mbi_out->flags |= MBI_MEMMAP;
            mbi_out->mmap_length = get_mb2_data(tag, mmap, size);
            mbi_out->mmap_length -= sizeof(multiboot2_tag_mmap_t);
            mbi_out->mmap_length /= get_mb2_data(tag, mmap, entry_size);
            mbi_out->mmap_length *= sizeof(*mmap_dst);

            mbi_out->mmap_addr = alloc_mem(mbi_out->mmap_length);

            mmap_src = get_mb2_data(tag, mmap, entries);
            mmap_dst = _p(mbi_out->mmap_addr);

            for ( i = 0; i < mbi_out->mmap_length / sizeof(*mmap_dst); i++ )
            {
                /* Init size member properly. */
                mmap_dst[i].size = sizeof(*mmap_dst);
                mmap_dst[i].size -= sizeof(mmap_dst[i].size);
                /* Now copy a given region data. */
                mmap_dst[i].base_addr_low = (u32)mmap_src->addr;
                mmap_dst[i].base_addr_high = (u32)(mmap_src->addr >> 32);
                mmap_dst[i].length_low = (u32)mmap_src->len;
                mmap_dst[i].length_high = (u32)(mmap_src->len >> 32);
                mmap_dst[i].type = mmap_src->type;
                mmap_src = _p(mmap_src) + get_mb2_data(tag, mmap, entry_size);
            }
            break;

        case MULTIBOOT2_TAG_TYPE_MODULE:
            if ( mod_idx >= mbi_out->mods_count )
                break;

            mbi_out_mods[mod_idx].mod_start = get_mb2_data(tag, module, mod_start);
            mbi_out_mods[mod_idx].mod_end = get_mb2_data(tag, module, mod_end);
            ptr = get_mb2_string(tag, module, cmdline);
            mbi_out_mods[mod_idx].string = copy_string(ptr);
            mbi_out_mods[mod_idx].reserved = 0;
            ++mod_idx;
            break;

        case MULTIBOOT2_TAG_TYPE_END:
            return mbi_out;

        default:
            break;
        }

    return mbi_out;
}

multiboot_info_t __stdcall *reloc(u32 mb_magic, u32 mbi_in, u32 trampoline)
{
    alloc = trampoline;

    if ( mb_magic == MULTIBOOT2_BOOTLOADER_MAGIC )
        return mbi2_reloc(mbi_in);
    else
        return mbi_reloc(mbi_in);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
