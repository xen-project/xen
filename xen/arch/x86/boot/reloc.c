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
 *   - 0x04(%esp) = MAGIC,
 *   - 0x08(%esp) = INFORMATION_ADDRESS,
 *   - 0x0c(%esp) = TOPMOST_LOW_MEMORY_STACK_ADDRESS.
 *   - 0x10(%esp) = BOOT_VIDEO_INFO_ADDRESS.
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

#include "../../../include/xen/kconfig.h"
#include <public/arch-x86/hvm/start_info.h>

#ifdef CONFIG_VIDEO
# include "video.h"

/* VESA control information */
struct __packed vesa_ctrl_info {
    uint8_t signature[4];
    uint16_t version;
    uint32_t oem_name;
    uint32_t capabilities;
    uint32_t mode_list;
    uint16_t mem_size;
    /* We don't use any further fields. */
};

/* VESA 2.0 mode information */
struct vesa_mode_info {
    uint16_t attrib;
    uint8_t window[14]; /* We don't use the individual fields. */
    uint16_t bytes_per_line;
    uint16_t width;
    uint16_t height;
    uint8_t cell_width;
    uint8_t cell_height;
    uint8_t nr_planes;
    uint8_t depth;
    uint8_t memory[5]; /* We don't use the individual fields. */
    struct boot_video_colors colors;
    uint8_t direct_color;
    uint32_t base;
    /* We don't use any further fields. */
};
#endif /* CONFIG_VIDEO */

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

static struct hvm_start_info *pvh_info_reloc(u32 in)
{
    struct hvm_start_info *out;

    out = _p(copy_mem(in, sizeof(*out)));

    if ( out->cmdline_paddr )
        out->cmdline_paddr = copy_string(out->cmdline_paddr);

    if ( out->nr_modules )
    {
        unsigned int i;
        struct hvm_modlist_entry *mods;

        out->modlist_paddr =
            copy_mem(out->modlist_paddr,
                     out->nr_modules * sizeof(struct hvm_modlist_entry));

        mods = _p(out->modlist_paddr);

        for ( i = 0; i < out->nr_modules; i++ )
        {
            if ( mods[i].cmdline_paddr )
                mods[i].cmdline_paddr = copy_string(mods[i].cmdline_paddr);
        }
    }

    return out;
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

static multiboot_info_t *mbi2_reloc(uint32_t mbi_in, uint32_t video_out)
{
    const multiboot2_fixed_t *mbi_fix = _p(mbi_in);
    const multiboot2_memory_map_t *mmap_src;
    const multiboot2_tag_t *tag;
    module_t *mbi_out_mods = NULL;
    memory_map_t *mmap_dst;
    multiboot_info_t *mbi_out;
#ifdef CONFIG_VIDEO
    struct boot_video_info *video = NULL;
#endif
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
        /*
         * We have to allocate one more module slot here. At some point
         * __start_xen() may put Xen image placement into it.
         */
        mbi_out->mods_addr = alloc_mem((mbi_out->mods_count + 1) *
                                       sizeof(*mbi_out_mods));
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

#ifdef CONFIG_VIDEO
        case MULTIBOOT2_TAG_TYPE_VBE:
            if ( video_out )
            {
                const struct vesa_ctrl_info *ci;
                const struct vesa_mode_info *mi;

                video = _p(video_out);
                ci = (void *)get_mb2_data(tag, vbe, vbe_control_info);
                mi = (void *)get_mb2_data(tag, vbe, vbe_mode_info);

                if ( ci->version >= 0x0200 && (mi->attrib & 0x9b) == 0x9b )
                {
                    video->capabilities = ci->capabilities;
                    video->lfb_linelength = mi->bytes_per_line;
                    video->lfb_width = mi->width;
                    video->lfb_height = mi->height;
                    video->lfb_depth = mi->depth;
                    video->lfb_base = mi->base;
                    video->lfb_size = ci->mem_size;
                    video->colors = mi->colors;
                    video->vesa_attrib = mi->attrib;
                }

                video->vesapm.seg = get_mb2_data(tag, vbe, vbe_interface_seg);
                video->vesapm.off = get_mb2_data(tag, vbe, vbe_interface_off);
            }
            break;

        case MULTIBOOT2_TAG_TYPE_FRAMEBUFFER:
            if ( (get_mb2_data(tag, framebuffer, framebuffer_type) !=
                  MULTIBOOT2_FRAMEBUFFER_TYPE_RGB) )
            {
                video_out = 0;
                video = NULL;
            }
            break;
#endif /* CONFIG_VIDEO */

        case MULTIBOOT2_TAG_TYPE_END:
            goto end; /* Cannot "break;" here. */

        default:
            break;
        }

 end:

#ifdef CONFIG_VIDEO
    if ( video )
        video->orig_video_isVGA = 0x23;
#endif

    return mbi_out;
}

void *__stdcall reloc(uint32_t magic, uint32_t in, uint32_t trampoline,
                      uint32_t video_info)
{
    alloc = trampoline;

    switch ( magic )
    {
    case MULTIBOOT_BOOTLOADER_MAGIC:
        return mbi_reloc(in);

    case MULTIBOOT2_BOOTLOADER_MAGIC:
        return mbi2_reloc(in, video_info);

    case XEN_HVM_START_MAGIC_VALUE:
        if ( IS_ENABLED(CONFIG_PVH_GUEST) )
            return pvh_info_reloc(in);
        /* Fallthrough */

    default:
        /* Nothing we can do */
        return NULL;
    }
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
