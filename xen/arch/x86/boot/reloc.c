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

#include <xen/compiler.h>
#include <xen/macros.h>
#include <xen/types.h>

#include <xen/kconfig.h>
#include <xen/multiboot.h>
#include <xen/multiboot2.h>
#include <xen/page-size.h>

#include <asm/trampoline.h>

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

#define get_mb2_data(tag, type, member)   (((const multiboot2_tag_##type##_t *)(tag))->member)
#define get_mb2_string(tag, type, member) ((uint32_t)get_mb2_data(tag, type, member))

typedef struct memctx {
    /*
     * Simple bump allocator.
     *
     * It starts from end of the trampoline heap and allocates downwards.
     */
    uint32_t ptr;
} memctx;

static uint32_t alloc_mem(uint32_t bytes, memctx *ctx)
{
    return ctx->ptr -= ROUNDUP(bytes, 16);
}

static void zero_mem(uint32_t s, uint32_t bytes)
{
    while ( bytes-- )
        *(char *)s++ = 0;
}

static uint32_t copy_mem(uint32_t src, uint32_t bytes, memctx *ctx)
{
    uint32_t dst, dst_ret;

    dst = alloc_mem(bytes, ctx);
    dst_ret = dst;

    while ( bytes-- )
        *(char *)dst++ = *(char *)src++;

    return dst_ret;
}

static uint32_t copy_string(uint32_t src, memctx *ctx)
{
    uint32_t p;

    if ( !src )
        return 0;

    for ( p = src; *(char *)p != '\0'; p++ )
        continue;

    return copy_mem(src, p - src + 1, ctx);
}

static struct hvm_start_info *pvh_info_reloc(uint32_t in, memctx *ctx)
{
    struct hvm_start_info *out;

    out = _p(copy_mem(in, sizeof(*out), ctx));

    if ( out->cmdline_paddr )
        out->cmdline_paddr = copy_string(out->cmdline_paddr, ctx);

    if ( out->nr_modules )
    {
        unsigned int i;
        struct hvm_modlist_entry *mods;

        out->modlist_paddr =
            copy_mem(out->modlist_paddr,
                     out->nr_modules * sizeof(struct hvm_modlist_entry), ctx);

        mods = _p(out->modlist_paddr);

        for ( i = 0; i < out->nr_modules; i++ )
        {
            if ( mods[i].cmdline_paddr )
                mods[i].cmdline_paddr = copy_string(mods[i].cmdline_paddr, ctx);
        }
    }

    return out;
}

static multiboot_info_t *mbi_reloc(uint32_t mbi_in, memctx *ctx)
{
    int i;
    multiboot_info_t *mbi_out;

    mbi_out = _p(copy_mem(mbi_in, sizeof(*mbi_out), ctx));

    if ( mbi_out->flags & MBI_CMDLINE )
        mbi_out->cmdline = copy_string(mbi_out->cmdline, ctx);

    if ( mbi_out->flags & MBI_MODULES )
    {
        module_t *mods;

        mbi_out->mods_addr = copy_mem(mbi_out->mods_addr,
                                      mbi_out->mods_count * sizeof(module_t), ctx);

        mods = _p(mbi_out->mods_addr);

        for ( i = 0; i < mbi_out->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = copy_string(mods[i].string, ctx);
        }
    }

    if ( mbi_out->flags & MBI_MEMMAP )
        mbi_out->mmap_addr = copy_mem(mbi_out->mmap_addr, mbi_out->mmap_length, ctx);

    if ( mbi_out->flags & MBI_LOADERNAME )
        mbi_out->boot_loader_name = copy_string(mbi_out->boot_loader_name, ctx);

    /* Mask features we don't understand or don't relocate. */
    mbi_out->flags &= (MBI_MEMLIMITS |
                       MBI_CMDLINE |
                       MBI_MODULES |
                       MBI_MEMMAP |
                       MBI_LOADERNAME);

    return mbi_out;
}

static multiboot_info_t *mbi2_reloc(uint32_t mbi_in, memctx *ctx)
{
    const multiboot2_fixed_t *mbi_fix = _p(mbi_in);
    const multiboot2_memory_map_t *mmap_src;
    const multiboot2_tag_t *tag;
    module_t *mbi_out_mods = NULL;
    memory_map_t *mmap_dst;
    multiboot_info_t *mbi_out;
#ifdef CONFIG_VIDEO
    struct boot_video_info *video = &boot_vid_info;
#endif
    uint32_t ptr;
    unsigned int i, mod_idx = 0;

    ptr = alloc_mem(sizeof(*mbi_out), ctx);
    mbi_out = _p(ptr);
    zero_mem(ptr, sizeof(*mbi_out));

    /* Skip Multiboot2 information fixed part. */
    ptr = ROUNDUP(mbi_in + sizeof(*mbi_fix), MULTIBOOT2_TAG_ALIGN);

    /* Get the number of modules. */
    for ( tag = _p(ptr); (uint32_t)tag - mbi_in < mbi_fix->total_size;
          tag = _p(ROUNDUP((uint32_t)tag + tag->size, MULTIBOOT2_TAG_ALIGN)) )
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
                                       sizeof(*mbi_out_mods), ctx);
        mbi_out_mods = _p(mbi_out->mods_addr);
    }

    /* Skip Multiboot2 information fixed part. */
    ptr = ROUNDUP(mbi_in + sizeof(*mbi_fix), MULTIBOOT2_TAG_ALIGN);

    /* Put all needed data into mbi_out. */
    for ( tag = _p(ptr); (uint32_t)tag - mbi_in < mbi_fix->total_size;
          tag = _p(ROUNDUP((uint32_t)tag + tag->size, MULTIBOOT2_TAG_ALIGN)) )
    {
        switch ( tag->type )
        {
        case MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME:
            mbi_out->flags |= MBI_LOADERNAME;
            ptr = get_mb2_string(tag, string, string);
            mbi_out->boot_loader_name = copy_string(ptr, ctx);
            break;

        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            mbi_out->flags |= MBI_CMDLINE;
            ptr = get_mb2_string(tag, string, string);
            mbi_out->cmdline = copy_string(ptr, ctx);
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

            mbi_out->mmap_addr = alloc_mem(mbi_out->mmap_length, ctx);

            mmap_src = get_mb2_data(tag, mmap, entries);
            mmap_dst = _p(mbi_out->mmap_addr);

            for ( i = 0; i < mbi_out->mmap_length / sizeof(*mmap_dst); i++ )
            {
                /* Init size member properly. */
                mmap_dst[i].size = sizeof(*mmap_dst);
                mmap_dst[i].size -= sizeof(mmap_dst[i].size);
                /* Now copy a given region data. */
                mmap_dst[i].base_addr_low = (uint32_t)mmap_src->addr;
                mmap_dst[i].base_addr_high = (uint32_t)(mmap_src->addr >> 32);
                mmap_dst[i].length_low = (uint32_t)mmap_src->len;
                mmap_dst[i].length_high = (uint32_t)(mmap_src->len >> 32);
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
            mbi_out_mods[mod_idx].string = copy_string(ptr, ctx);
            mbi_out_mods[mod_idx].reserved = 0;
            ++mod_idx;
            break;

#ifdef CONFIG_VIDEO
        case MULTIBOOT2_TAG_TYPE_VBE:
            if ( video )
            {
                const struct vesa_ctrl_info *ci;
                const struct vesa_mode_info *mi;

                ci = (const void *)get_mb2_data(tag, vbe, vbe_control_info);
                mi = (const void *)get_mb2_data(tag, vbe, vbe_mode_info);

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
                video = NULL;
            }
            break;
#endif /* CONFIG_VIDEO */

        case MULTIBOOT2_TAG_TYPE_END:
            goto end;

        default:
            break;
        }
    }

 end:

#ifdef CONFIG_VIDEO
    if ( video )
        video->orig_video_isVGA = 0x23;
#endif

    return mbi_out;
}

/* SAF-1-safe */
void *reloc(uint32_t magic, uint32_t in)
{
    memctx ctx = { trampoline_phys + TRAMPOLINE_HEAP_END };

    switch ( magic )
    {
    case MULTIBOOT_BOOTLOADER_MAGIC:
        return mbi_reloc(in, &ctx);

    case MULTIBOOT2_BOOTLOADER_MAGIC:
        return mbi2_reloc(in, &ctx);

    case XEN_HVM_START_MAGIC_VALUE:
        if ( IS_ENABLED(CONFIG_PVH_GUEST) )
            return pvh_info_reloc(in, &ctx);
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
