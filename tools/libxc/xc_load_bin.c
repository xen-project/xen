/******************************************************************************
 * xc_bin_load.c
 *
 * Based on xc_elf_load.c
 *
 * Loads simple binary images. It's like a .COM file in MS-DOS. No headers are
 * present. The only requirement is that it must have a xen_bin_image table
 * somewhere in the first 8192 bytes, starting on a 32-bit aligned address.
 * Those familiar with the multiboot specification should recognize this, it's
 * (almost) the same as the multiboot header.
 * The layout of the xen_bin_image table is:
 *
 * Offset Type Name          Note
 * 0      uint32_t  magic         required
 * 4      uint32_t  flags         required
 * 8      uint32_t  checksum      required
 * 12     uint32_t  header_addr   required
 * 16     uint32_t  load_addr     required
 * 20     uint32_t  load_end_addr required
 * 24     uint32_t  bss_end_addr  required
 * 28     uint32_t  entry_addr    required
 *
 * - magic
 *   Magic number identifying the table. For images to be loaded by Xen 3, the
 *   magic value is 0x336ec578 ("xEn3" with the 0x80 bit of the "E" set).
 * - flags
 *   bit 0: indicates whether the image needs to be loaded on a page boundary
 *   bit 1: reserved, must be 0 (the multiboot spec uses this bit to indicate
 *          that memory info should be passed to the image)
 *   bit 2: reserved, must be 0 (the multiboot spec uses this bit to indicate
 *          that the bootloader should pass video mode info to the image)
 *   bit 16: reserved, must be 1 (the multiboot spec uses this bit to indicate
 *           that the values in the fields header_addr - entry_addr are
 *           valid)
 *   All other bits should be set to 0.
 * - checksum
 *   When added to "magic" and "flags", the resulting value should be 0.
 * - header_addr
 *   Contains the virtual address corresponding to the beginning of the
 *   table - the memory location at which the magic value is supposed to be
 *   loaded. This field serves to synchronize the mapping between OS image
 *   offsets and virtual memory addresses.
 * - load_addr
 *   Contains the virtual address of the beginning of the text segment. The
 *   offset in the OS image file at which to start loading is defined by the
 *   offset at which the table was found, minus (header addr - load addr).
 *   load addr must be less than or equal to header addr.
 * - load_end_addr
 *   Contains the virtual address of the end of the data segment.
 *   (load_end_addr - load_addr) specifies how much data to load. This implies
 *   that the text and data segments must be consecutive in the OS image. If
 *   this field is zero, the domain builder assumes that the text and data
 *   segments occupy the whole OS image file.
 * - bss_end_addr
 *   Contains the virtual address of the end of the bss segment. The domain
 *   builder initializes this area to zero, and reserves the memory it occupies
 *   to avoid placing boot modules and other data relevant to the loaded image
 *   in that area. If this field is zero, the domain builder assumes that no bss
 *   segment is present.
 * - entry_addr
 *   The virtual address at which to start execution of the loaded image.
 *
 * Some of the field descriptions were copied from "The Multiboot
 * Specification", Copyright 1995, 96 Bryan Ford <baford@cs.utah.edu>,
 * Erich Stefan Boleyn <erich@uruk.org> Copyright 1999, 2000, 2001, 2002
 * Free Software Foundation, Inc.
 */

#include "xg_private.h"
#include <stdlib.h>

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

struct xen_bin_image_table
{
    unsigned long magic;
    unsigned long flags;
    unsigned long checksum;
    unsigned long header_addr;
    unsigned long load_addr;
    unsigned long load_end_addr;
    unsigned long bss_end_addr;
    unsigned long entry_addr;
};

#define XEN_REACTOS_MAGIC3 0x336ec578

#define XEN_REACTOS_FLAG_ALIGN4K     0x00000001
#define XEN_REACTOS_FLAG_NEEDMEMINFO 0x00000002
#define XEN_REACTOS_FLAG_NEEDVIDINFO 0x00000004
#define XEN_REACTOS_FLAG_ADDRSVALID  0x00010000

/* Flags we test for */
#define FLAGS_MASK     ((~ 0) & (~ XEN_REACTOS_FLAG_ALIGN4K))
#define FLAGS_REQUIRED XEN_REACTOS_FLAG_ADDRSVALID

static struct xen_bin_image_table *
findtable(const char *image, unsigned long image_size);
static int
parsebinimage(
    const char *image, unsigned long image_size,
    struct domain_setup_info *dsi);
static int
loadbinimage(
    const char *image, unsigned long image_size, int xch, uint32_t dom,
    unsigned long *parray, struct domain_setup_info *dsi);

int probe_bin(const char *image,
              unsigned long image_size,
              struct load_funcs *load_funcs)
{
    if ( findtable(image, image_size) == NULL )
        return -EINVAL;

    load_funcs->parseimage = parsebinimage;
    load_funcs->loadimage = loadbinimage;

    return 0;
}

static struct xen_bin_image_table *
findtable(const char *image, unsigned long image_size)
{
    struct xen_bin_image_table *table;
    unsigned long *probe_ptr;
    unsigned probe_index;
    unsigned probe_count;

    /* Don't go outside the image */
    if ( image_size < sizeof(struct xen_bin_image_table) )
        return NULL;

    probe_count = image_size;
    /* Restrict to first 8k */
    if ( probe_count > 8192 )
        probe_count = 8192;
    probe_count = (probe_count - sizeof(struct xen_bin_image_table)) /
                  sizeof(unsigned long);

    /* Search for the magic header */
    probe_ptr = (unsigned long *) image;
    table = NULL;
    for ( probe_index = 0; probe_index < probe_count; probe_index++ )
    {
        if ( XEN_REACTOS_MAGIC3 == *probe_ptr )
        {
            table = (struct xen_bin_image_table *) probe_ptr;
            /* Checksum correct? */
            if ( 0 == table->magic + table->flags + table->checksum )
            {
                return table;
            }
        }
        probe_ptr++;
    }

    return NULL;
}

static int parsebinimage(const char *image,
                         unsigned long image_size,
                         struct domain_setup_info *dsi)
{
    struct xen_bin_image_table *image_info;
    unsigned long start_addr;
    unsigned long end_addr;

    image_info = findtable(image, image_size);
    if ( NULL == image_info )
    {
        ERROR("Image does not have a valid xen_bin_image_table table.");
        return -EINVAL;
    }

    /* Check the flags */
    if ( FLAGS_REQUIRED != (image_info->flags & FLAGS_MASK) )
    {
        ERROR("xen_bin_image_table flags required 0x%08x found 0x%08lx",
              FLAGS_REQUIRED, image_info->flags & FLAGS_MASK);
        return -EINVAL;
    }

    /* Sanity check on the addresses */
    if ( image_info->header_addr < image_info->load_addr ||
         ((char *) image_info - image) <
         (image_info->header_addr - image_info->load_addr) )
    {
        ERROR("Invalid header_addr.");
        return -EINVAL;
    }
    start_addr = image_info->header_addr - ((char *) image_info - image);
    if ( 0 != image_info->load_end_addr &&
         ( image_info->load_end_addr < image_info->load_end_addr ||
           start_addr + image_size < image_info->load_end_addr ) )
    {
        ERROR("Invalid load_end_addr");
        return -EINVAL;
    }
    end_addr = (0 == image_info->load_end_addr ? start_addr + image_size :
                                                 image_info->load_end_addr);
    if ( 0 != image_info->bss_end_addr &&
         image_info->bss_end_addr < end_addr )
    {
        ERROR("Invalid bss_end_addr");
        return -EINVAL;
    }

    dsi->v_start = image_info->load_addr;
    if ( 0 != image_info->bss_end_addr )
    {
        dsi->v_end = image_info->bss_end_addr;
    }
    else if ( 0 != image_info->load_end_addr )
    {
        dsi->v_end = image_info->load_end_addr;
    }
    else
    {
        dsi->v_end = image_info->load_addr + image_size -
                     (((char *) image_info - image) -
                      (image_info->header_addr - image_info->load_addr));
    }
    dsi->v_kernstart = dsi->v_start;
    dsi->v_kernend = dsi->v_end;
    dsi->v_kernentry = image_info->entry_addr;
    dsi->xen_guest_string = "";

    return 0;
}

static int
loadbinimage(
    const char *image, unsigned long image_size, int xch, uint32_t dom,
    unsigned long *parray, struct domain_setup_info *dsi)
{
    unsigned long size;
    char         *va;
    unsigned long done, chunksz;
    struct xen_bin_image_table *image_info;

    image_info = findtable(image, image_size);
    if ( NULL == image_info )
    {
        ERROR("Image does not have a valid xen_bin_image_table table.");
        return -EINVAL;
    }

    /* Determine image size */
    if ( 0 == image_info->load_end_addr )
    {
        size = image_size  - (((char *) image_info - image) -
                              (image_info->header_addr -
                               image_info->load_addr));
    }
    else
    {
        size = image_info->load_end_addr - image_info->load_addr;
    }

    /* It's possible that we need to skip the first part of the image */
    image += ((char *)image_info - image) -
             (image_info->header_addr - image_info->load_addr);

    for ( done = 0; done < size; done += chunksz )
    {
        va = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_WRITE, parray[done>>PAGE_SHIFT]);
        chunksz = size - done;
        if ( chunksz > PAGE_SIZE )
            chunksz = PAGE_SIZE;
        memcpy(va, image + done, chunksz);
        munmap(va, PAGE_SIZE);
    }

    if ( 0 != image_info->bss_end_addr &&
         image_info->load_addr + size < image_info->bss_end_addr )
    {
        size = image_info->bss_end_addr - image_info->load_addr;
    }
    for ( ; done < size; done += chunksz )
    {
        va = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_WRITE, parray[done>>PAGE_SHIFT]);
        chunksz = size - done;
        if ( chunksz > (PAGE_SIZE - (done & (PAGE_SIZE-1))) )
            chunksz = PAGE_SIZE - (done & (PAGE_SIZE-1));
        memset(va + (done & (PAGE_SIZE-1)), 0, chunksz);
        munmap(va, PAGE_SIZE);
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
