/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#include <xen/config.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/byteorder.h>
#include <asm/setup.h>

#include "kernel.h"

/* Store kernel in first 8M of flash */
#define KERNEL_FLASH_ADDRESS 0x00000000UL
#define KERNEL_FLASH_SIZE    0x00800000UL

#define ZIMAGE_MAGIC_OFFSET 0x24
#define ZIMAGE_START_OFFSET 0x28
#define ZIMAGE_END_OFFSET   0x2c

#define ZIMAGE_MAGIC 0x016f2818

struct minimal_dtb_header {
    uint32_t magic;
    uint32_t total_size;
    /* There are other fields but we don't use them yet. */
};

#define DTB_MAGIC 0xd00dfeed

/**
 * copy_from_paddr - copy data from a physical address
 * @dst: destination virtual address
 * @paddr: source physical address
 * @len: length to copy
 */
void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len)
{
    void *src = (void *)FIXMAP_ADDR(FIXMAP_MISC);

    while (len) {
        paddr_t p;
        unsigned long l, s;

        p = paddr >> PAGE_SHIFT;
        s = paddr & (PAGE_SIZE-1);
        l = min(PAGE_SIZE - s, len);

        set_fixmap(FIXMAP_MISC, p, DEV_SHARED);
        memcpy(dst, src + s, l);

        paddr += l;
        dst += l;
        len -= l;
    }

    clear_fixmap(FIXMAP_MISC);
}

static void kernel_zimage_load(struct kernel_info *info)
{
    paddr_t load_addr = info->zimage.load_addr;
    paddr_t len = info->zimage.len;
    paddr_t flash = KERNEL_FLASH_ADDRESS;
    void *src = (void *)FIXMAP_ADDR(FIXMAP_MISC);
    unsigned long offs;

    printk("Loading %"PRIpaddr" byte zImage from flash %"PRIpaddr" to %"PRIpaddr"-%"PRIpaddr": [",
           len, flash, load_addr, load_addr + len);
    for ( offs = 0; offs < len; offs += PAGE_SIZE )
    {
        paddr_t ma = gvirt_to_maddr(load_addr + offs);
        void *dst = map_domain_page(ma>>PAGE_SHIFT);

        if ( ( offs % (1<<20) ) == 0 )
            printk(".");

        set_fixmap(FIXMAP_MISC, (flash+offs) >> PAGE_SHIFT, DEV_SHARED);
        memcpy(dst, src, PAGE_SIZE);
        clear_fixmap(FIXMAP_MISC);

        unmap_domain_page(dst);
    }
    printk("]\n");
}

/**
 * Check the image is a zImage and return the load address and length
 */
static int kernel_try_zimage_prepare(struct kernel_info *info)
{
    uint32_t *zimage = (void *)FIXMAP_ADDR(FIXMAP_MISC);
    uint32_t start, end;
    struct minimal_dtb_header dtb_hdr;

    set_fixmap(FIXMAP_MISC, KERNEL_FLASH_ADDRESS >> PAGE_SHIFT, DEV_SHARED);

    if (zimage[ZIMAGE_MAGIC_OFFSET/4] != ZIMAGE_MAGIC)
        return -EINVAL;

    start = zimage[ZIMAGE_START_OFFSET/4];
    end = zimage[ZIMAGE_END_OFFSET/4];

    clear_fixmap(FIXMAP_MISC);

    /*
     * Check for an appended DTB.
     */
    copy_from_paddr(&dtb_hdr, KERNEL_FLASH_ADDRESS + end - start, sizeof(dtb_hdr));
    if (be32_to_cpu(dtb_hdr.magic) == DTB_MAGIC) {
        end += be32_to_cpu(dtb_hdr.total_size);
    }

    /*
     * If start is zero, the zImage is position independent -- load it
     * at 32k from start of RAM.
     */
    if (start == 0)
        info->zimage.load_addr = info->mem.bank[0].start + 0x8000;
    else
        info->zimage.load_addr = start;
    info->zimage.len = end - start;

    info->entry = info->zimage.load_addr;
    info->load = kernel_zimage_load;

    return 0;
}

static void kernel_elf_load(struct kernel_info *info)
{
    printk("Loading ELF image into guest memory\n");
    info->elf.elf.dest = (void*)(unsigned long)info->elf.parms.virt_kstart;
    elf_load_binary(&info->elf.elf);

    printk("Free temporary kernel buffer\n");
    free_xenheap_pages(info->kernel_img, info->kernel_order);
}

static int kernel_try_elf_prepare(struct kernel_info *info)
{
    int rc;

    info->kernel_order = get_order_from_bytes(KERNEL_FLASH_SIZE);
    info->kernel_img = alloc_xenheap_pages(info->kernel_order, 0);
    if ( info->kernel_img == NULL )
        panic("Cannot allocate temporary buffer for kernel.\n");

    copy_from_paddr(info->kernel_img, KERNEL_FLASH_ADDRESS, KERNEL_FLASH_SIZE);

    if ( (rc = elf_init(&info->elf.elf, info->kernel_img, KERNEL_FLASH_SIZE )) != 0 )
        return rc;
#ifdef VERBOSE
    elf_set_verbose(&info->elf.elf);
#endif
    elf_parse_binary(&info->elf.elf);
    if ( (rc = elf_xen_parse(&info->elf.elf, &info->elf.parms)) != 0 )
        return rc;

    /*
     * TODO: can the ELF header be used to find the physical address
     * to load the image to?  Instead of assuming virt == phys.
     */
    info->entry = info->elf.parms.virt_entry;
    info->load = kernel_elf_load;

    return 0;
}

int kernel_prepare(struct kernel_info *info)
{
    int rc;

    rc = kernel_try_zimage_prepare(info);
    if (rc < 0)
        rc = kernel_try_elf_prepare(info);

    return rc;
}

void kernel_load(struct kernel_info *info)
{
    info->load(info);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
