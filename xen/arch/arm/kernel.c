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
#define ZIMAGE_HEADER_LEN   0x30

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
void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len, int attrindx)
{
    void *src = (void *)FIXMAP_ADDR(FIXMAP_MISC);

    while (len) {
        paddr_t p;
        unsigned long l, s;

        p = paddr >> PAGE_SHIFT;
        s = paddr & (PAGE_SIZE-1);
        l = min(PAGE_SIZE - s, len);

        set_fixmap(FIXMAP_MISC, p, attrindx);
        memcpy(dst, src + s, l);
        flush_xen_dcache_va_range(dst, l);

        paddr += l;
        dst += l;
        len -= l;
    }

    clear_fixmap(FIXMAP_MISC);
}

static void kernel_zimage_load(struct kernel_info *info)
{
    paddr_t load_addr = info->zimage.load_addr;
    paddr_t paddr = info->zimage.kernel_addr;
    paddr_t attr = info->load_attr;
    paddr_t len = info->zimage.len;
    unsigned long offs;

    printk("Loading zImage from %"PRIpaddr" to %"PRIpaddr"-%"PRIpaddr"\n",
           paddr, load_addr, load_addr + len);
    for ( offs = 0; offs < len; )
    {
        paddr_t s, l, ma = gvirt_to_maddr(load_addr + offs);
        void *dst = map_domain_page(ma>>PAGE_SHIFT);

        s = offs & ~PAGE_MASK;
        l = min(PAGE_SIZE - s, len);

        copy_from_paddr(dst + s, paddr + offs, l, attr);

        unmap_domain_page(dst);
        offs += l;
    }
}

/**
 * Check the image is a zImage and return the load address and length
 */
static int kernel_try_zimage_prepare(struct kernel_info *info,
                                     paddr_t addr, paddr_t size)
{
    uint32_t zimage[ZIMAGE_HEADER_LEN/4];
    uint32_t start, end;
    struct minimal_dtb_header dtb_hdr;

    if ( size < ZIMAGE_HEADER_LEN )
        return -EINVAL;

    copy_from_paddr(zimage, addr, sizeof(zimage), DEV_SHARED);

    if (zimage[ZIMAGE_MAGIC_OFFSET/4] != ZIMAGE_MAGIC)
        return -EINVAL;

    start = zimage[ZIMAGE_START_OFFSET/4];
    end = zimage[ZIMAGE_END_OFFSET/4];

    if ( (end - start) > size )
        return -EINVAL;

    /*
     * Check for an appended DTB.
     */
    if ( addr + end - start + sizeof(dtb_hdr) <= size )
    {
        copy_from_paddr(&dtb_hdr, addr + end - start,
                        sizeof(dtb_hdr), DEV_SHARED);
        if (be32_to_cpu(dtb_hdr.magic) == DTB_MAGIC) {
            end += be32_to_cpu(dtb_hdr.total_size);

            if ( end > addr + size )
                return -EINVAL;
        }
    }

    info->zimage.kernel_addr = addr;

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

static int kernel_try_elf_prepare(struct kernel_info *info,
                                  paddr_t addr, paddr_t size)
{
    int rc;

    info->kernel_order = get_order_from_bytes(size);
    info->kernel_img = alloc_xenheap_pages(info->kernel_order, 0);
    if ( info->kernel_img == NULL )
        panic("Cannot allocate temporary buffer for kernel.\n");

    copy_from_paddr(info->kernel_img, addr, size, info->load_attr);

    if ( (rc = elf_init(&info->elf.elf, info->kernel_img, size )) != 0 )
        goto err;
#ifdef VERBOSE
    elf_set_verbose(&info->elf.elf);
#endif
    elf_parse_binary(&info->elf.elf);
    if ( (rc = elf_xen_parse(&info->elf.elf, &info->elf.parms)) != 0 )
        goto err;

    /*
     * TODO: can the ELF header be used to find the physical address
     * to load the image to?  Instead of assuming virt == phys.
     */
    info->entry = info->elf.parms.virt_entry;
    info->load = kernel_elf_load;

    return 0;
err:
    free_xenheap_pages(info->kernel_img, info->kernel_order);
    return rc;
}

int kernel_prepare(struct kernel_info *info)
{
    int rc;

    paddr_t start, size;

    if ( early_info.modules.nr_mods > 1 )
        panic("Cannot handle dom0 initrd yet\n");

    if ( early_info.modules.nr_mods < 1 )
    {
        printk("No boot modules found, trying flash\n");
        start = KERNEL_FLASH_ADDRESS;
        size = KERNEL_FLASH_SIZE;
        info->load_attr = DEV_SHARED;
    }
    else
    {
        printk("Loading kernel from boot module 1\n");
        start = early_info.modules.module[1].start;
        size = early_info.modules.module[1].size;
        info->load_attr = BUFFERABLE;
    }

    rc = kernel_try_zimage_prepare(info, start, size);
    if (rc < 0)
        rc = kernel_try_elf_prepare(info, start, size);

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
