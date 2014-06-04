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
#include <xen/libfdt/libfdt.h>

#include "kernel.h"

/* Store kernel in first 8M of flash */
#define KERNEL_FLASH_ADDRESS 0x00000000UL
#define KERNEL_FLASH_SIZE    0x00800000UL

#define ZIMAGE32_MAGIC_OFFSET 0x24
#define ZIMAGE32_START_OFFSET 0x28
#define ZIMAGE32_END_OFFSET   0x2c
#define ZIMAGE32_HEADER_LEN   0x30

#define ZIMAGE32_MAGIC 0x016f2818

#define ZIMAGE64_MAGIC_V0 0x14000008
#define ZIMAGE64_MAGIC_V1 0x644d5241 /* "ARM\x64" */

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
        clean_xen_dcache_va_range(dst, l);

        paddr += l;
        dst += l;
        len -= l;
    }

    clear_fixmap(FIXMAP_MISC);
}

static void place_modules(struct kernel_info *info,
                         paddr_t kernel_start,
                         paddr_t kernel_end)
{
    /* Align DTB and initrd size to 2Mb. Linux only requires 4 byte alignment */
    const paddr_t initrd_len =
        ROUNDUP(early_info.modules.module[MOD_INITRD].size, MB(2));
    const paddr_t dtb_len = ROUNDUP(fdt_totalsize(info->fdt), MB(2));
    const paddr_t total = initrd_len + dtb_len;

    /* Convenient */
    const paddr_t mem_start = info->mem.bank[0].start;
    const paddr_t mem_size = info->mem.bank[0].size;
    const paddr_t mem_end = mem_start + mem_size;
    const paddr_t kernel_size = kernel_end - kernel_start;

    paddr_t addr;

    if ( total + kernel_size > mem_size )
        panic("Not enough memory in the first bank for the dtb+initrd");

    /*
     * DTB must be loaded such that it does not conflict with the
     * kernel decompressor. For 32-bit Linux Documentation/arm/Booting
     * recommends just after the 128MB boundary while for 64-bit Linux
     * the recommendation in Documentation/arm64/booting.txt is below
     * 512MB.
     *
     * If the bootloader provides an initrd, it will be loaded just
     * after the DTB.
     *
     * We try to place dtb+initrd at 128MB, (or, if we have less RAM,
     * as high as possible). If there is no space then fallback to
     * just after the kernel, if there is room, otherwise just before.
     */

    if ( kernel_end < MIN(mem_start + MB(128), mem_end - total) )
        addr = MIN(mem_start + MB(128), mem_end - total);
    else if ( mem_end - ROUNDUP(kernel_end, MB(2)) >= total )
        addr = ROUNDUP(kernel_end, MB(2));
    else if ( kernel_start - mem_start >= total )
        addr = kernel_start - total;
    else
    {
        panic("Unable to find suitable location for dtb+initrd");
        return;
    }

    info->dtb_paddr = addr;
    info->initrd_paddr = info->dtb_paddr + dtb_len;
}

static void kernel_zimage_load(struct kernel_info *info)
{
    paddr_t load_addr = info->zimage.load_addr;
    paddr_t paddr = info->zimage.kernel_addr;
    paddr_t attr = info->load_attr;
    paddr_t len = info->zimage.len;
    unsigned long offs;

    place_modules(info, load_addr, load_addr + len);

    printk("Loading zImage from %"PRIpaddr" to %"PRIpaddr"-%"PRIpaddr"\n",
           paddr, load_addr, load_addr + len);
    for ( offs = 0; offs < len; )
    {
        int rc;
        paddr_t s, l, ma;
        void *dst;

        s = offs & ~PAGE_MASK;
        l = min(PAGE_SIZE - s, len);

        rc = gvirt_to_maddr(load_addr + offs, &ma, GV2M_WRITE);
        if ( rc )
        {
            panic("Unable to map translate guest address");
            return;
        }

        dst = map_domain_page(ma>>PAGE_SHIFT);

        copy_from_paddr(dst + s, paddr + offs, l, attr);

        unmap_domain_page(dst);
        offs += l;
    }
}

#ifdef CONFIG_ARM_64
/*
 * Check if the image is a 64-bit zImage and setup kernel_info
 */
static int kernel_try_zimage64_prepare(struct kernel_info *info,
                                     paddr_t addr, paddr_t size)
{
    /* linux/Documentation/arm64/booting.txt */
    struct {
        uint32_t magic0;
        uint32_t res0;
        uint64_t text_offset;  /* Image load offset */
        uint64_t res1;
        uint64_t res2;
        /* zImage V1 only from here */
        uint64_t res3;
        uint64_t res4;
        uint64_t res5;
        uint32_t magic1;
        uint32_t res6;
    } zimage;
    uint64_t start, end;

    if ( size < sizeof(zimage) )
        return -EINVAL;

    copy_from_paddr(&zimage, addr, sizeof(zimage), DEV_SHARED);

    if ( zimage.magic0 != ZIMAGE64_MAGIC_V0 &&
         zimage.magic1 != ZIMAGE64_MAGIC_V1 )
        return -EINVAL;

    /* Currently there is no length in the header, so just use the size */
    start = 0;
    end = size;

    /*
     * Given the above this check is a bit pointless, but leave it
     * here in case someone adds a length field in the future.
     */
    if ( (end - start) > size )
        return -EINVAL;

    info->zimage.kernel_addr = addr;

    info->zimage.load_addr = info->mem.bank[0].start
        + zimage.text_offset;
    info->zimage.len = end - start;

    info->entry = info->zimage.load_addr;
    info->load = kernel_zimage_load;

    info->type = DOMAIN_PV64;

    return 0;
}
#endif

/*
 * Check if the image is a 32-bit zImage and setup kernel_info
 */
static int kernel_try_zimage32_prepare(struct kernel_info *info,
                                     paddr_t addr, paddr_t size)
{
    uint32_t zimage[ZIMAGE32_HEADER_LEN/4];
    uint32_t start, end;
    struct minimal_dtb_header dtb_hdr;

    if ( size < ZIMAGE32_HEADER_LEN )
        return -EINVAL;

    copy_from_paddr(zimage, addr, sizeof(zimage), DEV_SHARED);

    if (zimage[ZIMAGE32_MAGIC_OFFSET/4] != ZIMAGE32_MAGIC)
        return -EINVAL;

    start = zimage[ZIMAGE32_START_OFFSET/4];
    end = zimage[ZIMAGE32_END_OFFSET/4];

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
     * If start is zero, the zImage is position independent, in this
     * case Documentation/arm/Booting recommends loading below 128MiB
     * and above 32MiB. Load it as high as possible within these
     * constraints, while also avoiding the DTB.
     */
    if (start == 0)
    {
        paddr_t load_end;

        load_end = info->mem.bank[0].start + info->mem.bank[0].size;
        load_end = MIN(info->mem.bank[0].start + MB(128), load_end);

        info->zimage.load_addr = load_end - end;
        /* Align to 2MB */
        info->zimage.load_addr &= ~((2 << 20) - 1);
    }
    else
        info->zimage.load_addr = start;
    info->zimage.len = end - start;

    info->entry = info->zimage.load_addr;
    info->load = kernel_zimage_load;

#ifdef CONFIG_ARM_64
    info->type = DOMAIN_PV32;
#endif

    return 0;
}

static void kernel_elf_load(struct kernel_info *info)
{
    place_modules(info,
                  info->elf.parms.virt_kstart,
                  info->elf.parms.virt_kend);

    printk("Loading ELF image into guest memory\n");
    info->elf.elf.dest_base = (void*)(unsigned long)info->elf.parms.virt_kstart;
    info->elf.elf.dest_size =
         info->elf.parms.virt_kend - info->elf.parms.virt_kstart;

    elf_load_binary(&info->elf.elf);

    printk("Free temporary kernel buffer\n");
    free_xenheap_pages(info->kernel_img, info->kernel_order);
}

static int kernel_try_elf_prepare(struct kernel_info *info,
                                  paddr_t addr, paddr_t size)
{
    int rc;

    memset(&info->elf.elf, 0, sizeof(info->elf.elf));

    info->kernel_order = get_order_from_bytes(size);
    info->kernel_img = alloc_xenheap_pages(info->kernel_order, 0);
    if ( info->kernel_img == NULL )
        panic("Cannot allocate temporary buffer for kernel");

    copy_from_paddr(info->kernel_img, addr, size, info->load_attr);

    if ( (rc = elf_init(&info->elf.elf, info->kernel_img, size )) != 0 )
        goto err;
#ifdef VERBOSE
    elf_set_verbose(&info->elf.elf);
#endif
    elf_parse_binary(&info->elf.elf);
    if ( (rc = elf_xen_parse(&info->elf.elf, &info->elf.parms)) != 0 )
        goto err;

#ifdef CONFIG_ARM_64
    if ( elf_32bit(&info->elf.elf) )
        info->type = DOMAIN_PV32;
    else if ( elf_64bit(&info->elf.elf) )
        info->type = DOMAIN_PV64;
    else
    {
        printk("Unknown ELF class\n");
        rc = -EINVAL;
        goto err;
    }
#endif

    /*
     * TODO: can the ELF header be used to find the physical address
     * to load the image to?  Instead of assuming virt == phys.
     */
    info->entry = info->elf.parms.virt_entry;
    info->load = kernel_elf_load;

    if ( elf_check_broken(&info->elf.elf) )
        printk("Xen: warning: ELF kernel broken: %s\n",
               elf_check_broken(&info->elf.elf));

    return 0;
err:
    if ( elf_check_broken(&info->elf.elf) )
        printk("Xen: ELF kernel broken: %s\n",
               elf_check_broken(&info->elf.elf));

    free_xenheap_pages(info->kernel_img, info->kernel_order);
    return rc;
}

int kernel_prepare(struct kernel_info *info)
{
    int rc;

    paddr_t start, size;

    if ( early_info.modules.nr_mods < MOD_KERNEL )
    {
        printk("No boot modules found, trying flash\n");
        start = KERNEL_FLASH_ADDRESS;
        size = KERNEL_FLASH_SIZE;
        info->load_attr = DEV_SHARED;
    }
    else
    {
        printk("Loading kernel from boot module %d\n", MOD_KERNEL);
        start = early_info.modules.module[MOD_KERNEL].start;
        size = early_info.modules.module[MOD_KERNEL].size;
        info->load_attr = BUFFERABLE;
    }

#ifdef CONFIG_ARM_64
    rc = kernel_try_zimage64_prepare(info, start, size);
    if (rc < 0)
#endif
        rc = kernel_try_zimage32_prepare(info, start, size);
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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
