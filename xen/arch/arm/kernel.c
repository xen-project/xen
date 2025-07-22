/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#include <xen/byteorder.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/fdt-domain-build.h>
#include <xen/fdt-kernel.h>
#include <xen/guest_access.h>
#include <xen/gunzip.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/domain_build.h>
#include <asm/setup.h>

#define UIMAGE_MAGIC          0x27051956
#define UIMAGE_NMLEN          32

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

#define DTB_MAGIC 0xd00dfeedU

static void __init place_modules(struct kernel_info *info,
                                 paddr_t kernbase, paddr_t kernend)
{
    /* Align DTB and initrd size to 2Mb. Linux only requires 4 byte alignment */
    const struct boot_module *mod = info->bd.initrd;
    const struct membanks *mem = kernel_info_get_mem(info);
    const paddr_t initrd_len = ROUNDUP(mod ? mod->size : 0, MB(2));
    const paddr_t dtb_len = ROUNDUP(fdt_totalsize(info->fdt), MB(2));
    const paddr_t modsize = initrd_len + dtb_len;

    /* Convenient */
    const paddr_t rambase = mem->bank[0].start;
    const paddr_t ramsize = mem->bank[0].size;
    const paddr_t ramend = rambase + ramsize;
    const paddr_t kernsize = ROUNDUP(kernend, MB(2)) - kernbase;
    const paddr_t ram128mb = rambase + MB(128);

    paddr_t modbase;

    if ( modsize + kernsize > ramsize )
        panic("Not enough memory in the first bank for the kernel+dtb+initrd\n");

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
     * We try to place dtb+initrd at 128MB or if we have less RAM
     * as high as possible. If there is no space then fallback to
     * just before the kernel.
     *
     * If changing this then consider
     * tools/libxc/xc_dom_arm.c:arch_setup_meminit as well.
     */
    if ( ramend >= ram128mb + modsize && kernend < ram128mb )
        modbase = ram128mb;
    else if ( ramend - modsize > ROUNDUP(kernend, MB(2)) )
        modbase = ramend - modsize;
    else if ( kernbase - rambase > modsize )
        modbase = kernbase - modsize;
    else
    {
        panic("Unable to find suitable location for dtb+initrd\n");
        return;
    }

    info->dtb_paddr = modbase;
    info->initrd_paddr = info->dtb_paddr + dtb_len;
}

static paddr_t __init kernel_zimage_place(struct kernel_info *info)
{
    const struct membanks *mem = kernel_info_get_mem(info);
    paddr_t load_addr;

#ifdef CONFIG_ARM_64
    if ( (info->arch.type == DOMAIN_64BIT) && (info->zimage.start == 0) )
        return mem->bank[0].start + info->zimage.text_offset;
#endif

    /*
     * If start is zero, the zImage is position independent, in this
     * case Documentation/arm/Booting recommends loading below 128MiB
     * and above 32MiB. Load it as high as possible within these
     * constraints, while also avoiding the DTB.
     */
    if ( info->zimage.start == 0 )
    {
        paddr_t load_end;

        load_end = mem->bank[0].start + mem->bank[0].size;
        load_end = MIN(mem->bank[0].start + MB(128), load_end);

        load_addr = load_end - info->zimage.len;
        /* Align to 2MB */
        load_addr &= ~((2 << 20) - 1);
    }
    else
        load_addr = info->zimage.start;

    return load_addr;
}

static void __init kernel_zimage_load(struct kernel_info *info)
{
    paddr_t load_addr = kernel_zimage_place(info);
    paddr_t paddr = info->zimage.kernel_addr;
    paddr_t len = info->zimage.len;
    void *kernel;
    int rc;

    /*
     * If the image does not have a fixed entry point, then use the load
     * address as the entry point.
     */
    if ( info->entry == 0 )
        info->entry = load_addr;

    place_modules(info, load_addr, load_addr + len);

    printk("Loading zImage from %"PRIpaddr" to %"PRIpaddr"-%"PRIpaddr"\n",
           paddr, load_addr, load_addr + len);

    kernel = ioremap_wc(paddr, len);
    if ( !kernel )
        panic("Unable to map the %pd kernel\n", info->bd.d);

    rc = copy_to_guest_phys_flush_dcache(info->bd.d, load_addr,
                                         kernel, len);
    if ( rc != 0 )
        panic("Unable to copy the kernel in the %pd memory\n", info->bd.d);

    iounmap(kernel);
}

/*
 * Uimage CPU Architecture Codes
 */
#define IH_ARCH_ARM             2       /* ARM          */
#define IH_ARCH_ARM64           22      /* ARM64        */

/* uImage Compression Types */
#define IH_COMP_GZIP            1

/*
 * Check if the image is a uImage and setup kernel_info
 */
int __init kernel_uimage_probe(struct kernel_info *info,
                               struct boot_module *mod)
{
    struct {
        __be32 magic;   /* Image Header Magic Number */
        __be32 hcrc;    /* Image Header CRC Checksum */
        __be32 time;    /* Image Creation Timestamp  */
        __be32 size;    /* Image Data Size           */
        __be32 load;    /* Data Load Address         */
        __be32 ep;      /* Entry Point Address       */
        __be32 dcrc;    /* Image Data CRC Checksum   */
        uint8_t os;     /* Operating System          */
        uint8_t arch;   /* CPU architecture          */
        uint8_t type;   /* Image Type                */
        uint8_t comp;   /* Compression Type          */
        uint8_t name[UIMAGE_NMLEN]; /* Image Name  */
    } uimage;

    uint32_t len;
    paddr_t addr = mod->start;
    paddr_t size = mod->size;

    if ( size < sizeof(uimage) )
        return -ENOENT;

    copy_from_paddr(&uimage, addr, sizeof(uimage));

    if ( be32_to_cpu(uimage.magic) != UIMAGE_MAGIC )
        return -ENOENT;

    len = be32_to_cpu(uimage.size);

    if ( len > size - sizeof(uimage) )
        return -EINVAL;

    /* Only gzip compression is supported. */
    if ( uimage.comp && uimage.comp != IH_COMP_GZIP )
    {
        printk(XENLOG_ERR
               "Unsupported uImage compression type %"PRIu8"\n", uimage.comp);
        return -EOPNOTSUPP;
    }

    info->zimage.start = be32_to_cpu(uimage.load);
    info->entry = be32_to_cpu(uimage.ep);

    /*
     * While uboot considers 0x0 to be a valid load/start address, for Xen
     * to maintain parity with zImage, we consider 0x0 to denote position
     * independent image. That means Xen is free to load such an image at
     * any valid address.
     */
    if ( info->zimage.start == 0 )
        printk(XENLOG_INFO
               "No load address provided. Xen will decide where to load it.\n");
    else
        printk(XENLOG_INFO
               "Provided load address: %"PRIpaddr" and entry address: %"PRIpaddr"\n",
               info->zimage.start, info->entry);

    /*
     * If the image supports position independent execution, then user cannot
     * provide an entry point as Xen will load such an image at any appropriate
     * memory address. Thus, we need to return error.
     */
    if ( (info->zimage.start == 0) && (info->entry != 0) )
    {
        printk(XENLOG_ERR
               "Entry point cannot be non zero for PIE image.\n");
        return -EINVAL;
    }

    if ( uimage.comp )
    {
        int rc;

        /*
         * In case of a compressed uImage, the gzip header is right after
         * the u-boot header, so pass sizeof(uimage) as an offset to gzip
         * header.
         */
        rc = kernel_decompress(mod, sizeof(uimage));
        if ( rc )
            return rc;

        info->zimage.kernel_addr = mod->start;
        info->zimage.len = mod->size;
    }
    else
    {
        info->zimage.kernel_addr = addr + sizeof(uimage);
        info->zimage.len = len;
    }

    info->load = kernel_zimage_load;

#ifdef CONFIG_ARM_64
    switch ( uimage.arch )
    {
    case IH_ARCH_ARM:
        info->arch.type = DOMAIN_32BIT;
        break;
    case IH_ARCH_ARM64:
        info->arch.type = DOMAIN_64BIT;
        break;
    default:
        printk(XENLOG_ERR "Unsupported uImage arch type %d\n", uimage.arch);
        return -EINVAL;
    }

    /*
     * If there is a uImage header, then we do not parse zImage or zImage64
     * header. In other words if the user provides a uImage header on top of
     * zImage or zImage64 header, Xen uses the attributes of uImage header only.
     * Thus, Xen uses uimage.load attribute to determine the load address and
     * zimage.text_offset is ignored.
     */
    info->zimage.text_offset = 0;
#endif

    return 0;
}

#ifdef CONFIG_ARM_64
/*
 * Check if the image is a 64-bit Image.
 */
static int __init kernel_zimage64_probe(struct kernel_info *info,
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

    copy_from_paddr(&zimage, addr, sizeof(zimage));

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
    info->zimage.len = end - start;
    info->zimage.text_offset = zimage.text_offset;
    info->zimage.start = 0;

    info->load = kernel_zimage_load;

    info->arch.type = DOMAIN_64BIT;

    return 0;
}
#endif

/*
 * Check if the image is a 32-bit zImage and setup kernel_info
 */
static int __init kernel_zimage32_probe(struct kernel_info *info,
                                        paddr_t addr, paddr_t size)
{
    uint32_t zimage[ZIMAGE32_HEADER_LEN/4];
    uint32_t start, end;
    struct minimal_dtb_header dtb_hdr;

    if ( size < ZIMAGE32_HEADER_LEN )
        return -EINVAL;

    copy_from_paddr(zimage, addr, sizeof(zimage));

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
        copy_from_paddr(&dtb_hdr, addr + end - start, sizeof(dtb_hdr));
        if (be32_to_cpu(dtb_hdr.magic) == DTB_MAGIC) {
            end += be32_to_cpu(dtb_hdr.total_size);

            if ( end > addr + size )
                return -EINVAL;
        }
    }

    info->zimage.kernel_addr = addr;

    info->zimage.start = start;
    info->zimage.len = end - start;

    info->load = kernel_zimage_load;

#ifdef CONFIG_ARM_64
    info->arch.type = DOMAIN_32BIT;
#endif

    return 0;
}

int __init kernel_zimage_probe(struct kernel_info *info, paddr_t addr,
                               paddr_t size)
{
    int rc;

#ifdef CONFIG_ARM_64
    rc = kernel_zimage64_probe(info, addr, size);
    if (rc < 0)
#endif
        rc = kernel_zimage32_probe(info, addr, size);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
