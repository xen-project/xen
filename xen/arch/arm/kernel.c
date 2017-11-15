/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/byteorder.h>
#include <asm/setup.h>
#include <xen/libfdt/libfdt.h>
#include <xen/gunzip.h>
#include <xen/vmap.h>

#include "kernel.h"

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
        unsigned long l, s;

        s = paddr & (PAGE_SIZE-1);
        l = min(PAGE_SIZE - s, len);

        set_fixmap(FIXMAP_MISC, maddr_to_mfn(paddr), PAGE_HYPERVISOR_WC);
        memcpy(dst, src + s, l);
        clean_dcache_va_range(dst, l);

        paddr += l;
        dst += l;
        len -= l;
    }

    clear_fixmap(FIXMAP_MISC);
}

static void place_modules(struct kernel_info *info,
                          paddr_t kernbase, paddr_t kernend)
{
    /* Align DTB and initrd size to 2Mb. Linux only requires 4 byte alignment */
    const struct bootmodule *mod = info->initrd_bootmodule;
    const paddr_t initrd_len = ROUNDUP(mod ? mod->size : 0, MB(2));
    const paddr_t dtb_len = ROUNDUP(fdt_totalsize(info->fdt), MB(2));
    const paddr_t modsize = initrd_len + dtb_len;

    /* Convenient */
    const paddr_t rambase = info->mem.bank[0].start;
    const paddr_t ramsize = info->mem.bank[0].size;
    const paddr_t ramend = rambase + ramsize;
    const paddr_t kernsize = ROUNDUP(kernend, MB(2)) - kernbase;
    const paddr_t ram128mb = rambase + MB(128);

    paddr_t modbase;

    if ( modsize + kernsize > ramsize )
        panic("Not enough memory in the first bank for the kernel+dtb+initrd");

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
        panic("Unable to find suitable location for dtb+initrd");
        return;
    }

    info->dtb_paddr = modbase;
    info->initrd_paddr = info->dtb_paddr + dtb_len;
}

static paddr_t kernel_zimage_place(struct kernel_info *info)
{
    paddr_t load_addr;

#ifdef CONFIG_ARM_64
    if ( info->type == DOMAIN_64BIT )
        return info->mem.bank[0].start + info->zimage.text_offset;
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

        load_end = info->mem.bank[0].start + info->mem.bank[0].size;
        load_end = MIN(info->mem.bank[0].start + MB(128), load_end);

        load_addr = load_end - info->zimage.len;
        /* Align to 2MB */
        load_addr &= ~((2 << 20) - 1);
    }
    else
        load_addr = info->zimage.start;

    return load_addr;
}

static void kernel_zimage_load(struct kernel_info *info)
{
    paddr_t load_addr = kernel_zimage_place(info);
    paddr_t paddr = info->zimage.kernel_addr;
    paddr_t len = info->zimage.len;
    unsigned long offs;

    info->entry = load_addr;

    place_modules(info, load_addr, load_addr + len);

    printk("Loading zImage from %"PRIpaddr" to %"PRIpaddr"-%"PRIpaddr"\n",
           paddr, load_addr, load_addr + len);
    for ( offs = 0; offs < len; )
    {
        uint64_t par;
        paddr_t s, l, ma = 0;
        void *dst;

        s = offs & ~PAGE_MASK;
        l = min(PAGE_SIZE - s, len);

        par = gvirt_to_maddr(load_addr + offs, &ma, GV2M_WRITE);
        if ( par )
        {
            panic("Unable to map translate guest address");
            return;
        }

        dst = map_domain_page(maddr_to_mfn(ma));

        copy_from_paddr(dst + s, paddr + offs, l);

        unmap_domain_page(dst);
        offs += l;
    }
}

/*
 * Uimage CPU Architecture Codes
 */
#define IH_ARCH_ARM             2       /* ARM          */
#define IH_ARCH_ARM64           22      /* ARM64        */

/*
 * Check if the image is a uImage and setup kernel_info
 */
static int kernel_uimage_probe(struct kernel_info *info,
                                 paddr_t addr, paddr_t size)
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

    if ( size < sizeof(uimage) )
        return -EINVAL;

    copy_from_paddr(&uimage, addr, sizeof(uimage));

    if ( be32_to_cpu(uimage.magic) != UIMAGE_MAGIC )
        return -EINVAL;

    len = be32_to_cpu(uimage.size);

    if ( len > size - sizeof(uimage) )
        return -EINVAL;

    info->zimage.kernel_addr = addr + sizeof(uimage);
    info->zimage.len = len;

    info->entry = info->zimage.start;
    info->load = kernel_zimage_load;

#ifdef CONFIG_ARM_64
    switch ( uimage.arch )
    {
    case IH_ARCH_ARM:
        info->type = DOMAIN_32BIT;
        break;
    case IH_ARCH_ARM64:
        info->type = DOMAIN_64BIT;
        break;
    default:
        printk(XENLOG_ERR "Unsupported uImage arch type %d\n", uimage.arch);
        return -EINVAL;
    }
#endif

    return 0;
}

static __init uint32_t output_length(char *image, unsigned long image_len)
{
    return *(uint32_t *)&image[image_len - 4];
}

static __init int kernel_decompress(struct bootmodule *mod)
{
    char *output, *input;
    char magic[2];
    int rc;
    unsigned kernel_order_out;
    paddr_t output_size;
    struct page_info *pages;
    mfn_t mfn;
    int i;
    paddr_t addr = mod->start;
    paddr_t size = mod->size;

    if ( size < 2 )
        return -EINVAL;

    copy_from_paddr(magic, addr, sizeof(magic));

    /* only gzip is supported */
    if ( !gzip_check(magic, size) )
        return -EINVAL;

    input = ioremap_cache(addr, size);
    if ( input == NULL )
        return -EFAULT;

    output_size = output_length(input, size);
    kernel_order_out = get_order_from_bytes(output_size);
    pages = alloc_domheap_pages(NULL, kernel_order_out, 0);
    if ( pages == NULL )
    {
        iounmap(input);
        return -ENOMEM;
    }
    mfn = _mfn(page_to_mfn(pages));
    output = __vmap(&mfn, 1 << kernel_order_out, 1, 1, PAGE_HYPERVISOR, VMAP_DEFAULT);

    rc = perform_gunzip(output, input, size);
    clean_dcache_va_range(output, output_size);
    iounmap(input);
    vunmap(output);

    mod->start = page_to_maddr(pages);
    mod->size = output_size;

    /*
     * Need to free pages after output_size here because they won't be
     * freed by discard_initial_modules
     */
    i = PFN_UP(output_size);
    for ( ; i < (1 << kernel_order_out); i++ )
        free_domheap_page(pages + i);

    /*
     * Free the original kernel, update the pointers to the
     * decompressed kernel
     */
    dt_unreserved_regions(addr, addr + size, init_domheap_pages, 0);

    return 0;
}

#ifdef CONFIG_ARM_64
/*
 * Check if the image is a 64-bit Image.
 */
static int kernel_zimage64_probe(struct kernel_info *info,
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

    info->load = kernel_zimage_load;

    info->type = DOMAIN_64BIT;

    return 0;
}
#endif

/*
 * Check if the image is a 32-bit zImage and setup kernel_info
 */
static int kernel_zimage32_probe(struct kernel_info *info,
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
    info->type = DOMAIN_32BIT;
#endif

    return 0;
}

static void kernel_elf_load(struct kernel_info *info)
{
    /*
     * TODO: can the ELF header be used to find the physical address
     * to load the image to?  Instead of assuming virt == phys.
     */
    info->entry = info->elf.parms.virt_entry;

    place_modules(info,
                  info->elf.parms.virt_kstart,
                  info->elf.parms.virt_kend);

    printk("Loading ELF image into guest memory\n");
    info->elf.elf.dest_base = (void*)(unsigned long)info->elf.parms.virt_kstart;
    info->elf.elf.dest_size =
         info->elf.parms.virt_kend - info->elf.parms.virt_kstart;

    elf_load_binary(&info->elf.elf);

    printk("Free temporary kernel buffer\n");
    free_xenheap_pages(info->elf.kernel_img, info->elf.kernel_order);
}

static int kernel_elf_probe(struct kernel_info *info,
                            paddr_t addr, paddr_t size)
{
    int rc;

    memset(&info->elf.elf, 0, sizeof(info->elf.elf));

    info->elf.kernel_order = get_order_from_bytes(size);
    info->elf.kernel_img = alloc_xenheap_pages(info->elf.kernel_order, 0);
    if ( info->elf.kernel_img == NULL )
        panic("Cannot allocate temporary buffer for kernel");

    copy_from_paddr(info->elf.kernel_img, addr, size);

    if ( (rc = elf_init(&info->elf.elf, info->elf.kernel_img, size )) != 0 )
        goto err;
#ifdef CONFIG_VERBOSE_DEBUG
    elf_set_verbose(&info->elf.elf);
#endif
    elf_parse_binary(&info->elf.elf);
    if ( (rc = elf_xen_parse(&info->elf.elf, &info->elf.parms)) != 0 )
        goto err;

#ifdef CONFIG_ARM_64
    if ( elf_32bit(&info->elf.elf) )
        info->type = DOMAIN_32BIT;
    else if ( elf_64bit(&info->elf.elf) )
        info->type = DOMAIN_64BIT;
    else
    {
        printk("Unknown ELF class\n");
        rc = -EINVAL;
        goto err;
    }
#endif

    info->load = kernel_elf_load;

    if ( elf_check_broken(&info->elf.elf) )
        printk("Xen: warning: ELF kernel broken: %s\n",
               elf_check_broken(&info->elf.elf));

    return 0;
err:
    if ( elf_check_broken(&info->elf.elf) )
        printk("Xen: ELF kernel broken: %s\n",
               elf_check_broken(&info->elf.elf));

    free_xenheap_pages(info->elf.kernel_img, info->elf.kernel_order);
    return rc;
}

int kernel_probe(struct kernel_info *info)
{
    struct bootmodule *mod = boot_module_find_by_kind(BOOTMOD_KERNEL);
    int rc;

    if ( !mod || !mod->size )
    {
        printk(XENLOG_ERR "Missing kernel boot module?\n");
        return -ENOENT;
    }

    info->kernel_bootmodule = mod;

    printk("Loading kernel from boot module @ %"PRIpaddr"\n", mod->start);

    info->initrd_bootmodule = boot_module_find_by_kind(BOOTMOD_RAMDISK);
    if ( info->initrd_bootmodule )
        printk("Loading ramdisk from boot module @ %"PRIpaddr"\n",
               info->initrd_bootmodule->start);

    /* if it is a gzip'ed image, 32bit or 64bit, uncompress it */
    rc = kernel_decompress(mod);
    if (rc < 0 && rc != -EINVAL)
        return rc;

#ifdef CONFIG_ARM_64
    rc = kernel_zimage64_probe(info, mod->start, mod->size);
    if (rc < 0)
#endif
        rc = kernel_uimage_probe(info, mod->start, mod->size);
    if (rc < 0)
        rc = kernel_zimage32_probe(info, mod->start, mod->size);
    if (rc < 0)
        rc = kernel_elf_probe(info, mod->start, mod->size);

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
