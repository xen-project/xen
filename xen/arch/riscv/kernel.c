/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/compiler.h>
#include <xen/errno.h>
#include <xen/fdt-kernel.h>
#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/types.h>
#include <xen/vmap.h>

#include <asm/setup.h>

#define IMAGE64_MAGIC_V2 0x05435352 /* Magic number 2, le, "RSC\x05" */

/*
 * Machine word alignment could be useful for copying to be more efficient.
 * There is no reason for now to have bigger module alignment.
 */
#define MODULES_ALIGNMENT sizeof(unsigned long)

static void __init place_modules(struct kernel_info *info, paddr_t kernbase,
                                 paddr_t kernend)
{
    const struct boot_module *mod = info->bd.initrd;
    const struct membanks *banks = kernel_info_get_mem_const(info);
    const paddr_t initrd_len = ROUNDUP(mod ? mod->size : 0,
                                       MODULES_ALIGNMENT);
    const paddr_t dtb_len = ROUNDUP(fdt_totalsize(info->fdt),
                                    MODULES_ALIGNMENT);
    const paddr_t modsize = initrd_len + dtb_len;
    unsigned int bi = banks->nr_banks;

    if ( modsize < initrd_len )
        panic("Module size overflow: initrd + dtb size wraps paddr_t\n");

    /*
     * Place modules as high in RAM as possible, scanning banks from
     * last to first so that the end of the last bank is preferred.
     */
    while ( bi-- > 0 )
    {
        const struct membank *bank = &banks->bank[bi];
        const paddr_t bank_end = bank->start + bank->size;
        paddr_t modbase;

        if ( modsize > bank->size )
            continue;

        modbase = ROUNDDOWN(bank_end - modsize, MODULES_ALIGNMENT);

        if ( modbase < bank->start )
            continue;

        /*
         * If modules would overlap the kernel, try placing them below it.
         */
        if ( (modbase < ROUNDUP(kernend, MODULES_ALIGNMENT)) &&
             (modbase + modsize > kernbase) )
        {
            /* Avoid underflow below */
            if ( kernbase < modsize )
                continue;

            modbase = ROUNDDOWN(kernbase - modsize, MODULES_ALIGNMENT);
            if ( modbase < bank->start )
                continue;
        }

        info->dtb_paddr = modbase;
        info->initrd_paddr = modbase + dtb_len;

        return;
    }

    panic("Unable to find suitable location for dtb+initrd\n");
}

static paddr_t __init kernel_image_place(struct kernel_info *info)
{
    paddr_t load_addr = INVALID_PADDR;
    uint64_t image_size = info->image.image_size ?: info->image.len;
    const struct membanks *banks = kernel_info_get_mem_const(info);
    unsigned int nr_banks = banks->nr_banks;
    unsigned int bi;

    /*
     * At the moment, RISC-V's Linux kernel should be always position
     * independent based on "Per-MMU execution" of boot.rst:
     *   https://docs.kernel.org/arch/riscv/boot.html#pre-mmu-execution
     *
     * But just for the case when RISC-V's Linux kernel isn't position
     * independent it is needed to take load address from
     * info->image.start.
     *
     * If `start` is zero, the Image is position independent.
     */
    if ( likely(!info->image.start) )
    {
        for ( bi = 0; bi != nr_banks; bi++ )
        {
            const struct membank *bank = &banks->bank[bi];
            paddr_t bank_start = bank->start;
            /*
             * According to boot.rst kernel load address should be properly
             * aligned:
             *   https://docs.kernel.org/arch/riscv/boot.html#kernel-location
             *
             * As Image in this case is PIC we can ignore
             * info->image.text_offset.
             */
            paddr_t aligned_start = ROUNDUP(bank_start, KERNEL_LOAD_ADDR_ALIGNMENT);
            paddr_t bank_end = bank_start + bank->size;
            paddr_t bank_size;

            if ( aligned_start > bank_end )
                continue;

            bank_size = bank_end - aligned_start;

            if ( image_size <= bank_size )
            {
                load_addr = aligned_start;
                break;
            }
        }
    }
    else
    {
        load_addr = info->image.start + info->image.text_offset;

        WARN_ON(!IS_ALIGNED(load_addr, KERNEL_LOAD_ADDR_ALIGNMENT));

        /*
         * Reject a malformed image before the loop to avoid wrapping
         * load_addr + image_size in the per-bank check below by setting
         * bi = nr_banks.
         *
         * image_size covers the kernel from _start (placed at load_addr =
         * start + text_offset) through _end.  The alignment gap
         * [start, load_addr) is padding and need not lie within a bank.
         */
        bi = image_size <= (paddr_t)-1 - load_addr ? 0 : nr_banks;
        for ( ; bi != nr_banks; bi++ )
        {
            const struct membank *bank = &banks->bank[bi];
            paddr_t bank_start = bank->start;
            paddr_t bank_end = bank_start + bank->size;

            if ( (load_addr >= bank_start) &&
                 (load_addr + image_size <= bank_end) )
                break;
        }
    }

    if ( bi == nr_banks )
        panic("Failed to place kernel image in any memory bank\n");

    info->entry = load_addr;

    return load_addr;
}

static void __init kernel_image_load(struct kernel_info *info)
{
    int rc;
    paddr_t load_addr = kernel_image_place(info);
    paddr_t paddr = info->image.kernel_addr;
    paddr_t len = info->image.len;
    paddr_t effective_size = info->image.image_size ?: len;
    void *kernel;

    place_modules(info, load_addr, load_addr + effective_size);

    printk("Loading Image from %"PRIpaddr" to [%"PRIpaddr",%"PRIpaddr")\n",
            paddr, load_addr, load_addr + effective_size);

    kernel = ioremap_cache(paddr, len);

    if ( !kernel )
        panic("Unable to map kernel\n");

    /* Move kernel to proper location in guest phys map */
    rc = copy_to_guest_phys(info->bd.d, load_addr, kernel, len);

    if ( rc )
        panic("Unable to copy kernel to proper guest location\n");

    iounmap(kernel);
}

/* Check if the image is a 64-bit Image */
static int __init kernel_image64_probe(struct kernel_info *info,
                                       paddr_t addr, paddr_t size)
{
    /* https://www.kernel.org/doc/Documentation/riscv/boot-image-header.rst */
    struct {
        uint32_t code0;         /* Executable code */
        uint32_t code1;         /* Executable code */
        uint64_t text_offset;   /* Image load offset, little endian */
        uint64_t image_size;    /* Effective Image size, little endian */
        uint64_t flags;         /* kernel flags, little endian */
        uint32_t version;       /* Version of this header */
        uint32_t res1;          /* Reserved */
        uint64_t res2;          /* Reserved */
        uint64_t magic;         /* Deprecated: Magic number, little endian, "RISCV" */
        uint32_t magic2;        /* Magic number 2, little endian, "RSC\x05" */
        uint32_t res3;          /* Reserved for PE COFF offset */
    } image;
    uint64_t effective_size;

    if ( size < sizeof(image) )
        return -EINVAL;

    copy_from_paddr(&image, addr, sizeof(image));

    /* Magic v1 is deprecated and may be removed.  Only use v2 */
    if ( le32_to_cpu(image.magic2) != IMAGE64_MAGIC_V2 )
        return -EINVAL;

    effective_size = le64_to_cpu(image.image_size);

    if ( !effective_size )
        return -EINVAL;

    info->image.kernel_addr = addr;
    /* Actual size in the binary file */
    info->image.len = size;
    /* Total memory the kernel occupies at runtime */
    info->image.image_size = effective_size;
    info->image.text_offset = le64_to_cpu(image.text_offset);
    info->image.start = 0;

    info->load = kernel_image_load;

    return 0;
}

int __init kernel_image_probe(struct kernel_info *info, paddr_t addr,
                              paddr_t size)
{
#ifdef CONFIG_RISCV_64
    return kernel_image64_probe(info, addr, size);
#else
#   error "Only 64-bit RISC-V is supported"
#endif
}
