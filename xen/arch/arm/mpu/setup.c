/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/bug.h>
#include <xen/init.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/types.h>
#include <xen/sizes.h>
#include <asm/setup.h>

static paddr_t __initdata mapped_fdt_base = INVALID_PADDR;
static paddr_t __initdata mapped_fdt_limit = INVALID_PADDR;

void __init setup_pagetables(void) {}

void * __init early_fdt_map(paddr_t fdt_paddr)
{
    /* Map at least a page containing the DTB address, exclusive range */
    paddr_t base = round_pgdown(fdt_paddr);
    paddr_t limit = round_pgup(fdt_paddr + sizeof(struct fdt_header));
    unsigned int flags = PAGE_HYPERVISOR_RO;
    void *fdt_virt = (void *)fdt_paddr; /* virt == paddr for MPU */
    int rc;
    uint32_t size;
    unsigned long nr_mfns;

    /*
     * Check whether the physical FDT address is set and meets the minimum
     * alignment requirement. Since we are relying on MIN_FDT_ALIGN to be at
     * least 8 bytes so that we always access the magic and size fields
     * of the FDT header after mapping the first chunk, double check if
     * that is indeed the case.
     */
    BUILD_BUG_ON(MIN_FDT_ALIGN < 8);
    if ( !fdt_paddr || fdt_paddr % MIN_FDT_ALIGN )
        return NULL;

    /*
     * DTB at this address has already been mapped.`start_xen` calls this twice,
     * before and after `setup_page_tables`, which is a no-op on MPU.
     */
    if ( mapped_fdt_base == fdt_paddr )
        return fdt_virt;

    ASSERT(mapped_fdt_base == INVALID_PADDR);

    nr_mfns = (limit - base) >> PAGE_SHIFT;

    rc = map_pages_to_xen(base, maddr_to_mfn(base), nr_mfns, flags);
    if ( rc )
        panic("Unable to map the device-tree\n");

    mapped_fdt_base = fdt_paddr;
    mapped_fdt_limit = limit;

    if ( fdt_magic(fdt_virt) != FDT_MAGIC )
        return NULL;

    size = fdt_totalsize(fdt_virt);
    if ( size > MAX_FDT_SIZE )
        return NULL;

    limit = round_pgup(fdt_paddr + size);

    /* If the mapped range is not enough, map the rest of the DTB. */
    if ( limit > mapped_fdt_limit )
    {
        rc = destroy_xen_mappings(base, mapped_fdt_limit);
        if ( rc )
            panic("Unable to unmap the device-tree header\n");

        nr_mfns = (limit - base) >> PAGE_SHIFT;

        rc = map_pages_to_xen(base, maddr_to_mfn(base), nr_mfns, flags);
        if ( rc )
            panic("Unable to map the device-tree\n");

        mapped_fdt_limit = limit;
    }

    return fdt_virt;
}

/*
 * copy_from_paddr - copy data from a physical address
 * @dst: destination virtual address
 * @paddr: source physical address
 * @len: length to copy
 */
void __init copy_from_paddr(void *dst, paddr_t paddr, unsigned long len)
{
    paddr_t start_pg = round_pgdown(paddr);
    paddr_t end_pg   = round_pgup(paddr + len);
    unsigned long nr_mfns = (end_pg - start_pg) >> PAGE_SHIFT;
    mfn_t mfn = maddr_to_mfn(start_pg);

    if ( map_pages_to_xen(start_pg, mfn, nr_mfns, PAGE_HYPERVISOR_WC) )
        panic("Unable to map range for copy_from_paddr\n");

    memcpy(dst, maddr_to_virt(paddr), len);
    clean_dcache_va_range(dst, len);

    if ( destroy_xen_mappings(start_pg, end_pg) )
        panic("Unable to unmap range for copy_from_paddr\n");
}

void __init remove_early_mappings(void)
{
    int rc = destroy_xen_mappings(round_pgdown(mapped_fdt_base),
                                  mapped_fdt_limit);

    if ( rc )
        panic("Unable to unmap the device-tree\n");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
