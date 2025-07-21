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
    BUG_ON("unimplemented");
}

void __init remove_early_mappings(void)
{
    BUG_ON("unimplemented");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
