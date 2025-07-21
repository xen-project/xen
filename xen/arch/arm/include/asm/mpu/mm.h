/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_MM_H__
#define __ARM_MPU_MM_H__

#include <xen/bug.h>
#include <xen/macros.h>
#include <xen/page-size.h>
#include <xen/types.h>
#include <asm/mm.h>
#include <asm/mpu.h>

#define MPUMAP_REGION_OVERLAP      -1
#define MPUMAP_REGION_NOTFOUND      0
#define MPUMAP_REGION_FOUND         1
#define MPUMAP_REGION_INCLUSIVE     2

#define INVALID_REGION_IDX     0xFFU

extern struct page_info *frame_table;

extern uint8_t max_mpu_regions;

extern DECLARE_BITMAP(xen_mpumap_mask, MAX_MPU_REGION_NR);

extern pr_t xen_mpumap[MAX_MPU_REGION_NR];

#define virt_to_maddr(va) ((paddr_t)((vaddr_t)(va) & PADDR_MASK))

#ifdef CONFIG_ARM_32
#define is_xen_heap_page(page) ({ BUG_ON("unimplemented"); false; })
#define is_xen_heap_mfn(mfn) ({ BUG_ON("unimplemented"); false; })
#endif

/* On MPU systems there is no translation, ma == va. */
static inline void *maddr_to_virt(paddr_t ma)
{
    return _p(ma);
}

/* Convert between virtual address to page-info structure. */
static inline struct page_info *virt_to_page(const void *v)
{
    mfn_t mfn = _mfn(virt_to_mfn(v));

    ASSERT(mfn_valid(mfn));

    return mfn_to_page(mfn);
}

/* Utility function to be used whenever MPU regions are modified */
static inline void context_sync_mpu(void)
{
    /*
     * ARM DDI 0600B.a, C1.7.1
     * Writes to MPU registers are only guaranteed to be visible following a
     * Context synchronization event and DSB operation.
     */
    dsb(sy);
    isb();
}

/*
 * The following API requires context_sync_mpu() after being used to modify MPU
 * regions:
 *  - write_protection_region
 */

/* Reads the MPU region (into @pr_read) with index @sel from the HW */
void read_protection_region(pr_t *pr_read, uint8_t sel);

/* Writes the MPU region (from @pr_write) with index @sel to the HW */
void write_protection_region(const pr_t *pr_write, uint8_t sel);

/*
 * Creates a pr_t structure describing a protection region.
 *
 * @base: base address as base of the protection region.
 * @limit: exclusive address as limit of the protection region.
 * @flags: memory flags for the mapping.
 * @return: pr_t structure describing a protection region.
 */
pr_t pr_of_addr(paddr_t base, paddr_t limit, unsigned int flags);

/*
 * Checks whether a given memory range is present in the provided table of
 * MPU protection regions.
 *
 * @param table         Array of pr_t protection regions.
 * @param r_regions     Number of elements in `table`.
 * @param base          Start of the memory region to be checked (inclusive).
 * @param limit         End of the memory region to be checked (exclusive).
 * @param index         Set to the index of the region if an exact or inclusive
 *                      match is found, and INVALID_REGION otherwise.
 * @return: Return code indicating the result of the search:
 *          MPUMAP_REGION_NOTFOUND: no part of the range is present in `table`
 *          MPUMAP_REGION_FOUND: found an exact match in `table`
 *          MPUMAP_REGION_INCLUSIVE: found an inclusive match in `table`
 *          MPUMAP_REGION_OVERLAP: found an overlap with a mapping in `table`
 *
 * Note: make sure that the range [`base`, `limit`) refers to the memory region
 * inclusive of `base` and exclusive of `limit`.
 */
int mpumap_contains_region(pr_t *table, uint8_t nr_regions, paddr_t base,
                           paddr_t limit, uint8_t *index);

#endif /* __ARM_MPU_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
