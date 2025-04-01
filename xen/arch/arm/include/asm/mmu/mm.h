/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ARM_MMU_MM_H__
#define __ARM_MMU_MM_H__

#include <xen/bug.h>
#include <xen/pdx.h>
#include <xen/types.h>
#include <asm/mm.h>
#include <asm/mmu/layout.h>
#include <asm/page.h>

/* Non-boot CPUs use this to find the correct pagetables. */
extern uint64_t init_ttbr;

extern mfn_t directmap_mfn_start, directmap_mfn_end;
extern vaddr_t directmap_virt_end;
#ifdef CONFIG_ARM_64
extern vaddr_t directmap_virt_start;
extern unsigned long directmap_base_pdx;
#endif

#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)

#define virt_to_maddr(va) ({                                                   \
    vaddr_t va_ = (vaddr_t)(va);                                               \
    (paddr_t)((va_to_par(va_) & PADDR_MASK & PAGE_MASK) | (va_ & ~PAGE_MASK)); \
})

#ifdef CONFIG_ARM_32
/**
 * Find the virtual address corresponding to a machine address
 *
 * Only memory backing the XENHEAP has a corresponding virtual address to
 * be found. This is so we can save precious virtual space, as it's in
 * short supply on arm32. This mapping is not subject to PDX compression
 * because XENHEAP is known to be physically contiguous and can't hence
 * jump over the PDX hole. This means we can avoid the roundtrips
 * converting to/from pdx.
 *
 * @param ma Machine address
 * @return Virtual address mapped to `ma`
 */
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT(is_xen_heap_mfn(maddr_to_mfn(ma)));
    ma -= mfn_to_maddr(directmap_mfn_start);
    return (void *)(unsigned long) ma + XENHEAP_VIRT_START;
}
#else
/**
 * Find the virtual address corresponding to a machine address
 *
 * The directmap covers all conventional memory accesible by the
 * hypervisor. This means it's subject to PDX compression.
 *
 * Note there's an extra offset applied (directmap_base_pdx) on top of the
 * regular PDX compression logic. Its purpose is to skip over the initial
 * range of non-existing memory, should there be one.
 *
 * @param ma Machine address
 * @return Virtual address mapped to `ma`
 */
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT((mfn_to_pdx(maddr_to_mfn(ma)) - directmap_base_pdx) <
           (DIRECTMAP_SIZE >> PAGE_SHIFT));
    return (void *)(XENHEAP_VIRT_START -
                    (directmap_base_pdx << PAGE_SHIFT) +
                    maddr_to_directmapoff(ma));
}
#endif

/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *virt_to_page(const void *v)
{
    unsigned long va = (unsigned long)v;
    unsigned long pdx;

    ASSERT(va >= XENHEAP_VIRT_START);
    ASSERT(va < directmap_virt_end);

    pdx = (va - XENHEAP_VIRT_START) >> PAGE_SHIFT;
    pdx += mfn_to_pdx(directmap_mfn_start);
    return frame_table + pdx - frametable_base_pdx;
}

/*
 * Print a walk of a page table or p2m
 *
 * ttbr is the base address register (TTBR0_EL2 or VTTBR_EL2)
 * addr is the PA or IPA to translate
 * root_level is the starting level of the page table
 *   (e.g. TCR_EL2.SL0 or VTCR_EL2.SL0 )
 * nr_root_tables is the number of concatenated tables at the root.
 *   this can only be != 1 for P2M walks starting at the first or
 *   subsequent level.
 */
void dump_pt_walk(paddr_t ttbr, paddr_t addr,
                  unsigned int root_level,
                  unsigned int nr_root_tables);

/* Switch to a new root page-tables */
extern void switch_ttbr(uint64_t ttbr);
extern void relocate_and_switch_ttbr(uint64_t ttbr);

#endif /* __ARM_MMU_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
