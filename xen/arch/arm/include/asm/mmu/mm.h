/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ARM_MMU_MM_H__
#define __ARM_MMU_MM_H__

/* Non-boot CPUs use this to find the correct pagetables. */
extern uint64_t init_ttbr;

extern mfn_t directmap_mfn_start, directmap_mfn_end;
extern vaddr_t directmap_virt_end;
#ifdef CONFIG_ARM_64
extern vaddr_t directmap_virt_start;
extern unsigned long directmap_base_pdx;
#endif

#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)

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
