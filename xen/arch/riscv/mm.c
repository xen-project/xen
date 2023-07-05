/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/compiler.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/pfn.h>

#include <asm/early_printk.h>
#include <asm/csr.h>
#include <asm/current.h>
#include <asm/mm.h>
#include <asm/page.h>
#include <asm/processor.h>

struct mmu_desc {
    unsigned int num_levels;
    unsigned int pgtbl_count;
    pte_t *next_pgtbl;
    pte_t *pgtbl_base;
};

extern unsigned char cpu0_boot_stack[STACK_SIZE];

#define PHYS_OFFSET ((unsigned long)_start - XEN_VIRT_START)
#define LOAD_TO_LINK(addr) ((addr) - PHYS_OFFSET)
#define LINK_TO_LOAD(addr) ((addr) + PHYS_OFFSET)

/*
 * It is expected that Xen won't be more then 2 MB.
 * The check in xen.lds.S guarantees that.
 * At least 3 page tables (in case of Sv39 ) are needed to cover 2 MB.
 * One for each page level table with PAGE_SIZE = 4 Kb.
 *
 * One L0 page table can cover 2 MB(512 entries of one page table * PAGE_SIZE).
 *
 * It might be needed one more page table in case when Xen load address
 * isn't 2 MB aligned.
 */
#define PGTBL_INITIAL_COUNT ((CONFIG_PAGING_LEVELS - 1) + 1)

pte_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
stage1_pgtbl_root[PAGETABLE_ENTRIES];

pte_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
stage1_pgtbl_nonroot[PGTBL_INITIAL_COUNT * PAGETABLE_ENTRIES];

#define HANDLE_PGTBL(curr_lvl_num)                                          \
    index = pt_index(curr_lvl_num, page_addr);                              \
    if ( pte_is_valid(pgtbl[index]) )                                       \
    {                                                                       \
        /* Find L{ 0-3 } table */                                           \
        pgtbl = (pte_t *)pte_to_paddr(pgtbl[index]);                        \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        /* Allocate new L{0-3} page table */                                \
        if ( mmu_desc->pgtbl_count == PGTBL_INITIAL_COUNT )                 \
        {                                                                   \
            early_printk("(XEN) No initial table available\n");             \
            /* panic(), BUG() or ASSERT() aren't ready now. */              \
            die();                                                          \
        }                                                                   \
        mmu_desc->pgtbl_count++;                                            \
        pgtbl[index] = paddr_to_pte((unsigned long)mmu_desc->next_pgtbl,    \
                                    PTE_VALID);                             \
        pgtbl = mmu_desc->next_pgtbl;                                       \
        mmu_desc->next_pgtbl += PAGETABLE_ENTRIES;                          \
    }

static void __init setup_initial_mapping(struct mmu_desc *mmu_desc,
                                         unsigned long map_start,
                                         unsigned long map_end,
                                         unsigned long pa_start)
{
    unsigned int index;
    pte_t *pgtbl;
    unsigned long page_addr;

    if ( (unsigned long)_start % XEN_PT_LEVEL_SIZE(0) )
    {
        early_printk("(XEN) Xen should be loaded at 4k boundary\n");
        die();
    }

    if ( (map_start & ~XEN_PT_LEVEL_MAP_MASK(0)) ||
         (pa_start & ~XEN_PT_LEVEL_MAP_MASK(0)) )
    {
        early_printk("(XEN) map and pa start addresses should be aligned\n");
        /* panic(), BUG() or ASSERT() aren't ready now. */
        die();
    }

    for ( page_addr = map_start;
          page_addr < map_end;
          page_addr += XEN_PT_LEVEL_SIZE(0) )
    {
        pgtbl = mmu_desc->pgtbl_base;

        switch ( mmu_desc->num_levels )
        {
        case 4: /* Level 3 */
            HANDLE_PGTBL(3);
        case 3: /* Level 2 */
            HANDLE_PGTBL(2);
        case 2: /* Level 1 */
            HANDLE_PGTBL(1);
        case 1: /* Level 0 */
            {
                unsigned long paddr = (page_addr - map_start) + pa_start;
                unsigned int permissions = PTE_LEAF_DEFAULT;
                pte_t pte_to_be_written;

                index = pt_index(0, page_addr);

                if ( is_kernel_text(LINK_TO_LOAD(page_addr)) ||
                     is_kernel_inittext(LINK_TO_LOAD(page_addr)) )
                    permissions =
                        PTE_EXECUTABLE | PTE_READABLE | PTE_VALID;

                if ( is_kernel_rodata(LINK_TO_LOAD(page_addr)) )
                    permissions = PTE_READABLE | PTE_VALID;

                pte_to_be_written = paddr_to_pte(paddr, permissions);

                if ( !pte_is_valid(pgtbl[index]) )
                    pgtbl[index] = pte_to_be_written;
                else
                {
                    if ( (pgtbl[index].pte ^ pte_to_be_written.pte) &
                         ~(PTE_DIRTY | PTE_ACCESSED) )
                    {
                        early_printk("PTE overridden has occurred\n");
                        /* panic(), <asm/bug.h> aren't ready now. */
                        die();
                    }
                }
            }
        }
    }
}
#undef HANDLE_PGTBL

static bool __init check_pgtbl_mode_support(struct mmu_desc *mmu_desc,
                                            unsigned long load_start)
{
    bool is_mode_supported = false;
    unsigned int index;
    unsigned int page_table_level = (mmu_desc->num_levels - 1);
    unsigned level_map_mask = XEN_PT_LEVEL_MAP_MASK(page_table_level);

    unsigned long aligned_load_start = load_start & level_map_mask;
    unsigned long aligned_page_size = XEN_PT_LEVEL_SIZE(page_table_level);
    unsigned long xen_size = (unsigned long)(_end - start);

    if ( (load_start + xen_size) > (aligned_load_start + aligned_page_size) )
    {
        early_printk("please place Xen to be in range of PAGE_SIZE "
                     "where PAGE_SIZE is XEN_PT_LEVEL_SIZE( {L3 | L2 | L1} ) "
                     "depending on expected SATP_MODE \n"
                     "XEN_PT_LEVEL_SIZE is defined in <asm/page.h>\n");
        die();
    }

    index = pt_index(page_table_level, aligned_load_start);
    stage1_pgtbl_root[index] = paddr_to_pte(aligned_load_start,
                                            PTE_LEAF_DEFAULT | PTE_EXECUTABLE);

    sfence_vma();
    csr_write(CSR_SATP,
              PFN_DOWN((unsigned long)stage1_pgtbl_root) |
              RV_STAGE1_MODE << SATP_MODE_SHIFT);

    if ( (csr_read(CSR_SATP) >> SATP_MODE_SHIFT) == RV_STAGE1_MODE )
        is_mode_supported = true;

    csr_write(CSR_SATP, 0);

    sfence_vma();

    /* Clean MMU root page table */
    stage1_pgtbl_root[index] = paddr_to_pte(0x0, 0x0);

    return is_mode_supported;
}

/*
 * setup_initial_pagetables:
 *
 * Build the page tables for Xen that map the following:
 *  1. Calculate page table's level numbers.
 *  2. Init mmu description structure.
 *  3. Check that linker addresses range doesn't overlap
 *     with load addresses range
 *  4. Map all linker addresses and load addresses ( it shouldn't
 *     be 1:1 mapped and will be 1:1 mapped only in case if
 *     linker address is equal to load address ) with
 *     RW permissions by default.
 *  5. Setup proper PTE permissions for each section.
 */
void __init setup_initial_pagetables(void)
{
    struct mmu_desc mmu_desc = { CONFIG_PAGING_LEVELS, 0, NULL, NULL };

    /*
     * Access to _start, _end is always PC-relative thereby when access
     * them we will get load adresses of start and end of Xen.
     * To get linker addresses LOAD_TO_LINK() is required to use.
     */
    unsigned long load_start    = (unsigned long)_start;
    unsigned long load_end      = (unsigned long)_end;
    unsigned long linker_start  = LOAD_TO_LINK(load_start);
    unsigned long linker_end    = LOAD_TO_LINK(load_end);

    if ( (linker_start != load_start) &&
         (linker_start <= load_end) && (load_start <= linker_end) )
    {
        early_printk("(XEN) linker and load address ranges overlap\n");
        die();
    }

    if ( !check_pgtbl_mode_support(&mmu_desc, load_start) )
    {
        early_printk("requested MMU mode isn't supported by CPU\n"
                     "Please choose different in <asm/config.h>\n");
        die();
    }

    mmu_desc.pgtbl_base = stage1_pgtbl_root;
    mmu_desc.next_pgtbl = stage1_pgtbl_nonroot;

    setup_initial_mapping(&mmu_desc,
                          linker_start,
                          linker_end,
                          load_start);
}

void __init noreturn noinline enable_mmu()
{
    /*
     * Calculate a linker time address of the mmu_is_enabled
     * label and update CSR_STVEC with it.
     * MMU is configured in a way where linker addresses are mapped
     * on load addresses so in a case when linker addresses are not equal
     * to load addresses, after MMU is enabled, it will cause
     * an exception and jump to linker time addresses.
     * Otherwise if load addresses are equal to linker addresses the code
     * after mmu_is_enabled label will be executed without exception.
     */
    csr_write(CSR_STVEC, LOAD_TO_LINK((unsigned long)&&mmu_is_enabled));

    /* Ensure page table writes precede loading the SATP */
    sfence_vma();

    /* Enable the MMU and load the new pagetable for Xen */
    csr_write(CSR_SATP,
              PFN_DOWN((unsigned long)stage1_pgtbl_root) |
              RV_STAGE1_MODE << SATP_MODE_SHIFT);

    asm volatile ( ".p2align 2" );
 mmu_is_enabled:
    /*
     * Stack should be re-inited as:
     * 1. Right now an address of the stack is relative to load time
     *    addresses what will cause an issue in case of load start address
     *    isn't equal to linker start address.
     * 2. Addresses in stack are all load time relative which can be an
     *    issue in case when load start address isn't equal to linker
     *    start address.
     *
     * We can't return to the caller because the stack was reseted
     * and it may have stash some variable on the stack.
     * Jump to a brand new function as the stack was reseted
     */

    switch_stack_and_jump((unsigned long)cpu0_boot_stack + STACK_SIZE,
                          cont_after_mmu_is_enabled);
}
