/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/cache.h>
#include <xen/compiler.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/macros.h>
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

static unsigned long __ro_after_init phys_offset;

#define LOAD_TO_LINK(addr) ((unsigned long)(addr) - phys_offset)
#define LINK_TO_LOAD(addr) ((unsigned long)(addr) + phys_offset)

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
 *
 * CONFIG_PAGING_LEVELS page tables are needed for the identity mapping,
 * except that the root page table is shared with the initial mapping
 */
#define PGTBL_INITIAL_COUNT ((CONFIG_PAGING_LEVELS - 1) * 2 + 1)

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
    bool is_identity_mapping = map_start == pa_start;

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
                unsigned long addr = is_identity_mapping
                                     ? page_addr : LINK_TO_LOAD(page_addr);
                pte_t pte_to_be_written;

                index = pt_index(0, page_addr);

                if ( is_kernel_text(addr) ||
                     is_kernel_inittext(addr) )
                        permissions =
                            PTE_EXECUTABLE | PTE_READABLE | PTE_VALID;

                if ( is_kernel_rodata(addr) )
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
    unsigned long xen_size = (unsigned long)(_end - _start);

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

    unsigned long ident_start;
    unsigned long ident_end;

    /*
     * If the overlapping check will be removed then remove_identity_mapping()
     * logic should be updated.
     */
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

    if ( linker_start == load_start )
        return;

    ident_start = (unsigned long)turn_on_mmu & XEN_PT_LEVEL_MAP_MASK(0);
    ident_end = ident_start + PAGE_SIZE;

    setup_initial_mapping(&mmu_desc,
                          ident_start,
                          ident_end,
                          ident_start);
}

void __init remove_identity_mapping(void)
{
    unsigned int i;
    pte_t *pgtbl;
    unsigned int index, xen_index;
    unsigned long ident_start =
        LINK_TO_LOAD(turn_on_mmu) & XEN_PT_LEVEL_MAP_MASK(0);

    for ( pgtbl = stage1_pgtbl_root, i = CONFIG_PAGING_LEVELS; i; i-- )
    {
        index = pt_index(i - 1, ident_start);
        xen_index = pt_index(i - 1, XEN_VIRT_START);

        if ( index != xen_index )
        {
            pgtbl[index].pte = 0;
            break;
        }

        pgtbl = (pte_t *)LOAD_TO_LINK(pte_to_paddr(pgtbl[index]));
    }
}

/*
 * calc_phys_offset() should be used before MMU is enabled because access to
 * start() is PC-relative and in case when load_addr != linker_addr phys_offset
 * will have an incorrect value
 */
unsigned long __init calc_phys_offset(void)
{
    volatile unsigned long load_start = (unsigned long)_start;

    phys_offset = load_start - XEN_VIRT_START;
    return phys_offset;
}
