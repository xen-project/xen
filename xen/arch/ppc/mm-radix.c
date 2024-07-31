/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/sections.h>
#include <xen/types.h>
#include <xen/lib.h>

#include <asm/byteorder.h>
#include <asm/early_printk.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/regs.h>
#include <asm/msr.h>

void enable_mmu(void);

#ifdef CONFIG_DEBUG
#define radix_dprintk(msg, ...) printk(XENLOG_DEBUG msg, ## __VA_ARGS__)
#else
#define radix_dprintk(...)
#endif

#define INITIAL_LVL1_PD_COUNT      1
#define INITIAL_LVL2_LVL3_PD_COUNT 2
#define INITIAL_LVL4_PT_COUNT      256

static size_t __initdata initial_lvl1_pd_pool_used;
static struct lvl1_pd initial_lvl1_pd_pool[INITIAL_LVL1_PD_COUNT];

static size_t __initdata initial_lvl2_lvl3_pd_pool_used;
static struct lvl2_pd initial_lvl2_lvl3_pd_pool[INITIAL_LVL2_LVL3_PD_COUNT];

static size_t __initdata initial_lvl4_pt_pool_used;
static struct lvl4_pt initial_lvl4_pt_pool[INITIAL_LVL4_PT_COUNT];

/* Only reserve minimum Partition and Process tables  */
#define PATB_SIZE_LOG2 16 /* Only supported partition table size on POWER9 */
#define PATB_SIZE      (1UL << PATB_SIZE_LOG2)
#define PRTB_SIZE_LOG2 12
#define PRTB_SIZE      (1UL << PRTB_SIZE_LOG2)

static struct patb_entry
    __aligned(PATB_SIZE) initial_patb[PATB_SIZE / sizeof(struct patb_entry)];

static struct prtb_entry
    __aligned(PRTB_SIZE) initial_prtb[PRTB_SIZE / sizeof(struct prtb_entry)];

static __init struct lvl1_pd *lvl1_pd_pool_alloc(void)
{
    if ( initial_lvl1_pd_pool_used >= INITIAL_LVL1_PD_COUNT )
    {
        early_printk("Ran out of space for LVL1 PD!\n");
        die();
    }

    return &initial_lvl1_pd_pool[initial_lvl1_pd_pool_used++];
}

static __init struct lvl2_pd *lvl2_pd_pool_alloc(void)
{
    if ( initial_lvl2_lvl3_pd_pool_used >= INITIAL_LVL2_LVL3_PD_COUNT )
    {
        early_printk("Ran out of space for LVL2/3 PD!\n");
        die();
    }

    return &initial_lvl2_lvl3_pd_pool[initial_lvl2_lvl3_pd_pool_used++];
}

static __init struct lvl3_pd *lvl3_pd_pool_alloc(void)
{
    BUILD_BUG_ON(sizeof(struct lvl3_pd) != sizeof(struct lvl2_pd));

    return (struct lvl3_pd *) lvl2_pd_pool_alloc();
}

static __init struct lvl4_pt *lvl4_pt_pool_alloc(void)
{
    if ( initial_lvl4_pt_pool_used >= INITIAL_LVL4_PT_COUNT )
    {
        early_printk("Ran out of space for LVL4 PT!\n");
        die();
    }

    return &initial_lvl4_pt_pool[initial_lvl4_pt_pool_used++];
}

static void __init setup_initial_mapping(struct lvl1_pd *lvl1,
                                         vaddr_t map_start,
                                         vaddr_t map_end,
                                         paddr_t phys_base)
{
    uint64_t page_addr;

    if ( map_start & ~PAGE_MASK )
    {
        early_printk("Xen _start be aligned to 64k (PAGE_SIZE) boundary\n");
        die();
    }

    if ( phys_base & ~PAGE_MASK )
    {
        early_printk("Xen should be loaded at 64k (PAGE_SIZE) boundary\n");
        die();
    }

    for ( page_addr = map_start; page_addr < map_end; page_addr += PAGE_SIZE )
    {
        struct lvl2_pd *lvl2;
        struct lvl3_pd *lvl3;
        struct lvl4_pt *lvl4;
        pde_t *pde;
        pte_t *pte;

        /* Allocate LVL 2 PD if necessary */
        pde = pt_entry(lvl1, page_addr);
        if ( !pde_is_valid(*pde) )
        {
            lvl2 = lvl2_pd_pool_alloc();
            *pde = paddr_to_pde(__pa(lvl2), PDE_VALID,
                                XEN_PT_ENTRIES_LOG2_LVL_2);
        }
        else
            lvl2 = __va(pde_to_paddr(*pde));

        /* Allocate LVL 3 PD if necessary */
        pde = pt_entry(lvl2, page_addr);
        if ( !pde_is_valid(*pde) )
        {
            lvl3 = lvl3_pd_pool_alloc();
            *pde = paddr_to_pde(__pa(lvl3), PDE_VALID,
                                XEN_PT_ENTRIES_LOG2_LVL_3);
        }
        else
            lvl3 = __va(pde_to_paddr(*pde));

        /* Allocate LVL 4 PT if necessary */
        pde = pt_entry(lvl3, page_addr);
        if ( !pde_is_valid(*pde) )
        {
            lvl4 = lvl4_pt_pool_alloc();
            *pde = paddr_to_pde(__pa(lvl4), PDE_VALID,
                                XEN_PT_ENTRIES_LOG2_LVL_4);
        }
        else
            lvl4 = __va(pde_to_paddr(*pde));

        /* Finally, create PTE in LVL 4 PT */
        pte = pt_entry(lvl4, page_addr);
        if ( !pte_is_valid(*pte) )
        {
            unsigned long paddr = (page_addr - map_start) + phys_base;
            unsigned long flags;

            radix_dprintk("%016lx being mapped to %016lx\n", paddr, page_addr);
            if ( is_kernel_text(page_addr) || is_kernel_inittext(page_addr) )
            {
                radix_dprintk("%016lx being marked as TEXT (RX)\n", page_addr);
                flags = PTE_XEN_RX;
            }
            else if ( is_kernel_rodata(page_addr) )
            {
                radix_dprintk("%016lx being marked as RODATA (RO)\n", page_addr);
                flags = PTE_XEN_RO;
            }
            else
            {
                radix_dprintk("%016lx being marked as DEFAULT (RW)\n", page_addr);
                flags = PTE_XEN_RW;
            }

            *pte = paddr_to_pte(paddr, flags);
            radix_dprintk("%016lx is the result of PTE map\n",
                paddr_to_pte(paddr, flags).pte);
        }
        else
        {
            early_printk("BUG: Tried to create PTE for already-mapped page!");
            die();
        }
    }
}

static void __init setup_partition_table(struct lvl1_pd *root)
{
    unsigned long ptcr;

    /* Configure entry for LPID 0 to enable Radix and point to root PD */
    uint64_t patb0 = RTS_FIELD | __pa(root) | XEN_PT_ENTRIES_LOG2_LVL_1 |
                     PATB0_HR;
    uint64_t patb1 = __pa(initial_prtb) | (PRTB_SIZE_LOG2 - 12) | PATB1_GR;

    initial_patb[0].patb0 = cpu_to_be64(patb0);
    initial_patb[0].patb1 = cpu_to_be64(patb1);

    ptcr = __pa(initial_patb) | (PATB_SIZE_LOG2 - 12);
    mtspr(SPRN_PTCR, ptcr);
}

static void __init setup_process_table(struct lvl1_pd *root)
{
    /* Configure entry for PID 0 to point to root PD */
    uint64_t prtb0 = RTS_FIELD | __pa(root) | XEN_PT_ENTRIES_LOG2_LVL_1;

    initial_prtb[0].prtb0 = cpu_to_be64(prtb0);
}

void __init setup_initial_pagetables(void)
{
    struct lvl1_pd *root = lvl1_pd_pool_alloc();
    unsigned long lpcr;

    setup_initial_mapping(root, (vaddr_t)_start, (vaddr_t)_end, __pa(_start));

    /* Enable Radix mode in LPCR */
    lpcr = mfspr(SPRN_LPCR);
    mtspr(SPRN_LPCR, lpcr | LPCR_UPRT | LPCR_HR);
    early_printk("Enabled radix in LPCR\n");

    /* Set up initial process table */
    setup_process_table(root);

    /* Set up initial partition table */
    setup_partition_table(root);

    /* Flush TLB */
    tlbie_all();
    early_printk("Flushed TLB\n");

    /* Turn on the MMU */
    enable_mmu();
}

/*
 * TODO: Implement the functions below
 */
unsigned long __read_mostly frametable_base_pdx;

void put_page(struct page_info *page)
{
    BUG_ON("unimplemented");
}

void arch_dump_shared_mem_info(void)
{
    BUG_ON("unimplemented");
}

int xenmem_add_to_physmap_one(struct domain *d,
                              unsigned int space,
                              union add_to_physmap_extra extra,
                              unsigned long idx,
                              gfn_t gfn)
{
    BUG_ON("unimplemented");
}

int destroy_xen_mappings(unsigned long s, unsigned long e)
{
    BUG_ON("unimplemented");
}

int map_pages_to_xen(unsigned long virt,
                     mfn_t mfn,
                     unsigned long nr_mfns,
                     unsigned int flags)
{
    BUG_ON("unimplemented");
}

int __init populate_pt_range(unsigned long virt, unsigned long nr_mfns)
{
    BUG_ON("unimplemented");
}
