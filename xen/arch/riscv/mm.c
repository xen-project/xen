/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/bug.h>
#include <xen/compiler.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/libfdt/libfdt.h>
#include <xen/macros.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/sections.h>
#include <xen/sizes.h>

#include <asm/early_printk.h>
#include <asm/csr.h>
#include <asm/current.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/processor.h>

struct mmu_desc {
    unsigned int num_levels;
    unsigned int pgtbl_count;
    pte_t *next_pgtbl;
    pte_t *pgtbl_base;
};

unsigned long __ro_after_init phys_offset; /* = load_start - XEN_VIRT_START */

#define LOAD_TO_LINK(addr) ((unsigned long)(addr) - phys_offset)

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

pte_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
xen_fixmap[PAGETABLE_ENTRIES];

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
                                     ? page_addr : virt_to_maddr(page_addr);
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

void __init setup_fixmap_mappings(void)
{
    pte_t *pte, tmp;
    unsigned int i;

    BUILD_BUG_ON(FIX_LAST >= PAGETABLE_ENTRIES);

    pte = &stage1_pgtbl_root[pt_index(HYP_PT_ROOT_LEVEL, FIXMAP_ADDR(0))];

    /*
     * In RISC-V page table levels are numbered from Lx to L0 where
     * x is the highest page table level for currect  MMU mode ( for example,
     * for Sv39 has 3 page tables so the x = 2 (L2 -> L1 -> L0) ).
     *
     * In this cycle we want to find L1 page table because as L0 page table
     * xen_fixmap[] will be used.
     */
    for ( i = HYP_PT_ROOT_LEVEL; i-- > 1; )
    {
        BUG_ON(!pte_is_valid(*pte));

        pte = (pte_t *)LOAD_TO_LINK(pte_to_paddr(*pte));
        pte = &pte[pt_index(i, FIXMAP_ADDR(0))];
    }

    BUG_ON(pte_is_valid(*pte));

    tmp = paddr_to_pte(virt_to_maddr(&xen_fixmap), PTE_TABLE);
    write_pte(pte, tmp);

    RISCV_FENCE(rw, rw);
    sfence_vma();

    /*
     * We only need the zeroeth table allocated, but not the PTEs set, because
     * set_fixmap() will set them on the fly.
     */
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
        virt_to_maddr(turn_on_mmu) & XEN_PT_LEVEL_MAP_MASK(0);

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

void put_page(struct page_info *page)
{
    BUG_ON("unimplemented");
}

void arch_dump_shared_mem_info(void)
{
    BUG_ON("unimplemented");
}

int xenmem_add_to_physmap_one(struct domain *d, unsigned int space,
                              union add_to_physmap_extra extra,
                              unsigned long idx, gfn_t gfn)
{
    BUG_ON("unimplemented");

    return 0;
}

void share_xen_page_with_guest(struct page_info *page, struct domain *d,
                               enum XENSHARE_flags flags)
{
    BUG_ON("unimplemented");
}

void * __init early_fdt_map(paddr_t fdt_paddr)
{
    /* We are using 2MB superpage for mapping the FDT */
    paddr_t base_paddr = fdt_paddr & XEN_PT_LEVEL_MAP_MASK(1);
    paddr_t offset;
    void *fdt_virt;
    uint32_t size;
    int rc;

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

    /* The FDT is mapped using 2MB superpage */
    BUILD_BUG_ON(BOOT_FDT_VIRT_START % MB(2));

    rc = map_pages_to_xen(BOOT_FDT_VIRT_START, maddr_to_mfn(base_paddr),
                          MB(2) >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_RO);
    if ( rc )
        panic("Unable to map the device-tree.\n");

    offset = fdt_paddr % XEN_PT_LEVEL_SIZE(1);
    fdt_virt = (void *)BOOT_FDT_VIRT_START + offset;

    if ( fdt_magic(fdt_virt) != FDT_MAGIC )
        return NULL;

    size = fdt_totalsize(fdt_virt);
    if ( size > BOOT_FDT_VIRT_SIZE )
        return NULL;

    if ( (offset + size) > MB(2) )
    {
        rc = map_pages_to_xen(BOOT_FDT_VIRT_START + MB(2),
                              maddr_to_mfn(base_paddr + MB(2)),
                              MB(2) >> PAGE_SHIFT,
                              PAGE_HYPERVISOR_RO);
        if ( rc )
            panic("Unable to map the device-tree\n");
    }

    return fdt_virt;
}

vaddr_t __ro_after_init directmap_virt_start = DIRECTMAP_VIRT_START;

struct page_info *__ro_after_init frametable_virt_start = frame_table;

#ifndef CONFIG_RISCV_32

/*
 * Map a frame table to cover physical addresses ps through pe.
 * This function is expected to be called only once.
 */
static void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    paddr_t aligned_ps = ROUNDUP(ps, PAGE_SIZE);
    paddr_t aligned_pe = ROUNDDOWN(pe, PAGE_SIZE);
    unsigned long nr_mfns = PFN_DOWN(aligned_pe - aligned_ps);
    unsigned long frametable_size = nr_mfns * sizeof(*frame_table);
    mfn_t base_mfn;

    frametable_virt_start -= paddr_to_pfn(aligned_ps);

    if ( frametable_size > FRAMETABLE_SIZE )
        panic("The frametable cannot cover [%#"PRIpaddr", %#"PRIpaddr")\n",
              ps, pe);

    /*
     * align base_mfn and frametable_size to MB(2) to have superpage mapping
     * in map_pages_to_xen()
     */
    frametable_size = ROUNDUP(frametable_size, MB(2));
    base_mfn = alloc_boot_pages(PFN_DOWN(frametable_size), PFN_DOWN(MB(2)));

    if ( map_pages_to_xen(FRAMETABLE_VIRT_START, base_mfn,
                          PFN_DOWN(frametable_size),
                          PAGE_HYPERVISOR_RW) )
        panic("frametable mappings failed: %#lx -> %#lx\n",
              FRAMETABLE_VIRT_START, mfn_x(base_mfn));

    memset(&frame_table[0], 0, nr_mfns * sizeof(*frame_table));
    memset(&frame_table[nr_mfns], -1,
           frametable_size - (nr_mfns * sizeof(*frame_table)));
}

/* Map the region in the directmap area. */
static void __init setup_directmap_mappings(unsigned long base_mfn,
                                            unsigned long nr_mfns)
{
    static mfn_t __initdata directmap_mfn_start = INVALID_MFN_INITIALIZER;

    mfn_t base_mfn_t = _mfn(base_mfn);
    unsigned long base_addr = mfn_to_maddr(base_mfn_t);
    unsigned long high_bits_mask = XEN_PT_LEVEL_MAP_MASK(HYP_PT_ROOT_LEVEL);
    int res;

    /* First call sets the directmap physical and virtual offset. */
    if ( mfn_eq(directmap_mfn_start, INVALID_MFN) )
    {
        directmap_mfn_start = base_mfn_t;

       /*
        * The base address may not be aligned to the second level
        * size in case of Sv39 (e.g. 1GB when using 4KB pages).
        * This would prevent superpage mappings for all the regions
        * because the virtual address and machine address should
        * both be suitably aligned.
        *
        * Prevent that by offsetting the start of the directmap virtual
        * address.
        */
        directmap_virt_start -= (base_addr & high_bits_mask);
    }

    if ( base_mfn < mfn_x(directmap_mfn_start) )
        panic("can't add directmap mapping at %#lx below directmap start %#lx\n",
              base_mfn, mfn_x(directmap_mfn_start));

    if ( (res = map_pages_to_xen((vaddr_t)mfn_to_virt(base_mfn),
                          base_mfn_t, nr_mfns,
                          PAGE_HYPERVISOR_RW)) )
        panic("Directmap mappings for [%#"PRIpaddr", %#"PRIpaddr") failed: %d\n",
              mfn_to_maddr(base_mfn_t),
              mfn_to_maddr(mfn_add(base_mfn_t, nr_mfns)), res);
}

#else /* CONFIG_RISCV_32 */
#error setup_{directmap,frametable}_mapping() should be implemented for RV_32
#endif

/*
 * Setup memory management
 *
 * RISC-V 64 has a large virtual address space (the minimum supported
 * MMU mode is Sv39, which provides GBs of VA space).
 *
 * The directmap_virt_start is shifted lower in the VA space to
 * (DIRECTMAP_VIRT_START - masked_low_bits_of_ram_start_address) to avoid
 * wasting a large portion of the directmap space, this also allows for simple
 * VA <-> PA translations. Also aligns DIRECTMAP_VIRT_START to a GB boundary
 * (for Sv39; for other MMU mode boundaries will be bigger ) by masking the
 * bits of the RAM start address to enable the use of superpages in
 * map_pages_to_xen().
 *
 * The frametable is mapped starting from physical address RAM_START, so an
 * additional offset is applied in setup_frametable_mappings() to initialize
 * frametable_virt_start to minimize wasting of VA space and simplifying
 * page_to_mfn() and mfn_to_page() translations.
 */
void __init setup_mm(void)
{
    const struct membanks *banks = bootinfo_get_mem();
    paddr_t ram_start = INVALID_PADDR;
    paddr_t ram_end = 0;
    unsigned int i;

    /*
     * We need some memory to allocate the page-tables used for the directmap
     * mappings. But some regions may contain memory already allocated
     * for other uses (e.g. modules, reserved-memory...).
     *
     * For simplicity, add all the free regions in the boot allocator.
     */
    populate_boot_allocator();

    if ( !banks->nr_banks )
        panic("bank->nr_banks shouldn't be zero, check memory node in dts\n");

    for ( i = 0; i < banks->nr_banks; i++ )
    {
        const struct membank *bank = &banks->bank[i];
        paddr_t bank_start = ROUNDUP(bank->start, PAGE_SIZE);
        paddr_t bank_end = ROUNDDOWN(bank->start + bank->size, PAGE_SIZE);
        unsigned long bank_size = bank_end - bank_start;

        ram_start = min(ram_start, bank_start);
        ram_end = max(ram_end, bank_end);

        setup_directmap_mappings(PFN_DOWN(bank_start), PFN_DOWN(bank_size));
    }

    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);
}

void *__init arch_vmap_virt_end(void)
{
    return (void *)(VMAP_VIRT_START + VMAP_VIRT_SIZE);
}
