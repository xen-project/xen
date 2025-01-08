/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/llc-coloring.h>
#include <xen/mm.h>
#include <xen/pfn.h>

#include <asm/setup.h>
#include <asm/static-memory.h>
#include <asm/static-shmem.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

static DEFINE_PAGE_TABLE(xen_first_id);
static DEFINE_PAGE_TABLE(xen_second_id);
static DEFINE_PAGE_TABLE(xen_third_id);

/*
 * The identity mapping may start at physical address 0. So we don't want
 * to keep it mapped longer than necessary.
 *
 * When this is called, we are still using the boot_pgtable.
 *
 * We need to prepare the identity mapping for both the boot page tables
 * and runtime page tables.
 *
 * The logic to create the entry is slightly different because Xen may
 * be running at a different location at runtime.
 */
static void __init prepare_boot_identity_mapping(void)
{
    paddr_t id_addr = virt_to_maddr(_start);
    lpae_t pte;
    DECLARE_OFFSETS(id_offsets, id_addr);

    /*
     * We will be re-using the boot ID tables. They may not have been
     * zeroed but they should be unlinked. So it is fine to use
     * clear_page().
     */
    clear_page(boot_first_id);
    clear_page(boot_second_id);
    clear_page(boot_third_id);

    if ( id_offsets[0] >= IDENTITY_MAPPING_AREA_NR_L0 )
        panic("Cannot handle ID mapping above %uTB\n",
              IDENTITY_MAPPING_AREA_NR_L0 >> 1);

    /* Link first ID table */
    pte = mfn_to_xen_entry(virt_to_mfn(boot_first_id), MT_NORMAL);
    pte.pt.table = 1;
    pte.pt.xn = 0;

    write_pte(&boot_pgtable[id_offsets[0]], pte);

    /* Link second ID table */
    pte = mfn_to_xen_entry(virt_to_mfn(boot_second_id), MT_NORMAL);
    pte.pt.table = 1;
    pte.pt.xn = 0;

    write_pte(&boot_first_id[id_offsets[1]], pte);

    /* Link third ID table */
    pte = mfn_to_xen_entry(virt_to_mfn(boot_third_id), MT_NORMAL);
    pte.pt.table = 1;
    pte.pt.xn = 0;

    write_pte(&boot_second_id[id_offsets[2]], pte);

    /* The mapping in the third table will be created at a later stage */
}

static void __init prepare_runtime_identity_mapping(void)
{
    paddr_t id_addr = virt_to_maddr(_start);
    lpae_t pte;
    DECLARE_OFFSETS(id_offsets, id_addr);

    if ( id_offsets[0] >= IDENTITY_MAPPING_AREA_NR_L0 )
        panic("Cannot handle ID mapping above %uTB\n",
              IDENTITY_MAPPING_AREA_NR_L0 >> 1);

    /* Link first ID table */
    pte = pte_of_xenaddr((vaddr_t)xen_first_id);
    pte.pt.table = 1;
    pte.pt.xn = 0;

    write_pte(&xen_pgtable[id_offsets[0]], pte);

    /* Link second ID table */
    pte = pte_of_xenaddr((vaddr_t)xen_second_id);
    pte.pt.table = 1;
    pte.pt.xn = 0;

    write_pte(&xen_first_id[id_offsets[1]], pte);

    /* Link third ID table */
    pte = pte_of_xenaddr((vaddr_t)xen_third_id);
    pte.pt.table = 1;
    pte.pt.xn = 0;

    write_pte(&xen_second_id[id_offsets[2]], pte);

    /* The mapping in the third table will be created at a later stage */
}

void __init arch_setup_page_tables(void)
{
    prepare_boot_identity_mapping();
    prepare_runtime_identity_mapping();
}

/*
 * Enable/disable the identity mapping in the live page-tables (i.e.
 * the one pointed by TTBR_EL2).
 *
 * Note that nested call (e.g. enable=true, enable=true) is not
 * supported.
 */
static void update_identity_mapping(bool enable)
{
    paddr_t id_addr = virt_to_maddr(_start);
    int rc;

    if ( enable )
        rc = map_pages_to_xen(id_addr, maddr_to_mfn(id_addr), 1,
                              PAGE_HYPERVISOR_RX);
    else
        rc = destroy_xen_mappings(id_addr, id_addr + PAGE_SIZE);

    BUG_ON(rc);
}

void update_boot_mapping(bool enable)
{
    update_identity_mapping(enable);
}

extern void switch_ttbr_id(uint64_t ttbr);
extern void relocate_xen(uint64_t ttbr, void *src, void *dst, size_t len);

typedef void (switch_ttbr_fn)(uint64_t ttbr);
typedef void (relocate_xen_fn)(uint64_t ttbr, void *src, void *dst, size_t len);

#ifdef CONFIG_LLC_COLORING
void __init relocate_and_switch_ttbr(uint64_t ttbr)
{
    vaddr_t id_addr = virt_to_maddr(relocate_xen);
    relocate_xen_fn *fn = (relocate_xen_fn *)id_addr;
    lpae_t pte;

    /* Enable the identity mapping in the boot page tables */
    update_identity_mapping(true);

    /* Enable the identity mapping in the runtime page tables */
    pte = pte_of_xenaddr((vaddr_t)relocate_xen);
    pte.pt.table = 1;
    pte.pt.xn = 0;
    pte.pt.ro = 1;
    write_pte(&xen_third_id[third_table_offset(id_addr)], pte);

    /* Relocate Xen and switch TTBR */
    fn(ttbr, _start, (void *)BOOT_RELOC_VIRT_START, _end - _start);

    /*
     * Disable the identity mapping in the runtime page tables.
     * Note it is not necessary to disable it in the boot page tables
     * because they are not going to be used by this CPU anymore.
     */
    update_identity_mapping(false);
}
#endif

void __init switch_ttbr(uint64_t ttbr)
{
    vaddr_t id_addr = virt_to_maddr(switch_ttbr_id);
    switch_ttbr_fn *fn = (switch_ttbr_fn *)id_addr;
    lpae_t pte;

    /* Enable the identity mapping in the boot page tables */
    update_identity_mapping(true);

    /* Enable the identity mapping in the runtime page tables */
    pte = pte_of_xenaddr((vaddr_t)switch_ttbr_id);
    pte.pt.table = 1;
    pte.pt.xn = 0;
    pte.pt.ro = 1;
    write_pte(&xen_third_id[third_table_offset(id_addr)], pte);

    /* Switch TTBR */
    fn(ttbr);

    /*
     * Disable the identity mapping in the runtime page tables.
     * Note it is not necessary to disable it in the boot page tables
     * because they are not going to be used by this CPU anymore.
     */
    update_identity_mapping(false);
}

/* Map the region in the directmap area. */
static void __init setup_directmap_mappings(unsigned long base_mfn,
                                            unsigned long nr_mfns)
{
    int rc;

    /* First call sets the directmap physical and virtual offset. */
    if ( mfn_eq(directmap_mfn_start, INVALID_MFN) )
    {
        unsigned long mfn_gb = base_mfn & ~((FIRST_SIZE >> PAGE_SHIFT) - 1);

        directmap_mfn_start = _mfn(base_mfn);
        directmap_base_pdx = mfn_to_pdx(_mfn(base_mfn));
        /*
         * The base address may not be aligned to the first level
         * size (e.g. 1GB when using 4KB pages). This would prevent
         * superpage mappings for all the regions because the virtual
         * address and machine address should both be suitably aligned.
         *
         * Prevent that by offsetting the start of the directmap virtual
         * address.
         */
        directmap_virt_start = DIRECTMAP_VIRT_START +
            (base_mfn - mfn_gb) * PAGE_SIZE;
    }

    if ( base_mfn < mfn_x(directmap_mfn_start) )
        panic("cannot add directmap mapping at %lx below heap start %lx\n",
              base_mfn, mfn_x(directmap_mfn_start));

    rc = map_pages_to_xen((vaddr_t)__mfn_to_virt(base_mfn),
                          _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");
}

void __init setup_mm(void)
{
    const struct membanks *banks = bootinfo_get_mem();
    paddr_t ram_start = INVALID_PADDR;
    paddr_t ram_end = 0;
    paddr_t ram_size = 0;
    unsigned int i;

    init_pdx();

    /*
     * We need some memory to allocate the page-tables used for the directmap
     * mappings. But some regions may contain memory already allocated
     * for other uses (e.g. modules, reserved-memory...).
     *
     * For simplicity, add all the free regions in the boot allocator.
     */
    populate_boot_allocator();

    total_pages = 0;

    for ( i = 0; i < banks->nr_banks; i++ )
    {
        const struct membank *bank = &banks->bank[i];
        paddr_t bank_end = bank->start + bank->size;

        ram_size = ram_size + bank->size;
        ram_start = min(ram_start, bank->start);
        ram_end = max(ram_end, bank_end);

        setup_directmap_mappings(PFN_DOWN(bank->start),
                                 PFN_DOWN(bank->size));
    }

    total_pages += ram_size >> PAGE_SHIFT;

    directmap_virt_end = XENHEAP_VIRT_START + ram_end - ram_start;
    directmap_mfn_start = maddr_to_mfn(ram_start);
    directmap_mfn_end = maddr_to_mfn(ram_end);

    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    init_staticmem_pages();
    init_sharedmem_pages();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
