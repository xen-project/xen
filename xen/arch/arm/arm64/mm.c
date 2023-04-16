/* SPDX-License-Identifier: GPL-2.0 */

#include <xen/init.h>
#include <xen/mm.h>

#include <asm/setup.h>

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
        panic("Cannot handle ID mapping above 2TB\n");

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
        panic("Cannot handle ID mapping above 2TB\n");

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

void update_identity_mapping(bool enable)
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

extern void switch_ttbr_id(uint64_t ttbr);

typedef void (switch_ttbr_fn)(uint64_t ttbr);

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
