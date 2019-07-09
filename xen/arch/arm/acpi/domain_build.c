/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <acpi/actables.h>
#include <asm/kernel.h>
#include <asm/domain_build.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

#define ACPI_DOM0_FDT_MIN_SIZE 4096

static int __init acpi_iomem_deny_access(struct domain *d)
{
    acpi_status status;
    struct acpi_table_spcr *spcr = NULL;
    unsigned long mfn;
    int rc;

    /* Firstly permit full MMIO capabilities. */
    rc = iomem_permit_access(d, 0UL, ~0UL);
    if ( rc )
        return rc;

    /* TODO: Deny MMIO access for SMMU, GIC ITS */
    status = acpi_get_table(ACPI_SIG_SPCR, 0,
                            (struct acpi_table_header **)&spcr);

    if ( ACPI_FAILURE(status) )
    {
        printk("Failed to get SPCR table\n");
        return -EINVAL;
    }

    mfn = spcr->serial_port.address >> PAGE_SHIFT;
    /* Deny MMIO access for UART */
    rc = iomem_deny_access(d, mfn, mfn + 1);
    if ( rc )
        return rc;

    /* Deny MMIO access for GIC regions */
    return gic_iomem_deny_access(d);
}

static int __init acpi_route_spis(struct domain *d)
{
    int i, res;
    struct irq_desc *desc;

    /*
     * Route the IRQ to hardware domain and permit the access.
     * The interrupt type will be set by set by the hardware domain.
     */
    for( i = NR_LOCAL_IRQS; i < vgic_num_irqs(d); i++ )
    {
        /*
         * TODO: Exclude the SPIs SMMU uses which should not be routed to
         * the hardware domain.
         */
        desc = irq_to_desc(i);
        if ( desc->action != NULL)
            continue;

        /* XXX: Shall we use a proper devname? */
        res = map_irq_to_domain(d, i, true, "ACPI");
        if ( res )
            return res;
    }

    return 0;
}

static int __init acpi_make_hypervisor_node(const struct kernel_info *kinfo,
                                            struct membank tbl_add[])
{
    const char compat[] =
        "xen,xen-"__stringify(XEN_VERSION)"."__stringify(XEN_SUBVERSION)"\0"
        "xen,xen";
    int res;
    /* Convenience alias */
    void *fdt = kinfo->fdt;

    dt_dprintk("Create hypervisor node\n");

    /* See linux Documentation/devicetree/bindings/arm/xen.txt */
    res = fdt_begin_node(fdt, "hypervisor");
    if ( res )
        return res;

    /* Cannot use fdt_property_string due to embedded nulls */
    res = fdt_property(fdt, "compatible", compat, sizeof(compat));
    if ( res )
        return res;

    res = acpi_make_efi_nodes(fdt, tbl_add);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

/*
 * Prepare a minimal DTB for Dom0 which contains bootargs, initrd, memory
 * information, EFI table.
 */
static int __init create_acpi_dtb(struct kernel_info *kinfo,
                                  struct membank tbl_add[])
{
    int new_size;
    int ret;

    dt_dprintk("Prepare a min DTB for DOM0\n");

    /* Allocate min size for DT */
    new_size = ACPI_DOM0_FDT_MIN_SIZE;
    kinfo->fdt = xmalloc_bytes(new_size);

    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    /* Create a new empty DT for DOM0 */
    ret = fdt_create(kinfo->fdt, new_size);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish_reservemap(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_begin_node(kinfo->fdt, "");
    if ( ret < 0 )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#address-cells", 2);
    if ( ret )
        return ret;

    ret = fdt_property_cell(kinfo->fdt, "#size-cells", 1);
    if ( ret )
        return ret;

    /* Create a chosen node for DOM0 */
    ret = make_chosen_node(kinfo);
    if ( ret )
        goto err;

    ret = acpi_make_hypervisor_node(kinfo, tbl_add);
    if ( ret )
        goto err;

    ret = fdt_end_node(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);
    return -EINVAL;
}

static void __init acpi_map_other_tables(struct domain *d)
{
    int i;
    unsigned long res;
    u64 addr, size;

    /* Map all ACPI tables to Dom0 using 1:1 mappings. */
    for( i = 0; i < acpi_gbl_root_table_list.count; i++ )
    {
        addr = acpi_gbl_root_table_list.tables[i].address;
        size = acpi_gbl_root_table_list.tables[i].length;
        res = map_regions_p2mt(d,
                               gaddr_to_gfn(addr),
                               PFN_UP(size),
                               maddr_to_mfn(addr),
                               p2m_mmio_direct_c);
        if ( res )
        {
             panic(XENLOG_ERR "Unable to map ACPI region 0x%"PRIx64
                   " - 0x%"PRIx64" in domain\n",
                   addr & PAGE_MASK, PAGE_ALIGN(addr + size) - 1);
        }
    }
}

static int __init acpi_create_rsdp(struct domain *d, struct membank tbl_add[])
{

    struct acpi_table_rsdp *rsdp = NULL;
    u64 addr;
    u64 table_size = sizeof(struct acpi_table_rsdp);
    u8 *base_ptr;
    u8 checksum;

    addr = acpi_os_get_root_pointer();
    if ( !addr  )
    {
        printk("Unable to get acpi root pointer\n");
        return -EINVAL;
    }
    rsdp = acpi_os_map_memory(addr, table_size);
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_RSDP);
    memcpy(base_ptr, rsdp, table_size);
    acpi_os_unmap_memory(rsdp, table_size);

    rsdp = (struct acpi_table_rsdp *)base_ptr;
    /* Replace xsdt_physical_address */
    rsdp->xsdt_physical_address = tbl_add[TBL_XSDT].start;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, rsdp), table_size);
    rsdp->checksum = rsdp->checksum - checksum;

    tbl_add[TBL_RSDP].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_RSDP);
    tbl_add[TBL_RSDP].size = table_size;

    return 0;
}

static void __init acpi_xsdt_modify_entry(u64 entry[],
                                          unsigned long entry_count,
                                          char *signature, u64 addr)
{
    int i;
    struct acpi_table_header *table;
    u64 size = sizeof(struct acpi_table_header);

    for( i = 0; i < entry_count; i++ )
    {
        table = acpi_os_map_memory(entry[i], size);
        if ( ACPI_COMPARE_NAME(table->signature, signature) )
        {
            entry[i] = addr;
            acpi_os_unmap_memory(table, size);
            break;
        }
        acpi_os_unmap_memory(table, size);
    }
}

static int __init acpi_create_xsdt(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_rsdp *rsdp_tbl;
    struct acpi_table_xsdt *xsdt = NULL;
    u64 table_size, addr;
    unsigned long entry_count;
    u8 *base_ptr;
    u8 checksum;

    addr = acpi_os_get_root_pointer();
    if ( !addr )
    {
        printk("Unable to get acpi root pointer\n");
        return -EINVAL;
    }
    rsdp_tbl = acpi_os_map_memory(addr, sizeof(struct acpi_table_rsdp));
    table = acpi_os_map_memory(rsdp_tbl->xsdt_physical_address,
                               sizeof(struct acpi_table_header));

    /* Add place for STAO table in XSDT table */
    table_size = table->length + sizeof(u64);
    entry_count = (table->length - sizeof(struct acpi_table_header))
                  / sizeof(u64);
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_XSDT);
    memcpy(base_ptr, table, table->length);
    acpi_os_unmap_memory(table, sizeof(struct acpi_table_header));
    acpi_os_unmap_memory(rsdp_tbl, sizeof(struct acpi_table_rsdp));

    xsdt = (struct acpi_table_xsdt *)base_ptr;
    acpi_xsdt_modify_entry(xsdt->table_offset_entry, entry_count,
                           ACPI_SIG_FADT, tbl_add[TBL_FADT].start);
    acpi_xsdt_modify_entry(xsdt->table_offset_entry, entry_count,
                           ACPI_SIG_MADT, tbl_add[TBL_MADT].start);
    xsdt->table_offset_entry[entry_count] = tbl_add[TBL_STAO].start;

    xsdt->header.length = table_size;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, xsdt), table_size);
    xsdt->header.checksum -= checksum;

    tbl_add[TBL_XSDT].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_XSDT);
    tbl_add[TBL_XSDT].size = table_size;

    return 0;
}

static int __init acpi_create_stao(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_stao *stao = NULL;
    u32 table_size = sizeof(struct acpi_table_stao);
    u32 offset = acpi_get_table_offset(tbl_add, TBL_STAO);
    acpi_status status;
    u8 *base_ptr, checksum;

    /* Copy OEM and ASL compiler fields from another table, use MADT */
    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        printk("STAO: Failed to get MADT table, %s\n", msg);
        return -EINVAL;
    }

    base_ptr = d->arch.efi_acpi_table + offset;
    memcpy(base_ptr, table, sizeof(struct acpi_table_header));

    stao = (struct acpi_table_stao *)base_ptr;
    memcpy(stao->header.signature, ACPI_SIG_STAO, 4);
    stao->header.revision = 1;
    stao->header.length = table_size;
    stao->ignore_uart = 1;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, stao), table_size);
    stao->header.checksum -= checksum;

    tbl_add[TBL_STAO].start = d->arch.efi_acpi_gpa + offset;
    tbl_add[TBL_STAO].size = table_size;

    return 0;
}

static int __init acpi_create_madt(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_madt *madt = NULL;
    struct acpi_subtable_header *header;
    struct acpi_madt_generic_distributor *gicd;
    u32 table_size = sizeof(struct acpi_table_madt);
    u32 offset = acpi_get_table_offset(tbl_add, TBL_MADT);
    int ret;
    acpi_status status;
    u8 *base_ptr, checksum;

    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        printk("Failed to get MADT table, %s\n", msg);
        return -EINVAL;
    }

    base_ptr = d->arch.efi_acpi_table + offset;
    memcpy(base_ptr, table, table_size);

    /* Add Generic Distributor. */
    header = acpi_table_get_entry_madt(ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR, 0);
    if ( !header )
    {
        printk("Can't get GICD entry\n");
        return -EINVAL;
    }
    gicd = container_of(header, struct acpi_madt_generic_distributor, header);
    memcpy(base_ptr + table_size, gicd,
                sizeof(struct acpi_madt_generic_distributor));
    table_size += sizeof(struct acpi_madt_generic_distributor);

    /* Add other subtables. */
    ret = gic_make_hwdom_madt(d, offset + table_size);
    if ( ret < 0 )
    {
        printk("Failed to get other subtables\n");
        return -EINVAL;
    }
    table_size += ret;

    madt = (struct acpi_table_madt *)base_ptr;
    madt->header.length = table_size;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, madt), table_size);
    madt->header.checksum -= checksum;

    tbl_add[TBL_MADT].start = d->arch.efi_acpi_gpa + offset;
    tbl_add[TBL_MADT].size = table_size;

    return 0;
}

static int __init acpi_create_fadt(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_fadt *fadt = NULL;
    u64 table_size;
    acpi_status status;
    u8 *base_ptr;
    u8 checksum;

    status = acpi_get_table(ACPI_SIG_FADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        printk("Failed to get FADT table, %s\n", msg);
        return -EINVAL;
    }

    table_size = table->length;
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_FADT);
    memcpy(base_ptr, table, table_size);
    fadt = (struct acpi_table_fadt *)base_ptr;

    /* Set PSCI_COMPLIANT and PSCI_USE_HVC */
    fadt->arm_boot_flags |= (ACPI_FADT_PSCI_COMPLIANT | ACPI_FADT_PSCI_USE_HVC);
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, fadt), table_size);
    fadt->header.checksum -= checksum;

    tbl_add[TBL_FADT].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_FADT);
    tbl_add[TBL_FADT].size = table_size;

    return 0;
}

static int __init estimate_acpi_efi_size(struct domain *d,
                                         struct kernel_info *kinfo)
{
    size_t efi_size, acpi_size, madt_size;
    u64 addr;
    struct acpi_table_rsdp *rsdp_tbl;
    struct acpi_table_header *table;

    efi_size = estimate_efi_size(kinfo->mem.nr_banks);

    acpi_size = ROUNDUP(sizeof(struct acpi_table_fadt), 8);
    acpi_size += ROUNDUP(sizeof(struct acpi_table_stao), 8);

    madt_size = gic_get_hwdom_madt_size(d);
    acpi_size += ROUNDUP(madt_size, 8);

    addr = acpi_os_get_root_pointer();
    if ( !addr )
    {
        printk("Unable to get acpi root pointer\n");
        return -EINVAL;
    }

    rsdp_tbl = acpi_os_map_memory(addr, sizeof(struct acpi_table_rsdp));
    if ( !rsdp_tbl )
    {
        printk("Unable to map RSDP table\n");
        return -EINVAL;
    }

    table = acpi_os_map_memory(rsdp_tbl->xsdt_physical_address,
                               sizeof(struct acpi_table_header));
    acpi_os_unmap_memory(rsdp_tbl, sizeof(struct acpi_table_rsdp));
    if ( !table )
    {
        printk("Unable to map XSDT table\n");
        return -EINVAL;
    }

    /* Add place for STAO table in XSDT table */
    acpi_size += ROUNDUP(table->length + sizeof(u64), 8);
    acpi_os_unmap_memory(table, sizeof(struct acpi_table_header));

    acpi_size += ROUNDUP(sizeof(struct acpi_table_rsdp), 8);
    d->arch.efi_acpi_len = PAGE_ALIGN(ROUNDUP(efi_size, 8)
                                      + ROUNDUP(acpi_size, 8));

    return 0;
}

int __init prepare_acpi(struct domain *d, struct kernel_info *kinfo)
{
    int rc = 0;
    int order;
    struct membank tbl_add[TBL_MMAX] = {};

    rc = estimate_acpi_efi_size(d, kinfo);
    if ( rc != 0 )
        return rc;

    order = get_order_from_bytes(d->arch.efi_acpi_len);
    d->arch.efi_acpi_table = alloc_xenheap_pages(order, 0);
    if ( d->arch.efi_acpi_table == NULL )
    {
        printk("unable to allocate memory!\n");
        return -ENOMEM;
    }
    memset(d->arch.efi_acpi_table, 0, d->arch.efi_acpi_len);

    /*
     * For ACPI, Dom0 doesn't use kinfo->gnttab_start to get the grant table
     * region. So we use it as the ACPI table mapped address. Also it needs to
     * check if the size of grant table region is enough for those ACPI tables.
     */
    d->arch.efi_acpi_gpa = kinfo->gnttab_start;
    if ( kinfo->gnttab_size < d->arch.efi_acpi_len )
    {
        printk("The grant table region is not enough to fit the ACPI tables!\n");
        return -EINVAL;
    }

    rc = acpi_create_fadt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_madt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_stao(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_xsdt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_rsdp(d, tbl_add);
    if ( rc != 0 )
        return rc;

    acpi_map_other_tables(d);
    acpi_create_efi_system_table(d, tbl_add);
    acpi_create_efi_mmap_table(d, &kinfo->mem, tbl_add);

    /* Map the EFI and ACPI tables to Dom0 */
    rc = map_regions_p2mt(d,
                          gaddr_to_gfn(d->arch.efi_acpi_gpa),
                          PFN_UP(d->arch.efi_acpi_len),
                          virt_to_mfn(d->arch.efi_acpi_table),
                          p2m_mmio_direct_c);
    if ( rc != 0 )
    {
        printk(XENLOG_ERR "Unable to map EFI/ACPI table 0x%"PRIx64
               " - 0x%"PRIx64" in domain %d\n",
               d->arch.efi_acpi_gpa & PAGE_MASK,
               PAGE_ALIGN(d->arch.efi_acpi_gpa + d->arch.efi_acpi_len) - 1,
               d->domain_id);
        return rc;
    }

    /*
     * Flush the cache for this region, otherwise DOM0 may read wrong data when
     * the cache is disabled.
     */
    clean_and_invalidate_dcache_va_range(d->arch.efi_acpi_table,
                                         d->arch.efi_acpi_len);

    rc = create_acpi_dtb(kinfo, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_route_spis(d);
    if ( rc != 0 )
        return rc;

    rc = acpi_iomem_deny_access(d);
    if ( rc != 0 )
        return rc;

    /*
     * All PPIs have been registered, allocate the event channel
     * interrupts.
     */
    evtchn_allocate(d);

    return 0;
}
