/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Copyright (C) Ashok Raj <ashok.raj@intel.com>
 * Copyright (C) Shaohua Li <shaohua.li@intel.com>
 * Copyright (C) Allen Kay <allen.m.kay@intel.com> - adapted to xen
 */

#include <xen/init.h>
#include <xen/bitmap.h>
#include <xen/errno.h>
#include <xen/kernel.h>
#include <xen/acpi.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/string.h>
#include "dmar.h"
#include "iommu.h"
#include "extern.h"

#undef PREFIX
#define PREFIX VTDPREFIX "ACPI DMAR:"
#define DEBUG

#define MIN_SCOPE_LEN (sizeof(struct acpi_pci_path) + \
                       sizeof(struct acpi_dev_scope))

LIST_HEAD(acpi_drhd_units);
LIST_HEAD(acpi_rmrr_units);
LIST_HEAD(acpi_atsr_units);
LIST_HEAD(acpi_rhsa_units);

u8 dmar_host_address_width;

void dmar_scope_add_buses(struct dmar_scope *scope, u16 sec_bus, u16 sub_bus)
{
    sub_bus &= 0xff;
    if (sec_bus > sub_bus)
        return;

    while ( sec_bus <= sub_bus )
        set_bit(sec_bus++, scope->buses);
}

void dmar_scope_remove_buses(struct dmar_scope *scope, u16 sec_bus, u16 sub_bus)
{
    sub_bus &= 0xff;
    if (sec_bus > sub_bus)
        return;

    while ( sec_bus <= sub_bus )
        clear_bit(sec_bus++, scope->buses);
}

static int __init acpi_register_drhd_unit(struct acpi_drhd_unit *drhd)
{
    /*
     * add INCLUDE_ALL at the tail, so scan the list will find it at
     * the very end.
     */
    if ( drhd->include_all )
        list_add_tail(&drhd->list, &acpi_drhd_units);
    else
        list_add(&drhd->list, &acpi_drhd_units);
    return 0;
}

static int __init acpi_register_rmrr_unit(struct acpi_rmrr_unit *rmrr)
{
    list_add(&rmrr->list, &acpi_rmrr_units);
    return 0;
}

static void __init disable_all_dmar_units(void)
{
    struct acpi_drhd_unit *drhd, *_drhd;
    struct acpi_rmrr_unit *rmrr, *_rmrr;
    struct acpi_atsr_unit *atsr, *_atsr;

    list_for_each_entry_safe ( drhd, _drhd, &acpi_drhd_units, list )
    {
        list_del(&drhd->list);
        xfree(drhd);
    }
    list_for_each_entry_safe ( rmrr, _rmrr, &acpi_rmrr_units, list )
    {
        list_del(&rmrr->list);
        xfree(rmrr);
    }
    list_for_each_entry_safe ( atsr, _atsr, &acpi_atsr_units, list )
    {
        list_del(&atsr->list);
        xfree(atsr);
    }
}

static int acpi_ioapic_device_match(
    struct list_head *ioapic_list, unsigned int apic_id)
{
    struct acpi_ioapic_unit *ioapic;
    list_for_each_entry( ioapic, ioapic_list, list ) {
        if (ioapic->apic_id == apic_id)
            return 1;
    }
    return 0;
}

struct acpi_drhd_unit * ioapic_to_drhd(unsigned int apic_id)
{
    struct acpi_drhd_unit *drhd;
    list_for_each_entry( drhd, &acpi_drhd_units, list )
        if ( acpi_ioapic_device_match(&drhd->ioapic_list, apic_id) )
            return drhd;
    return NULL;
}

struct acpi_drhd_unit * iommu_to_drhd(struct iommu *iommu)
{
    struct acpi_drhd_unit *drhd;

    if ( iommu == NULL )
        return NULL;

    list_for_each_entry( drhd, &acpi_drhd_units, list )
        if ( drhd->iommu == iommu )
            return drhd;

    return NULL;
}

struct iommu * ioapic_to_iommu(unsigned int apic_id)
{
    struct acpi_drhd_unit *drhd;

    list_for_each_entry( drhd, &acpi_drhd_units, list )
        if ( acpi_ioapic_device_match(&drhd->ioapic_list, apic_id) )
            return drhd->iommu;
    return NULL;
}

static int __init acpi_register_atsr_unit(struct acpi_atsr_unit *atsr)
{
    /*
     * add ALL_PORTS at the tail, so scan the list will find it at
     * the very end.
     */
    if ( atsr->all_ports )
        list_add_tail(&atsr->list, &acpi_atsr_units);
    else
        list_add(&atsr->list, &acpi_atsr_units);
    return 0;
}

struct acpi_drhd_unit * acpi_find_matched_drhd_unit(struct pci_dev *pdev)
{
    u8 bus, devfn;
    struct acpi_drhd_unit *drhd;
    struct acpi_drhd_unit *include_all = NULL;
    int i;

    if ( pdev == NULL )
        return NULL;

    if ( pdev->info.is_extfn )
    {
        bus = pdev->bus;
        devfn = 0;
    }
    else if ( pdev->info.is_virtfn )
    {
        bus = pdev->info.physfn.bus;
        devfn = PCI_SLOT(pdev->info.physfn.devfn) ? 0 : pdev->info.physfn.devfn;
    }
    else
    {
        bus = pdev->bus;
        devfn = pdev->devfn;
    }

    list_for_each_entry ( drhd, &acpi_drhd_units, list )
    {
        for (i = 0; i < drhd->scope.devices_cnt; i++)
            if ( drhd->scope.devices[i] == PCI_BDF2(bus, devfn) )
                return drhd;

        if ( test_bit(bus, drhd->scope.buses) )
            return drhd;

        if ( drhd->include_all )
            include_all = drhd;
    }
    return include_all;
}

struct acpi_atsr_unit * acpi_find_matched_atsr_unit(u8 bus, u8 devfn)
{
    struct acpi_atsr_unit *atsr;
    struct acpi_atsr_unit *all_ports = NULL;

    list_for_each_entry ( atsr, &acpi_atsr_units, list )
    {
        if ( test_bit(bus, atsr->scope.buses) )
            return atsr;

        if ( atsr->all_ports )
            all_ports = atsr;
    }
    return all_ports;
}

struct acpi_rhsa_unit * drhd_to_rhsa(struct acpi_drhd_unit *drhd)
{
    struct acpi_rhsa_unit *rhsa;

    if ( drhd == NULL )
        return NULL;

    list_for_each_entry ( rhsa, &acpi_rhsa_units, list )
    {
        if ( rhsa->address == drhd->address )
            return rhsa;
    }
    return NULL;
}

/*
 * Count number of devices in device scope.  Do not include PCI sub
 * hierarchies.
 */
static int scope_device_count(void *start, void *end)
{
    struct acpi_dev_scope *scope;
    int count = 0;

    while ( start < end )
    {
        scope = start;
        if ( (scope->length < MIN_SCOPE_LEN) ||
             (scope->dev_type >= ACPI_DEV_ENTRY_COUNT) )
        {
            dprintk(XENLOG_WARNING VTDPREFIX, "Invalid device scope.\n");
            return -EINVAL;
        }

        if ( scope->dev_type == ACPI_DEV_P2PBRIDGE ||
             scope->dev_type == ACPI_DEV_ENDPOINT ||
             scope->dev_type == ACPI_DEV_IOAPIC ||
             scope->dev_type == ACPI_DEV_MSI_HPET )
            count++;

        start += scope->length;
    }

    return count;
}


static int __init acpi_parse_dev_scope(void *start, void *end,
                                       void *acpi_entry, int type)
{
    struct dmar_scope *scope = acpi_entry;
    struct acpi_ioapic_unit *acpi_ioapic_unit;
    struct acpi_dev_scope *acpi_scope;
    u16 bus, sub_bus, sec_bus;
    struct acpi_pci_path *path;
    int depth, cnt, didx = 0;

    if ( (cnt = scope_device_count(start, end)) < 0 )
        return cnt;

    scope->devices_cnt = cnt;
    if ( cnt > 0 )
    {
        scope->devices = xmalloc_array(u16, cnt);
        if ( !scope->devices )
            return -ENOMEM;
        memset(scope->devices, 0, sizeof(u16) * cnt);
    }

    while ( start < end )
    {
        acpi_scope = start;
        path = (struct acpi_pci_path *)(acpi_scope + 1);
        depth = (acpi_scope->length - sizeof(struct acpi_dev_scope))
		    / sizeof(struct acpi_pci_path);
        bus = acpi_scope->start_bus;

        while ( --depth > 0 )
        {
            bus = pci_conf_read8(bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            path++;
        }

        switch ( acpi_scope->dev_type )
        {
        case ACPI_DEV_P2PBRIDGE:
            sec_bus = pci_conf_read8(
                bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            sub_bus = pci_conf_read8(
                bus, path->dev, path->fn, PCI_SUBORDINATE_BUS);
            if ( iommu_verbose )
                dprintk(VTDPREFIX,
                        "  bridge: %x:%x.%x  start = %x sec = %x  sub = %x\n",
                        bus, path->dev, path->fn,
                        acpi_scope->start_bus, sec_bus, sub_bus);

            dmar_scope_add_buses(scope, sec_bus, sub_bus);
            break;

        case ACPI_DEV_MSI_HPET:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "  MSI HPET: %x:%x.%x\n",
                        bus, path->dev, path->fn);
            break;

        case ACPI_DEV_ENDPOINT:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "  endpoint: %x:%x.%x\n",
                        bus, path->dev, path->fn);
            break;

        case ACPI_DEV_IOAPIC:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "  IOAPIC: %x:%x.%x\n",
                        bus, path->dev, path->fn);

            if ( type == DMAR_TYPE )
            {
                struct acpi_drhd_unit *drhd = acpi_entry;
                acpi_ioapic_unit = xmalloc(struct acpi_ioapic_unit);
                if ( !acpi_ioapic_unit )
                    return -ENOMEM;
                acpi_ioapic_unit->apic_id = acpi_scope->enum_id;
                acpi_ioapic_unit->ioapic.bdf.bus = bus;
                acpi_ioapic_unit->ioapic.bdf.dev = path->dev;
                acpi_ioapic_unit->ioapic.bdf.func = path->fn;
                list_add(&acpi_ioapic_unit->list, &drhd->ioapic_list);
            }

            break;
        }
        scope->devices[didx++] = PCI_BDF(bus, path->dev, path->fn);
        start += acpi_scope->length;
   }

    return 0;
}

static int __init acpi_dmar_check_length(
    struct acpi_dmar_entry_header *h, unsigned int min_len)
{
    if ( h->length >= min_len )
        return 0;
    dprintk(XENLOG_ERR VTDPREFIX,
            "Invalid ACPI DMAR entry length: 0x%x\n",
            h->length);
    return -EINVAL;
}

static int __init
acpi_parse_one_drhd(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_drhd * drhd = (struct acpi_table_drhd *)header;
    void *dev_scope_start, *dev_scope_end;
    struct acpi_drhd_unit *dmaru;
    void *addr;
    int ret;
    static int include_all = 0;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*drhd))) != 0 )
        return ret;

    dmaru = xmalloc(struct acpi_drhd_unit);
    if ( !dmaru )
        return -ENOMEM;
    memset(dmaru, 0, sizeof(struct acpi_drhd_unit));

    dmaru->address = drhd->address;
    dmaru->include_all = drhd->flags & 1; /* BIT0: INCLUDE_ALL */
    INIT_LIST_HEAD(&dmaru->ioapic_list);
    if ( iommu_verbose )
        dprintk(VTDPREFIX, "  dmaru->address = %"PRIx64"\n",
                dmaru->address);

    addr = map_to_nocache_virt(0, drhd->address);
    dmaru->ecap = dmar_readq(addr, DMAR_ECAP_REG);

    dev_scope_start = (void *)(drhd + 1);
    dev_scope_end = ((void *)drhd) + header->length;
    ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                               dmaru, DMAR_TYPE);

    if ( dmaru->include_all )
    {
        if ( iommu_verbose )
            dprintk(VTDPREFIX, "  flags: INCLUDE_ALL\n");
        /* Only allow one INCLUDE_ALL */
        if ( include_all )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Only one INCLUDE_ALL device scope is allowed\n");
            ret = -EINVAL;
        }
        include_all = 1;
    }

    if ( ret )
        xfree(dmaru);
    else if ( force_iommu || dmaru->include_all )
        acpi_register_drhd_unit(dmaru);
    else
    {
        u8 b, d, f;
        int i, invalid_cnt = 0;
        void *p;

        for ( i = 0, p = dev_scope_start; i < dmaru->scope.devices_cnt;
              i++, p += ((struct acpi_dev_scope *)p)->length )
        {
            if ( ((struct acpi_dev_scope *)p)->dev_type == ACPI_DEV_IOAPIC ||
                 ((struct acpi_dev_scope *)p)->dev_type == ACPI_DEV_MSI_HPET )
                continue;

            b = PCI_BUS(dmaru->scope.devices[i]);
            d = PCI_SLOT(dmaru->scope.devices[i]);
            f = PCI_FUNC(dmaru->scope.devices[i]);

            if ( pci_device_detect(b, d, f) == 0 )
            {
                dprintk(XENLOG_WARNING VTDPREFIX,
                    "  Non-existent device (%x:%x.%x) is reported "
                    "in this DRHD's scope!\n", b, d, f);
                invalid_cnt++;
            }
        }

        if ( invalid_cnt )
        {
            xfree(dmaru);

            if ( iommu_workaround_bios_bug &&
                 invalid_cnt == dmaru->scope.devices_cnt )
            {
                dprintk(XENLOG_WARNING VTDPREFIX,
                    "  Workaround BIOS bug: ignore the DRHD due to all "
                    "devices under its scope are not PCI discoverable!\n");
            }
            else
            {
                dprintk(XENLOG_WARNING VTDPREFIX,
                    "  The DRHD is invalid due to there are devices under "
                    "its scope are not PCI discoverable! Pls try option "
                    "iommu=force or iommu=workaround_bios_bug if you "
                    "really want VT-d\n");
                ret = -EINVAL;
            }
        }
        else
            acpi_register_drhd_unit(dmaru);
    }

    return ret;
}

static int __init
acpi_parse_one_rmrr(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_rmrr *rmrr = (struct acpi_table_rmrr *)header;
    struct acpi_rmrr_unit *rmrru;
    void *dev_scope_start, *dev_scope_end;
    u64 base_addr = rmrr->base_address, end_addr = rmrr->end_address;
    int ret;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*rmrr))) != 0 )
        return ret;

#ifdef CONFIG_X86
    /* This check is here simply to detect when RMRR values are
     * not properly represented in the system memory map and
     * inform the user
     */
    if ( (!page_is_ram_type(paddr_to_pfn(base_addr), RAM_TYPE_RESERVED)) ||
         (!page_is_ram_type(paddr_to_pfn(end_addr) - 1, RAM_TYPE_RESERVED)) )
    {
        dprintk(XENLOG_WARNING VTDPREFIX,
                "  RMRR address range not in reserved memory "
                "base = %"PRIx64" end = %"PRIx64"; "
                "iommu_inclusive_mapping=1 parameter may be needed.\n",
                base_addr, end_addr);
    }
#endif

    rmrru = xmalloc(struct acpi_rmrr_unit);
    if ( !rmrru )
        return -ENOMEM;
    memset(rmrru, 0, sizeof(struct acpi_rmrr_unit));

    rmrru->base_address = base_addr;
    rmrru->end_address = end_addr;

    dev_scope_start = (void *)(rmrr + 1);
    dev_scope_end   = ((void *)rmrr) + header->length;
    ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                               rmrru, RMRR_TYPE);

    if ( ret || (rmrru->scope.devices_cnt == 0) )
        xfree(rmrru);
    else
    {
        u8 b, d, f;
        int i, ignore = 0;

        for ( i = 0; i < rmrru->scope.devices_cnt; i++ )
        {
            b = PCI_BUS(rmrru->scope.devices[i]);
            d = PCI_SLOT(rmrru->scope.devices[i]);
            f = PCI_FUNC(rmrru->scope.devices[i]);

            if ( pci_device_detect(b, d, f) == 0 )
            {
                dprintk(XENLOG_WARNING VTDPREFIX,
                    "  Non-existent device (%x:%x.%x) is reported "
                    "in RMRR (%"PRIx64", %"PRIx64")'s scope!\n",
                    b, d, f, rmrru->base_address, rmrru->end_address);
                ignore = 1;
            }
            else
            {
                ignore = 0;
                break;
            }
        }

        if ( ignore )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                "  Ignore the RMRR (%"PRIx64", %"PRIx64") due to "
                "devices under its scope are not PCI discoverable!\n",
                rmrru->base_address, rmrru->end_address);
            xfree(rmrru);
        }
        else if ( base_addr > end_addr )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                "  The RMRR (%"PRIx64", %"PRIx64") is incorrect!\n",
                rmrru->base_address, rmrru->end_address);
            xfree(rmrru);
            ret = -EFAULT;
        }
        else
        {
            if ( iommu_verbose )
                dprintk(VTDPREFIX,
                        "  RMRR region: base_addr %"PRIx64
                        " end_address %"PRIx64"\n",
                        rmrru->base_address, rmrru->end_address);
            acpi_register_rmrr_unit(rmrru);
        }
    }

    return ret;
}

static int __init
acpi_parse_one_atsr(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_atsr *atsr = (struct acpi_table_atsr *)header;
    struct acpi_atsr_unit *atsru;
    int ret;
    static int all_ports;
    void *dev_scope_start, *dev_scope_end;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*atsr))) != 0 )
        return ret;

    atsru = xmalloc(struct acpi_atsr_unit);
    if ( !atsru )
        return -ENOMEM;
    memset(atsru, 0, sizeof(struct acpi_atsr_unit));

    atsru->all_ports = atsr->flags & 1; /* BIT0: ALL_PORTS */
    if ( iommu_verbose )
        dprintk(VTDPREFIX,
                "  atsru->all_ports: %x\n", atsru->all_ports);
    if ( !atsru->all_ports )
    {
        dev_scope_start = (void *)(atsr + 1);
        dev_scope_end   = ((void *)atsr) + header->length;
        ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                                   atsru, ATSR_TYPE);
    }
    else
    {
        if ( iommu_verbose )
            dprintk(VTDPREFIX, "  flags: ALL_PORTS\n");
        /* Only allow one ALL_PORTS */
        if ( all_ports )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Only one ALL_PORTS device scope is allowed\n");
            ret = -EINVAL;
        }
        all_ports = 1;
    }

    if ( ret )
        xfree(atsr);
    else
        acpi_register_atsr_unit(atsru);
    return ret;
}

static int __init
acpi_parse_one_rhsa(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_rhsa *rhsa = (struct acpi_table_rhsa *)header;
    struct acpi_rhsa_unit *rhsau;
    int ret;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*rhsa))) != 0 )
        return ret;

    rhsau = xmalloc(struct acpi_rhsa_unit);
    if ( !rhsau )
        return -ENOMEM;
    memset(rhsau, 0, sizeof(struct acpi_rhsa_unit));

    rhsau->address = rhsa->address;
    rhsau->proximity_domain = rhsa->proximity_domain;
    list_add_tail(&rhsau->list, &acpi_rhsa_units);
    if ( iommu_verbose )
        dprintk(VTDPREFIX,
                "  rhsau->address: %"PRIx64
                " rhsau->proximity_domain: %"PRIx32"\n",
                rhsau->address, rhsau->proximity_domain);

    return ret;
}

static int __init acpi_parse_dmar(struct acpi_table_header *table)
{
    struct acpi_table_dmar *dmar;
    struct acpi_dmar_entry_header *entry_header;
    int ret = 0;

    dmar = (struct acpi_table_dmar *)table;

    if ( !iommu_enabled )
    {
        ret = -EINVAL;
        goto out;
    }

    if ( !dmar->width )
    {
        dprintk(XENLOG_WARNING VTDPREFIX, "Zero: Invalid DMAR width\n");
        ret = -EINVAL;
        goto out;
    }

    dmar_host_address_width = dmar->width + 1;
    if ( iommu_verbose )
        dprintk(VTDPREFIX, "Host address width %d\n",
                dmar_host_address_width);

    entry_header = (struct acpi_dmar_entry_header *)(dmar + 1);
    while ( ((unsigned long)entry_header) <
            (((unsigned long)dmar) + table->length) )
    {
        ret = acpi_dmar_check_length(
            entry_header, sizeof(struct acpi_dmar_entry_header));
        if ( ret )
            break;

        switch ( entry_header->type )
        {
        case ACPI_DMAR_DRHD:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "found ACPI_DMAR_DRHD:\n");
            ret = acpi_parse_one_drhd(entry_header);
            break;
        case ACPI_DMAR_RMRR:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "found ACPI_DMAR_RMRR:\n");
            ret = acpi_parse_one_rmrr(entry_header);
            break;
        case ACPI_DMAR_ATSR:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "found ACPI_DMAR_ATSR:\n");
            ret = acpi_parse_one_atsr(entry_header);
            break;
        case ACPI_DMAR_RHSA:
            if ( iommu_verbose )
                dprintk(VTDPREFIX, "found ACPI_DMAR_RHSA:\n");
            ret = acpi_parse_one_rhsa(entry_header);
            break;
        default:
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Unknown DMAR structure type %x\n",
                    entry_header->type);
            break;
        }
        if ( ret )
            break;

        entry_header = ((void *)entry_header + entry_header->length);
    }

    if ( ret )
    {
        printk(XENLOG_WARNING
               "Failed to parse ACPI DMAR.  Disabling VT-d.\n");
        disable_all_dmar_units();
    }

out:
    /* Zap ACPI DMAR signature to prevent dom0 using vt-d HW. */
    dmar->header.signature[0] = '\0';
    return ret;
}

#ifdef CONFIG_X86
#include <asm/tboot.h>
/* ACPI tables may not be DMA protected by tboot, so use DMAR copy */
/* SINIT saved in SinitMleData in TXT heap (which is DMA protected) */
#define parse_dmar_table(h) tboot_parse_dmar_table(h)
#else
#define parse_dmar_table(h) acpi_table_parse(ACPI_SIG_DMAR, h)
#endif

int __init acpi_dmar_init(void)
{
    return parse_dmar_table(acpi_parse_dmar);
}
