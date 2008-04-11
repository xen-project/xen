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
#include <xen/kernel.h>
#include <xen/acpi.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <asm/string.h>
#include "dmar.h"
#include "../pci-direct.h"
#include "../pci_regs.h"

int vtd_enabled;
boolean_param("vtd", vtd_enabled);

#undef PREFIX
#define PREFIX VTDPREFIX "ACPI DMAR:"
#define DEBUG

#define MIN_SCOPE_LEN (sizeof(struct acpi_pci_path) + \
                       sizeof(struct acpi_dev_scope))

LIST_HEAD(acpi_drhd_units);
LIST_HEAD(acpi_rmrr_units);
LIST_HEAD(acpi_atsr_units);

u8 dmar_host_address_width;

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
    list_for_each_entry( drhd, &acpi_drhd_units, list ) {
        if ( acpi_ioapic_device_match(&drhd->ioapic_list, apic_id) ) {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "ioapic_to_drhd: drhd->address = %lx\n",
                    drhd->address);
            return drhd;
        }
    }
    return NULL;
}

struct iommu * ioapic_to_iommu(unsigned int apic_id)
{
    struct acpi_drhd_unit *drhd;

    list_for_each_entry( drhd, &acpi_drhd_units, list ) {
        if ( acpi_ioapic_device_match(&drhd->ioapic_list, apic_id) ) {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "ioapic_to_iommu: drhd->address = %lx\n",
                    drhd->address);
            return drhd->iommu;
        }
    }
    dprintk(XENLOG_INFO VTDPREFIX, "returning NULL\n");
    return NULL;
}

static int acpi_pci_device_match(struct pci_dev *devices, int cnt,
                                 struct pci_dev *dev)
{
    int i;

    for ( i = 0; i < cnt; i++ )
    {
        if ( (dev->bus == devices->bus) &&
             (dev->devfn == devices->devfn) )
            return 1;
        devices++;
    }
    return 0;
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

struct acpi_drhd_unit * acpi_find_matched_drhd_unit(struct pci_dev *dev)
{
    struct acpi_drhd_unit *drhd;
    struct acpi_drhd_unit *include_all_drhd;

    include_all_drhd = NULL;
    list_for_each_entry ( drhd, &acpi_drhd_units, list )
    {
        if ( drhd->include_all )
        {
            include_all_drhd = drhd;
            continue;
        }

        if ( acpi_pci_device_match(drhd->devices,
                                   drhd->devices_cnt, dev) )
        {
            dprintk(XENLOG_INFO VTDPREFIX, 
                    "acpi_find_matched_drhd_unit: drhd->address = %lx\n",
                    drhd->address);
            return drhd;
        }
    }

    if ( include_all_drhd )
    {
        dprintk(XENLOG_INFO VTDPREFIX, 
                "acpi_find_matched_drhd_unit:include_all_drhd->addr = %lx\n",
                include_all_drhd->address);
        return include_all_drhd;
    }

    return NULL;
}

struct acpi_rmrr_unit * acpi_find_matched_rmrr_unit(struct pci_dev *dev)
{
    struct acpi_rmrr_unit *rmrr;

    list_for_each_entry ( rmrr, &acpi_rmrr_units, list )
    {
        if ( acpi_pci_device_match(rmrr->devices,
                                   rmrr->devices_cnt, dev) )
            return rmrr;
    }

    return NULL;
}

struct acpi_atsr_unit * acpi_find_matched_atsr_unit(struct pci_dev *dev)
{
    struct acpi_atsr_unit *atsru;
    struct acpi_atsr_unit *all_ports_atsru;

    all_ports_atsru = NULL;
    list_for_each_entry ( atsru, &acpi_atsr_units, list )
    {
        if ( atsru->all_ports )
            all_ports_atsru = atsru;
        if ( acpi_pci_device_match(atsru->devices,
                                   atsru->devices_cnt, dev) )
            return atsru;
    }

    if ( all_ports_atsru )
    {
        dprintk(XENLOG_INFO VTDPREFIX,
                "acpi_find_matched_atsr_unit: all_ports_atsru\n");
        return all_ports_atsru;;
    }

    return NULL;
}

static int scope_device_count(void *start, void *end)
{
    struct acpi_dev_scope *scope;
    u16 bus, sub_bus, sec_bus;
    struct acpi_pci_path *path;
    int depth, count = 0;
    u8 dev, func;
    u32 l;

    while ( start < end )
    {
        scope = start;
        if ( (scope->length < MIN_SCOPE_LEN) ||
             (scope->dev_type >= ACPI_DEV_ENTRY_COUNT) )
        {
            dprintk(XENLOG_WARNING VTDPREFIX, "Invalid device scope\n");
            return -EINVAL;
        }

        path = (struct acpi_pci_path *)(scope + 1);
        bus = scope->start_bus;
        depth = (scope->length - sizeof(struct acpi_dev_scope))
		    / sizeof(struct acpi_pci_path);
        while ( --depth > 0 )
        {
            bus = read_pci_config_byte(
                bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            path++;
        }

        if ( scope->dev_type == ACPI_DEV_ENDPOINT )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found endpoint: bdf = %x:%x:%x\n",
                    bus, path->dev, path->fn);
            count++;
        }
        else if ( scope->dev_type == ACPI_DEV_P2PBRIDGE )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found bridge: bdf = %x:%x:%x\n",
                    bus, path->dev, path->fn);
            sec_bus = read_pci_config_byte(
                bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            sub_bus = read_pci_config_byte(
                bus, path->dev, path->fn, PCI_SUBORDINATE_BUS);

            while ( sec_bus <= sub_bus )
            {
                for ( dev = 0; dev < 32; dev++ )
                {
                    for ( func = 0; func < 8; func++ )
                    {
                        l = read_pci_config(
                            sec_bus, dev, func, PCI_VENDOR_ID);

                        /* some broken boards return 0 or
                         * ~0 if a slot is empty
                         */
                        if ( l == 0xffffffff || l == 0x00000000 ||
                             l == 0x0000ffff || l == 0xffff0000 )
                            break;
                        count++;
                    }
                }
                sec_bus++;
            }
        }
        else if ( scope->dev_type == ACPI_DEV_IOAPIC )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found IOAPIC: bdf = %x:%x:%x\n",
                    bus, path->dev, path->fn);
            count++;
        }
        else
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found MSI HPET: bdf = %x:%x:%x\n",
                    bus, path->dev, path->fn);
            count++;
        }

        start += scope->length;
    }

    return count;
}

static int __init acpi_parse_dev_scope(
    void *start, void *end, void *acpi_entry, int type)
{
    struct acpi_dev_scope *scope;
    u16 bus, sub_bus, sec_bus;
    struct acpi_pci_path *path;
    struct acpi_ioapic_unit *acpi_ioapic_unit = NULL;
    int depth;
    struct pci_dev *pdev;
    u8 dev, func;
    u32 l;

    int *cnt = NULL;
    struct pci_dev **devices = NULL;
    struct acpi_drhd_unit *dmaru = (struct acpi_drhd_unit *) acpi_entry;
    struct acpi_rmrr_unit *rmrru = (struct acpi_rmrr_unit *) acpi_entry;
    struct acpi_atsr_unit *atsru = (struct acpi_atsr_unit *) acpi_entry;

    switch (type) {
        case DMAR_TYPE:
            cnt = &(dmaru->devices_cnt);
            devices = &(dmaru->devices);
            break;
        case RMRR_TYPE:
            cnt = &(rmrru->devices_cnt);
            devices = &(rmrru->devices);
            break;
        case ATSR_TYPE:
            cnt = &(atsru->devices_cnt);
            devices = &(atsru->devices);
            break;
        default:
            dprintk(XENLOG_ERR VTDPREFIX, "invalid vt-d acpi entry type\n");
    }

    *cnt = scope_device_count(start, end);
    if ( *cnt == 0 )
    {
        dprintk(XENLOG_INFO VTDPREFIX, "acpi_parse_dev_scope: no device\n");
        return 0;
    }

    *devices = xmalloc_array(struct pci_dev,  *cnt);
    if ( !*devices )
        return -ENOMEM;
    memset(*devices, 0, sizeof(struct pci_dev) * (*cnt));

    pdev = *devices;
    while ( start < end )
    {
        scope = start;
        path = (struct acpi_pci_path *)(scope + 1);
        depth = (scope->length - sizeof(struct acpi_dev_scope))
		    / sizeof(struct acpi_pci_path);
        bus = scope->start_bus;

        while ( --depth > 0 )
        {
            bus = read_pci_config_byte(
                bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            path++;
        }

        if ( scope->dev_type == ACPI_DEV_ENDPOINT )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found endpoint: bdf = %x:%x:%x\n",
                    bus, path->dev, path->fn);
            pdev->bus = bus;
            pdev->devfn = PCI_DEVFN(path->dev, path->fn);
            pdev++;
        }
        else if ( scope->dev_type == ACPI_DEV_P2PBRIDGE )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found bridge: bus = %x dev = %x func = %x\n",
                    bus, path->dev, path->fn);
            sec_bus = read_pci_config_byte(
                bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            sub_bus = read_pci_config_byte(
                bus, path->dev, path->fn, PCI_SUBORDINATE_BUS);

            while ( sec_bus <= sub_bus )
            {
                for ( dev = 0; dev < 32; dev++ )
                {
                    for ( func = 0; func < 8; func++ )
                    {
                        l = read_pci_config(
                            sec_bus, dev, func, PCI_VENDOR_ID);

                        /* some broken boards return 0 or
                         * ~0 if a slot is empty
                         */
                        if ( l == 0xffffffff || l == 0x00000000 ||
                             l == 0x0000ffff || l == 0xffff0000 )
                            break;

                        pdev->bus = sec_bus;
                        pdev->devfn = PCI_DEVFN(dev, func);
                        pdev++;
                    }
                }
                sec_bus++;
            }
        }
        else if ( scope->dev_type == ACPI_DEV_IOAPIC )
        {
            acpi_ioapic_unit = xmalloc(struct acpi_ioapic_unit);
            if ( !acpi_ioapic_unit )
                return -ENOMEM;
            acpi_ioapic_unit->apic_id = scope->enum_id;
            acpi_ioapic_unit->ioapic.bdf.bus = bus;
            acpi_ioapic_unit->ioapic.bdf.dev = path->dev;
            acpi_ioapic_unit->ioapic.bdf.func = path->fn;
            list_add(&acpi_ioapic_unit->list, &dmaru->ioapic_list);
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found IOAPIC: bus = %x dev = %x func = %x\n",
                    bus, path->dev, path->fn);
        }
        else
            dprintk(XENLOG_INFO VTDPREFIX,
                    "found MSI HPET: bus = %x dev = %x func = %x\n",
                    bus, path->dev, path->fn);
        start += scope->length;
    }

    return 0;
}

static int __init
acpi_parse_one_drhd(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_drhd * drhd = (struct acpi_table_drhd *)header;
    struct acpi_drhd_unit *dmaru;
    int ret = 0;
    static int include_all;
    void *dev_scope_start, *dev_scope_end;

    dmaru = xmalloc(struct acpi_drhd_unit);
    if ( !dmaru )
        return -ENOMEM;
    memset(dmaru, 0, sizeof(struct acpi_drhd_unit));

    dmaru->address = drhd->address;
    dmaru->include_all = drhd->flags & 1; /* BIT0: INCLUDE_ALL */
    INIT_LIST_HEAD(&dmaru->ioapic_list);
    dprintk(XENLOG_INFO VTDPREFIX, "dmaru->address = %lx\n", dmaru->address);

    dev_scope_start = (void *)(drhd + 1);
    dev_scope_end   = ((void *)drhd) + header->length;
    ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                               dmaru, DMAR_TYPE);

    if ( dmaru->include_all )
    {
        dprintk(XENLOG_INFO VTDPREFIX, "found INCLUDE_ALL\n");
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
    else
        acpi_register_drhd_unit(dmaru);
    return ret;
}

static int __init
acpi_parse_one_rmrr(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_rmrr *rmrr = (struct acpi_table_rmrr *)header;
    struct acpi_rmrr_unit *rmrru;
    void *dev_scope_start, *dev_scope_end;
    int ret = 0;

    rmrru = xmalloc(struct acpi_rmrr_unit);
    if ( !rmrru )
        return -ENOMEM;
    memset(rmrru, 0, sizeof(struct acpi_rmrr_unit));

    rmrru->base_address = rmrr->base_address;
    rmrru->end_address = rmrr->end_address;
    dev_scope_start = (void *)(rmrr + 1);
    dev_scope_end   = ((void *)rmrr) + header->length;
    ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                               rmrru, RMRR_TYPE);
    if ( ret || (rmrru->devices_cnt == 0) )
        xfree(rmrru);
    else
        acpi_register_rmrr_unit(rmrru);
    return ret;
}

static int __init
acpi_parse_one_atsr(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_atsr *atsr = (struct acpi_table_atsr *)header;
    struct acpi_atsr_unit *atsru;
    int ret = 0;
    static int all_ports;
    void *dev_scope_start, *dev_scope_end;

    atsru = xmalloc(struct acpi_atsr_unit);
    if ( !atsru )
        return -ENOMEM;
    memset(atsru, 0, sizeof(struct acpi_atsr_unit));

    atsru->all_ports = atsr->flags & 1; /* BIT0: ALL_PORTS */
    if ( !atsru->all_ports )
    {
        dev_scope_start = (void *)(atsr + 1);
        dev_scope_end   = ((void *)atsr) + header->length;
        ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                                   atsru, ATSR_TYPE);
    }
    else {
        dprintk(XENLOG_INFO VTDPREFIX, "found ALL_PORTS\n");
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

static int __init acpi_parse_dmar(unsigned long phys_addr,
                                  unsigned long size)
{
    struct acpi_table_dmar *dmar = NULL;
    struct acpi_dmar_entry_header *entry_header;
    int ret = 0;

    if ( !phys_addr || !size )
        return -EINVAL;

    dmar = (struct acpi_table_dmar *)__acpi_map_table(phys_addr, size);
    if ( !dmar )
    {
        dprintk(XENLOG_WARNING VTDPREFIX, "Unable to map DMAR\n");
        return -ENODEV;
    }

    if ( !dmar->width )
    {
        dprintk(XENLOG_WARNING VTDPREFIX, "Zero: Invalid DMAR width\n");
        return -EINVAL;
    }

    dmar_host_address_width = dmar->width;
    dprintk(XENLOG_INFO VTDPREFIX, "Host address width %d\n",
            dmar_host_address_width);

    entry_header = (struct acpi_dmar_entry_header *)(dmar + 1);
    while ( ((unsigned long)entry_header) <
            (((unsigned long)dmar) + size) )
    {
        switch ( entry_header->type )
        {
        case ACPI_DMAR_DRHD:
            dprintk(XENLOG_INFO VTDPREFIX, "found ACPI_DMAR_DRHD\n");
            ret = acpi_parse_one_drhd(entry_header);
            break;
        case ACPI_DMAR_RMRR:
            dprintk(XENLOG_INFO VTDPREFIX, "found ACPI_DMAR_RMRR\n");
            ret = acpi_parse_one_rmrr(entry_header);
            break;
        case ACPI_DMAR_ATSR:
            dprintk(XENLOG_INFO VTDPREFIX, "found ACPI_DMAR_ATSR\n");
            ret = acpi_parse_one_atsr(entry_header);
            break;
        default:
            dprintk(XENLOG_WARNING VTDPREFIX, "Unknown DMAR structure type\n");
            ret = -EINVAL;
            break;
        }
        if ( ret )
            break;

        entry_header = ((void *)entry_header + entry_header->length);
    }

    /* Zap APCI DMAR signature to prevent dom0 using vt-d HW. */
    dmar->header.signature[0] = '\0';

    return ret;
}

int acpi_dmar_init(void)
{
    int rc;

    if ( !vtd_enabled )
        return -ENODEV;

    if ( (rc = vtd_hw_check()) != 0 )
        return rc;

    acpi_table_parse(ACPI_DMAR, acpi_parse_dmar);

    if ( list_empty(&acpi_drhd_units) )
    {
        dprintk(XENLOG_ERR VTDPREFIX, "No DMAR devices found\n");
        vtd_enabled = 0;
        return -ENODEV;
    }

    printk("Intel VT-d has been enabled\n");

    return 0;
}
