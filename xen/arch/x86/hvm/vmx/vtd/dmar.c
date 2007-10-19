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
#include "pci-direct.h"
#include "pci_regs.h"

#define VTDPREFIX
int vtd_enabled;
boolean_param("vtd", vtd_enabled);

#undef PREFIX
#define PREFIX VTDPREFIX "ACPI DMAR:"
#define DEBUG

#define MIN_SCOPE_LEN (sizeof(struct acpi_pci_path) + sizeof(struct acpi_dev_scope))

LIST_HEAD(acpi_drhd_units);
LIST_HEAD(acpi_rmrr_units);
LIST_HEAD(acpi_atsr_units);
LIST_HEAD(acpi_ioapic_units);

u8 dmar_host_address_width;

static int __init acpi_register_drhd_unit(struct acpi_drhd_unit *drhd)
{
    /*
     * add INCLUDE_ALL at the tail, so scan the list will find it at
     * the very end.
     */
    if (drhd->include_all)
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

static int acpi_pci_device_match(struct pci_dev *devices, int cnt,
                 struct pci_dev *dev)
{
    int i;

    for (i = 0; i < cnt; i++) {
        if ((dev->bus == devices->bus) &&
            (dev->devfn == devices->devfn))
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
    if (atsr->all_ports)
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
    list_for_each_entry(drhd, &acpi_drhd_units, list) {
        if (drhd->include_all)
            include_all_drhd = drhd;
        if (acpi_pci_device_match(drhd->devices,
                        drhd->devices_cnt, dev))
        {
            gdprintk(XENLOG_INFO VTDPREFIX, 
                     "acpi_find_matched_drhd_unit: drhd->address = %lx\n",
                     drhd->address);
            return drhd;
        }
    }

    if (include_all_drhd) {
        gdprintk(XENLOG_INFO VTDPREFIX, 
                 "acpi_find_matched_drhd_unit:include_all_drhd->addr = %lx\n",
                 include_all_drhd->address);
        return include_all_drhd;;
    }

    return(NULL);
}

struct acpi_rmrr_unit * acpi_find_matched_rmrr_unit(struct pci_dev *dev)
{
    struct acpi_rmrr_unit *rmrr;

    list_for_each_entry(rmrr, &acpi_rmrr_units, list) {
        if (acpi_pci_device_match(rmrr->devices,
                        rmrr->devices_cnt, dev))
            goto out;
    }
    rmrr = NULL;
out:
    return rmrr;
}

struct acpi_atsr_unit * acpi_find_matched_atsr_unit(struct pci_dev *dev)
{
    struct acpi_atsr_unit *atsru;
    struct acpi_atsr_unit *all_ports_atsru;

    all_ports_atsru = NULL;
    list_for_each_entry(atsru, &acpi_atsr_units, list) {
        if (atsru->all_ports)
            all_ports_atsru = atsru;
        if (acpi_pci_device_match(atsru->devices, atsru->devices_cnt, dev))
            return atsru;
    }
    if (all_ports_atsru) {
        gdprintk(XENLOG_INFO VTDPREFIX, 
                 "acpi_find_matched_atsr_unit: all_ports_atsru\n");
        return all_ports_atsru;;
    }
    return(NULL);
}

static int __init acpi_parse_dev_scope(void *start, void *end, int *cnt,
                       struct pci_dev **devices)
{
    struct acpi_dev_scope *scope;
    u8 bus, sub_bus, sec_bus;
    struct acpi_pci_path *path;
    struct acpi_ioapic_unit *acpi_ioapic_unit = NULL;
    int count, dev_count=0;
    struct pci_dev *pdev;
    u8 dev, func;
    u32 l;
    void *tmp;

    *cnt = 0;
    tmp = start;
    while (start < end) {
        scope = start;
        if (scope->length < MIN_SCOPE_LEN ||
            (scope->dev_type != ACPI_DEV_ENDPOINT &&
            scope->dev_type != ACPI_DEV_P2PBRIDGE)) {
            printk(KERN_WARNING PREFIX "Invalid device scope\n");
            return -EINVAL;
        }
        (*cnt)++;
        start += scope->length;
    }

    start = tmp;
    while (start < end) {
        scope = start;
        path = (struct acpi_pci_path *)(scope + 1);
        count = (scope->length - sizeof(struct acpi_dev_scope))
		    /sizeof(struct acpi_pci_path);
        bus = scope->start_bus;

        while (--count) {
            bus = read_pci_config_byte(bus, path->dev,
                                       path->fn, PCI_SECONDARY_BUS);
            path++;
        }

        if (scope->dev_type == ACPI_DEV_ENDPOINT) {
            printk(KERN_WARNING PREFIX
                "found endpoint: bdf = %x:%x:%x\n", bus, path->dev, path->fn);
                dev_count++;
        } else if (scope->dev_type == ACPI_DEV_P2PBRIDGE) {
            printk(KERN_WARNING PREFIX
                "found bridge: bdf = %x:%x:%x\n", bus, path->dev, path->fn);

            sec_bus = read_pci_config_byte(bus, path->dev,
                                       path->fn, PCI_SECONDARY_BUS);
            sub_bus = read_pci_config_byte(bus, path->dev,
                                       path->fn, PCI_SUBORDINATE_BUS);
            while (sec_bus <= sub_bus) {
                for (dev = 0; dev < 32; dev++) {
                    for (func = 0; func < 8; func++) {
                        l = read_pci_config(sec_bus, dev, func, PCI_VENDOR_ID);

                        /* some broken boards return 0 or ~0 if a slot is empty: */
                        if (l == 0xffffffff || l == 0x00000000 ||
                            l == 0x0000ffff || l == 0xffff0000)
                            break;
                        dev_count++;
                    }
                }
                sec_bus++;
            }
        } else if (scope->dev_type == ACPI_DEV_IOAPIC) {
            printk(KERN_WARNING PREFIX
                "found IOAPIC: bdf = %x:%x:%x\n", bus, path->dev, path->fn);
            dev_count++;
        } else {
            printk(KERN_WARNING PREFIX
                "found MSI HPET: bdf = %x:%x:%x\n", bus, path->dev, path->fn);
            dev_count++;
        }

        start += scope->length;
    }

    *cnt = dev_count;
    *devices = xmalloc_array(struct pci_dev,  *cnt);
    if (!*devices)
        return -ENOMEM;
    memset(*devices, 0, sizeof(struct pci_dev) * (*cnt));

    pdev = *devices;
    start = tmp;
    while (start < end) {
        scope = start;
        path = (struct acpi_pci_path *)(scope + 1);
        count = (scope->length - sizeof(struct acpi_dev_scope))
		    /sizeof(struct acpi_pci_path);
        bus = scope->start_bus;

        while (--count) {
            bus = read_pci_config_byte(bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            path++;
        }

        if (scope->dev_type == ACPI_DEV_ENDPOINT) {
            printk(KERN_WARNING PREFIX
                "found endpoint: bdf = %x:%x:%x\n", bus, path->dev, path->fn);

            pdev->bus = bus;
            pdev->devfn = PCI_DEVFN(path->dev, path->fn);
            pdev++;
        } else if (scope->dev_type == ACPI_DEV_P2PBRIDGE) {
            printk(KERN_WARNING PREFIX
                "found bridge: bus = %x dev = %x func = %x\n", bus, path->dev, path->fn);

            sec_bus = read_pci_config_byte(bus, path->dev, path->fn, PCI_SECONDARY_BUS);
            sub_bus = read_pci_config_byte(bus, path->dev, path->fn, PCI_SUBORDINATE_BUS);

            while (sec_bus <= sub_bus) {
                for (dev = 0; dev < 32; dev++) {
                    for (func = 0; func < 8; func++) {
                        l = read_pci_config(sec_bus, dev, func, PCI_VENDOR_ID);

                        /* some broken boards return 0 or ~0 if a slot is empty: */
                        if (l == 0xffffffff || l == 0x00000000 ||
                            l == 0x0000ffff || l == 0xffff0000)
                            break;

                        pdev->bus = sec_bus;
                        pdev->devfn = PCI_DEVFN(dev, func);
                        pdev++;
                    }
                }
                sec_bus++;
            }
        } else if (scope->dev_type == ACPI_DEV_IOAPIC) {
            acpi_ioapic_unit = xmalloc(struct acpi_ioapic_unit);
            acpi_ioapic_unit->apic_id = scope->enum_id;
            acpi_ioapic_unit->ioapic.bdf.bus = bus;
            acpi_ioapic_unit->ioapic.bdf.dev = path->dev;
            acpi_ioapic_unit->ioapic.bdf.func = path->fn;
            list_add(&acpi_ioapic_unit->list, &acpi_ioapic_units);
            printk(KERN_WARNING PREFIX
                "found IOAPIC: bus = %x dev = %x func = %x\n", bus, path->dev, path->fn);
        } else {
            printk(KERN_WARNING PREFIX
                "found MSI HPET: bus = %x dev = %x func = %x\n", bus, path->dev, path->fn);
        }
        
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

    dmaru = xmalloc(struct acpi_drhd_unit);
    if (!dmaru)
        return -ENOMEM;
    memset(dmaru, 0, sizeof(struct acpi_drhd_unit));

    dmaru->address = drhd->address;
    dmaru->include_all = drhd->flags & 1; /* BIT0: INCLUDE_ALL */
    printk(KERN_WARNING PREFIX "dmaru->address = %lx\n", dmaru->address);

    if (!dmaru->include_all) {
        ret = acpi_parse_dev_scope((void *)(drhd + 1),
                ((void *)drhd) + header->length,
                &dmaru->devices_cnt, &dmaru->devices);
    }
    else {
        printk(KERN_WARNING PREFIX "found INCLUDE_ALL\n");
        /* Only allow one INCLUDE_ALL */
        if (include_all) {
            printk(KERN_WARNING PREFIX "Only one INCLUDE_ALL "
                "device scope is allowed\n");
            ret = -EINVAL;
        }
        include_all = 1;
    }

    if (ret)
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
    int ret = 0;

    rmrru = xmalloc(struct acpi_rmrr_unit);
    if (!rmrru)
        return -ENOMEM;
    memset(rmrru, 0, sizeof(struct acpi_rmrr_unit));

#ifdef VTD_DEBUG
    gdprintk(XENLOG_INFO VTDPREFIX,
        "acpi_parse_one_rmrr: base = %lx end = %lx\n",
        rmrr->base_address, rmrr->end_address);
#endif

    rmrru->base_address = rmrr->base_address;
    rmrru->end_address = rmrr->end_address;
    ret = acpi_parse_dev_scope((void *)(rmrr + 1),
            ((void*)rmrr) + header->length,
            &rmrru->devices_cnt, &rmrru->devices);

    if (ret || (rmrru->devices_cnt == 0))
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

    atsru = xmalloc(struct acpi_atsr_unit);
    if (!atsru)
        return -ENOMEM;
    memset(atsru, 0, sizeof(struct acpi_atsr_unit));

    atsru->all_ports = atsr->flags & 1; /* BIT0: ALL_PORTS */
    if (!atsru->all_ports) {
        ret = acpi_parse_dev_scope((void *)(atsr + 1),
                ((void *)atsr) + header->length,
                &atsru->devices_cnt, &atsru->devices);
    }
    else {
        printk(KERN_WARNING PREFIX "found ALL_PORTS\n");
        /* Only allow one ALL_PORTS */
        if (all_ports) {
            printk(KERN_WARNING PREFIX "Only one ALL_PORTS "
                "device scope is allowed\n");
            ret = -EINVAL;
        }
        all_ports = 1;
    }

    if (ret)
        xfree(atsr);
    else
        acpi_register_atsr_unit(atsru);
    return ret;
}

static void __init
acpi_table_print_dmar_entry(struct acpi_dmar_entry_header *header)
{
    struct acpi_table_drhd *drhd;
    struct acpi_table_rmrr *rmrr;

    switch (header->type) {
    case ACPI_DMAR_DRHD:
        drhd = (struct acpi_table_drhd *)header;
        break;
    case ACPI_DMAR_RMRR:
        rmrr = (struct acpi_table_rmrr *)header;
        break;
    }
}

static int __init
acpi_parse_dmar(unsigned long phys_addr, unsigned long size)
{
    struct acpi_table_dmar *dmar = NULL;
    struct acpi_dmar_entry_header *entry_header;
    int ret = 0;

    if (!phys_addr || !size)
        return -EINVAL;

    dmar = (struct acpi_table_dmar *)__acpi_map_table(phys_addr, size);
    if (!dmar) {
        printk (KERN_WARNING PREFIX "Unable to map DMAR\n");
        return -ENODEV;
    }

    if (!dmar->haw) {
        printk (KERN_WARNING PREFIX "Zero: Invalid DMAR haw\n");
        return -EINVAL;
    }

    dmar_host_address_width = dmar->haw;
    printk (KERN_INFO PREFIX "Host address width %d\n",
        dmar_host_address_width);

    entry_header = (struct acpi_dmar_entry_header *)(dmar + 1);
    while (((unsigned long)entry_header) < (((unsigned long)dmar) + size)) {
        acpi_table_print_dmar_entry(entry_header);

        switch (entry_header->type) {
        case ACPI_DMAR_DRHD:
            printk (KERN_INFO PREFIX "found ACPI_DMAR_DRHD\n");
            ret = acpi_parse_one_drhd(entry_header);
            break;
        case ACPI_DMAR_RMRR:
            printk (KERN_INFO PREFIX "found ACPI_DMAR_RMRR\n");
            ret = acpi_parse_one_rmrr(entry_header);
            break;
        case ACPI_DMAR_ATSR:
            printk (KERN_INFO PREFIX "found ACPI_DMAR_RMRR\n");
            ret = acpi_parse_one_atsr(entry_header);
            break;
        default:
            printk(KERN_WARNING PREFIX "Unknown DMAR structure type\n");
            ret = -EINVAL;
            break;
        }
        if (ret)
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

    if (!vtd_enabled)
        return -ENODEV;

    if ((rc = vtd_hw_check()) != 0)
        return rc;

    acpi_table_parse(ACPI_DMAR, acpi_parse_dmar);

    if (list_empty(&acpi_drhd_units)) {
        printk(KERN_ERR PREFIX "No DMAR devices found\n");
        vtd_enabled = 0;
        return -ENODEV;
    }

    return 0;
}
