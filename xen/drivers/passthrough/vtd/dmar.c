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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <asm/atomic.h>
#include <asm/string.h>
#include "dmar.h"
#include "iommu.h"
#include "extern.h"
#include "vtd.h"

#undef PREFIX
#define PREFIX VTDPREFIX "ACPI DMAR:"
#define DEBUG

#define MIN_SCOPE_LEN (sizeof(struct acpi_dmar_device_scope) + \
                       sizeof(struct acpi_dmar_pci_path))

LIST_HEAD_READ_MOSTLY(acpi_drhd_units);
LIST_HEAD_READ_MOSTLY(acpi_rmrr_units);
static LIST_HEAD_READ_MOSTLY(acpi_atsr_units);
static LIST_HEAD_READ_MOSTLY(acpi_rhsa_units);

static struct acpi_table_header *__read_mostly dmar_table;
static int __read_mostly dmar_flags;
static u64 __read_mostly igd_drhd_address;

static void __init dmar_scope_add_buses(struct dmar_scope *scope, u16 sec_bus,
                                        u16 sub_bus)
{
    sub_bus &= 0xff;
    if (sec_bus > sub_bus)
        return;

    while ( sec_bus <= sub_bus )
        set_bit(sec_bus++, scope->buses);
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

static void scope_devices_free(struct dmar_scope *scope)
{
    if ( !scope )
        return;

    scope->devices_cnt = 0;
    xfree(scope->devices);
    scope->devices = NULL;
}

static void __init disable_all_dmar_units(void)
{
    struct acpi_drhd_unit *drhd, *_drhd;
    struct acpi_rmrr_unit *rmrr, *_rmrr;
    struct acpi_atsr_unit *atsr, *_atsr;

    list_for_each_entry_safe ( drhd, _drhd, &acpi_drhd_units, list )
    {
        list_del(&drhd->list);
        scope_devices_free(&drhd->scope);
        iommu_free(drhd);
        xfree(drhd);
    }
    list_for_each_entry_safe ( rmrr, _rmrr, &acpi_rmrr_units, list )
    {
        list_del(&rmrr->list);
        scope_devices_free(&rmrr->scope);
        xfree(rmrr);
    }
    list_for_each_entry_safe ( atsr, _atsr, &acpi_atsr_units, list )
    {
        list_del(&atsr->list);
        scope_devices_free(&atsr->scope);
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

static bool_t acpi_hpet_device_match(
    struct list_head *list, unsigned int hpet_id)
{
    struct acpi_hpet_unit *hpet;

    list_for_each_entry( hpet, list, list )
        if (hpet->id == hpet_id)
            return 1;
    return 0;
}

struct acpi_drhd_unit *hpet_to_drhd(unsigned int hpet_id)
{
    struct acpi_drhd_unit *drhd;

    list_for_each_entry( drhd, &acpi_drhd_units, list )
        if ( acpi_hpet_device_match(&drhd->hpet_list, hpet_id) )
            return drhd;
    return NULL;
}

struct iommu *hpet_to_iommu(unsigned int hpet_id)
{
    struct acpi_drhd_unit *drhd = hpet_to_drhd(hpet_id);

    return drhd ? drhd->iommu : NULL;
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

struct acpi_drhd_unit *acpi_find_matched_drhd_unit(const struct pci_dev *pdev)
{
    u8 bus, devfn;
    struct acpi_drhd_unit *drhd;
    struct acpi_drhd_unit *include_all = NULL;
    int i;

    if ( pdev == NULL )
        return NULL;

    if ( pdev->info.is_virtfn )
    {
        bus = pdev->info.physfn.bus;
        devfn = !pdev->info.is_extfn ? pdev->info.physfn.devfn : 0;
    }
    else if ( pdev->info.is_extfn )
    {
        bus = pdev->bus;
        devfn = 0;
    }
    else
    {
        bus = pdev->bus;
        devfn = pdev->devfn;
    }

    list_for_each_entry ( drhd, &acpi_drhd_units, list )
    {
        if ( drhd->segment != pdev->seg )
            continue;

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

struct acpi_atsr_unit *acpi_find_matched_atsr_unit(const struct pci_dev *pdev)
{
    struct acpi_atsr_unit *atsr;
    struct acpi_atsr_unit *all_ports = NULL;

    list_for_each_entry ( atsr, &acpi_atsr_units, list )
    {
        if ( atsr->segment != pdev->seg )
            continue;

        if ( test_bit(pdev->bus, atsr->scope.buses) )
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

int is_igd_drhd(struct acpi_drhd_unit *drhd)
{
    return drhd && (drhd->address == igd_drhd_address);
}

/*
 * Count number of devices in device scope.  Do not include PCI sub
 * hierarchies.
 */
static int __init scope_device_count(const void *start, const void *end)
{
    const struct acpi_dmar_device_scope *scope;
    int count = 0;

    while ( start < end )
    {
        scope = start;
        if ( scope->length < MIN_SCOPE_LEN )
        {
            printk(XENLOG_WARNING VTDPREFIX "Invalid device scope\n");
            return -EINVAL;
        }

        if ( scope->entry_type == ACPI_DMAR_SCOPE_TYPE_BRIDGE ||
             scope->entry_type == ACPI_DMAR_SCOPE_TYPE_ENDPOINT ||
             scope->entry_type == ACPI_DMAR_SCOPE_TYPE_IOAPIC ||
             scope->entry_type == ACPI_DMAR_SCOPE_TYPE_HPET )
            count++;

        start += scope->length;
    }

    return count;
}


static int __init acpi_parse_dev_scope(
    const void *start, const void *end, struct dmar_scope *scope,
    int type, u16 seg)
{
    struct acpi_ioapic_unit *acpi_ioapic_unit;
    const struct acpi_dmar_device_scope *acpi_scope;
    u16 bus, sub_bus, sec_bus;
    const struct acpi_dmar_pci_path *path;
    struct acpi_drhd_unit *drhd = type == DMAR_TYPE ?
        container_of(scope, struct acpi_drhd_unit, scope) : NULL;
    int depth, cnt, didx = 0, ret;

    if ( (cnt = scope_device_count(start, end)) < 0 )
        return cnt;

    if ( cnt > 0 )
    {
        scope->devices = xzalloc_array(u16, cnt);
        if ( !scope->devices )
            return -ENOMEM;
    }
    scope->devices_cnt = cnt;

    while ( start < end )
    {
        acpi_scope = start;
        path = (const void *)(acpi_scope + 1);
        depth = (acpi_scope->length - sizeof(*acpi_scope)) / sizeof(*path);
        bus = acpi_scope->bus;

        while ( --depth > 0 )
        {
            bus = pci_conf_read8(seg, bus, path->dev, path->fn,
                                 PCI_SECONDARY_BUS);
            path++;
        }

        switch ( acpi_scope->entry_type )
        {
        case ACPI_DMAR_SCOPE_TYPE_BRIDGE:
            sec_bus = pci_conf_read8(seg, bus, path->dev, path->fn,
                                     PCI_SECONDARY_BUS);
            sub_bus = pci_conf_read8(seg, bus, path->dev, path->fn,
                                     PCI_SUBORDINATE_BUS);
            if ( iommu_verbose )
                printk(VTDPREFIX
                       " bridge: %04x:%02x:%02x.%u start=%x sec=%x sub=%x\n",
                       seg, bus, path->dev, path->fn,
                       acpi_scope->bus, sec_bus, sub_bus);

            dmar_scope_add_buses(scope, sec_bus, sub_bus);
            break;

        case ACPI_DMAR_SCOPE_TYPE_HPET:
            if ( iommu_verbose )
                printk(VTDPREFIX " MSI HPET: %04x:%02x:%02x.%u\n",
                       seg, bus, path->dev, path->fn);

            if ( drhd )
            {
                struct acpi_hpet_unit *acpi_hpet_unit;

                ret = -ENOMEM;
                acpi_hpet_unit = xmalloc(struct acpi_hpet_unit);
                if ( !acpi_hpet_unit )
                    goto out;
                acpi_hpet_unit->id = acpi_scope->enumeration_id;
                acpi_hpet_unit->bus = bus;
                acpi_hpet_unit->dev = path->dev;
                acpi_hpet_unit->func = path->fn;
                list_add(&acpi_hpet_unit->list, &drhd->hpet_list);
            }

            break;

        case ACPI_DMAR_SCOPE_TYPE_ENDPOINT:
            if ( iommu_verbose )
                printk(VTDPREFIX " endpoint: %04x:%02x:%02x.%u\n",
                       seg, bus, path->dev, path->fn);

            if ( drhd )
            {
                if ( (seg == 0) && (bus == 0) && (path->dev == 2) &&
                     (path->fn == 0) )
                    igd_drhd_address = drhd->address;
            }

            break;

        case ACPI_DMAR_SCOPE_TYPE_IOAPIC:
            if ( iommu_verbose )
                printk(VTDPREFIX " IOAPIC: %04x:%02x:%02x.%u\n",
                       seg, bus, path->dev, path->fn);

            if ( drhd )
            {
                ret = -ENOMEM;
                acpi_ioapic_unit = xmalloc(struct acpi_ioapic_unit);
                if ( !acpi_ioapic_unit )
                    goto out;
                acpi_ioapic_unit->apic_id = acpi_scope->enumeration_id;
                acpi_ioapic_unit->ioapic.bdf.bus = bus;
                acpi_ioapic_unit->ioapic.bdf.dev = path->dev;
                acpi_ioapic_unit->ioapic.bdf.func = path->fn;
                list_add(&acpi_ioapic_unit->list, &drhd->ioapic_list);
            }

            break;

        default:
            if ( iommu_verbose )
                printk(XENLOG_WARNING VTDPREFIX "Unknown scope type %#x\n",
                       acpi_scope->entry_type);
            start += acpi_scope->length;
            continue;
        }
        scope->devices[didx++] = PCI_BDF(bus, path->dev, path->fn);
        start += acpi_scope->length;
   }

    ret = 0;

 out:
    if ( ret )
        scope_devices_free(scope);

    return ret;
}

static int __init acpi_dmar_check_length(
    const struct acpi_dmar_header *h, unsigned int min_len)
{
    if ( h->length >= min_len )
        return 0;
    printk(XENLOG_ERR VTDPREFIX "Invalid ACPI DMAR entry length: %#x\n",
           h->length);
    return -EINVAL;
}

static int __init
acpi_parse_one_drhd(struct acpi_dmar_header *header)
{
    struct acpi_dmar_hardware_unit *drhd =
        container_of(header, struct acpi_dmar_hardware_unit, header);
    void *dev_scope_start, *dev_scope_end;
    struct acpi_drhd_unit *dmaru;
    int ret;
    static int include_all = 0;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*drhd))) != 0 )
        return ret;

    if ( !drhd->address || !(drhd->address + 1) )
        return -ENODEV;

    dmaru = xzalloc(struct acpi_drhd_unit);
    if ( !dmaru )
        return -ENOMEM;

    dmaru->address = drhd->address;
    dmaru->segment = drhd->segment;
    dmaru->include_all = drhd->flags & ACPI_DMAR_INCLUDE_ALL;
    INIT_LIST_HEAD(&dmaru->ioapic_list);
    INIT_LIST_HEAD(&dmaru->hpet_list);
    if ( iommu_verbose )
        printk(VTDPREFIX "  dmaru->address = %"PRIx64"\n", dmaru->address);

    ret = iommu_alloc(dmaru);
    if ( ret )
        goto out;

    dev_scope_start = (void *)(drhd + 1);
    dev_scope_end = ((void *)drhd) + header->length;
    ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                               &dmaru->scope, DMAR_TYPE, drhd->segment);

    if ( dmaru->include_all )
    {
        if ( iommu_verbose )
            printk(VTDPREFIX "  flags: INCLUDE_ALL\n");
        /* Only allow one INCLUDE_ALL */
        if ( drhd->segment == 0 && include_all )
        {
            printk(XENLOG_WARNING VTDPREFIX
                   "Only one INCLUDE_ALL device scope is allowed\n");
            ret = -EINVAL;
        }
        if ( drhd->segment == 0 )
            include_all = 1;
    }

    if ( ret )
        goto out;
    else if ( force_iommu || dmaru->include_all )
        acpi_register_drhd_unit(dmaru);
    else
    {
        u8 b, d, f;
        unsigned int i = 0;
        union {
            const void *raw;
            const struct acpi_dmar_device_scope *scope;
        } p;

        /* Skip checking if segment is not accessible yet. */
        if ( !pci_known_segment(drhd->segment) )
            i = UINT_MAX;

        for ( p.raw = dev_scope_start; i < dmaru->scope.devices_cnt;
              i++, p.raw += p.scope->length )
        {
            if ( p.scope->entry_type == ACPI_DMAR_SCOPE_TYPE_IOAPIC ||
                 p.scope->entry_type == ACPI_DMAR_SCOPE_TYPE_HPET )
                continue;

            b = PCI_BUS(dmaru->scope.devices[i]);
            d = PCI_SLOT(dmaru->scope.devices[i]);
            f = PCI_FUNC(dmaru->scope.devices[i]);

            if ( !pci_device_detect(drhd->segment, b, d, f) )
                printk(XENLOG_WARNING VTDPREFIX
                       " Non-existent device (%04x:%02x:%02x.%u) in this DRHD's scope!\n",
                       drhd->segment, b, d, f);
        }

        acpi_register_drhd_unit(dmaru);
    }

out:
    if ( ret )
    {
        scope_devices_free(&dmaru->scope);
        iommu_free(dmaru);
        xfree(dmaru);
    }

    return ret;
}

static int register_one_rmrr(struct acpi_rmrr_unit *rmrru)
{
    bool ignore = false;
    unsigned int i = 0;
    int ret = 0;

    /* Skip checking if segment is not accessible yet. */
    if ( !pci_known_segment(rmrru->segment) )
        i = UINT_MAX;

    for ( ; i < rmrru->scope.devices_cnt; i++ )
    {
        u8 b = PCI_BUS(rmrru->scope.devices[i]);
        u8 d = PCI_SLOT(rmrru->scope.devices[i]);
        u8 f = PCI_FUNC(rmrru->scope.devices[i]);

        if ( pci_device_detect(rmrru->segment, b, d, f) == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    " Non-existent device (%04x:%02x:%02x.%u) is reported"
                    " in RMRR (%"PRIx64", %"PRIx64")'s scope!\n",
                    rmrru->segment, b, d, f,
                    rmrru->base_address, rmrru->end_address);
            ignore = true;
        }
        else
        {
            ignore = false;
            break;
        }
    }

    if ( ignore )
    {
        dprintk(XENLOG_WARNING VTDPREFIX,
                "  Ignore the RMRR (%"PRIx64", %"PRIx64") due to "
                "devices under its scope are not PCI discoverable!\n",
                rmrru->base_address, rmrru->end_address);
        scope_devices_free(&rmrru->scope);
        xfree(rmrru);
        return 1;
    }
    else if ( rmrru->base_address > rmrru->end_address )
    {
        dprintk(XENLOG_WARNING VTDPREFIX,
                "  The RMRR (%"PRIx64", %"PRIx64") is incorrect!\n",
                rmrru->base_address, rmrru->end_address);
        scope_devices_free(&rmrru->scope);
        xfree(rmrru);
        ret = -EFAULT;
    }
    else
    {
        if ( iommu_verbose )
            dprintk(VTDPREFIX,
                    "  RMRR region: base_addr %"PRIx64" end_addr %"PRIx64"\n",
                    rmrru->base_address, rmrru->end_address);
        acpi_register_rmrr_unit(rmrru);
    }

    return ret;
}

static int __init
acpi_parse_one_rmrr(struct acpi_dmar_header *header)
{
    struct acpi_dmar_reserved_memory *rmrr =
        container_of(header, struct acpi_dmar_reserved_memory, header);
    struct acpi_rmrr_unit *rmrru;
    void *dev_scope_start, *dev_scope_end;
    u64 base_addr = rmrr->base_address, end_addr = rmrr->end_address;
    int ret;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*rmrr))) != 0 )
        return ret;

    list_for_each_entry(rmrru, &acpi_rmrr_units, list)
       if ( base_addr <= rmrru->end_address && rmrru->base_address <= end_addr )
       {
           printk(XENLOG_ERR VTDPREFIX
                  "Overlapping RMRRs [%"PRIx64",%"PRIx64"] and [%"PRIx64",%"PRIx64"]\n",
                  rmrru->base_address, rmrru->end_address,
                  base_addr, end_addr);
           return -EEXIST;
       }

    /* This check is here simply to detect when RMRR values are
     * not properly represented in the system memory map and
     * inform the user
     */
    if ( (!page_is_ram_type(paddr_to_pfn(base_addr), RAM_TYPE_RESERVED)) ||
         (!page_is_ram_type(paddr_to_pfn(end_addr), RAM_TYPE_RESERVED)) )
    {
        printk(XENLOG_WARNING VTDPREFIX
               "  RMRR address range %"PRIx64"..%"PRIx64" not in reserved memory;"
               " need \"iommu_inclusive_mapping=1\"?\n",
                base_addr, end_addr);
    }

    rmrru = xzalloc(struct acpi_rmrr_unit);
    if ( !rmrru )
        return -ENOMEM;

    rmrru->base_address = base_addr;
    rmrru->end_address = end_addr;
    rmrru->segment = rmrr->segment;

    dev_scope_start = (void *)(rmrr + 1);
    dev_scope_end   = ((void *)rmrr) + header->length;
    ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                               &rmrru->scope, RMRR_TYPE, rmrr->segment);

    if ( !ret && (rmrru->scope.devices_cnt != 0) )
    {
        ret = register_one_rmrr(rmrru);
        /*
         * register_one_rmrr() returns greater than 0 when a specified
         * PCIe device cannot be detected. To prevent VT-d from being
         * disabled in such cases, reset the return value to 0 here.
         */
        if ( ret > 0 )
            ret = 0;

    }
    else
        xfree(rmrru);

    return ret;
}

static int __init
acpi_parse_one_atsr(struct acpi_dmar_header *header)
{
    struct acpi_dmar_atsr *atsr =
        container_of(header, struct acpi_dmar_atsr, header);
    struct acpi_atsr_unit *atsru;
    int ret;
    static int all_ports;
    void *dev_scope_start, *dev_scope_end;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*atsr))) != 0 )
        return ret;

    atsru = xzalloc(struct acpi_atsr_unit);
    if ( !atsru )
        return -ENOMEM;

    atsru->segment = atsr->segment;
    atsru->all_ports = atsr->flags & ACPI_DMAR_ALL_PORTS;
    if ( iommu_verbose )
        printk(VTDPREFIX "  atsru->all_ports: %x\n", atsru->all_ports);
    if ( !atsru->all_ports )
    {
        dev_scope_start = (void *)(atsr + 1);
        dev_scope_end   = ((void *)atsr) + header->length;
        ret = acpi_parse_dev_scope(dev_scope_start, dev_scope_end,
                                   &atsru->scope, ATSR_TYPE, atsr->segment);
    }
    else
    {
        if ( iommu_verbose )
            printk(VTDPREFIX "  flags: ALL_PORTS\n");
        /* Only allow one ALL_PORTS */
        if ( atsr->segment == 0 && all_ports )
        {
            printk(XENLOG_WARNING VTDPREFIX
                   "Only one ALL_PORTS device scope is allowed\n");
            ret = -EINVAL;
        }
        if ( atsr->segment == 0 )
            all_ports = 1;
    }

    if ( ret )
    {
        scope_devices_free(&atsru->scope);
        xfree(atsru);
    }
    else
        acpi_register_atsr_unit(atsru);
    return ret;
}

static int __init
acpi_parse_one_rhsa(struct acpi_dmar_header *header)
{
    struct acpi_dmar_rhsa *rhsa =
        container_of(header, struct acpi_dmar_rhsa, header);
    struct acpi_rhsa_unit *rhsau;
    int ret;

    if ( (ret = acpi_dmar_check_length(header, sizeof(*rhsa))) != 0 )
        return ret;

    rhsau = xzalloc(struct acpi_rhsa_unit);
    if ( !rhsau )
        return -ENOMEM;

    rhsau->address = rhsa->base_address;
    rhsau->proximity_domain = rhsa->proximity_domain;
    list_add_tail(&rhsau->list, &acpi_rhsa_units);
    if ( iommu_verbose )
        printk(VTDPREFIX
               "  rhsau->address: %"PRIx64" rhsau->proximity_domain: %"PRIx32"\n",
               rhsau->address, rhsau->proximity_domain);

    return ret;
}

static int __init acpi_parse_dmar(struct acpi_table_header *table)
{
    struct acpi_table_dmar *dmar;
    struct acpi_dmar_header *entry_header;
    u8 dmar_host_address_width;
    int ret = 0;

    dmar = (struct acpi_table_dmar *)table;
    dmar_flags = dmar->flags;

    if ( !iommu_enable && !iommu_intremap )
    {
        ret = -EINVAL;
        goto out;
    }

    if ( !dmar->width )
    {
        printk(XENLOG_WARNING VTDPREFIX "Zero: Invalid DMAR width\n");
        ret = -EINVAL;
        goto out;
    }

    dmar_host_address_width = dmar->width + 1;
    if ( iommu_verbose )
        printk(VTDPREFIX "Host address width %d\n", dmar_host_address_width);

    entry_header = (void *)(dmar + 1);
    while ( ((unsigned long)entry_header) <
            (((unsigned long)dmar) + table->length) )
    {
        ret = acpi_dmar_check_length(entry_header, sizeof(*entry_header));
        if ( ret )
            break;

        switch ( entry_header->type )
        {
        case ACPI_DMAR_TYPE_HARDWARE_UNIT:
            if ( iommu_verbose )
                printk(VTDPREFIX "found ACPI_DMAR_DRHD:\n");
            ret = acpi_parse_one_drhd(entry_header);
            break;
        case ACPI_DMAR_TYPE_RESERVED_MEMORY:
            if ( iommu_verbose )
                printk(VTDPREFIX "found ACPI_DMAR_RMRR:\n");
            ret = acpi_parse_one_rmrr(entry_header);
            break;
        case ACPI_DMAR_TYPE_ATSR:
            if ( iommu_verbose )
                printk(VTDPREFIX "found ACPI_DMAR_ATSR:\n");
            ret = acpi_parse_one_atsr(entry_header);
            break;
        case ACPI_DMAR_HARDWARE_AFFINITY:
            if ( iommu_verbose )
                printk(VTDPREFIX "found ACPI_DMAR_RHSA:\n");
            ret = acpi_parse_one_rhsa(entry_header);
            break;
        default:
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Ignore unknown DMAR structure type (%#x)\n",
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
    acpi_dmar_zap();
    return ret;
}

#define MAX_USER_RMRR_PAGES 16
#define MAX_USER_RMRR 10

/* RMRR units derived from command line rmrr option. */
#define MAX_USER_RMRR_DEV 20
struct user_rmrr {
    struct list_head list;
    unsigned long base_pfn, end_pfn;
    unsigned int dev_count;
    u32 sbdf[MAX_USER_RMRR_DEV];
};

static unsigned int __initdata nr_rmrr;
static struct user_rmrr __initdata user_rmrrs[MAX_USER_RMRR];

/* Macro for RMRR inclusive range formatting. */
#define ERMRRU_FMT "[%lx-%lx]"
#define ERMRRU_ARG(eru) eru.base_pfn, eru.end_pfn

static int __init add_user_rmrr(void)
{
    struct acpi_rmrr_unit *rmrr, *rmrru;
    unsigned int idx, seg, i;
    unsigned long base, end;
    bool overlap;

    for ( i = 0; i < nr_rmrr; i++ )
    {
        base = user_rmrrs[i].base_pfn;
        end = user_rmrrs[i].end_pfn;

        if ( base > end )
        {
            printk(XENLOG_ERR VTDPREFIX
                   "Invalid RMRR Range "ERMRRU_FMT"\n",
                   ERMRRU_ARG(user_rmrrs[i]));
            continue;
        }

        if ( (end - base) >= MAX_USER_RMRR_PAGES )
        {
            printk(XENLOG_ERR VTDPREFIX
                   "RMRR range "ERMRRU_FMT" exceeds "\
                   __stringify(MAX_USER_RMRR_PAGES)" pages\n",
                   ERMRRU_ARG(user_rmrrs[i]));
            continue;
        }

        overlap = false;
        list_for_each_entry(rmrru, &acpi_rmrr_units, list)
        {
            if ( pfn_to_paddr(base) <= rmrru->end_address &&
                 rmrru->base_address <= pfn_to_paddr(end) )
            {
                printk(XENLOG_ERR VTDPREFIX
                       "Overlapping RMRRs: "ERMRRU_FMT" and [%lx-%lx]\n",
                       ERMRRU_ARG(user_rmrrs[i]),
                       paddr_to_pfn(rmrru->base_address),
                       paddr_to_pfn(rmrru->end_address));
                overlap = true;
                break;
            }
        }
        /* Don't add overlapping RMRR. */
        if ( overlap )
            continue;

        do
        {
            if ( !mfn_valid(_mfn(base)) )
            {
                printk(XENLOG_ERR VTDPREFIX
                       "Invalid pfn in RMRR range "ERMRRU_FMT"\n",
                       ERMRRU_ARG(user_rmrrs[i]));
                break;
            }
        } while ( base++ < end );

        /* Invalid pfn in range as the loop ended before end_pfn was reached. */
        if ( base <= end )
            continue;

        rmrr = xzalloc(struct acpi_rmrr_unit);
        if ( !rmrr )
            return -ENOMEM;

        rmrr->scope.devices = xmalloc_array(u16, user_rmrrs[i].dev_count);
        if ( !rmrr->scope.devices )
        {
            xfree(rmrr);
            return -ENOMEM;
        }

        seg = 0;
        for ( idx = 0; idx < user_rmrrs[i].dev_count; idx++ )
        {
            rmrr->scope.devices[idx] = user_rmrrs[i].sbdf[idx];
            seg |= PCI_SEG(user_rmrrs[i].sbdf[idx]);
        }
        if ( seg != PCI_SEG(user_rmrrs[i].sbdf[0]) )
        {
            printk(XENLOG_ERR VTDPREFIX
                   "Segments are not equal for RMRR range "ERMRRU_FMT"\n",
                   ERMRRU_ARG(user_rmrrs[i]));
            scope_devices_free(&rmrr->scope);
            xfree(rmrr);
            continue;
        }

        rmrr->segment = seg;
        rmrr->base_address = pfn_to_paddr(user_rmrrs[i].base_pfn);
        /* Align the end_address to the end of the page */
        rmrr->end_address = pfn_to_paddr(user_rmrrs[i].end_pfn) | ~PAGE_MASK;
        rmrr->scope.devices_cnt = user_rmrrs[i].dev_count;

        if ( register_one_rmrr(rmrr) )
            printk(XENLOG_ERR VTDPREFIX
                   "Could not register RMMR range "ERMRRU_FMT"\n",
                   ERMRRU_ARG(user_rmrrs[i]));
    }

    return 0;
}

#include <asm/tboot.h>
/* ACPI tables may not be DMA protected by tboot, so use DMAR copy */
/* SINIT saved in SinitMleData in TXT heap (which is DMA protected) */
#define parse_dmar_table(h) tboot_parse_dmar_table(h)

int __init acpi_dmar_init(void)
{
    acpi_physical_address dmar_addr;
    acpi_native_uint dmar_len;
    int ret;

    if ( ACPI_SUCCESS(acpi_get_table_phys(ACPI_SIG_DMAR, 0,
                                          &dmar_addr, &dmar_len)) )
    {
        map_pages_to_xen((unsigned long)__va(dmar_addr), maddr_to_mfn(dmar_addr),
                         PFN_UP(dmar_addr + dmar_len) - PFN_DOWN(dmar_addr),
                         PAGE_HYPERVISOR);
        dmar_table = __va(dmar_addr);
    }

    ret = parse_dmar_table(acpi_parse_dmar);

    if ( !ret )
    {
        iommu_init_ops = &intel_iommu_init_ops;

        return add_user_rmrr();
    }

    return ret;
}

void acpi_dmar_reinstate(void)
{
    uint32_t sig = 0x52414d44; /* "DMAR" */

    if ( dmar_table )
        write_atomic((uint32_t*)&dmar_table->signature[0], sig);
}

void acpi_dmar_zap(void)
{
    uint32_t sig = 0x44414d52; /* "RMAD" - doesn't alter table checksum */

    if ( dmar_table )
        write_atomic((uint32_t*)&dmar_table->signature[0], sig);
}

bool_t platform_supports_intremap(void)
{
    const unsigned int mask = ACPI_DMAR_INTR_REMAP;

    return (dmar_flags & mask) == ACPI_DMAR_INTR_REMAP;
}

bool_t __init platform_supports_x2apic(void)
{
    const unsigned int mask = ACPI_DMAR_INTR_REMAP | ACPI_DMAR_X2APIC_OPT_OUT;

    return cpu_has_x2apic && ((dmar_flags & mask) == ACPI_DMAR_INTR_REMAP);
}

int intel_iommu_get_reserved_device_memory(iommu_grdm_t *func, void *ctxt)
{
    struct acpi_rmrr_unit *rmrr, *rmrr_cur = NULL;
    unsigned int i;
    u16 bdf;

    for_each_rmrr_device ( rmrr, bdf, i )
    {
        int rc;

        if ( rmrr == rmrr_cur )
            continue;

        rc = func(PFN_DOWN(rmrr->base_address),
                  PFN_UP(rmrr->end_address) - PFN_DOWN(rmrr->base_address),
                  PCI_SBDF2(rmrr->segment, bdf).sbdf, ctxt);

        if ( unlikely(rc < 0) )
            return rc;

        if ( rc )
            rmrr_cur = rmrr;
    }

    return 0;
}

/*
 * Parse rmrr Xen command line options and add parsed devices and regions into
 * acpi_rmrr_unit list to mapped as RMRRs parsed from ACPI.
 * Format:
 * rmrr=start<-end>=[s1]bdf1[,[s1]bdf2[,...]];start<-end>=[s2]bdf1[,[s2]bdf2[,...]]
 * If the segment of the first device is not specified,
 * segment zero will be used.
 * If other segments are not specified, first device segment will be used.
 * If a segment is specified for other than the first device, and it does not
 * match the one specified for the first one, an error will be reported.
 */
static int __init parse_rmrr_param(const char *str)
{
    const char *s = str, *cur, *stmp;
    unsigned int seg, bus, dev, func, dev_count;
    unsigned long start, end;

    do {
        if ( nr_rmrr >= MAX_USER_RMRR )
            return -E2BIG;

        start = simple_strtoul(cur = s, &s, 16);
        if ( cur == s )
            return -EINVAL;

        if ( *s == '-' )
        {
            end = simple_strtoul(cur = s + 1, &s, 16);
            if ( cur == s )
                return -EINVAL;
        }
        else
            end = start;

        user_rmrrs[nr_rmrr].base_pfn = start;
        user_rmrrs[nr_rmrr].end_pfn = end;

        if ( *s != '=' )
            continue;

        do {
            bool def_seg = false;

            stmp = parse_pci_seg(s + 1, &seg, &bus, &dev, &func, &def_seg);
            if ( !stmp )
                return -EINVAL;

            /*
             * Not specified.
             * Segment will be replaced with one from first device.
             */
            if ( user_rmrrs[nr_rmrr].dev_count && def_seg )
                seg = PCI_SEG(user_rmrrs[nr_rmrr].sbdf[0]);

            /* Keep sbdf's even if they differ and later report an error. */
            dev_count = user_rmrrs[nr_rmrr].dev_count;
            user_rmrrs[nr_rmrr].sbdf[dev_count] =
               PCI_SBDF(seg, bus, dev, func).sbdf;

            user_rmrrs[nr_rmrr].dev_count++;
            s = stmp;
        } while ( *s == ',' &&
                  user_rmrrs[nr_rmrr].dev_count < MAX_USER_RMRR_DEV );

        if ( user_rmrrs[nr_rmrr].dev_count )
            nr_rmrr++;

    } while ( *s++ == ';' );

    return s[-1] ? -EINVAL : 0;
}
custom_param("rmrr", parse_rmrr_param);
