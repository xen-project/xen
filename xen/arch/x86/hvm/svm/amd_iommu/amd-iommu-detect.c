/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <asm/iommu.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include "pci-direct.h"
#include "pci_regs.h"

static int __init valid_bridge_bus_config(int bus, int dev, int func,
            int *sec_bus, int *sub_bus)
{
    int pri_bus;

    pri_bus = read_pci_config_byte(bus, dev, func, PCI_PRIMARY_BUS);
    *sec_bus = read_pci_config_byte(bus, dev, func, PCI_SECONDARY_BUS);
    *sub_bus = read_pci_config_byte(bus, dev, func, PCI_SUBORDINATE_BUS);

    return ( pri_bus == bus && *sec_bus > bus && *sub_bus >= *sec_bus );
}

int __init get_iommu_last_downstream_bus(struct amd_iommu *iommu)
{
    int bus, dev, func;
    int devfn, hdr_type;
    int sec_bus, sub_bus;
    int multi_func;

    bus = iommu->last_downstream_bus = iommu->root_bus;
    iommu->downstream_bus_present[bus] = 1;
    dev = PCI_SLOT(iommu->first_devfn);
    multi_func = PCI_FUNC(iommu->first_devfn) > 0;
    for ( devfn = iommu->first_devfn; devfn <= iommu->last_devfn; ++devfn ) {
        /* skipping to next device#? */
        if ( dev != PCI_SLOT(devfn) ) {
            dev = PCI_SLOT(devfn);
            multi_func = 0;
        }
        func = PCI_FUNC(devfn);
 
        if ( !VALID_PCI_VENDOR_ID(
            read_pci_config_16(bus, dev, func, PCI_VENDOR_ID)) )
            continue;

        hdr_type = read_pci_config_byte(bus, dev, func,
                PCI_HEADER_TYPE);
        if ( func == 0 )
            multi_func = IS_PCI_MULTI_FUNCTION(hdr_type);

        if ( (func == 0 || multi_func) &&
            IS_PCI_TYPE1_HEADER(hdr_type) ) {
            if (!valid_bridge_bus_config(bus, dev, func,
                &sec_bus, &sub_bus))
                return -ENODEV;

            if ( sub_bus > iommu->last_downstream_bus )
                iommu->last_downstream_bus = sub_bus;
            do {
                iommu->downstream_bus_present[sec_bus] = 1;
            } while ( sec_bus++ < sub_bus );
        }
    }

    return 0;
}

int __init get_iommu_capabilities(u8 bus, u8 dev, u8 func, u8 cap_ptr,
            struct amd_iommu *iommu)
{
    u32 cap_header, cap_range;
    u64 mmio_bar;

    /* remove it when BIOS available */
    write_pci_config(bus, dev, func,
        cap_ptr + PCI_CAP_MMIO_BAR_HIGH_OFFSET, 0x00000000);
    write_pci_config(bus, dev, func,
        cap_ptr + PCI_CAP_MMIO_BAR_LOW_OFFSET, 0x40000001);
    /* remove it when BIOS available */

    mmio_bar = (u64)read_pci_config(bus, dev, func,
             cap_ptr + PCI_CAP_MMIO_BAR_HIGH_OFFSET) << 32;
    mmio_bar |= read_pci_config(bus, dev, func,
            cap_ptr + PCI_CAP_MMIO_BAR_LOW_OFFSET) &
            PCI_CAP_MMIO_BAR_LOW_MASK;
    iommu->mmio_base_phys = (unsigned long)mmio_bar;

    if ( (mmio_bar == 0) || ( (mmio_bar & 0x3FFF) != 0 ) ) {
        dprintk(XENLOG_ERR ,
                "AMD IOMMU: Invalid MMIO_BAR = 0x%"PRIx64"\n", mmio_bar);
        return -ENODEV;
    }

    cap_header = read_pci_config(bus, dev, func, cap_ptr);
    iommu->revision = get_field_from_reg_u32(cap_header,
                  PCI_CAP_REV_MASK, PCI_CAP_REV_SHIFT);
    iommu->iotlb_support = get_field_from_reg_u32(cap_header,
                PCI_CAP_IOTLB_MASK, PCI_CAP_IOTLB_SHIFT);
    iommu->ht_tunnel_support = get_field_from_reg_u32(cap_header,
                    PCI_CAP_HT_TUNNEL_MASK,
                    PCI_CAP_HT_TUNNEL_SHIFT);
    iommu->not_present_cached = get_field_from_reg_u32(cap_header,
                    PCI_CAP_NP_CACHE_MASK,
                    PCI_CAP_NP_CACHE_SHIFT);

    cap_range = read_pci_config(bus, dev, func,
            cap_ptr + PCI_CAP_RANGE_OFFSET);
    iommu->root_bus = get_field_from_reg_u32(cap_range,
                PCI_CAP_BUS_NUMBER_MASK,
                PCI_CAP_BUS_NUMBER_SHIFT);
    iommu->first_devfn = get_field_from_reg_u32(cap_range,
                PCI_CAP_FIRST_DEVICE_MASK,
                PCI_CAP_FIRST_DEVICE_SHIFT);
    iommu->last_devfn = get_field_from_reg_u32(cap_range,
                PCI_CAP_LAST_DEVICE_MASK,
                PCI_CAP_LAST_DEVICE_SHIFT);

    return 0;
}

static int __init scan_caps_for_iommu(int bus, int dev, int func,
            iommu_detect_callback_ptr_t iommu_detect_callback)
{
    int cap_ptr, cap_id, cap_type;
    u32 cap_header;
    int count, error = 0;

    count = 0;
    cap_ptr = read_pci_config_byte(bus, dev, func,
            PCI_CAPABILITY_LIST);
    while ( cap_ptr >= PCI_MIN_CAP_OFFSET &&
        count < PCI_MAX_CAP_BLOCKS && !error ) {
        cap_ptr &= PCI_CAP_PTR_MASK;
        cap_header = read_pci_config(bus, dev, func, cap_ptr);
        cap_id = get_field_from_reg_u32(cap_header,
                PCI_CAP_ID_MASK, PCI_CAP_ID_SHIFT);

        if ( cap_id == PCI_CAP_ID_SECURE_DEVICE ) {
            cap_type = get_field_from_reg_u32(cap_header,
                    PCI_CAP_TYPE_MASK, PCI_CAP_TYPE_SHIFT);
            if ( cap_type == PCI_CAP_TYPE_IOMMU ) {
                error = iommu_detect_callback(
                        bus, dev, func, cap_ptr);
            }
        }

        cap_ptr = get_field_from_reg_u32(cap_header,
                PCI_CAP_NEXT_PTR_MASK, PCI_CAP_NEXT_PTR_SHIFT);
        ++count;    }

    return error;
}

static int __init scan_functions_for_iommu(int bus, int dev,
            iommu_detect_callback_ptr_t iommu_detect_callback)
{
    int func, hdr_type;
    int count, error = 0;

    func = 0;
    count = 1;
    while ( VALID_PCI_VENDOR_ID(read_pci_config_16(bus, dev, func,
            PCI_VENDOR_ID)) && !error && func < count ) {
        hdr_type = read_pci_config_byte(bus, dev, func,
                PCI_HEADER_TYPE);

        if ( func == 0 && IS_PCI_MULTI_FUNCTION(hdr_type) )
            count = PCI_MAX_FUNC_COUNT;

        if ( IS_PCI_TYPE0_HEADER(hdr_type) ||
            IS_PCI_TYPE1_HEADER(hdr_type) ) {
            error =  scan_caps_for_iommu(bus, dev, func,
                    iommu_detect_callback);
        }
        ++func;
    }

    return error;
}


int __init scan_for_iommu(iommu_detect_callback_ptr_t iommu_detect_callback)
{
    int bus, dev, error = 0;

    for ( bus = 0; bus < PCI_MAX_BUS_COUNT && !error; ++bus ) {
        for ( dev = 0; dev < PCI_MAX_DEV_COUNT && !error; ++dev ) {
            error =  scan_functions_for_iommu(bus, dev,
                  iommu_detect_callback);
        }
    }

    return error;
}

