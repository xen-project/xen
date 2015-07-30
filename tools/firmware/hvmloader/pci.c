/*
 * pci.c: HVM PCI setup.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
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
 */

#include "util.h"
#include "hypercall.h"
#include "config.h"
#include "pci_regs.h"

#include <xen/memory.h>
#include <xen/hvm/ioreq.h>
#include <xen/hvm/hvm_xs_strings.h>
#include <xen/hvm/e820.h>
#include <stdbool.h>

unsigned long pci_mem_start = HVM_BELOW_4G_MMIO_START;
unsigned long pci_mem_end = PCI_MEM_END;
uint64_t pci_hi_mem_start = 0, pci_hi_mem_end = 0;

enum virtual_vga virtual_vga = VGA_none;
unsigned long igd_opregion_pgbase = 0;

/* Check if the specified range conflicts with any reserved device memory. */
static bool check_overlap_all(uint64_t start, uint64_t size)
{
    unsigned int i;

    for ( i = 0; i < memory_map.nr_map; i++ )
    {
        if ( memory_map.map[i].type == E820_RESERVED &&
             check_overlap(start, size,
                           memory_map.map[i].addr,
                           memory_map.map[i].size) )
            return true;
    }

    return false;
}

/* Find the lowest RMRR ending above base but below 4G. */
static int find_next_rmrr(uint32_t base)
{
    unsigned int i;
    int next_rmrr = -1;
    uint64_t end, min_end = 1ULL << 32;

    for ( i = 0; i < memory_map.nr_map ; i++ )
    {
        end = memory_map.map[i].addr + memory_map.map[i].size;

        if ( memory_map.map[i].type == E820_RESERVED &&
             end > base && end <= min_end )
        {
            next_rmrr = i;
            min_end = end;
        }
    }

    return next_rmrr;
}

void pci_setup(void)
{
    uint8_t is_64bar, using_64bar, bar64_relocate = 0;
    uint32_t devfn, bar_reg, cmd, bar_data, bar_data_upper;
    uint64_t base, bar_sz, bar_sz_upper, mmio_total = 0;
    uint32_t vga_devfn = 256;
    uint16_t class, vendor_id, device_id;
    unsigned int bar, pin, link, isa_irq;
    int next_rmrr;

    /* Resources assignable to PCI devices via BARs. */
    struct resource {
        uint64_t base, max;
    } *resource, mem_resource, high_mem_resource, io_resource;

    /* Create a list of device BARs in descending order of size. */
    struct bars {
        uint32_t is_64bar;
        uint32_t devfn;
        uint32_t bar_reg;
        uint64_t bar_sz;
    } *bars = (struct bars *)scratch_start;
    unsigned int i, nr_bars = 0;
    uint64_t mmio_hole_size = 0;

    const char *s;
    /*
     * Do we allow hvmloader to relocate guest memory in order to
     * increase the size of the lowmem MMIO hole?  Defaulting to 1
     * here will mean that non-libxl toolstacks (including xend and
     * home-grown ones) means that those using qemu-xen will still
     * experience the memory relocation bug described below; but it
     * also means that those using qemu-traditional will *not*
     * experience any change; and it also means that there is a
     * work-around for those using qemu-xen, namely switching to
     * qemu-traditional.
     *
     * If we defaulted to 0, and failing to resize the hole caused any
     * problems with qemu-traditional, then there is no work-around.
     *
     * Since xend can only use qemu-traditional, I think this is the
     * option that will have the least impact.
     */
    bool allow_memory_relocate = 1;

    s = xenstore_read(HVM_XS_ALLOW_MEMORY_RELOCATE, NULL);
    if ( s )
        allow_memory_relocate = strtoll(s, NULL, 0);
    printf("Relocating guest memory for lowmem MMIO space %s\n",
           allow_memory_relocate?"enabled":"disabled");

    s = xenstore_read("platform/mmio_hole_size", NULL);
    if ( s )
        mmio_hole_size = strtoll(s, NULL, 0);

    /* Program PCI-ISA bridge with appropriate link routes. */
    isa_irq = 0;
    for ( link = 0; link < 4; link++ )
    {
        do { isa_irq = (isa_irq + 1) & 15;
        } while ( !(PCI_ISA_IRQ_MASK & (1U << isa_irq)) );
        pci_writeb(PCI_ISA_DEVFN, 0x60 + link, isa_irq);
        printf("PCI-ISA link %u routed to IRQ%u\n", link, isa_irq);
    }

    /* Program ELCR to match PCI-wired IRQs. */
    outb(0x4d0, (uint8_t)(PCI_ISA_IRQ_MASK >> 0));
    outb(0x4d1, (uint8_t)(PCI_ISA_IRQ_MASK >> 8));

    /* Scan the PCI bus and map resources. */
    for ( devfn = 0; devfn < 256; devfn++ )
    {
        class     = pci_readw(devfn, PCI_CLASS_DEVICE);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);
        if ( (vendor_id == 0xffff) && (device_id == 0xffff) )
            continue;

        ASSERT((devfn != PCI_ISA_DEVFN) ||
               ((vendor_id == 0x8086) && (device_id == 0x7000)));

        switch ( class )
        {
        case 0x0300:
            /* If emulated VGA is found, preserve it as primary VGA. */
            if ( (vendor_id == 0x1234) && (device_id == 0x1111) )
            {
                vga_devfn = devfn;
                virtual_vga = VGA_std;
            }
            else if ( (vendor_id == 0x1013) && (device_id == 0xb8) )
            {
                vga_devfn = devfn;
                virtual_vga = VGA_cirrus;
            }
            else if ( virtual_vga == VGA_none )
            {
                vga_devfn = devfn;
                virtual_vga = VGA_pt;
                if ( vendor_id == 0x8086 )
                {
                    igd_opregion_pgbase = mem_hole_alloc(IGD_OPREGION_PAGES);
                    /*
                     * Write the the OpRegion offset to give the opregion
                     * address to the device model. The device model will trap 
                     * and map the OpRegion at the give address.
                     */
                    pci_writel(vga_devfn, PCI_INTEL_OPREGION,
                               igd_opregion_pgbase << PAGE_SHIFT);
                }
            }
            break;
        case 0x0680:
            /* PIIX4 ACPI PM. Special device with special PCI config space. */
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7113));
            pci_writew(devfn, 0x20, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0xd2, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0x22, 0x0000);
            pci_writew(devfn, 0x3c, 0x0009); /* Hardcoded IRQ9 */
            pci_writew(devfn, 0x3d, 0x0001);
            pci_writel(devfn, 0x40, ACPI_PM1A_EVT_BLK_ADDRESS_V1 | 1);
            pci_writeb(devfn, 0x80, 0x01); /* enable PM io space */
            break;
        case 0x0101:
            if ( vendor_id == 0x8086 )
            {
                /* Intel ICHs since PIIX3: enable IDE legacy mode. */
                pci_writew(devfn, 0x40, 0x8000); /* enable IDE0 */
                pci_writew(devfn, 0x42, 0x8000); /* enable IDE1 */
            }
            break;
        }

        /* Map the I/O memory and port resources. */
        for ( bar = 0; bar < 7; bar++ )
        {
            bar_sz_upper = 0;
            bar_reg = PCI_BASE_ADDRESS_0 + 4*bar;
            if ( bar == 6 )
                bar_reg = PCI_ROM_ADDRESS;

            bar_data = pci_readl(devfn, bar_reg);
            if ( bar_reg != PCI_ROM_ADDRESS )
            {
                is_64bar = !!((bar_data & (PCI_BASE_ADDRESS_SPACE |
                             PCI_BASE_ADDRESS_MEM_TYPE_MASK)) ==
                             (PCI_BASE_ADDRESS_SPACE_MEMORY |
                             PCI_BASE_ADDRESS_MEM_TYPE_64));
                pci_writel(devfn, bar_reg, ~0);
            }
            else
            {
                is_64bar = 0;
                pci_writel(devfn, bar_reg,
                           (bar_data | PCI_ROM_ADDRESS_MASK) &
                           ~PCI_ROM_ADDRESS_ENABLE);
            }
            bar_sz = pci_readl(devfn, bar_reg);
            pci_writel(devfn, bar_reg, bar_data);

            if ( bar_reg != PCI_ROM_ADDRESS )
                bar_sz &= (((bar_data & PCI_BASE_ADDRESS_SPACE) ==
                            PCI_BASE_ADDRESS_SPACE_MEMORY) ?
                           PCI_BASE_ADDRESS_MEM_MASK :
                           (PCI_BASE_ADDRESS_IO_MASK & 0xffff));
            else
                bar_sz &= PCI_ROM_ADDRESS_MASK;
            if (is_64bar) {
                bar_data_upper = pci_readl(devfn, bar_reg + 4);
                pci_writel(devfn, bar_reg + 4, ~0);
                bar_sz_upper = pci_readl(devfn, bar_reg + 4);
                pci_writel(devfn, bar_reg + 4, bar_data_upper);
                bar_sz = (bar_sz_upper << 32) | bar_sz;
            }
            bar_sz &= ~(bar_sz - 1);
            if ( bar_sz == 0 )
                continue;

            for ( i = 0; i < nr_bars; i++ )
                if ( bars[i].bar_sz < bar_sz )
                    break;

            if ( i != nr_bars )
                memmove(&bars[i+1], &bars[i], (nr_bars-i) * sizeof(*bars));

            bars[i].is_64bar = is_64bar;
            bars[i].devfn   = devfn;
            bars[i].bar_reg = bar_reg;
            bars[i].bar_sz  = bar_sz;

            if ( ((bar_data & PCI_BASE_ADDRESS_SPACE) ==
                  PCI_BASE_ADDRESS_SPACE_MEMORY) ||
                 (bar_reg == PCI_ROM_ADDRESS) )
                mmio_total += bar_sz;

            nr_bars++;

            /*The upper half is already calculated, skip it! */
            if (is_64bar)
                bar++;
        }

        /* Map the interrupt. */
        pin = pci_readb(devfn, PCI_INTERRUPT_PIN);
        if ( pin != 0 )
        {
            /* This is the barber's pole mapping used by Xen. */
            link = ((pin - 1) + (devfn >> 3)) & 3;
            isa_irq = pci_readb(PCI_ISA_DEVFN, 0x60 + link);
            pci_writeb(devfn, PCI_INTERRUPT_LINE, isa_irq);
            printf("pci dev %02x:%x INT%c->IRQ%u\n",
                   devfn>>3, devfn&7, 'A'+pin-1, isa_irq);
        }

        /* Enable bus mastering. */
        cmd = pci_readw(devfn, PCI_COMMAND);
        cmd |= PCI_COMMAND_MASTER;
        pci_writew(devfn, PCI_COMMAND, cmd);
    }

    if ( mmio_hole_size )
    {
        uint64_t max_ram_below_4g = (1ULL << 32) - mmio_hole_size;

        if ( max_ram_below_4g > HVM_BELOW_4G_MMIO_START )
        {
            printf("max_ram_below_4g=0x"PRIllx
                   " too big for mmio_hole_size=0x"PRIllx
                   " has been ignored.\n",
                   PRIllx_arg(max_ram_below_4g),
                   PRIllx_arg(mmio_hole_size));
        }
        else
        {
            pci_mem_start = max_ram_below_4g;
            printf("pci_mem_start=0x%lx (was 0x%x) for mmio_hole_size=%lu\n",
                   pci_mem_start, HVM_BELOW_4G_MMIO_START,
                   (long)mmio_hole_size);
        }
    }
    else
    {
        /*
         * At the moment qemu-xen can't deal with relocated memory regions.
         * It's too close to the release to make a proper fix; for now,
         * only allow the MMIO hole to grow large enough to move guest memory
         * if we're running qemu-traditional.  Items that don't fit will be
         * relocated into the 64-bit address space.
         *
         * This loop now does the following:
         * - If allow_memory_relocate, increase the MMIO hole until it's
         *   big enough, or until it's 2GiB
         * - If !allow_memory_relocate, increase the MMIO hole until it's
         *   big enough, or until it's 2GiB, or until it overlaps guest
         *   memory
         */
        while ( (mmio_total > (pci_mem_end - pci_mem_start))
                && ((pci_mem_start << 1) != 0)
                && (allow_memory_relocate
                    || (((pci_mem_start << 1) >> PAGE_SHIFT)
                        >= hvm_info->low_mem_pgend)) )
            pci_mem_start <<= 1;

        /*
         * Try to accommodate RMRRs in our MMIO region on a best-effort basis.
         * If we have RMRRs in the range, then make pci_mem_start just after
         * hvm_info->low_mem_pgend.
         */
        if ( pci_mem_start > (hvm_info->low_mem_pgend << PAGE_SHIFT) &&
             check_overlap_all(pci_mem_start, pci_mem_end-pci_mem_start) )
            pci_mem_start = hvm_info->low_mem_pgend << PAGE_SHIFT;
    }

    if ( mmio_total > (pci_mem_end - pci_mem_start) )
    {
        printf("Low MMIO hole not large enough for all devices,"
               " relocating some BARs to 64-bit\n");
        bar64_relocate = 1;
    }

    /* Relocate RAM that overlaps PCI space (in 64k-page chunks). */
    while ( (pci_mem_start >> PAGE_SHIFT) < hvm_info->low_mem_pgend )
    {
        struct xen_add_to_physmap xatp;
        unsigned int nr_pages = min_t(
            unsigned int,
            hvm_info->low_mem_pgend - (pci_mem_start >> PAGE_SHIFT),
            (1u << 16) - 1);
        if ( hvm_info->high_mem_pgend == 0 )
            hvm_info->high_mem_pgend = 1ull << (32 - PAGE_SHIFT);
        hvm_info->low_mem_pgend -= nr_pages;
        printf("Relocating 0x%x pages from "PRIllx" to "PRIllx\
               " for lowmem MMIO hole\n",
               nr_pages,
               PRIllx_arg(((uint64_t)hvm_info->low_mem_pgend)<<PAGE_SHIFT),
               PRIllx_arg(((uint64_t)hvm_info->high_mem_pgend)<<PAGE_SHIFT));
        xatp.domid = DOMID_SELF;
        xatp.space = XENMAPSPACE_gmfn_range;
        xatp.idx   = hvm_info->low_mem_pgend;
        xatp.gpfn  = hvm_info->high_mem_pgend;
        xatp.size  = nr_pages;
        if ( hypercall_memory_op(XENMEM_add_to_physmap, &xatp) != 0 )
            BUG();
        hvm_info->high_mem_pgend += nr_pages;
    }

    /* Sync memory map[] if necessary. */
    adjust_memory_map();

    high_mem_resource.base = ((uint64_t)hvm_info->high_mem_pgend) << PAGE_SHIFT;
    if ( high_mem_resource.base < 1ull << 32 )
    {
        if ( hvm_info->high_mem_pgend != 0 )
            printf("WARNING: hvm_info->high_mem_pgend %x"
                   " does not point into high memory!",
                   hvm_info->high_mem_pgend);
        high_mem_resource.base = 1ull << 32;
    }
    printf("%sRAM in high memory; setting high_mem resource base to "PRIllx"\n",
           hvm_info->high_mem_pgend?"":"No ",
           PRIllx_arg(high_mem_resource.base));
    high_mem_resource.max = 1ull << cpu_phys_addr();
    mem_resource.base = pci_mem_start;
    mem_resource.max = pci_mem_end;
    io_resource.base = 0xc000;
    io_resource.max = 0x10000;

    next_rmrr = find_next_rmrr(pci_mem_start);

    /* Assign iomem and ioport resources in descending order of size. */
    for ( i = 0; i < nr_bars; i++ )
    {
        devfn   = bars[i].devfn;
        bar_reg = bars[i].bar_reg;
        bar_sz  = bars[i].bar_sz;

        /*
         * Relocate to high memory if the total amount of MMIO needed
         * is more than the low MMIO available.  Because devices are
         * processed in order of bar_sz, this will preferentially
         * relocate larger devices to high memory first.
         *
         * NB: The code here is rather fragile, as the check here to see
         * whether bar_sz will fit in the low MMIO region doesn't match the
         * real check made below, which involves aligning the base offset of the
         * bar with the size of the bar itself.  As it happens, this will always
         * be satisfied because:
         * - The first one will succeed because the MMIO hole can only start at
         *   0x{f,e,c,8}00000000.  If it fits, it will be aligned properly.
         * - All subsequent ones will be aligned because the list is ordered
         *   large to small, and bar_sz is always a power of 2. (At least
         *   the code here assumes it to be.)
         * Should either of those two conditions change, this code will break.
         */
        using_64bar = bars[i].is_64bar && bar64_relocate
            && (mmio_total > (mem_resource.max - mem_resource.base));
        bar_data = pci_readl(devfn, bar_reg);

        if ( (bar_data & PCI_BASE_ADDRESS_SPACE) ==
             PCI_BASE_ADDRESS_SPACE_MEMORY )
        {
            /* Mapping high memory if PCI device is 64 bits bar */
            if ( using_64bar ) {
                if ( high_mem_resource.base & (bar_sz - 1) )
                    high_mem_resource.base = high_mem_resource.base - 
                        (high_mem_resource.base & (bar_sz - 1)) + bar_sz;
                if ( !pci_hi_mem_start )
                    pci_hi_mem_start = high_mem_resource.base;
                resource = &high_mem_resource;
                bar_data &= ~PCI_BASE_ADDRESS_MEM_MASK;
            } 
            else {
                resource = &mem_resource;
                bar_data &= ~PCI_BASE_ADDRESS_MEM_MASK;
            }
            mmio_total -= bar_sz;
        }
        else
        {
            resource = &io_resource;
            bar_data &= ~PCI_BASE_ADDRESS_IO_MASK;
        }

        base = (resource->base  + bar_sz - 1) & ~(uint64_t)(bar_sz - 1);

        /* If we're using mem_resource, check for RMRR conflicts. */
        while ( resource == &mem_resource &&
                next_rmrr >= 0 &&
                check_overlap(base, bar_sz,
                              memory_map.map[next_rmrr].addr,
                              memory_map.map[next_rmrr].size) )
        {
            base = memory_map.map[next_rmrr].addr + memory_map.map[next_rmrr].size;
            base = (base + bar_sz - 1) & ~(bar_sz - 1);
            next_rmrr = find_next_rmrr(base);
        }

        bar_data |= (uint32_t)base;
        bar_data_upper = (uint32_t)(base >> 32);
        base += bar_sz;

        if ( (base < resource->base) || (base > resource->max) )
        {
            printf("pci dev %02x:%x bar %02x size "PRIllx": no space for "
                   "resource!\n", devfn>>3, devfn&7, bar_reg,
                   PRIllx_arg(bar_sz));
            continue;
        }

        resource->base = base;

        pci_writel(devfn, bar_reg, bar_data);
        if (using_64bar)
            pci_writel(devfn, bar_reg + 4, bar_data_upper);
        printf("pci dev %02x:%x bar %02x size "PRIllx": %x%08x\n",
               devfn>>3, devfn&7, bar_reg,
               PRIllx_arg(bar_sz),
               bar_data_upper, bar_data);
			

        /* Now enable the memory or I/O mapping. */
        cmd = pci_readw(devfn, PCI_COMMAND);
        if ( (bar_reg == PCI_ROM_ADDRESS) ||
             ((bar_data & PCI_BASE_ADDRESS_SPACE) ==
              PCI_BASE_ADDRESS_SPACE_MEMORY) )
            cmd |= PCI_COMMAND_MEMORY;
        else
            cmd |= PCI_COMMAND_IO;
        pci_writew(devfn, PCI_COMMAND, cmd);
    }

    if ( pci_hi_mem_start )
    {
        /*
         * Make end address alignment match the start address one's so that
         * fewer variable range MTRRs are needed to cover the range.
         */
        pci_hi_mem_end = ((high_mem_resource.base - 1) |
                          ((pci_hi_mem_start & -pci_hi_mem_start) - 1)) + 1;
    }

    if ( vga_devfn != 256 )
    {
        /*
         * VGA registers live in I/O space so ensure that primary VGA
         * has IO enabled, even if there is no I/O BAR on that
         * particular device.
         */
        cmd = pci_readw(vga_devfn, PCI_COMMAND);
        cmd |= PCI_COMMAND_IO;
        pci_writew(vga_devfn, PCI_COMMAND, cmd);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
