/*
 * Generic functionality for handling accesses to the PCI header from the
 * configuration space.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/vpci.h>

#include <xsm/xsm.h>

#include <asm/event.h>
#include <asm/p2m.h>

#define MAPPABLE_BAR(x)                                                 \
    ((x)->type == VPCI_BAR_MEM32 || (x)->type == VPCI_BAR_MEM64_LO ||   \
     (x)->type == VPCI_BAR_ROM)

struct map_data {
    struct domain *d;
    const struct vpci_bar *bar;
    bool map;
};

static int cf_check map_range(
    unsigned long s, unsigned long e, void *data, unsigned long *c)
{
    const struct map_data *map = data;
    /* Start address of the BAR as seen by the guest. */
    unsigned long start_gfn = PFN_DOWN(map->bar->guest_addr);
    /* Physical start address of the BAR. */
    unsigned long start_mfn = PFN_DOWN(map->bar->addr);
    int rc;

    for ( ; ; )
    {
        unsigned long size = e - s + 1;
        /*
         * Ranges to be mapped don't always start at the BAR start address, as
         * there can be holes or partially consumed ranges. Account for the
         * offset of the current address from the BAR start.
         */
        unsigned long map_mfn = start_mfn + s - start_gfn;
        unsigned long m_end = map_mfn + size - 1;

        if ( !iomem_access_permitted(map->d, map_mfn, m_end) )
        {
            printk(XENLOG_G_WARNING
                   "%pd denied access to MMIO range [%#lx, %#lx]\n",
                   map->d, map_mfn, m_end);
            return -EPERM;
        }

        rc = xsm_iomem_mapping(XSM_HOOK, map->d, map_mfn, m_end, map->map);
        if ( rc )
        {
            printk(XENLOG_G_WARNING
                   "%pd XSM denied access to MMIO range [%#lx, %#lx]: %d\n",
                   map->d, map_mfn, m_end, rc);
            return rc;
        }

        /*
         * ARM TODOs:
         * - On ARM whether the memory is prefetchable or not should be passed
         *   to map_mmio_regions in order to decide which memory attributes
         *   should be used.
         *
         * - {un}map_mmio_regions doesn't support preemption.
         */

        rc = map->map ? map_mmio_regions(map->d, _gfn(s), size, _mfn(map_mfn))
                      : unmap_mmio_regions(map->d, _gfn(s), size, _mfn(map_mfn));
        if ( rc == 0 )
        {
            *c += size;
            break;
        }
        if ( rc < 0 )
        {
            printk(XENLOG_G_WARNING
                   "Failed to %smap [%lx %lx] -> [%lx %lx] for %pd: %d\n",
                   map->map ? "" : "un", s, e, map_mfn,
                   map_mfn + size, map->d, rc);
            break;
        }
        ASSERT(rc < size);
        *c += rc;
        s += rc;
        if ( general_preempt_check() )
                return -ERESTART;
    }

    return rc;
}

/*
 * The rom_only parameter is used to signal the map/unmap helpers that the ROM
 * BAR's enable bit has changed with the memory decoding bit already enabled.
 * If rom_only is not set then it's the memory decoding bit that changed.
 */
static void modify_decoding(const struct pci_dev *pdev, uint16_t cmd,
                            bool rom_only)
{
    struct vpci_header *header = &pdev->vpci->header;
    bool map = cmd & PCI_COMMAND_MEMORY;
    unsigned int i;

    /*
     * Make sure there are no mappings in the MSIX MMIO areas, so that accesses
     * can be trapped (and emulated) by Xen when the memory decoding bit is
     * enabled.
     *
     * FIXME: punching holes after the p2m has been set up might be racy for
     * DomU usage, needs to be revisited.
     */
#ifdef CONFIG_HAS_PCI_MSI
    if ( map && !rom_only && vpci_make_msix_hole(pdev) )
        return;
#endif

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];

        if ( !MAPPABLE_BAR(bar) )
            continue;

        if ( rom_only && bar->type == VPCI_BAR_ROM )
        {
            unsigned int rom_pos = (i == PCI_HEADER_NORMAL_NR_BARS)
                                   ? PCI_ROM_ADDRESS : PCI_ROM_ADDRESS1;
            uint32_t val = bar->addr |
                           (map ? PCI_ROM_ADDRESS_ENABLE : 0);

            if ( pci_check_bar(pdev, _mfn(PFN_DOWN(bar->addr)),
                               _mfn(PFN_DOWN(bar->addr + bar->size - 1))) )
                bar->enabled = map;
            header->rom_enabled = map;
            pci_conf_write32(pdev->sbdf, rom_pos, val);
            return;
        }

        if ( !rom_only &&
             (bar->type != VPCI_BAR_ROM || header->rom_enabled) &&
             pci_check_bar(pdev, _mfn(PFN_DOWN(bar->addr)),
                           _mfn(PFN_DOWN(bar->addr + bar->size - 1))) )
            bar->enabled = map;
    }

    if ( !rom_only )
    {
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
        header->bars_mapped = map;
    }
    else
        ASSERT_UNREACHABLE();
}

bool vpci_process_pending(struct vcpu *v)
{
    struct pci_dev *pdev = v->vpci.pdev;
    struct vpci_header *header = NULL;
    unsigned int i;

    if ( !pdev )
        return false;

    read_lock(&v->domain->pci_lock);

    if ( !pdev->vpci || (v->domain != pdev->domain) )
    {
        v->vpci.pdev = NULL;
        read_unlock(&v->domain->pci_lock);
        return false;
    }

    header = &pdev->vpci->header;
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];
        struct map_data data = {
            .d = v->domain,
            .map = v->vpci.cmd & PCI_COMMAND_MEMORY,
            .bar = bar,
        };
        int rc;

        if ( rangeset_is_empty(bar->mem) )
            continue;

        rc = rangeset_consume_ranges(bar->mem, map_range, &data);

        if ( rc == -ERESTART )
        {
            read_unlock(&v->domain->pci_lock);
            return true;
        }

        if ( rc )
        {
            spin_lock(&pdev->vpci->lock);
            /* Disable memory decoding unconditionally on failure. */
            modify_decoding(pdev, v->vpci.cmd & ~PCI_COMMAND_MEMORY,
                            false);
            spin_unlock(&pdev->vpci->lock);

            /* Clean all the rangesets */
            for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
                if ( !rangeset_is_empty(header->bars[i].mem) )
                     rangeset_purge(header->bars[i].mem);

            v->vpci.pdev = NULL;

            read_unlock(&v->domain->pci_lock);

            if ( !is_hardware_domain(v->domain) )
                domain_crash(v->domain);

            return false;
        }
    }
    v->vpci.pdev = NULL;

    spin_lock(&pdev->vpci->lock);
    modify_decoding(pdev, v->vpci.cmd, v->vpci.rom_only);
    spin_unlock(&pdev->vpci->lock);

    read_unlock(&v->domain->pci_lock);

    return false;
}

static int __init apply_map(struct domain *d, const struct pci_dev *pdev,
                            uint16_t cmd)
{
    struct vpci_header *header = &pdev->vpci->header;
    int rc = 0;
    unsigned int i;

    ASSERT(rw_is_write_locked(&d->pci_lock));

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];
        struct map_data data = { .d = d, .map = true, .bar = bar };

        if ( rangeset_is_empty(bar->mem) )
            continue;

        while ( (rc = rangeset_consume_ranges(bar->mem, map_range,
                                              &data)) == -ERESTART )
        {
            /*
             * It's safe to drop and reacquire the lock in this context
             * without risking pdev disappearing because devices cannot be
             * removed until the initial domain has been started.
             */
            write_unlock(&d->pci_lock);
            process_pending_softirqs();
            write_lock(&d->pci_lock);
        }
    }
    if ( !rc )
        modify_decoding(pdev, cmd, false);

    return rc;
}

static void defer_map(struct domain *d, struct pci_dev *pdev,
                      uint16_t cmd, bool rom_only)
{
    struct vcpu *curr = current;

    /*
     * FIXME: when deferring the {un}map the state of the device should not
     * be trusted. For example the enable bit is toggled after the device
     * is mapped. This can lead to parallel mapping operations being
     * started for the same device if the domain is not well-behaved.
     */
    curr->vpci.pdev = pdev;
    curr->vpci.cmd = cmd;
    curr->vpci.rom_only = rom_only;
    /*
     * Raise a scheduler softirq in order to prevent the guest from resuming
     * execution with pending mapping operations, to trigger the invocation
     * of vpci_process_pending().
     */
    raise_softirq(SCHEDULE_SOFTIRQ);
}

static int modify_bars(const struct pci_dev *pdev, uint16_t cmd, bool rom_only)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct pci_dev *tmp, *dev = NULL;
    const struct domain *d;
    const struct vpci_msix *msix = pdev->vpci->msix;
    unsigned int i, j;
    int rc;

    ASSERT(rw_is_write_locked(&pdev->domain->pci_lock));

    /*
     * Create a rangeset per BAR that represents the current device memory
     * region and compare it against all the currently active BAR memory
     * regions. If an overlap is found, subtract it from the region to be
     * mapped/unmapped.
     *
     * First fill the rangesets with the BAR of this device or with the ROM
     * BAR only, depending on whether the guest is toggling the memory decode
     * bit of the command register, or the enable bit of the ROM BAR register.
     *
     * For non-hardware domain we use guest physical addresses.
     */
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];
        unsigned long start = PFN_DOWN(bar->addr);
        unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);
        unsigned long start_guest = PFN_DOWN(bar->guest_addr);
        unsigned long end_guest = PFN_DOWN(bar->guest_addr + bar->size - 1);

        if ( !bar->mem )
            continue;

        if ( !MAPPABLE_BAR(bar) ||
             (rom_only ? bar->type != VPCI_BAR_ROM
                       : (bar->type == VPCI_BAR_ROM && !header->rom_enabled)) ||
             /* Skip BARs already in the requested state. */
             bar->enabled == !!(cmd & PCI_COMMAND_MEMORY) )
            continue;

        if ( !pci_check_bar(pdev, _mfn(start), _mfn(end)) )
        {
            printk(XENLOG_G_WARNING
                   "%pp: not mapping BAR [%lx, %lx] invalid position\n",
                   &pdev->sbdf, start, end);
            continue;
        }

        ASSERT(rangeset_is_empty(bar->mem));

        /*
         * Make sure that the guest set address has the same page offset
         * as the physical address on the host or otherwise things won't work as
         * expected.
         */
        if ( PAGE_OFFSET(bar->guest_addr) != PAGE_OFFSET(bar->addr) )
        {
            gprintk(XENLOG_G_WARNING,
                    "%pp: can't map BAR%u - offset mismatch: %#lx vs %#lx\n",
                    &pdev->sbdf, i, bar->guest_addr, bar->addr);
            return -EINVAL;
        }

        rc = rangeset_add_range(bar->mem, start_guest, end_guest);
        if ( rc )
        {
            printk(XENLOG_G_WARNING "Failed to add [%lx, %lx]: %d\n",
                   start_guest, end_guest, rc);
            return rc;
        }

        /* Check for overlap with the already setup BAR ranges. */
        for ( j = 0; j < i; j++ )
        {
            struct vpci_bar *prev_bar = &header->bars[j];

            if ( rangeset_is_empty(prev_bar->mem) )
                continue;

            rc = rangeset_remove_range(prev_bar->mem, start_guest, end_guest);
            if ( rc )
            {
                gprintk(XENLOG_WARNING,
                       "%pp: failed to remove overlapping range [%lx, %lx]: %d\n",
                        &pdev->sbdf, start_guest, end_guest, rc);
                return rc;
            }
        }

        rc = pci_sanitize_bar_memory(bar->mem);
        if ( rc )
        {
            gprintk(XENLOG_WARNING,
                    "%pp: failed to sanitize BAR#%u memory: %d\n",
                    &pdev->sbdf, i, rc);
            return rc;
        }
    }

    /* Remove any MSIX regions if present. */
    for ( i = 0; msix && i < ARRAY_SIZE(msix->tables); i++ )
    {
        unsigned long start = PFN_DOWN(vmsix_table_addr(pdev->vpci, i));
        unsigned long end = PFN_DOWN(vmsix_table_addr(pdev->vpci, i) +
                                     vmsix_table_size(pdev->vpci, i) - 1);

        for ( j = 0; j < ARRAY_SIZE(header->bars); j++ )
        {
            const struct vpci_bar *bar = &header->bars[j];

            if ( rangeset_is_empty(bar->mem) )
                continue;

            rc = rangeset_remove_range(bar->mem, start, end);
            if ( rc )
            {
                gprintk(XENLOG_WARNING,
                       "%pp: failed to remove MSIX table [%lx, %lx]: %d\n",
                        &pdev->sbdf, start, end, rc);
                return rc;
            }
        }
    }

    /*
     * Check for overlaps with other BARs. Note that only BARs that are
     * currently mapped (enabled) are checked for overlaps. Note also that
     * for hwdom we also need to include hidden, i.e. DomXEN's, devices.
     */
    for ( d = pdev->domain != dom_xen ? pdev->domain : hardware_domain; ; )
    {
        for_each_pdev ( d, tmp )
        {
            if ( !tmp->vpci )
                /*
                 * For the hardware domain it's possible to have devices
                 * assigned to it that are not handled by vPCI, either because
                 * those are read-only devices, or because vPCI setup has
                 * failed.
                 */
                continue;

            if ( tmp == pdev )
            {
                /*
                 * Need to store the device so it's not constified and defer_map
                 * can modify it in case of error.
                 */
                dev = tmp;
                if ( !rom_only )
                    /*
                     * If memory decoding is toggled avoid checking against the
                     * same device, or else all regions will be removed from the
                     * memory map in the unmap case.
                     */
                    continue;
            }

            for ( i = 0; i < ARRAY_SIZE(tmp->vpci->header.bars); i++ )
            {
                const struct vpci_bar *remote_bar = &tmp->vpci->header.bars[i];
                unsigned long start = PFN_DOWN(remote_bar->guest_addr);
                unsigned long end = PFN_DOWN(remote_bar->guest_addr +
                                             remote_bar->size - 1);

                if ( !remote_bar->enabled )
                    continue;

                for ( j = 0; j < ARRAY_SIZE(header->bars); j++)
                {
                    const struct vpci_bar *bar = &header->bars[j];

                    if ( !rangeset_overlaps_range(bar->mem, start, end) ||
                         /*
                          * If only the ROM enable bit is toggled check against
                          * other BARs in the same device for overlaps, but not
                          * against the same ROM BAR.
                          */
                         (rom_only &&
                          tmp == pdev &&
                          bar->type == VPCI_BAR_ROM) )
                        continue;

                    rc = rangeset_remove_range(bar->mem, start, end);
                    if ( rc )
                    {
                        gprintk(XENLOG_WARNING,
                                "%pp: failed to remove [%lx, %lx]: %d\n",
                                &pdev->sbdf, start, end, rc);
                        return rc;
                    }
                }
            }
        }

        if ( !is_hardware_domain(d) )
            break;

        d = dom_xen;
    }

    ASSERT(dev);

    if ( system_state < SYS_STATE_active )
    {
        /*
         * Mappings might be created when building Dom0 if the memory decoding
         * bit of PCI devices is enabled. In that case it's not possible to
         * defer the operation, so call apply_map in order to create the
         * mappings right away. Note that at build time this function will only
         * be called iff the memory decoding bit is enabled, thus the operation
         * will always be to establish mappings and process all the BARs.
         */
        ASSERT((cmd & PCI_COMMAND_MEMORY) && !rom_only);
        return apply_map(pdev->domain, pdev, cmd);
    }

    defer_map(dev->domain, dev, cmd, rom_only);

    return 0;
}

static void cf_check cmd_write(
    const struct pci_dev *pdev, unsigned int reg, uint32_t cmd, void *data)
{
    struct vpci_header *header = data;

    if ( !is_hardware_domain(pdev->domain) )
    {
        const struct vpci *vpci = pdev->vpci;

        if ( (vpci->msi && vpci->msi->enabled) ||
             (vpci->msix && vpci->msix->enabled) )
            cmd |= PCI_COMMAND_INTX_DISABLE;

        header->guest_cmd = cmd;
    }

    /*
     * Let Dom0 play with all the bits directly except for the memory
     * decoding one. Bits that are not allowed for DomU are already
     * handled above and by the rsvdp_mask.
     */
    if ( header->bars_mapped != !!(cmd & PCI_COMMAND_MEMORY) )
        /*
         * Ignore the error. No memory has been added or removed from the p2m
         * (because the actual p2m changes are deferred in defer_map) and the
         * memory decoding bit has not been changed, so leave everything as-is,
         * hoping the guest will realize and try again.
         */
        modify_bars(pdev, cmd, false);
    else
        pci_conf_write16(pdev->sbdf, reg, cmd);
}

static uint32_t cf_check guest_cmd_read(
    const struct pci_dev *pdev, unsigned int reg, void *data)
{
    const struct vpci_header *header = data;

    return header->guest_cmd;
}

static void cf_check bar_write(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    bool hi = false;

    ASSERT(is_hardware_domain(pdev->domain));

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }
    else
        val &= PCI_BASE_ADDRESS_MEM_MASK;

    /*
     * Xen only cares whether the BAR is mapped into the p2m, so allow BAR
     * writes as long as the BAR is not mapped into the p2m.
     */
    if ( bar->enabled )
    {
        /* If the value written is the current one avoid printing a warning. */
        if ( val != (uint32_t)(bar->addr >> (hi ? 32 : 0)) )
            gprintk(XENLOG_WARNING,
                    "%pp: ignored BAR %zu write while mapped\n",
                    &pdev->sbdf, bar - pdev->vpci->header.bars + hi);
        return;
    }


    /*
     * Update the cached address, so that when memory decoding is enabled
     * Xen can map the BAR into the guest p2m.
     */
    bar->addr &= ~(0xffffffffULL << (hi ? 32 : 0));
    bar->addr |= (uint64_t)val << (hi ? 32 : 0);
    /* Update guest address, so hardware domain BAR is identity mapped. */
    bar->guest_addr = bar->addr;

    /* Make sure Xen writes back the same value for the BAR RO bits. */
    if ( !hi )
    {
        val |= bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32
                                           : PCI_BASE_ADDRESS_MEM_TYPE_64;
        val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
    }

    pci_conf_write32(pdev->sbdf, reg, val);
}

static void cf_check guest_mem_bar_write(const struct pci_dev *pdev,
                                         unsigned int reg, uint32_t val,
                                         void *data)
{
    struct vpci_bar *bar = data;
    bool hi = false;
    uint64_t guest_addr;

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }
    else
    {
        val &= PCI_BASE_ADDRESS_MEM_MASK;
    }

    guest_addr = bar->guest_addr;
    guest_addr &= ~(0xffffffffULL << (hi ? 32 : 0));
    guest_addr |= (uint64_t)val << (hi ? 32 : 0);

    /* Allow guest to size BAR correctly */
    guest_addr &= ~(bar->size - 1);

    /*
     * Xen only cares whether the BAR is mapped into the p2m, so allow BAR
     * writes as long as the BAR is not mapped into the p2m.
     */
    if ( bar->enabled )
    {
        /* If the value written is the current one avoid printing a warning. */
        if ( guest_addr != bar->guest_addr )
            gprintk(XENLOG_WARNING,
                    "%pp: ignored guest BAR %zu write while mapped\n",
                    &pdev->sbdf, bar - pdev->vpci->header.bars + hi);
        return;
    }
    bar->guest_addr = guest_addr;
}

static uint32_t cf_check guest_mem_bar_read(const struct pci_dev *pdev,
                                            unsigned int reg, void *data)
{
    const struct vpci_bar *bar = data;
    uint32_t reg_val;

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        return bar->guest_addr >> 32;
    }

    reg_val = bar->guest_addr;
    reg_val |= bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32 :
                                             PCI_BASE_ADDRESS_MEM_TYPE_64;
    reg_val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;

    return reg_val;
}

static void cf_check rom_write(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *rom = data;
    bool new_enabled = val & PCI_ROM_ADDRESS_ENABLE;

    /*
     * See comment in bar_write(). Additionally since the ROM BAR has an enable
     * bit some writes are allowed while the BAR is mapped, as long as the
     * write is to unmap the ROM BAR.
     */
    if ( rom->enabled && new_enabled )
    {
        gprintk(XENLOG_WARNING,
                "%pp: ignored ROM BAR write while mapped\n",
                &pdev->sbdf);
        return;
    }

    if ( !rom->enabled )
    {
        /*
         * If the ROM BAR is not mapped update the address field so the
         * correct address is mapped into the p2m.
         */
        rom->addr = val & PCI_ROM_ADDRESS_MASK;
        rom->guest_addr = rom->addr;
    }

    if ( !header->bars_mapped || rom->enabled == new_enabled )
    {
        /* Just update the ROM BAR field. */
        header->rom_enabled = new_enabled;
        pci_conf_write32(pdev->sbdf, reg, val);
    }
    /*
     * Pass PCI_COMMAND_MEMORY or 0 to signal a map/unmap request, note that
     * this fabricated command is never going to be written to the register.
     */
    else if ( modify_bars(pdev, new_enabled ? PCI_COMMAND_MEMORY : 0, true) )
        /*
         * No memory has been added or removed from the p2m (because the actual
         * p2m changes are deferred in defer_map) and the ROM enable bit has
         * not been changed, so leave everything as-is, hoping the guest will
         * realize and try again. It's important to not update rom->addr in the
         * unmap case if modify_bars has failed, or future attempts would
         * attempt to unmap the wrong address.
         */
        return;

    if ( !new_enabled )
    {
        rom->addr = val & PCI_ROM_ADDRESS_MASK;
        rom->guest_addr = rom->addr;
    }
}

static int bar_add_rangeset(const struct pci_dev *pdev, struct vpci_bar *bar,
                            unsigned int i)
{
    char str[32];

    snprintf(str, sizeof(str), "%pp:BAR%u", &pdev->sbdf, i);

    bar->mem = rangeset_new(pdev->domain, str, RANGESETF_no_print);

    return !bar->mem ? -ENOMEM : 0;
}

static int cf_check init_header(struct pci_dev *pdev)
{
    uint16_t cmd;
    uint64_t addr, size;
    unsigned int i, num_bars, rom_reg;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    int rc;
    bool mask_cap_list = false;
    bool is_hwdom = is_hardware_domain(pdev->domain);

    ASSERT(rw_is_write_locked(&pdev->domain->pci_lock));

    switch ( pci_conf_read8(pdev->sbdf, PCI_HEADER_TYPE) & 0x7f )
    {
    case PCI_HEADER_TYPE_NORMAL:
        num_bars = PCI_HEADER_NORMAL_NR_BARS;
        rom_reg = PCI_ROM_ADDRESS;
        break;

    case PCI_HEADER_TYPE_BRIDGE:
        num_bars = PCI_HEADER_BRIDGE_NR_BARS;
        rom_reg = PCI_ROM_ADDRESS1;
        break;

    default:
        return -EOPNOTSUPP;
    }

    /*
     * Setup a handler for the command register.
     *
     * TODO: If support for emulated bits is added, re-visit how to handle
     * PCI_COMMAND_PARITY, PCI_COMMAND_SERR, and PCI_COMMAND_FAST_BACK.
     */
    rc = vpci_add_register_mask(pdev->vpci,
                                is_hwdom ? vpci_hw_read16 : guest_cmd_read,
                                cmd_write, PCI_COMMAND, 2, header, 0, 0,
                                is_hwdom ? 0
                                         : PCI_COMMAND_RSVDP_MASK |
                                           PCI_COMMAND_IO |
                                           PCI_COMMAND_PARITY |
                                           PCI_COMMAND_WAIT |
                                           PCI_COMMAND_SERR |
                                           PCI_COMMAND_FAST_BACK,
                                0);
    if ( rc )
        return rc;

    if ( !is_hwdom )
    {
        if ( pci_conf_read16(pdev->sbdf, PCI_STATUS) & PCI_STATUS_CAP_LIST )
        {
            /* Only expose capabilities to the guest that vPCI can handle. */
            unsigned int next, ttl = 48;
            static const unsigned int supported_caps[] = {
                PCI_CAP_ID_MSI,
                PCI_CAP_ID_MSIX,
            };

            next = pci_find_next_cap_ttl(pdev->sbdf, PCI_CAPABILITY_LIST,
                                         supported_caps,
                                         ARRAY_SIZE(supported_caps), &ttl);

            rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                                   PCI_CAPABILITY_LIST, 1,
                                   (void *)(uintptr_t)next);
            if ( rc )
                return rc;

            next &= ~3;

            if ( !next )
                /*
                 * If we don't have any supported capabilities to expose to the
                 * guest, mask the PCI_STATUS_CAP_LIST bit in the status
                 * register.
                 */
                mask_cap_list = true;

            while ( next && ttl )
            {
                unsigned int pos = next;

                next = pci_find_next_cap_ttl(pdev->sbdf,
                                             pos + PCI_CAP_LIST_NEXT,
                                             supported_caps,
                                             ARRAY_SIZE(supported_caps), &ttl);

                rc = vpci_add_register(pdev->vpci, vpci_hw_read8, NULL,
                                       pos + PCI_CAP_LIST_ID, 1, NULL);
                if ( rc )
                    return rc;

                rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                                       pos + PCI_CAP_LIST_NEXT, 1,
                                       (void *)(uintptr_t)next);
                if ( rc )
                    return rc;

                next &= ~3;
            }
        }

        /* Extended capabilities read as zero, write ignore */
        rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL, 0x100, 4,
                               (void *)0);
        if ( rc )
            return rc;
    }

    /* Utilize rsvdp_mask to hide PCI_STATUS_CAP_LIST from the guest. */
    rc = vpci_add_register_mask(pdev->vpci, vpci_hw_read16, vpci_hw_write16,
                                PCI_STATUS, 2, NULL,
                                PCI_STATUS_RO_MASK &
                                    ~(mask_cap_list ? PCI_STATUS_CAP_LIST : 0),
                                PCI_STATUS_RW1C_MASK,
                                mask_cap_list ? PCI_STATUS_CAP_LIST : 0,
                                PCI_STATUS_RSVDZ_MASK);
    if ( rc )
        return rc;

    if ( pdev->ignore_bars )
        return 0;

    cmd = pci_conf_read16(pdev->sbdf, PCI_COMMAND);

    /*
     * For DomUs, clear PCI_COMMAND_{MASTER,MEMORY,IO} and other
     * DomU-controllable bits in PCI_COMMAND. Devices assigned to DomUs will
     * start with memory decoding disabled, and modify_bars() will not be called
     * at the end of this function.
     */
    if ( !is_hwdom )
        cmd &= ~(PCI_COMMAND_VGA_PALETTE | PCI_COMMAND_INVALIDATE |
                 PCI_COMMAND_SPECIAL | PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY |
                 PCI_COMMAND_IO);

    header->guest_cmd = cmd;

    /* Disable memory decoding before sizing. */
    if ( !is_hwdom || (cmd & PCI_COMMAND_MEMORY) )
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd & ~PCI_COMMAND_MEMORY);

    for ( i = 0; i < num_bars; i++ )
    {
        uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;
        uint32_t val;

        if ( i && bars[i - 1].type == VPCI_BAR_MEM64_LO )
        {
            bars[i].type = VPCI_BAR_MEM64_HI;
            rc = vpci_add_register(pdev->vpci,
                                   is_hwdom ? vpci_hw_read32
                                            : guest_mem_bar_read,
                                   is_hwdom ? bar_write : guest_mem_bar_write,
                                   reg, 4, &bars[i]);
            if ( rc )
                goto fail;

            continue;
        }

        val = pci_conf_read32(pdev->sbdf, reg);
        if ( (val & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        {
            bars[i].type = VPCI_BAR_IO;
            if ( !IS_ENABLED(CONFIG_X86) && !is_hwdom )
            {
                rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                                       reg, 4, (void *)0);
                if ( rc )
                    goto fail;
            }

            continue;
        }
        if ( (val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
             PCI_BASE_ADDRESS_MEM_TYPE_64 )
            bars[i].type = VPCI_BAR_MEM64_LO;
        else
            bars[i].type = VPCI_BAR_MEM32;

        rc = bar_add_rangeset(pdev, &bars[i], i);
        if ( rc )
            goto fail;

        rc = pci_size_mem_bar(pdev->sbdf, reg, &addr, &size,
                              (i == num_bars - 1) ? PCI_BAR_LAST : 0);
        if ( rc < 0 )
            goto fail;

        if ( size == 0 )
        {
            bars[i].type = VPCI_BAR_EMPTY;

            if ( !is_hwdom )
            {
                rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                                       reg, 4, (void *)0);
                if ( rc )
                    goto fail;
            }

            continue;
        }

        bars[i].addr = addr;
        bars[i].guest_addr = addr;
        bars[i].size = size;
        bars[i].prefetchable = val & PCI_BASE_ADDRESS_MEM_PREFETCH;

        rc = vpci_add_register(pdev->vpci,
                               is_hwdom ? vpci_hw_read32 : guest_mem_bar_read,
                               is_hwdom ? bar_write : guest_mem_bar_write,
                               reg, 4, &bars[i]);
        if ( rc )
            goto fail;
    }

    /* Check expansion ROM. */
    rc = is_hwdom ? pci_size_mem_bar(pdev->sbdf, rom_reg, &addr, &size,
                                     PCI_BAR_ROM)
                  : 0;
    if ( rc > 0 && size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->addr = addr;
        rom->guest_addr = addr;
        header->rom_enabled = pci_conf_read32(pdev->sbdf, rom_reg) &
                              PCI_ROM_ADDRESS_ENABLE;

        rc = vpci_add_register(pdev->vpci, vpci_hw_read32, rom_write, rom_reg,
                               4, rom);
        if ( rc )
            rom->type = VPCI_BAR_EMPTY;
        else
        {
            rc = bar_add_rangeset(pdev, rom, num_bars);
            if ( rc )
                goto fail;
        }
    }
    else if ( !is_hwdom )
    {
        /* TODO: Check expansion ROM, we do not handle ROM for guests for now */
        header->bars[num_bars].type = VPCI_BAR_EMPTY;
        rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                               rom_reg, 4, (void *)0);
        if ( rc )
            goto fail;
    }

    return (cmd & PCI_COMMAND_MEMORY) ? modify_bars(pdev, cmd, false) : 0;

 fail:
    pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
    return rc;
}
REGISTER_VPCI_INIT(init_header, VPCI_PRIORITY_HIGH);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
