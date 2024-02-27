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
    bool map;
};

static int cf_check map_range(
    unsigned long s, unsigned long e, void *data, unsigned long *c)
{
    const struct map_data *map = data;
    int rc;

    for ( ; ; )
    {
        unsigned long size = e - s + 1;

        if ( !iomem_access_permitted(map->d, s, e) )
        {
            printk(XENLOG_G_WARNING
                   "%pd denied access to MMIO range [%#lx, %#lx]\n",
                   map->d, s, e);
            return -EPERM;
        }

        rc = xsm_iomem_mapping(XSM_HOOK, map->d, s, e, map->map);
        if ( rc )
        {
            printk(XENLOG_G_WARNING
                   "%pd XSM denied access to MMIO range [%#lx, %#lx]: %d\n",
                   map->d, s, e, rc);
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

        rc = map->map ? map_mmio_regions(map->d, _gfn(s), size, _mfn(s))
                      : unmap_mmio_regions(map->d, _gfn(s), size, _mfn(s));
        if ( rc == 0 )
        {
            *c += size;
            break;
        }
        if ( rc < 0 )
        {
            printk(XENLOG_G_WARNING
                   "Failed to identity %smap [%lx, %lx] for d%d: %d\n",
                   map->map ? "" : "un", s, e, map->d->domain_id, rc);
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
    if ( v->vpci.mem )
    {
        struct map_data data = {
            .d = v->domain,
            .map = v->vpci.cmd & PCI_COMMAND_MEMORY,
        };
        int rc = rangeset_consume_ranges(v->vpci.mem, map_range, &data);

        if ( rc == -ERESTART )
            return true;

        write_lock(&v->domain->pci_lock);
        spin_lock(&v->vpci.pdev->vpci->lock);
        /* Disable memory decoding unconditionally on failure. */
        modify_decoding(v->vpci.pdev,
                        rc ? v->vpci.cmd & ~PCI_COMMAND_MEMORY : v->vpci.cmd,
                        !rc && v->vpci.rom_only);
        spin_unlock(&v->vpci.pdev->vpci->lock);

        rangeset_destroy(v->vpci.mem);
        v->vpci.mem = NULL;
        if ( rc )
            /*
             * FIXME: in case of failure remove the device from the domain.
             * Note that there might still be leftover mappings. While this is
             * safe for Dom0, for DomUs the domain will likely need to be
             * killed in order to avoid leaking stale p2m mappings on
             * failure.
             */
            vpci_deassign_device(v->vpci.pdev);
        write_unlock(&v->domain->pci_lock);
    }

    return false;
}

static int __init apply_map(struct domain *d, const struct pci_dev *pdev,
                            struct rangeset *mem, uint16_t cmd)
{
    struct map_data data = { .d = d, .map = true };
    int rc;

    ASSERT(rw_is_write_locked(&d->pci_lock));

    while ( (rc = rangeset_consume_ranges(mem, map_range, &data)) == -ERESTART )
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

    rangeset_destroy(mem);
    if ( !rc )
        modify_decoding(pdev, cmd, false);

    return rc;
}

static void defer_map(struct domain *d, struct pci_dev *pdev,
                      struct rangeset *mem, uint16_t cmd, bool rom_only)
{
    struct vcpu *curr = current;

    /*
     * FIXME: when deferring the {un}map the state of the device should not
     * be trusted. For example the enable bit is toggled after the device
     * is mapped. This can lead to parallel mapping operations being
     * started for the same device if the domain is not well-behaved.
     */
    curr->vpci.pdev = pdev;
    curr->vpci.mem = mem;
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
    struct rangeset *mem = rangeset_new(NULL, NULL, 0);
    struct pci_dev *tmp, *dev = NULL;
    const struct domain *d;
    const struct vpci_msix *msix = pdev->vpci->msix;
    unsigned int i;
    int rc;

    ASSERT(rw_is_write_locked(&pdev->domain->pci_lock));

    if ( !mem )
        return -ENOMEM;

    /*
     * Create a rangeset that represents the current device BARs memory region
     * and compare it against all the currently active BAR memory regions. If
     * an overlap is found, subtract it from the region to be mapped/unmapped.
     *
     * First fill the rangeset with all the BARs of this device or with the ROM
     * BAR only, depending on whether the guest is toggling the memory decode
     * bit of the command register, or the enable bit of the ROM BAR register.
     */
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        const struct vpci_bar *bar = &header->bars[i];
        unsigned long start = PFN_DOWN(bar->addr);
        unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);

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

        rc = rangeset_add_range(mem, start, end);
        if ( rc )
        {
            printk(XENLOG_G_WARNING "Failed to add [%lx, %lx]: %d\n",
                   start, end, rc);
            rangeset_destroy(mem);
            return rc;
        }
    }

    /* Remove any MSIX regions if present. */
    for ( i = 0; msix && i < ARRAY_SIZE(msix->tables); i++ )
    {
        unsigned long start = PFN_DOWN(vmsix_table_addr(pdev->vpci, i));
        unsigned long end = PFN_DOWN(vmsix_table_addr(pdev->vpci, i) +
                                     vmsix_table_size(pdev->vpci, i) - 1);

        rc = rangeset_remove_range(mem, start, end);
        if ( rc )
        {
            printk(XENLOG_G_WARNING
                   "Failed to remove MSIX table [%lx, %lx]: %d\n",
                   start, end, rc);
            rangeset_destroy(mem);
            return rc;
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
                const struct vpci_bar *bar = &tmp->vpci->header.bars[i];
                unsigned long start = PFN_DOWN(bar->addr);
                unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);

                if ( !bar->enabled ||
                     !rangeset_overlaps_range(mem, start, end) ||
                     /*
                      * If only the ROM enable bit is toggled check against
                      * other BARs in the same device for overlaps, but not
                      * against the same ROM BAR.
                      */
                     (rom_only && tmp == pdev && bar->type == VPCI_BAR_ROM) )
                    continue;

                rc = rangeset_remove_range(mem, start, end);
                if ( rc )
                {
                    printk(XENLOG_G_WARNING "Failed to remove [%lx, %lx]: %d\n",
                           start, end, rc);
                    rangeset_destroy(mem);
                    return rc;
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
        return apply_map(pdev->domain, pdev, mem, cmd);
    }

    defer_map(dev->domain, dev, mem, cmd, rom_only);

    return 0;
}

static void cf_check cmd_write(
    const struct pci_dev *pdev, unsigned int reg, uint32_t cmd, void *data)
{
    struct vpci_header *header = data;

    /*
     * Let Dom0 play with all the bits directly except for the memory
     * decoding one.
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

static void cf_check bar_write(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    bool hi = false;

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

    /* Make sure Xen writes back the same value for the BAR RO bits. */
    if ( !hi )
    {
        val |= bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32
                                           : PCI_BASE_ADDRESS_MEM_TYPE_64;
        val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
    }

    pci_conf_write32(pdev->sbdf, reg, val);
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
        /*
         * If the ROM BAR is not mapped update the address field so the
         * correct address is mapped into the p2m.
         */
        rom->addr = val & PCI_ROM_ADDRESS_MASK;

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
        rom->addr = val & PCI_ROM_ADDRESS_MASK;
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

    /* Setup a handler for the command register. */
    rc = vpci_add_register(pdev->vpci, vpci_hw_read16, cmd_write, PCI_COMMAND,
                           2, header);
    if ( rc )
        return rc;

    if ( !is_hardware_domain(pdev->domain) )
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

    /* Disable memory decoding before sizing. */
    cmd = pci_conf_read16(pdev->sbdf, PCI_COMMAND);
    if ( cmd & PCI_COMMAND_MEMORY )
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd & ~PCI_COMMAND_MEMORY);

    for ( i = 0; i < num_bars; i++ )
    {
        uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;
        uint32_t val;

        if ( i && bars[i - 1].type == VPCI_BAR_MEM64_LO )
        {
            bars[i].type = VPCI_BAR_MEM64_HI;
            rc = vpci_add_register(pdev->vpci, vpci_hw_read32, bar_write, reg,
                                   4, &bars[i]);
            if ( rc )
                goto fail;

            continue;
        }

        val = pci_conf_read32(pdev->sbdf, reg);
        if ( (val & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        {
            bars[i].type = VPCI_BAR_IO;
            continue;
        }
        if ( (val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
             PCI_BASE_ADDRESS_MEM_TYPE_64 )
            bars[i].type = VPCI_BAR_MEM64_LO;
        else
            bars[i].type = VPCI_BAR_MEM32;

        rc = pci_size_mem_bar(pdev->sbdf, reg, &addr, &size,
                              (i == num_bars - 1) ? PCI_BAR_LAST : 0);
        if ( rc < 0 )
            goto fail;

        if ( size == 0 )
        {
            bars[i].type = VPCI_BAR_EMPTY;
            continue;
        }

        bars[i].addr = addr;
        bars[i].size = size;
        bars[i].prefetchable = val & PCI_BASE_ADDRESS_MEM_PREFETCH;

        rc = vpci_add_register(pdev->vpci, vpci_hw_read32, bar_write, reg, 4,
                               &bars[i]);
        if ( rc )
            goto fail;
    }

    /* Check expansion ROM. */
    rc = pci_size_mem_bar(pdev->sbdf, rom_reg, &addr, &size, PCI_BAR_ROM);
    if ( rc > 0 && size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->addr = addr;
        header->rom_enabled = pci_conf_read32(pdev->sbdf, rom_reg) &
                              PCI_ROM_ADDRESS_ENABLE;

        rc = vpci_add_register(pdev->vpci, vpci_hw_read32, rom_write, rom_reg,
                               4, rom);
        if ( rc )
            rom->type = VPCI_BAR_EMPTY;
    }

    return (cmd & PCI_COMMAND_MEMORY) ? modify_bars(pdev, cmd, false) : 0;

 fail:
    pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
    return rc;
}
REGISTER_VPCI_INIT(init_header, VPCI_PRIORITY_MIDDLE);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
