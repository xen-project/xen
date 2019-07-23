/*
 * Handlers for accesses to the MSI-X capability structure and the memory
 * region.
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

#include <xen/sched.h>
#include <xen/vpci.h>

#include <asm/msi.h>
#include <asm/p2m.h>

#define VMSIX_SIZE(num) offsetof(struct vpci_msix, entries[num])

#define VMSIX_ADDR_IN_RANGE(addr, vpci, nr)                               \
    ((addr) >= vmsix_table_addr(vpci, nr) &&                              \
     (addr) < vmsix_table_addr(vpci, nr) + vmsix_table_size(vpci, nr))

static uint32_t control_read(const struct pci_dev *pdev, unsigned int reg,
                             void *data)
{
    const struct vpci_msix *msix = data;

    return (msix->max_entries - 1) |
           (msix->enabled ? PCI_MSIX_FLAGS_ENABLE : 0) |
           (msix->masked ? PCI_MSIX_FLAGS_MASKALL : 0);
}

static int update_entry(struct vpci_msix_entry *entry,
                        const struct pci_dev *pdev, unsigned int nr)
{
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    int rc = vpci_msix_arch_disable_entry(entry, pdev);

    /* Ignore ENOENT, it means the entry wasn't setup. */
    if ( rc && rc != -ENOENT )
    {
        gprintk(XENLOG_WARNING,
                "%04x:%02x:%02x.%u: unable to disable entry %u for update: %d\n",
                pdev->seg, pdev->bus, slot, func, nr, rc);
        return rc;
    }

    rc = vpci_msix_arch_enable_entry(entry, pdev,
                                     vmsix_table_base(pdev->vpci,
                                                      VPCI_MSIX_TABLE));
    if ( rc )
    {
        gprintk(XENLOG_WARNING,
                "%04x:%02x:%02x.%u: unable to enable entry %u: %d\n",
                pdev->seg, pdev->bus, slot, func, nr, rc);
        /* Entry is likely not properly configured. */
        return rc;
    }

    return 0;
}

static void control_write(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data)
{
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msix *msix = data;
    bool new_masked = val & PCI_MSIX_FLAGS_MASKALL;
    bool new_enabled = val & PCI_MSIX_FLAGS_ENABLE;
    unsigned int i;
    int rc;

    if ( new_masked == msix->masked && new_enabled == msix->enabled )
        return;

    /*
     * According to the PCI 3.0 specification, switching the enable bit to 1
     * or the function mask bit to 0 should cause all the cached addresses
     * and data fields to be recalculated.
     *
     * In order to avoid the overhead of disabling and enabling all the
     * entries every time the guest sets the maskall bit, Xen will only
     * perform the disable and enable sequence when the guest has written to
     * the entry.
     */
    if ( new_enabled && !new_masked && (!msix->enabled || msix->masked) )
    {
        for ( i = 0; i < msix->max_entries; i++ )
        {
            if ( msix->entries[i].masked || !msix->entries[i].updated ||
                 update_entry(&msix->entries[i], pdev, i) )
                continue;

            msix->entries[i].updated = false;
        }
    }
    else if ( !new_enabled && msix->enabled )
    {
        /* Guest has disabled MSIX, disable all entries. */
        for ( i = 0; i < msix->max_entries; i++ )
        {
            /*
             * NB: vpci_msix_arch_disable can be called for entries that are
             * not setup, it will return -ENOENT in that case.
             */
            rc = vpci_msix_arch_disable_entry(&msix->entries[i], pdev);
            switch ( rc )
            {
            case 0:
                /*
                 * Mark the entry successfully disabled as updated, so that on
                 * the next enable the entry is properly setup. This is done
                 * so that the following flow works correctly:
                 *
                 * mask entry -> disable MSIX -> enable MSIX -> unmask entry
                 *
                 * Without setting 'updated', the 'unmask entry' step will fail
                 * because the entry has not been updated, so it would not be
                 * mapped/bound at all.
                 */
                msix->entries[i].updated = true;
                break;
            case -ENOENT:
                /* Ignore non-present entry. */
                break;
            default:
                gprintk(XENLOG_WARNING,
                        "%04x:%02x:%02x.%u: unable to disable entry %u: %d\n",
                        pdev->seg, pdev->bus, slot, func, i, rc);
                return;
            }
        }
    }

    msix->masked = new_masked;
    msix->enabled = new_enabled;

    val = control_read(pdev, reg, data);
    if ( pci_msi_conf_write_intercept(msix->pdev, reg, 2, &val) >= 0 )
        pci_conf_write16(pdev->sbdf, reg, val);
}

static struct vpci_msix *msix_find(const struct domain *d, unsigned long addr)
{
    struct vpci_msix *msix;

    list_for_each_entry ( msix, &d->arch.hvm.msix_tables, next )
    {
        const struct vpci_bar *bars = msix->pdev->vpci->header.bars;
        unsigned int i;

        for ( i = 0; i < ARRAY_SIZE(msix->tables); i++ )
            if ( bars[msix->tables[i] & PCI_MSIX_BIRMASK].enabled &&
                 VMSIX_ADDR_IN_RANGE(addr, msix->pdev->vpci, i) )
                return msix;
    }

    return NULL;
}

static int msix_accept(struct vcpu *v, unsigned long addr)
{
    return !!msix_find(v->domain, addr);
}

static bool access_allowed(const struct pci_dev *pdev, unsigned long addr,
                           unsigned int len)
{
    /* Only allow aligned 32/64b accesses. */
    if ( (len == 4 || len == 8) && !(addr & (len - 1)) )
        return true;

    gprintk(XENLOG_WARNING,
            "%04x:%02x:%02x.%u: unaligned or invalid size MSI-X table access\n",
            pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

    return false;
}

static struct vpci_msix_entry *get_entry(struct vpci_msix *msix,
                                         paddr_t addr)
{
    paddr_t start = vmsix_table_addr(msix->pdev->vpci, VPCI_MSIX_TABLE);

    return &msix->entries[(addr - start) / PCI_MSIX_ENTRY_SIZE];
}

static int msix_read(struct vcpu *v, unsigned long addr, unsigned int len,
                     unsigned long *data)
{
    const struct domain *d = v->domain;
    struct vpci_msix *msix = msix_find(d, addr);
    const struct vpci_msix_entry *entry;
    unsigned int offset;

    *data = ~0ul;

    if ( !msix )
        return X86EMUL_RETRY;

    if ( !access_allowed(msix->pdev, addr, len) )
        return X86EMUL_OKAY;

    if ( VMSIX_ADDR_IN_RANGE(addr, msix->pdev->vpci, VPCI_MSIX_PBA) )
    {
        /*
         * Access to PBA.
         *
         * TODO: note that this relies on having the PBA identity mapped to the
         * guest address space. If this changes the address will need to be
         * translated.
         */
        switch ( len )
        {
        case 4:
            *data = readl(addr);
            break;

        case 8:
            *data = readq(addr);
            break;

        default:
            ASSERT_UNREACHABLE();
            break;
        }

        return X86EMUL_OKAY;
    }

    spin_lock(&msix->pdev->vpci->lock);
    entry = get_entry(msix, addr);
    offset = addr & (PCI_MSIX_ENTRY_SIZE - 1);

    switch ( offset )
    {
    case PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET:
        *data = entry->addr;
        break;

    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        *data = entry->addr >> 32;
        break;

    case PCI_MSIX_ENTRY_DATA_OFFSET:
        *data = entry->data;
        if ( len == 8 )
            *data |=
                (uint64_t)(entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0) << 32;
        break;

    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
        *data = entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0;
        break;

    default:
        ASSERT_UNREACHABLE();
        break;
    }
    spin_unlock(&msix->pdev->vpci->lock);

    return X86EMUL_OKAY;
}

static int msix_write(struct vcpu *v, unsigned long addr, unsigned int len,
                      unsigned long data)
{
    const struct domain *d = v->domain;
    struct vpci_msix *msix = msix_find(d, addr);
    struct vpci_msix_entry *entry;
    unsigned int offset;

    if ( !msix )
        return X86EMUL_RETRY;

    if ( !access_allowed(msix->pdev, addr, len) )
        return X86EMUL_OKAY;

    if ( VMSIX_ADDR_IN_RANGE(addr, msix->pdev->vpci, VPCI_MSIX_PBA) )
    {
        /* Ignore writes to PBA for DomUs, it's behavior is undefined. */
        if ( is_hardware_domain(d) )
        {
            switch ( len )
            {
            case 4:
                writel(data, addr);
                break;

            case 8:
                writeq(data, addr);
                break;

            default:
                ASSERT_UNREACHABLE();
                break;
            }
        }

        return X86EMUL_OKAY;
    }

    spin_lock(&msix->pdev->vpci->lock);
    entry = get_entry(msix, addr);
    offset = addr & (PCI_MSIX_ENTRY_SIZE - 1);

    /*
     * NB: Xen allows writes to the data/address registers with the entry
     * unmasked. The specification says this is undefined behavior, and Xen
     * implements it as storing the written value, which will be made effective
     * in the next mask/unmask cycle. This also mimics the implementation in
     * QEMU.
     */
    switch ( offset )
    {
    case PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET:
        entry->updated = true;
        if ( len == 8 )
        {
            entry->addr = data;
            break;
        }
        entry->addr &= ~0xffffffffull;
        entry->addr |= data;
        break;

    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        entry->updated = true;
        entry->addr &= 0xffffffff;
        entry->addr |= (uint64_t)data << 32;
        break;

    case PCI_MSIX_ENTRY_DATA_OFFSET:
        entry->updated = true;
        entry->data = data;

        if ( len == 4 )
            break;

        data >>= 32;
        /* fallthrough */
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
    {
        bool new_masked = data & PCI_MSIX_VECTOR_BITMASK;
        const struct pci_dev *pdev = msix->pdev;

        if ( entry->masked == new_masked )
            /* No change in the mask bit, nothing to do. */
            break;

        /*
         * Update the masked state before calling vpci_msix_arch_enable_entry,
         * so that it picks the new state.
         */
        entry->masked = new_masked;
        if ( !new_masked && msix->enabled && !msix->masked && entry->updated )
        {
            /*
             * If MSI-X is enabled, the function mask is not active, the entry
             * is being unmasked and there have been changes to the address or
             * data fields Xen needs to disable and enable the entry in order
             * to pick up the changes.
             */
            if ( update_entry(entry, pdev, vmsix_entry_nr(msix, entry)) )
                break;

            entry->updated = false;
        }
        else
            vpci_msix_arch_mask_entry(entry, pdev, entry->masked);

        break;
    }

    default:
        ASSERT_UNREACHABLE();
        break;
    }
    spin_unlock(&msix->pdev->vpci->lock);

    return X86EMUL_OKAY;
}

static const struct hvm_mmio_ops vpci_msix_table_ops = {
    .check = msix_accept,
    .read = msix_read,
    .write = msix_write,
};

int vpci_make_msix_hole(const struct pci_dev *pdev)
{
    struct domain *d = pdev->domain;
    unsigned int i;

    if ( !pdev->vpci->msix )
        return 0;

    /* Make sure there's a hole for the MSIX table/PBA in the p2m. */
    for ( i = 0; i < ARRAY_SIZE(pdev->vpci->msix->tables); i++ )
    {
        unsigned long start = PFN_DOWN(vmsix_table_addr(pdev->vpci, i));
        unsigned long end = PFN_DOWN(vmsix_table_addr(pdev->vpci, i) +
                                     vmsix_table_size(pdev->vpci, i) - 1);

        for ( ; start <= end; start++ )
        {
            p2m_type_t t;
            mfn_t mfn = get_gfn_query(d, start, &t);

            switch ( t )
            {
            case p2m_mmio_dm:
            case p2m_invalid:
                break;
            case p2m_mmio_direct:
                if ( mfn_x(mfn) == start )
                {
                    clear_identity_p2m_entry(d, start);
                    break;
                }
                /* fallthrough. */
            default:
                put_gfn(d, start);
                gprintk(XENLOG_WARNING,
                        "%04x:%02x:%02x.%u: existing mapping (mfn: %" PRI_mfn
                        "type: %d) at %#lx clobbers MSIX MMIO area\n",
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                        PCI_FUNC(pdev->devfn), mfn_x(mfn), t, start);
                return -EEXIST;
            }
            put_gfn(d, start);
        }
    }

    return 0;
}

static int init_msix(struct pci_dev *pdev)
{
    struct domain *d = pdev->domain;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    unsigned int msix_offset, i, max_entries;
    uint16_t control;
    int rc;

    msix_offset = pci_find_cap_offset(pdev->seg, pdev->bus, slot, func,
                                      PCI_CAP_ID_MSIX);
    if ( !msix_offset )
        return 0;

    control = pci_conf_read16(pdev->sbdf, msix_control_reg(msix_offset));

    max_entries = msix_table_size(control);

    pdev->vpci->msix = xzalloc_bytes(VMSIX_SIZE(max_entries));
    if ( !pdev->vpci->msix )
        return -ENOMEM;

    pdev->vpci->msix->max_entries = max_entries;
    pdev->vpci->msix->pdev = pdev;

    pdev->vpci->msix->tables[VPCI_MSIX_TABLE] =
        pci_conf_read32(pdev->sbdf, msix_table_offset_reg(msix_offset));
    pdev->vpci->msix->tables[VPCI_MSIX_PBA] =
        pci_conf_read32(pdev->sbdf, msix_pba_offset_reg(msix_offset));

    for ( i = 0; i < pdev->vpci->msix->max_entries; i++)
    {
        pdev->vpci->msix->entries[i].masked = true;
        vpci_msix_arch_init_entry(&pdev->vpci->msix->entries[i]);
    }

    rc = vpci_add_register(pdev->vpci, control_read, control_write,
                           msix_control_reg(msix_offset), 2, pdev->vpci->msix);
    if ( rc )
        return rc;

    if ( list_empty(&d->arch.hvm.msix_tables) )
        register_mmio_handler(d, &vpci_msix_table_ops);

    list_add(&pdev->vpci->msix->next, &d->arch.hvm.msix_tables);

    return 0;
}
REGISTER_VPCI_INIT(init_msix, VPCI_PRIORITY_HIGH);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
