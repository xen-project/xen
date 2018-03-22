/*
 * Handlers for accesses to the MSI capability structure.
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
#include <xen/softirq.h>
#include <xen/vpci.h>

#include <asm/msi.h>

static uint32_t control_read(const struct pci_dev *pdev, unsigned int reg,
                             void *data)
{
    const struct vpci_msi *msi = data;

    return MASK_INSR(fls(msi->max_vectors) - 1, PCI_MSI_FLAGS_QMASK) |
           MASK_INSR(fls(msi->vectors) - 1, PCI_MSI_FLAGS_QSIZE) |
           (msi->enabled ? PCI_MSI_FLAGS_ENABLE : 0) |
           (msi->masking ? PCI_MSI_FLAGS_MASKBIT : 0) |
           (msi->address64 ? PCI_MSI_FLAGS_64BIT : 0);
}

static void control_write(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data)
{
    struct vpci_msi *msi = data;
    unsigned int vectors = min_t(uint8_t,
                                 1u << MASK_EXTR(val, PCI_MSI_FLAGS_QSIZE),
                                 msi->max_vectors);
    bool new_enabled = val & PCI_MSI_FLAGS_ENABLE;

    /*
     * No change if the enable field and the number of vectors is
     * the same or the device is not enabled, in which case the
     * vectors field can be updated directly.
     */
    if ( new_enabled == msi->enabled &&
         (vectors == msi->vectors || !msi->enabled) )
    {
        msi->vectors = vectors;
        return;
    }

    if ( new_enabled )
    {
        /*
         * If the device is already enabled it means the number of
         * enabled messages has changed. Disable and re-enable the
         * device in order to apply the change.
         */
        if ( msi->enabled )
        {
            vpci_msi_arch_disable(msi, pdev);
            msi->enabled = false;
        }

        if ( vpci_msi_arch_enable(msi, pdev, vectors) )
            return;
    }
    else
        vpci_msi_arch_disable(msi, pdev);

    msi->vectors = vectors;
    msi->enabled = new_enabled;

    pci_conf_write16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), reg,
                     control_read(pdev, reg, data));
}

static void update_msi(const struct pci_dev *pdev, struct vpci_msi *msi)
{
    if ( !msi->enabled )
        return;

    vpci_msi_arch_disable(msi, pdev);
    if ( vpci_msi_arch_enable(msi, pdev, msi->vectors) )
        msi->enabled = false;
}

/* Handlers for the address field (32bit or low part of a 64bit address). */
static uint32_t address_read(const struct pci_dev *pdev, unsigned int reg,
                             void *data)
{
    const struct vpci_msi *msi = data;

    return msi->address;
}

static void address_write(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear low part. */
    msi->address &= ~0xffffffffull;
    msi->address |= val;

    update_msi(pdev, msi);
}

/* Handlers for the high part of a 64bit address field. */
static uint32_t address_hi_read(const struct pci_dev *pdev, unsigned int reg,
                                void *data)
{
    const struct vpci_msi *msi = data;

    return msi->address >> 32;
}

static void address_hi_write(const struct pci_dev *pdev, unsigned int reg,
                             uint32_t val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear and update high part. */
    msi->address &= 0xffffffff;
    msi->address |= (uint64_t)val << 32;

    update_msi(pdev, msi);
}

/* Handlers for the data field. */
static uint32_t data_read(const struct pci_dev *pdev, unsigned int reg,
                          void *data)
{
    const struct vpci_msi *msi = data;

    return msi->data;
}

static void data_write(const struct pci_dev *pdev, unsigned int reg,
                       uint32_t val, void *data)
{
    struct vpci_msi *msi = data;

    msi->data = val;

    update_msi(pdev, msi);
}

/* Handlers for the MSI mask bits. */
static uint32_t mask_read(const struct pci_dev *pdev, unsigned int reg,
                          void *data)
{
    const struct vpci_msi *msi = data;

    return msi->mask;
}

static void mask_write(const struct pci_dev *pdev, unsigned int reg,
                       uint32_t val, void *data)
{
    struct vpci_msi *msi = data;
    uint32_t dmask = msi->mask ^ val;

    if ( !dmask )
        return;

    if ( msi->enabled )
    {
        unsigned int i;

        for ( i = ffs(dmask) - 1; dmask && i < msi->vectors;
              i = ffs(dmask) - 1 )
        {
            vpci_msi_arch_mask(msi, pdev, i, (val >> i) & 1);
            __clear_bit(i, &dmask);
        }
    }

    msi->mask = val;
}

static int init_msi(struct pci_dev *pdev)
{
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    unsigned int pos = pci_find_cap_offset(pdev->seg, pdev->bus, slot, func,
                                           PCI_CAP_ID_MSI);
    uint16_t control;
    int ret;

    if ( !pos )
        return 0;

    pdev->vpci->msi = xzalloc(struct vpci_msi);
    if ( !pdev->vpci->msi )
        return -ENOMEM;

    ret = vpci_add_register(pdev->vpci, control_read, control_write,
                            msi_control_reg(pos), 2, pdev->vpci->msi);
    if ( ret )
        /*
         * NB: there's no need to free the msi struct or remove the register
         * handlers form the config space, the caller will take care of the
         * cleanup.
         */
        return ret;

    /* Get the maximum number of vectors the device supports. */
    control = pci_conf_read16(pdev->seg, pdev->bus, slot, func,
                              msi_control_reg(pos));

    /*
     * FIXME: I've only been able to test this code with devices using a single
     * MSI interrupt and no mask register.
     */
    pdev->vpci->msi->max_vectors = multi_msi_capable(control);
    ASSERT(pdev->vpci->msi->max_vectors <= 32);

    /* The multiple message enable is 0 after reset (1 message enabled). */
    pdev->vpci->msi->vectors = 1;

    /* No PIRQ bound yet. */
    vpci_msi_arch_init(pdev->vpci->msi);

    pdev->vpci->msi->address64 = is_64bit_address(control);
    pdev->vpci->msi->masking = is_mask_bit_support(control);

    ret = vpci_add_register(pdev->vpci, address_read, address_write,
                            msi_lower_address_reg(pos), 4, pdev->vpci->msi);
    if ( ret )
        return ret;

    ret = vpci_add_register(pdev->vpci, data_read, data_write,
                            msi_data_reg(pos, pdev->vpci->msi->address64), 2,
                            pdev->vpci->msi);
    if ( ret )
        return ret;

    if ( pdev->vpci->msi->address64 )
    {
        ret = vpci_add_register(pdev->vpci, address_hi_read, address_hi_write,
                                msi_upper_address_reg(pos), 4, pdev->vpci->msi);
        if ( ret )
            return ret;
    }

    if ( pdev->vpci->msi->masking )
    {
        ret = vpci_add_register(pdev->vpci, mask_read, mask_write,
                                msi_mask_bits_reg(pos,
                                                  pdev->vpci->msi->address64),
                                4, pdev->vpci->msi);
        if ( ret )
            return ret;
        /*
         * FIXME: do not add any handler for the pending bits for the hardware
         * domain, which means direct access. This will be revisited when
         * adding unprivileged domain support.
         */
    }

    return 0;
}
REGISTER_VPCI_INIT(init_msi, VPCI_PRIORITY_LOW);

void vpci_dump_msi(void)
{
    const struct domain *d;

    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
    {
        const struct pci_dev *pdev;

        if ( !has_vpci(d) )
            continue;

        printk("vPCI MSI/MSI-X d%d\n", d->domain_id);

        list_for_each_entry ( pdev, &d->arch.pdev_list, domain_list )
        {
            const struct vpci_msi *msi;
            const struct vpci_msix *msix;

            if ( !pdev->vpci || !spin_trylock(&pdev->vpci->lock) )
                continue;

            msi = pdev->vpci->msi;
            if ( msi && msi->enabled )
            {
                printk("%04x:%02x:%02x.%u MSI\n", pdev->seg, pdev->bus,
                       PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

                printk("  enabled: %d 64-bit: %d",
                       msi->enabled, msi->address64);
                if ( msi->masking )
                    printk(" mask=%08x", msi->mask);
                printk(" vectors max: %u enabled: %u\n",
                       msi->max_vectors, msi->vectors);

                vpci_msi_arch_print(msi);
            }

            msix = pdev->vpci->msix;
            if ( msix && msix->enabled )
            {
                int rc;

                printk("%04x:%02x:%02x.%u MSI-X\n", pdev->seg, pdev->bus,
                       PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

                printk("  entries: %u maskall: %d enabled: %d\n",
                       msix->max_entries, msix->masked, msix->enabled);

                rc = vpci_msix_arch_print(msix);
                if ( rc )
                {
                    /*
                     * On error vpci_msix_arch_print will always return without
                     * holding the lock.
                     */
                    printk("unable to print all MSI-X entries: %d\n", rc);
                    process_pending_softirqs();
                    continue;
                }
            }

            spin_unlock(&pdev->vpci->lock);
            process_pending_softirqs();
        }
    }
    rcu_read_unlock(&domlist_read_lock);
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
