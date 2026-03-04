/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Capability handling for guest PCI configuration space.
 */

#include "private.h"

#include <xen/sched.h>

extern const vpci_capability_t __start_vpci_array[];
extern const vpci_capability_t __end_vpci_array[];
#define NUM_VPCI_INIT (__end_vpci_array - __start_vpci_array)

static struct vpci_register *vpci_get_previous_cap_register(
    const struct vpci *vpci, unsigned int offset)
{
    unsigned int next;
    struct vpci_register *r;

    if ( offset < 0x40 )
    {
        ASSERT_UNREACHABLE();
        return NULL;
    }

    for ( r = vpci_get_register(vpci, PCI_CAPABILITY_LIST, 1); r;
          r = next >= 0x40 ? vpci_get_register(vpci,
                                               next + PCI_CAP_LIST_NEXT, 1)
                           : NULL )
    {
        next = (unsigned int)(uintptr_t)r->private;
        ASSERT(next == (uintptr_t)r->private);
        if ( next == offset )
            break;
    }

    return r;
}

static int vpci_capability_hide(const struct pci_dev *pdev, unsigned int cap)
{
    const unsigned int offset = pci_find_cap_offset(pdev->sbdf, cap);
    struct vpci_register *prev_r, *next_r;
    struct vpci *vpci = pdev->vpci;

    if ( !offset )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    spin_lock(&vpci->lock);
    prev_r = vpci_get_previous_cap_register(vpci, offset);
    next_r = vpci_get_register(vpci, offset + PCI_CAP_LIST_NEXT, 1);
    if ( !prev_r || !next_r )
    {
        spin_unlock(&vpci->lock);
        return -ENODEV;
    }

    prev_r->private = next_r->private;
    /*
     * Not calling vpci_remove_registers() here is to avoid redoing
     * the register search.
     */
    list_del(&next_r->node);
    spin_unlock(&vpci->lock);
    xfree(next_r);

    if ( !is_hardware_domain(pdev->domain) )
        return vpci_remove_registers(vpci, offset + PCI_CAP_LIST_ID, 1);

    return 0;
}

static struct vpci_register *vpci_get_previous_ext_cap_register(
    const struct vpci *vpci, unsigned int offset)
{
    unsigned int pos = PCI_CFG_SPACE_SIZE;
    struct vpci_register *r;

    if ( offset <= PCI_CFG_SPACE_SIZE )
    {
        ASSERT_UNREACHABLE();
        return NULL;
    }

    for ( r = vpci_get_register(vpci, pos, 4); r;
          r = pos > PCI_CFG_SPACE_SIZE ? vpci_get_register(vpci, pos, 4)
                                       : NULL )
    {
        uint32_t header = (uint32_t)(uintptr_t)r->private;

        ASSERT(header == (uintptr_t)r->private);

        pos = PCI_EXT_CAP_NEXT(header);
        if ( pos == offset )
            break;
    }

    return r;
}

static int vpci_ext_capability_hide(
    const struct pci_dev *pdev, unsigned int cap)
{
    const unsigned int offset = pci_find_ext_capability(pdev, cap);
    struct vpci_register *r, *prev_r;
    struct vpci *vpci = pdev->vpci;
    uint32_t header, pre_header;

    if ( offset < PCI_CFG_SPACE_SIZE )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    spin_lock(&vpci->lock);
    r = vpci_get_register(vpci, offset, 4);
    if ( !r )
    {
        spin_unlock(&vpci->lock);
        return -ENODEV;
    }

    header = (uint32_t)(uintptr_t)r->private;
    if ( offset == PCI_CFG_SPACE_SIZE )
    {
        if ( PCI_EXT_CAP_NEXT(header) <= PCI_CFG_SPACE_SIZE )
            r->private = (void *)0;
        else
            /*
             * The first extended capability (0x100) can not be removed from
             * the linked list, so instead mask its capability ID to return 0
             * hopefully forcing OSes to skip it.
             */
            r->private = (void *)(uintptr_t)(header & ~PCI_EXT_CAP_ID(header));

        spin_unlock(&vpci->lock);
        return 0;
    }

    prev_r = vpci_get_previous_ext_cap_register(vpci, offset);
    if ( !prev_r )
    {
        spin_unlock(&vpci->lock);
        return -ENODEV;
    }

    pre_header = (uint32_t)(uintptr_t)prev_r->private;
    pre_header &= ~PCI_EXT_CAP_NEXT_MASK;
    pre_header |= header & PCI_EXT_CAP_NEXT_MASK;
    prev_r->private = (void *)(uintptr_t)pre_header;

    list_del(&r->node);
    spin_unlock(&vpci->lock);
    xfree(r);

    return 0;
}

static int vpci_init_capability_list(struct pci_dev *pdev)
{
    int rc;
    bool mask_cap_list = false;
    bool is_hwdom = is_hardware_domain(pdev->domain);

    if ( pci_conf_read16(pdev->sbdf, PCI_STATUS) & PCI_STATUS_CAP_LIST )
    {
        /* Only expose capabilities to the guest that vPCI can handle. */
        unsigned int next, ttl = 48;
        static const unsigned int supported_caps[] = {
            PCI_CAP_ID_MSI,
            PCI_CAP_ID_MSIX,
        };
        /*
         * For dom0, we should expose all capabilities instead of a fixed
         * capabilities array, so setting n to 0 here is to get the next
         * capability position directly in pci_find_next_cap_ttl.
         */
        const unsigned int n = is_hwdom ? 0 : ARRAY_SIZE(supported_caps);

        next = pci_find_next_cap_ttl(pdev->sbdf, PCI_CAPABILITY_LIST,
                                     supported_caps, n, &ttl);

        rc = vpci_add_register(pdev->vpci, vpci_read_val,
                               is_hwdom ? vpci_hw_write8 : NULL,
                               PCI_CAPABILITY_LIST, 1,
                               (void *)(uintptr_t)next);
        if ( rc )
            return rc;

        next &= ~3;

        if ( !next && !is_hwdom )
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
                                         supported_caps, n, &ttl);

            if ( !is_hwdom )
            {
                rc = vpci_add_register(pdev->vpci, vpci_hw_read8, NULL,
                                       pos + PCI_CAP_LIST_ID, 1, NULL);
                if ( rc )
                    return rc;
            }

            rc = vpci_add_register(pdev->vpci, vpci_read_val,
                                   is_hwdom ? vpci_hw_write8 : NULL,
                                   pos + PCI_CAP_LIST_NEXT, 1,
                                   (void *)(uintptr_t)next);
            if ( rc )
                return rc;

            next &= ~3;
        }
    }

    /* Return early for the hw domain, no masking of PCI_STATUS. */
    if ( is_hwdom )
        return 0;

    /* Utilize rsvdp_mask to hide PCI_STATUS_CAP_LIST from the guest. */
    return vpci_add_register_mask(pdev->vpci, vpci_hw_read16, vpci_hw_write16,
                                  PCI_STATUS, 2, NULL,
                                  PCI_STATUS_RO_MASK &
                                    ~(mask_cap_list ? PCI_STATUS_CAP_LIST : 0),
                                  PCI_STATUS_RW1C_MASK,
                                  mask_cap_list ? PCI_STATUS_CAP_LIST : 0,
                                  PCI_STATUS_RSVDZ_MASK);
}

static int vpci_init_ext_capability_list(const struct pci_dev *pdev)
{
    unsigned int pos = PCI_CFG_SPACE_SIZE;

    if ( !pdev->ext_cfg )
        return 0;

    if ( !is_hardware_domain(pdev->domain) )
        /* Extended capabilities read as zero, write ignore for DomU */
        return vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                                 pos, 4, (void *)0);

    do
    {
        uint32_t header = pci_conf_read32(pdev->sbdf, pos);
        int rc;

        if ( header == 0xffffffffU )
        {
            printk(XENLOG_WARNING
                   "%pd %pp: broken extended cap list, offset %#x\n",
                   pdev->domain, &pdev->sbdf, pos);
            return 0;
        }

        rc = vpci_add_register(pdev->vpci, vpci_read_val, NULL,
                               pos, 4, (void *)(uintptr_t)header);
        if ( rc == -EEXIST )
        {
            printk(XENLOG_WARNING
                   "%pd %pp: overlap in extended cap list, offset %#x\n",
                   pdev->domain, &pdev->sbdf, pos);
            return 0;
        }

        if ( rc )
            return rc;

        pos = PCI_EXT_CAP_NEXT(header);
    } while ( pos >= PCI_CFG_SPACE_SIZE );

    return 0;
}

int vpci_init_capabilities(struct pci_dev *pdev)
{
    int rc;

    rc = vpci_init_capability_list(pdev);
    if ( rc )
        return rc;

    rc = vpci_init_ext_capability_list(pdev);
    if ( rc )
        return rc;

    for ( unsigned int i = 0; i < NUM_VPCI_INIT; i++ )
    {
        const vpci_capability_t *capability = &__start_vpci_array[i];
        const unsigned int cap = capability->id;
        const bool is_ext = capability->is_ext;
        unsigned int pos = 0;

        if ( !is_ext )
            pos = pci_find_cap_offset(pdev->sbdf, cap);
        else if ( is_hardware_domain(pdev->domain) )
            pos = pci_find_ext_capability(pdev, cap);

        if ( !pos )
            continue;

        rc = capability->init(pdev);
        if ( rc )
        {
            const char *type = is_ext ? "extended" : "legacy";

            printk(XENLOG_WARNING
                   "%pd %pp: init %s cap %u fail rc=%d, mask it\n",
                   pdev->domain, &pdev->sbdf, type, cap, rc);

            if ( capability->cleanup )
            {
                rc = capability->cleanup(pdev, true);
                if ( rc )
                {
                    printk(XENLOG_ERR "%pd %pp: clean %s cap %u fail rc=%d\n",
                           pdev->domain, &pdev->sbdf, type, cap, rc);
                    if ( !is_hardware_domain(pdev->domain) )
                        return rc;
                }
            }

            if ( !is_ext )
                rc = vpci_capability_hide(pdev, cap);
            else
                rc = vpci_ext_capability_hide(pdev, cap);
            if ( rc )
            {
                printk(XENLOG_ERR "%pd %pp: hide %s cap %u fail rc=%d\n",
                       pdev->domain, &pdev->sbdf, type, cap, rc);
                return rc;
            }
        }
    }

    return 0;
}

void vpci_cleanup_capabilities(struct pci_dev *pdev)
{
    for ( unsigned int i = 0; i < NUM_VPCI_INIT; i++ )
    {
        const vpci_capability_t *capability = &__start_vpci_array[i];
        const unsigned int cap = capability->id;
        unsigned int pos = 0;

        if ( !capability->cleanup )
            continue;

        if ( !capability->is_ext )
            pos = pci_find_cap_offset(pdev->sbdf, cap);
        else if ( is_hardware_domain(pdev->domain) )
            pos = pci_find_ext_capability(pdev, cap);
        if ( pos )
        {
            int rc = capability->cleanup(pdev, false);

            if ( rc )
                printk(XENLOG_ERR "%pd %pp: clean %s cap %u fail rc=%d\n",
                       pdev->domain, &pdev->sbdf,
                       capability->is_ext ? "extended" : "legacy", cap, rc);
        }
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
