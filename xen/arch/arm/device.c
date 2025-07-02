/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/device.c
 *
 * Helpers to use a device retrieved via the device tree.
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2013 Linaro Limited.
 */

#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/iocap.h>
#include <xen/lib.h>

#include <asm/setup.h>

int map_irq_to_domain(struct domain *d, unsigned int irq,
                      bool need_mapping, const char *devname)
{
    int res;

    res = irq_permit_access(d, irq);
    if ( res )
    {
        printk(XENLOG_ERR "Unable to permit to %pd access to IRQ %u\n", d, irq);
        return res;
    }

    if ( need_mapping )
    {
        /*
         * Checking the return of vgic_reserve_virq is not
         * necessary. It should not fail except when we try to map
         * the IRQ twice. This can legitimately happen if the IRQ is shared
         */
        vgic_reserve_virq(d, irq);

        res = route_irq_to_guest(d, irq, irq, devname);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map IRQ%u to %pd\n", irq, d);
            return res;
        }
    }

    dt_dprintk("  - IRQ: %u\n", irq);
    return 0;
}

int map_range_to_domain(const struct dt_device_node *dev,
                        uint64_t addr, uint64_t len, void *data)
{
    struct map_range_data *mr_data = data;
    struct domain *d = mr_data->d;
    int res;

    if ( (addr != (paddr_t)addr) || (((paddr_t)~0 - addr) < len) )
    {
        printk(XENLOG_ERR "%s: [0x%"PRIx64", 0x%"PRIx64"] exceeds the maximum allowed PA width (%u bits)",
               dt_node_full_name(dev), addr, (addr + len), PADDR_BITS);
        return -ERANGE;
    }

    /*
     * reserved-memory regions are RAM carved out for a special purpose.
     * They are not MMIO and therefore a domain should not be able to
     * manage them via the IOMEM interface.
     */
    if ( strncasecmp(dt_node_full_name(dev), "/reserved-memory/",
                     strlen("/reserved-memory/")) != 0 )
    {
        res = iomem_permit_access(d, paddr_to_pfn(addr),
                                  paddr_to_pfn(addr + len - 1));
        if ( res )
        {
            printk(XENLOG_ERR "Unable to permit to dom%d access to"
                    " 0x%"PRIx64" - 0x%"PRIx64"\n",
                    d->domain_id,
                    addr & PAGE_MASK, PAGE_ALIGN(addr + len) - 1);
            return res;
        }
    }

    if ( !mr_data->skip_mapping )
    {
        res = map_regions_p2mt(d,
                               gaddr_to_gfn(addr),
                               PFN_UP(len),
                               maddr_to_mfn(addr),
                               mr_data->p2mt);

        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map 0x%"PRIx64
                   " - 0x%"PRIx64" in domain %d\n",
                   addr & PAGE_MASK, PAGE_ALIGN(addr + len) - 1,
                   d->domain_id);
            return res;
        }
    }

    dt_dprintk("  - MMIO: %010"PRIx64" - %010"PRIx64" P2MType=%x\n",
               addr, addr + len, mr_data->p2mt);

    if ( mr_data->iomem_ranges )
    {
        res = rangeset_add_range(mr_data->iomem_ranges,
                                 paddr_to_pfn(addr),
                                 paddr_to_pfn(addr + len - 1));
        if ( res )
            return res;
    }

    return 0;
}

/*
 * map_device_irqs_to_domain retrieves the interrupts configuration from
 * a device tree node and maps those interrupts to the target domain.
 *
 * Returns:
 *   < 0 error
 *   0   success
 */
int map_device_irqs_to_domain(struct domain *d,
                              struct dt_device_node *dev,
                              bool need_mapping,
                              struct rangeset *irq_ranges)
{
    unsigned int i, nirq;
    int res, irq;
    struct dt_raw_irq rirq;

    nirq = dt_number_of_irq(dev);

    /* Give permission and map IRQs */
    for ( i = 0; i < nirq; i++ )
    {
        res = dt_device_get_raw_irq(dev, i, &rirq);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        /*
         * Don't map IRQ that have no physical meaning
         * ie: IRQ whose controller is not the GIC
         */
        if ( rirq.controller != dt_interrupt_controller )
        {
            dt_dprintk("irq %u not connected to primary controller. Connected to %s\n",
                      i, dt_node_full_name(rirq.controller));
            continue;
        }

        irq = platform_get_irq(dev, i);
        if ( irq < 0 )
        {
            printk(XENLOG_ERR "Unable to get irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return irq;
        }

        res = map_irq_to_domain(d, irq, need_mapping, dt_node_name(dev));
        if ( res )
            return res;

        if ( irq_ranges )
        {
            res = rangeset_add_singleton(irq_ranges, irq);
            if ( res )
                return res;
        }
    }

    return 0;
}

static int map_dt_irq_to_domain(const struct dt_device_node *dev,
                                const struct dt_irq *dt_irq,
                                void *data)
{
    struct map_range_data *mr_data = data;
    struct domain *d = mr_data->d;
    unsigned int irq = dt_irq->irq;
    int res;

    if ( irq < NR_LOCAL_IRQS )
    {
        printk(XENLOG_ERR "%s: IRQ%u is not a SPI\n", dt_node_name(dev), irq);
        return -EINVAL;
    }

    /* Setup the IRQ type */
    res = irq_set_spi_type(irq, dt_irq->type);
    if ( res )
    {
        printk(XENLOG_ERR "%s: Unable to setup IRQ%u to %pd\n",
               dt_node_name(dev), irq, d);
        return res;
    }

    res = map_irq_to_domain(d, irq, !mr_data->skip_mapping, dt_node_name(dev));
    if ( res )
        return res;

    if ( mr_data->irq_ranges )
        res = rangeset_add_singleton(mr_data->irq_ranges, irq);

    return res;
}

/*
 * For a node which describes a discoverable bus (such as a PCI bus)
 * then we may need to perform additional mappings in order to make
 * the child resources available to domain 0.
 */
static int map_device_children(const struct dt_device_node *dev,
                               struct map_range_data *mr_data)
{
    if ( dt_device_type_is_equal(dev, "pci") )
    {
        int ret;

        dt_dprintk("Mapping children of %s to guest\n",
                   dt_node_full_name(dev));

        ret = dt_for_each_irq_map(dev, &map_dt_irq_to_domain, mr_data);
        if ( ret < 0 )
            return ret;

        ret = dt_for_each_range(dev, &map_range_to_domain, mr_data);
        if ( ret < 0 )
            return ret;
    }

    return 0;
}

/*
 * For a given device node:
 *  - Give permission to the guest to manage IRQ and MMIO range
 *  - Retrieve the IRQ configuration (i.e edge/level) from device tree
 * When the device is not marked for guest passthrough:
 *  - Try to call iommu_add_dt_device to protect the device by an IOMMU
 *  - Assign the device to the guest if it's protected by an IOMMU
 *  - Map the IRQs and iomem regions to DOM0
 */
int handle_device(struct domain *d, struct dt_device_node *dev, p2m_type_t p2mt,
                  struct rangeset *iomem_ranges, struct rangeset *irq_ranges)
{
    unsigned int naddr;
    unsigned int i;
    int res;
    paddr_t addr, size;
    bool own_device = !dt_device_for_passthrough(dev);
    /*
     * We want to avoid mapping the MMIO in dom0 for the following cases:
     *   - The device is owned by dom0 (i.e. it has been flagged for
     *     passthrough).
     *   - PCI host bridges with driver in Xen. They will later be mapped by
     *     pci_host_bridge_mappings().
     */
    struct map_range_data mr_data = {
        .d = d,
        .p2mt = p2mt,
        .skip_mapping = !own_device ||
                        (has_vpci(d) &&
                        (device_get_class(dev) == DEVICE_PCI_HOSTBRIDGE)),
        .iomem_ranges = iomem_ranges,
        .irq_ranges = irq_ranges
    };

    naddr = dt_number_of_address(dev);

    dt_dprintk("%s passthrough = %d naddr = %u\n",
               dt_node_full_name(dev), own_device, naddr);

    if ( own_device )
    {
        dt_dprintk("Check if %s is behind the IOMMU and add it\n",
                   dt_node_full_name(dev));

        res = iommu_add_dt_device(dev);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Failed to add %s to the IOMMU\n",
                   dt_node_full_name(dev));
            return res;
        }

        if ( dt_device_is_protected(dev) )
        {
            dt_dprintk("%s setup iommu\n", dt_node_full_name(dev));
            res = iommu_assign_dt_device(d, dev);
            if ( res )
            {
                printk(XENLOG_ERR "Failed to setup the IOMMU for %s\n",
                       dt_node_full_name(dev));
                return res;
            }
        }
    }

    res = map_device_irqs_to_domain(d, dev, own_device, irq_ranges);
    if ( res < 0 )
        return res;

    /* Give permission and map MMIOs */
    for ( i = 0; i < naddr; i++ )
    {
        res = dt_device_get_paddr(dev, i, &addr, &size);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve address %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        res = map_range_to_domain(dev, addr, size, &mr_data);
        if ( res )
            return res;
    }

    res = map_device_children(dev, &mr_data);
    if ( res )
        return res;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
