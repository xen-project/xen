
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/vpci.h>

#ifndef COMPAT
typedef long ret_t;
#endif

ret_t pci_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    ret_t ret;

    switch ( cmd )
    {
    case PHYSDEVOP_pci_device_add: {
        struct physdev_pci_device_add add;
        struct pci_dev_info pdev_info;
        nodeid_t node = NUMA_NO_NODE;

        if ( !is_pci_passthrough_enabled() )
            return -EOPNOTSUPP;

        ret = -EFAULT;
        if ( copy_from_guest(&add, arg, 1) != 0 )
            break;

        pdev_info.is_extfn = (add.flags & XEN_PCI_DEV_EXTFN);
        if ( add.flags & XEN_PCI_DEV_VIRTFN )
        {
            pdev_info.is_virtfn = true;
            pdev_info.physfn.bus = add.physfn.bus;
            pdev_info.physfn.devfn = add.physfn.devfn;
        }
        else
            pdev_info.is_virtfn = false;

#ifdef CONFIG_NUMA
        if ( add.flags & XEN_PCI_DEV_PXM )
        {
            uint32_t pxm;
            size_t optarr_off = offsetof(struct physdev_pci_device_add, optarr) /
                                sizeof(add.optarr[0]);

            if ( copy_from_guest_offset(&pxm, arg, optarr_off, 1) )
                break;

            node = pxm_to_node(pxm);
        }
#endif

        ret = pci_add_device(add.seg, add.bus, add.devfn, &pdev_info, node);
        break;
    }

    case PHYSDEVOP_pci_device_remove: {
        struct physdev_pci_device dev;

        if ( !is_pci_passthrough_enabled() )
            return -EOPNOTSUPP;

        ret = -EFAULT;
        if ( copy_from_guest(&dev, arg, 1) != 0 )
            break;

        ret = pci_remove_device(dev.seg, dev.bus, dev.devfn);
        break;
    }

    case PHYSDEVOP_pci_device_reset:
    {
        struct pci_device_reset dev_reset;
        struct pci_dev *pdev;
        pci_sbdf_t sbdf;

        ret = -EFAULT;
        if ( copy_from_guest(&dev_reset, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        if ( dev_reset.flags & ~PCI_DEVICE_RESET_MASK )
            break;

        sbdf = PCI_SBDF(dev_reset.dev.seg,
                        dev_reset.dev.bus,
                        dev_reset.dev.devfn);

        ret = xsm_resource_setup_pci(XSM_PRIV, sbdf.sbdf);
        if ( ret )
            break;

        pcidevs_lock();
        pdev = pci_get_pdev(NULL, sbdf);
        if ( !pdev )
        {
            pcidevs_unlock();
            ret = -ENODEV;
            break;
        }

        write_lock(&pdev->domain->pci_lock);
        pcidevs_unlock();
        switch ( dev_reset.flags & PCI_DEVICE_RESET_MASK )
        {
        case PCI_DEVICE_RESET_COLD:
        case PCI_DEVICE_RESET_WARM:
        case PCI_DEVICE_RESET_HOT:
        case PCI_DEVICE_RESET_FLR:
            ret = vpci_reset_device(pdev);
            break;

        default:
            ret = -EINVAL;
            break;
        }
        write_unlock(&pdev->domain->pci_lock);

        break;
    }

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
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
