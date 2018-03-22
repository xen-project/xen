
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <xen/serial.h>
#include <asm/current.h>
#include <asm/io_apic.h>
#include <asm/msi.h>
#include <asm/hvm/irq.h>
#include <asm/hypercall.h>
#include <public/xen.h>
#include <public/physdev.h>
#include <xsm/xsm.h>
#include <asm/p2m.h>

int physdev_map_pirq(domid_t, int type, int *index, int *pirq_p,
                     struct msi_info *);
int physdev_unmap_pirq(domid_t, int pirq);

#include "x86_64/mmconfig.h"

#ifndef COMPAT
typedef long ret_t;

static int physdev_hvm_map_pirq(
    struct domain *d, int type, int *index, int *pirq)
{
    int ret = 0;

    ASSERT(!is_hardware_domain(d));

    spin_lock(&d->event_lock);
    switch ( type )
    {
    case MAP_PIRQ_TYPE_GSI: {
        const struct hvm_irq_dpci *hvm_irq_dpci;
        unsigned int machine_gsi = 0;

        if ( *index < 0 || *index >= NR_HVM_DOMU_IRQS )
        {
            ret = -EINVAL;
            break;
        }

        /* find the machine gsi corresponding to the
         * emulated gsi */
        hvm_irq_dpci = domain_get_irq_dpci(d);
        if ( hvm_irq_dpci )
        {
            const struct hvm_girq_dpci_mapping *girq;

            BUILD_BUG_ON(ARRAY_SIZE(hvm_irq_dpci->girq) < NR_HVM_DOMU_IRQS);
            list_for_each_entry ( girq,
                                  &hvm_irq_dpci->girq[*index],
                                  list )
                machine_gsi = girq->machine_gsi;
        }
        /* found one, this mean we are dealing with a pt device */
        if ( machine_gsi )
        {
            *index = domain_pirq_to_irq(d, machine_gsi);
            *pirq = machine_gsi;
            ret = (*pirq > 0) ? 0 : *pirq;
        }
        /* we didn't find any, this means we are dealing
         * with an emulated device */
        else
        {
            if ( *pirq < 0 )
                *pirq = get_free_pirq(d, type);
            ret = map_domain_emuirq_pirq(d, *pirq, *index);
        }
        break;
    }

    default:
        ret = -EINVAL;
        dprintk(XENLOG_G_WARNING, "map type %d not supported yet\n", type);
        break;
    }

    spin_unlock(&d->event_lock);
    return ret;
}

int physdev_map_pirq(domid_t domid, int type, int *index, int *pirq_p,
                     struct msi_info *msi)
{
    struct domain *d = current->domain;
    int ret;

    if ( domid == DOMID_SELF && is_hvm_domain(d) && has_pirq(d) )
    {
        /*
         * Only makes sense for vector-based callback, else HVM-IRQ logic
         * calls back into itself and deadlocks on hvm_domain.irq_lock.
         */
        if ( !is_hvm_pv_evtchn_domain(d) )
            return -EINVAL;

        return physdev_hvm_map_pirq(d, type, index, pirq_p);
    }

    d = rcu_lock_domain_by_any_id(domid);
    if ( d == NULL )
        return -ESRCH;

    ret = xsm_map_domain_pirq(XSM_DM_PRIV, d);
    if ( ret )
        goto free_domain;

    /* Verify or get irq. */
    switch ( type )
    {
    case MAP_PIRQ_TYPE_GSI:
        ret = allocate_and_map_gsi_pirq(d, *index, pirq_p);
        break;

    case MAP_PIRQ_TYPE_MSI:
    case MAP_PIRQ_TYPE_MULTI_MSI:
        ret = allocate_and_map_msi_pirq(d, *index, pirq_p, type, msi);
        break;

    default:
        dprintk(XENLOG_G_ERR, "dom%d: wrong map_pirq type %x\n",
                d->domain_id, type);
        ret = -EINVAL;
        break;
    }

 free_domain:
    rcu_unlock_domain(d);
    return ret;
}

int physdev_unmap_pirq(domid_t domid, int pirq)
{
    struct domain *d;
    int ret = 0;

    d = rcu_lock_domain_by_any_id(domid);
    if ( d == NULL )
        return -ESRCH;

    if ( domid != DOMID_SELF || !is_hvm_domain(d) || !has_pirq(d) )
        ret = xsm_unmap_domain_pirq(XSM_DM_PRIV, d);
    if ( ret )
        goto free_domain;

    if ( is_hvm_domain(d) && has_pirq(d) )
    {
        spin_lock(&d->event_lock);
        if ( domain_pirq_to_emuirq(d, pirq) != IRQ_UNBOUND )
            ret = unmap_domain_pirq_emuirq(d, pirq);
        spin_unlock(&d->event_lock);
        if ( domid == DOMID_SELF || ret )
            goto free_domain;
    }

    pcidevs_lock();
    spin_lock(&d->event_lock);
    ret = unmap_domain_pirq(d, pirq);
    spin_unlock(&d->event_lock);
    pcidevs_unlock();

 free_domain:
    rcu_unlock_domain(d);
    return ret;
}
#endif /* COMPAT */

ret_t do_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int irq;
    ret_t ret;
    struct domain *currd = current->domain;

    switch ( cmd )
    {
    case PHYSDEVOP_eoi: {
        struct physdev_eoi eoi;
        struct pirq *pirq;

        ret = -EFAULT;
        if ( copy_from_guest(&eoi, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( eoi.irq >= currd->nr_pirqs )
            break;
        spin_lock(&currd->event_lock);
        pirq = pirq_info(currd, eoi.irq);
        if ( !pirq ) {
            spin_unlock(&currd->event_lock);
            break;
        }
        if ( currd->arch.auto_unmask )
            evtchn_unmask(pirq->evtchn);
        if ( is_pv_domain(currd) || domain_pirq_to_irq(currd, eoi.irq) > 0 )
            pirq_guest_eoi(pirq);
        if ( is_hvm_domain(currd) &&
             domain_pirq_to_emuirq(currd, eoi.irq) > 0 )
        {
            struct hvm_irq *hvm_irq = hvm_domain_irq(currd);
            int gsi = domain_pirq_to_emuirq(currd, eoi.irq);

            /* if this is a level irq and count > 0, send another
             * notification */ 
            if ( gsi >= NR_ISAIRQS /* ISA irqs are edge triggered */
                    && hvm_irq->gsi_assert_count[gsi] )
                send_guest_pirq(currd, pirq);
        }
        spin_unlock(&currd->event_lock);
        ret = 0;
        break;
    }

    case PHYSDEVOP_pirq_eoi_gmfn_v2:
    case PHYSDEVOP_pirq_eoi_gmfn_v1: {
        struct physdev_pirq_eoi_gmfn info;
        struct page_info *page;

        ret = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        page = get_page_from_gfn(current->domain, info.gmfn, NULL, P2M_ALLOC);
        if ( !page )
            break;
        if ( !get_page_type(page, PGT_writable_page) )
        {
            put_page(page);
            break;
        }

        if ( cmpxchg(&currd->arch.pirq_eoi_map_mfn,
                     0, page_to_mfn(page)) != 0 )
        {
            put_page_and_type(page);
            ret = -EBUSY;
            break;
        }

        currd->arch.pirq_eoi_map = __map_domain_page_global(page);
        if ( currd->arch.pirq_eoi_map == NULL )
        {
            currd->arch.pirq_eoi_map_mfn = 0;
            put_page_and_type(page);
            ret = -ENOSPC;
            break;
        }
        if ( cmd == PHYSDEVOP_pirq_eoi_gmfn_v1 )
            currd->arch.auto_unmask = 1;

        ret = 0;
        break;
    }

    /* Legacy since 0x00030202. */
    case PHYSDEVOP_IRQ_UNMASK_NOTIFY: {
        ret = pirq_guest_unmask(currd);
        break;
    }

    case PHYSDEVOP_irq_status_query: {
        struct physdev_irq_status_query irq_status_query;
        ret = -EFAULT;
        if ( copy_from_guest(&irq_status_query, arg, 1) != 0 )
            break;
        irq = irq_status_query.irq;
        ret = -EINVAL;
        if ( (irq < 0) || (irq >= currd->nr_pirqs) )
            break;
        irq_status_query.flags = 0;
        if ( is_hvm_domain(currd) &&
             domain_pirq_to_irq(currd, irq) <= 0 &&
             domain_pirq_to_emuirq(currd, irq) == IRQ_UNBOUND )
        {
            ret = -EINVAL;
            break;
        }

        /*
         * Even edge-triggered or message-based IRQs can need masking from
         * time to time. If teh guest is not dynamically checking for this
         * via the new pirq_eoi_map mechanism, it must conservatively always
         * execute the EOI hypercall. In practice, this only really makes a
         * difference for maskable MSI sources, and if those are supported
         * then dom0 is probably modern anyway.
         */
        irq_status_query.flags |= XENIRQSTAT_needs_eoi;
        if ( pirq_shared(currd, irq) )
            irq_status_query.flags |= XENIRQSTAT_shared;
        ret = __copy_to_guest(arg, &irq_status_query, 1) ? -EFAULT : 0;
        break;
    }

    case PHYSDEVOP_map_pirq: {
        physdev_map_pirq_t map;
        struct msi_info msi;

        ret = -EFAULT;
        if ( copy_from_guest(&map, arg, 1) != 0 )
            break;

        switch ( map.type )
        {
        case MAP_PIRQ_TYPE_MSI_SEG:
            map.type = MAP_PIRQ_TYPE_MSI;
            msi.seg = map.bus >> 16;
            break;

        case MAP_PIRQ_TYPE_MULTI_MSI:
            if ( map.table_base )
                return -EINVAL;
            msi.seg = map.bus >> 16;
            break;

        default:
            msi.seg = 0;
            break;
        }
        msi.bus = map.bus;
        msi.devfn = map.devfn;
        msi.entry_nr = map.entry_nr;
        msi.table_base = map.table_base;
        ret = physdev_map_pirq(map.domid, map.type, &map.index, &map.pirq,
                               &msi);

        if ( map.type == MAP_PIRQ_TYPE_MULTI_MSI )
            map.entry_nr = msi.entry_nr;
        if ( __copy_to_guest(arg, &map, 1) )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_unmap_pirq: {
        struct physdev_unmap_pirq unmap;

        ret = -EFAULT;
        if ( copy_from_guest(&unmap, arg, 1) != 0 )
            break;

        ret = physdev_unmap_pirq(unmap.domid, unmap.pirq);
        break;
    }

    case PHYSDEVOP_apic_read: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = xsm_apic(XSM_PRIV, currd, cmd);
        if ( ret )
            break;
        ret = ioapic_guest_read(apic.apic_physbase, apic.reg, &apic.value);
        if ( __copy_to_guest(arg, &apic, 1) )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_apic_write: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = xsm_apic(XSM_PRIV, currd, cmd);
        if ( ret )
            break;
        ret = ioapic_guest_write(apic.apic_physbase, apic.reg, apic.value);
        break;
    }

    case PHYSDEVOP_alloc_irq_vector: {
        struct physdev_irq irq_op;

        ret = -EFAULT;
        if ( copy_from_guest(&irq_op, arg, 1) != 0 )
            break;

        /* Use the APIC check since this dummy hypercall should still only
         * be called by the domain with access to program the ioapic */
        ret = xsm_apic(XSM_PRIV, currd, cmd);
        if ( ret )
            break;

        /* Vector is only used by hypervisor, and dom0 shouldn't
           touch it in its world, return irq_op.irq as the vecotr,
           and make this hypercall dummy, and also defer the vector 
           allocation when dom0 tries to programe ioapic entry. */
        irq_op.vector = irq_op.irq;
        ret = 0;
        
        if ( __copy_to_guest(arg, &irq_op, 1) )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_set_iopl: {
        struct vcpu *curr = current;
        struct physdev_set_iopl set_iopl;

        ret = -EFAULT;
        if ( copy_from_guest(&set_iopl, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( set_iopl.iopl > 3 )
            break;
        ret = 0;
        curr->arch.pv_vcpu.iopl = MASK_INSR(set_iopl.iopl, X86_EFLAGS_IOPL);
        break;
    }

    case PHYSDEVOP_set_iobitmap: {
        struct vcpu *curr = current;
        struct physdev_set_iobitmap set_iobitmap;

        ret = -EFAULT;
        if ( copy_from_guest(&set_iobitmap, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( !guest_handle_okay(set_iobitmap.bitmap, IOBMP_BYTES) ||
             (set_iobitmap.nr_ports > 65536) )
            break;
        ret = 0;
#ifndef COMPAT
        curr->arch.pv_vcpu.iobmp = set_iobitmap.bitmap;
#else
        guest_from_compat_handle(curr->arch.pv_vcpu.iobmp,
                                 set_iobitmap.bitmap);
#endif
        curr->arch.pv_vcpu.iobmp_limit = set_iobitmap.nr_ports;
        break;
    }

    case PHYSDEVOP_manage_pci_add: {
        struct physdev_manage_pci manage_pci;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_add_device(0, manage_pci.bus, manage_pci.devfn,
                             NULL, NUMA_NO_NODE);
        break;
    }

    case PHYSDEVOP_manage_pci_remove: {
        struct physdev_manage_pci manage_pci;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_remove_device(0, manage_pci.bus, manage_pci.devfn);
        break;
    }

    case PHYSDEVOP_manage_pci_add_ext: {
        struct physdev_manage_pci_ext manage_pci_ext;
        struct pci_dev_info pdev_info;

        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci_ext, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        if ( (manage_pci_ext.is_extfn > 1) || (manage_pci_ext.is_virtfn > 1) )
            break;

        pdev_info.is_extfn = manage_pci_ext.is_extfn;
        pdev_info.is_virtfn = manage_pci_ext.is_virtfn;
        pdev_info.physfn.bus = manage_pci_ext.physfn.bus;
        pdev_info.physfn.devfn = manage_pci_ext.physfn.devfn;
        ret = pci_add_device(0, manage_pci_ext.bus,
                             manage_pci_ext.devfn,
                             &pdev_info, NUMA_NO_NODE);
        break;
    }

    case PHYSDEVOP_pci_device_add: {
        struct physdev_pci_device_add add;
        struct pci_dev_info pdev_info;
        nodeid_t node;

        ret = -EFAULT;
        if ( copy_from_guest(&add, arg, 1) != 0 )
            break;

        pdev_info.is_extfn = !!(add.flags & XEN_PCI_DEV_EXTFN);
        if ( add.flags & XEN_PCI_DEV_VIRTFN )
        {
            pdev_info.is_virtfn = 1;
            pdev_info.physfn.bus = add.physfn.bus;
            pdev_info.physfn.devfn = add.physfn.devfn;
        }
        else
            pdev_info.is_virtfn = 0;

        if ( add.flags & XEN_PCI_DEV_PXM )
        {
            uint32_t pxm;
            size_t optarr_off = offsetof(struct physdev_pci_device_add, optarr) /
                                sizeof(add.optarr[0]);

            if ( copy_from_guest_offset(&pxm, arg, optarr_off, 1) )
                break;

            node = pxm_to_node(pxm);
        }
        else
            node = NUMA_NO_NODE;

        ret = pci_add_device(add.seg, add.bus, add.devfn, &pdev_info, node);
        break;
    }

    case PHYSDEVOP_pci_device_remove: {
        struct physdev_pci_device dev;

        ret = -EFAULT;
        if ( copy_from_guest(&dev, arg, 1) != 0 )
            break;

        ret = pci_remove_device(dev.seg, dev.bus, dev.devfn);
        break;
    }

    case PHYSDEVOP_prepare_msix:
    case PHYSDEVOP_release_msix: {
        struct physdev_pci_device dev;

        if ( copy_from_guest(&dev, arg, 1) )
            ret = -EFAULT;
        else
            ret = xsm_resource_setup_pci(XSM_PRIV,
                                         (dev.seg << 16) | (dev.bus << 8) |
                                         dev.devfn) ?:
                  pci_prepare_msix(dev.seg, dev.bus, dev.devfn,
                                   cmd != PHYSDEVOP_prepare_msix);
        break;
    }

    case PHYSDEVOP_pci_mmcfg_reserved: {
        struct physdev_pci_mmcfg_reserved info;

        ret = xsm_resource_setup_misc(XSM_PRIV);
        if ( ret )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) )
            break;

        ret = pci_mmcfg_reserved(info.address, info.segment,
                                 info.start_bus, info.end_bus, info.flags);
        if ( !ret && has_vpci(currd) )
        {
            /*
             * For HVM (PVH) domains try to add the newly found MMCFG to the
             * domain.
             */
            ret = register_vpci_mmcfg_handler(currd, info.address,
                                              info.start_bus, info.end_bus,
                                              info.segment);
        }

        break;
    }

    case PHYSDEVOP_restore_msi: {
        struct physdev_restore_msi restore_msi;
        struct pci_dev *pdev;

        ret = -EFAULT;
        if ( copy_from_guest(&restore_msi, arg, 1) != 0 )
            break;

        pcidevs_lock();
        pdev = pci_get_pdev(0, restore_msi.bus, restore_msi.devfn);
        ret = pdev ? pci_restore_msi_state(pdev) : -ENODEV;
        pcidevs_unlock();
        break;
    }

    case PHYSDEVOP_restore_msi_ext: {
        struct physdev_pci_device dev;
        struct pci_dev *pdev;

        ret = -EFAULT;
        if ( copy_from_guest(&dev, arg, 1) != 0 )
            break;

        pcidevs_lock();
        pdev = pci_get_pdev(dev.seg, dev.bus, dev.devfn);
        ret = pdev ? pci_restore_msi_state(pdev) : -ENODEV;
        pcidevs_unlock();
        break;
    }

    case PHYSDEVOP_setup_gsi: {
        struct physdev_setup_gsi setup_gsi;

        ret = -EFAULT;
        if ( copy_from_guest(&setup_gsi, arg, 1) != 0 )
            break;
        
        ret = -EINVAL;
        if ( setup_gsi.gsi < 0 || setup_gsi.gsi >= nr_irqs_gsi )
            break;

        ret = xsm_resource_setup_gsi(XSM_PRIV, setup_gsi.gsi);
        if ( ret )
            break;

        ret = mp_register_gsi(setup_gsi.gsi, setup_gsi.triggering,
                              setup_gsi.polarity);
        break; 
    }
    case PHYSDEVOP_get_free_pirq: {
        struct physdev_get_free_pirq out;

        ret = -EFAULT;
        if ( copy_from_guest(&out, arg, 1) != 0 )
            break;

        spin_lock(&currd->event_lock);

        ret = get_free_pirq(currd, out.type);
        if ( ret >= 0 )
        {
            struct pirq *info = pirq_get_info(currd, ret);

            if ( info )
                info->arch.irq = PIRQ_ALLOCATED;
            else
                ret = -ENOMEM;
        }

        spin_unlock(&currd->event_lock);

        if ( ret >= 0 )
        {
            out.pirq = ret;
            ret = __copy_to_guest(arg, &out, 1) ? -EFAULT : 0;
        }

        break;
    }

    case PHYSDEVOP_dbgp_op: {
        struct physdev_dbgp_op op;

        if ( !is_hardware_domain(currd) )
            ret = -EPERM;
        else if ( copy_from_guest(&op, arg, 1) )
            ret = -EFAULT;
        else
            ret = dbgp_op(&op);
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
