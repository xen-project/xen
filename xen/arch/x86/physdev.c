
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <asm/current.h>
#include <asm/msi.h>
#include <asm/hypercall.h>
#include <public/xen.h>
#include <public/physdev.h>
#include <xsm/xsm.h>
#include <asm/p2m.h>

#ifndef COMPAT
typedef long ret_t;
#endif

int
ioapic_guest_read(
    unsigned long physbase, unsigned int reg, u32 *pval);
int
ioapic_guest_write(
    unsigned long physbase, unsigned int reg, u32 pval);

static int physdev_hvm_map_pirq(
    struct domain *d, struct physdev_map_pirq *map)
{
    int pirq, ret = 0;

    spin_lock(&d->event_lock);
    switch ( map->type )
    {
    case MAP_PIRQ_TYPE_GSI: {
        struct hvm_irq_dpci *hvm_irq_dpci;
        struct hvm_girq_dpci_mapping *girq;
        uint32_t machine_gsi = 0;

        /* find the machine gsi corresponding to the
         * emulated gsi */
        hvm_irq_dpci = domain_get_irq_dpci(d);
        if ( hvm_irq_dpci )
        {
            list_for_each_entry ( girq,
                                  &hvm_irq_dpci->girq[map->index],
                                  list )
                machine_gsi = girq->machine_gsi;
        }
        /* found one, this mean we are dealing with a pt device */
        if ( machine_gsi )
        {
            map->index = domain_pirq_to_irq(d, machine_gsi);
            pirq = machine_gsi;
            ret = (pirq > 0) ? 0 : pirq;
        }
        /* we didn't find any, this means we are dealing
         * with an emulated device */
        else
        {
            pirq = map->pirq;
            if ( pirq < 0 )
                pirq = get_free_pirq(d, map->type, map->index);
            ret = map_domain_emuirq_pirq(d, pirq, map->index);
        }
        map->pirq = pirq;
        break;
    }

    default:
        ret = -EINVAL;
        dprintk(XENLOG_G_WARNING, "map type %d not supported yet\n", map->type);
        break;
    }

    spin_unlock(&d->event_lock);
    return ret;
}

static int physdev_map_pirq(struct physdev_map_pirq *map)
{
    struct domain *d;
    int pirq, irq, ret = 0;
    struct msi_info _msi;
    void *map_data = NULL;

    ret = rcu_lock_target_domain_by_id(map->domid, &d);
    if ( ret )
        return ret;

    if ( map->domid == DOMID_SELF && is_hvm_domain(d) )
    {
        ret = physdev_hvm_map_pirq(d, map);
        goto free_domain;
    }

    if ( !IS_PRIV_FOR(current->domain, d) )
    {
        ret = -EPERM;
        goto free_domain;
    }

    /* Verify or get irq. */
    switch ( map->type )
    {
    case MAP_PIRQ_TYPE_GSI:
        if ( map->index < 0 || map->index >= nr_irqs_gsi )
        {
            dprintk(XENLOG_G_ERR, "dom%d: map invalid irq %d\n",
                    d->domain_id, map->index);
            ret = -EINVAL;
            goto free_domain;
        }

        irq = domain_pirq_to_irq(current->domain, map->index);
        if ( irq <= 0 )
        {
            if ( IS_PRIV(current->domain) )
                irq = map->index;
            else {
                dprintk(XENLOG_G_ERR, "dom%d: map pirq with incorrect irq!\n",
                        d->domain_id);
                ret = -EINVAL;
                goto free_domain;
            }
        }
        break;

    case MAP_PIRQ_TYPE_MSI:
        irq = map->index;
        if ( irq == -1 )
            irq = create_irq();

        if ( irq < 0 || irq >= nr_irqs )
        {
            dprintk(XENLOG_G_ERR, "dom%d: can't create irq for msi!\n",
                    d->domain_id);
            ret = -EINVAL;
            goto free_domain;
        }

        _msi.bus = map->bus;
        _msi.devfn = map->devfn;
        _msi.entry_nr = map->entry_nr;
        _msi.table_base = map->table_base;
        _msi.irq = irq;
        map_data = &_msi;
        break;

    default:
        dprintk(XENLOG_G_ERR, "dom%d: wrong map_pirq type %x\n",
                d->domain_id, map->type);
        ret = -EINVAL;
        goto free_domain;
    }

    spin_lock(&pcidevs_lock);
    /* Verify or get pirq. */
    spin_lock(&d->event_lock);
    pirq = domain_irq_to_pirq(d, irq);
    if ( map->pirq < 0 )
    {
        if ( pirq )
        {
            dprintk(XENLOG_G_ERR, "dom%d: %d:%d already mapped to %d\n",
                    d->domain_id, map->index, map->pirq,
                    pirq);
            if ( pirq < 0 )
            {
                ret = -EBUSY;
                goto done;
            }
        }
        else
        {
            pirq = get_free_pirq(d, map->type, map->index);
            if ( pirq < 0 )
            {
                dprintk(XENLOG_G_ERR, "dom%d: no free pirq\n", d->domain_id);
                ret = pirq;
                goto done;
            }
        }
    }
    else
    {
        if ( pirq && pirq != map->pirq )
        {
            dprintk(XENLOG_G_ERR, "dom%d: pirq %d conflicts with irq %d\n",
                    d->domain_id, map->index, map->pirq);
            ret = -EEXIST;
            goto done;
        }
        else
            pirq = map->pirq;
    }

    ret = map_domain_pirq(d, pirq, irq, map->type, map_data);
    if ( ret == 0 )
        map->pirq = pirq;

    if ( !ret && is_hvm_domain(d) )
        map_domain_emuirq_pirq(d, pirq, IRQ_PT);

 done:
    spin_unlock(&d->event_lock);
    spin_unlock(&pcidevs_lock);
    if ( (ret != 0) && (map->type == MAP_PIRQ_TYPE_MSI) && (map->index == -1) )
        destroy_irq(irq);
 free_domain:
    rcu_unlock_domain(d);
    return ret;
}

static int physdev_unmap_pirq(struct physdev_unmap_pirq *unmap)
{
    struct domain *d;
    int ret;

    ret = rcu_lock_target_domain_by_id(unmap->domid, &d);
    if ( ret )
        return ret;

    if ( is_hvm_domain(d) )
    {
        spin_lock(&d->event_lock);
        ret = unmap_domain_pirq_emuirq(d, unmap->pirq);
        spin_unlock(&d->event_lock);
        if ( unmap->domid == DOMID_SELF || ret )
            goto free_domain;
    }

    ret = -EPERM;
    if ( !IS_PRIV_FOR(current->domain, d) )
        goto free_domain;

    spin_lock(&pcidevs_lock);
    spin_lock(&d->event_lock);
    ret = unmap_domain_pirq(d, unmap->pirq);
    spin_unlock(&d->event_lock);
    spin_unlock(&pcidevs_lock);

 free_domain:
    rcu_unlock_domain(d);
    return ret;
}

ret_t do_physdev_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    int irq;
    ret_t ret;
    struct vcpu *v = current;

    switch ( cmd )
    {
    case PHYSDEVOP_eoi: {
        struct physdev_eoi eoi;
        ret = -EFAULT;
        if ( copy_from_guest(&eoi, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( eoi.irq >= v->domain->nr_pirqs )
            break;
        if ( v->domain->arch.pirq_eoi_map )
            evtchn_unmask(v->domain->pirq_to_evtchn[eoi.irq]);
        if ( !is_hvm_domain(v->domain) ||
             domain_pirq_to_emuirq(v->domain, eoi.irq) == IRQ_PT )
            ret = pirq_guest_eoi(v->domain, eoi.irq);
        else
            ret = 0;
        break;
    }

    case PHYSDEVOP_pirq_eoi_gmfn: {
        struct physdev_pirq_eoi_gmfn info;
        unsigned long mfn;

        ret = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        mfn = gmfn_to_mfn(current->domain, info.gmfn);
        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), v->domain,
                                PGT_writable_page) )
            break;

        if ( cmpxchg(&v->domain->arch.pirq_eoi_map_mfn, 0, mfn) != 0 )
        {
            put_page_and_type(mfn_to_page(mfn));
            ret = -EBUSY;
            break;
        }

        v->domain->arch.pirq_eoi_map = map_domain_page_global(mfn);
        if ( v->domain->arch.pirq_eoi_map == NULL )
        {
            v->domain->arch.pirq_eoi_map_mfn = 0;
            put_page_and_type(mfn_to_page(mfn));
            ret = -ENOSPC;
            break;
        }

        ret = 0;
        break;
    }

    /* Legacy since 0x00030202. */
    case PHYSDEVOP_IRQ_UNMASK_NOTIFY: {
        ret = pirq_guest_unmask(v->domain);
        break;
    }

    case PHYSDEVOP_irq_status_query: {
        struct physdev_irq_status_query irq_status_query;
        ret = -EFAULT;
        if ( copy_from_guest(&irq_status_query, arg, 1) != 0 )
            break;
        irq = irq_status_query.irq;
        ret = -EINVAL;
        if ( (irq < 0) || (irq >= v->domain->nr_pirqs) )
            break;
        irq_status_query.flags = 0;
        if ( is_hvm_domain(v->domain) &&
             domain_pirq_to_emuirq(v->domain, irq) != IRQ_PT )
        {
            ret = copy_to_guest(arg, &irq_status_query, 1) ? -EFAULT : 0;
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
        if ( pirq_shared(v->domain, irq) )
            irq_status_query.flags |= XENIRQSTAT_shared;
        ret = copy_to_guest(arg, &irq_status_query, 1) ? -EFAULT : 0;
        break;
    }

    case PHYSDEVOP_map_pirq: {
        struct physdev_map_pirq map;

        ret = -EFAULT;
        if ( copy_from_guest(&map, arg, 1) != 0 )
            break;

        ret = physdev_map_pirq(&map);

        if ( copy_to_guest(arg, &map, 1) != 0 )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_unmap_pirq: {
        struct physdev_unmap_pirq unmap;

        ret = -EFAULT;
        if ( copy_from_guest(&unmap, arg, 1) != 0 )
            break;

        ret = physdev_unmap_pirq(&unmap);
        break;
    }

    case PHYSDEVOP_apic_read: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;
        ret = xsm_apic(v->domain, cmd);
        if ( ret )
            break;
        ret = ioapic_guest_read(apic.apic_physbase, apic.reg, &apic.value);
        if ( copy_to_guest(arg, &apic, 1) != 0 )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_apic_write: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;
        ret = xsm_apic(v->domain, cmd);
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

        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;

        ret = xsm_assign_vector(v->domain, irq_op.irq);
        if ( ret )
            break;

        /* Vector is only used by hypervisor, and dom0 shouldn't
           touch it in its world, return irq_op.irq as the vecotr,
           and make this hypercall dummy, and also defer the vector 
           allocation when dom0 tries to programe ioapic entry. */
        irq_op.vector = irq_op.irq;
        ret = 0;
        
        if ( copy_to_guest(arg, &irq_op, 1) != 0 )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_set_iopl: {
        struct physdev_set_iopl set_iopl;
        ret = -EFAULT;
        if ( copy_from_guest(&set_iopl, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( set_iopl.iopl > 3 )
            break;
        ret = 0;
        v->arch.pv_vcpu.iopl = set_iopl.iopl;
        break;
    }

    case PHYSDEVOP_set_iobitmap: {
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
        v->arch.pv_vcpu.iobmp = set_iobitmap.bitmap;
#else
        guest_from_compat_handle(v->arch.pv_vcpu.iobmp, set_iobitmap.bitmap);
#endif
        v->arch.pv_vcpu.iobmp_limit = set_iobitmap.nr_ports;
        break;
    }

    case PHYSDEVOP_manage_pci_add: {
        struct physdev_manage_pci manage_pci;
        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_add_device(manage_pci.bus, manage_pci.devfn);
        break;
    }

    case PHYSDEVOP_manage_pci_remove: {
        struct physdev_manage_pci manage_pci;
        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_remove_device(manage_pci.bus, manage_pci.devfn);
        break;
    }

    case PHYSDEVOP_manage_pci_add_ext: {
        struct physdev_manage_pci_ext manage_pci_ext;
        struct pci_dev_info pdev_info;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;

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
        ret = pci_add_device_ext(manage_pci_ext.bus,
                                 manage_pci_ext.devfn,
                                 &pdev_info);
        break;
    }

    case PHYSDEVOP_restore_msi: {
        struct physdev_restore_msi restore_msi;
        struct pci_dev *pdev;

        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&restore_msi, arg, 1) != 0 )
            break;

        spin_lock(&pcidevs_lock);
        pdev = pci_get_pdev(restore_msi.bus, restore_msi.devfn);
        ret = pdev ? pci_restore_msi_state(pdev) : -ENODEV;
        spin_unlock(&pcidevs_lock);
        break;
    }
    case PHYSDEVOP_setup_gsi: {
        struct physdev_setup_gsi setup_gsi;

        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&setup_gsi, arg, 1) != 0 )
            break;
        
        ret = -EINVAL;
        if ( setup_gsi.gsi < 0 || setup_gsi.gsi >= nr_irqs_gsi )
            break;
        ret = mp_register_gsi(setup_gsi.gsi, setup_gsi.triggering,
                              setup_gsi.polarity);
        break; 
    }
    case PHYSDEVOP_get_free_pirq: {
        struct physdev_get_free_pirq out;
        struct domain *d;

        d = rcu_lock_current_domain();
        
        ret = -EFAULT;
        if ( copy_from_guest(&out, arg, 1) != 0 )
            break;

        spin_lock(&d->event_lock);
        out.pirq = get_free_pirq(d, out.type, 0);
        d->arch.pirq_irq[out.pirq] = PIRQ_ALLOCATED;
        spin_unlock(&d->event_lock);

        ret = copy_to_guest(arg, &out, 1) ? -EFAULT : 0;

        rcu_unlock_domain(d);
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
