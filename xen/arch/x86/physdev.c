
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

#ifndef COMPAT
typedef long ret_t;
#endif

int
ioapic_guest_read(
    unsigned long physbase, unsigned int reg, u32 *pval);
int
ioapic_guest_write(
    unsigned long physbase, unsigned int reg, u32 pval);


extern struct hw_interrupt_type pci_msi_type;

static int get_free_pirq(struct domain *d, int type, int index)
{
    int i;

    if ( d == NULL )
        return -EINVAL;

    ASSERT(spin_is_locked(&d->arch.irq_lock));

    if ( type == MAP_PIRQ_TYPE_GSI )
    {
        for ( i = 16; i < NR_PIRQS; i++ )
            if ( !d->arch.pirq_vector[i] )
                break;
        if ( i == NR_PIRQS )
            return -ENOSPC;
    }
    else
    {
        for ( i = NR_PIRQS - 1; i >= 16; i-- )
            if ( !d->arch.pirq_vector[i] )
                break;
        if ( i == 16 )
            return -ENOSPC;
    }

    return i;
}

/*
 * Caller hold the irq_lock
 */
static int map_domain_pirq(struct domain *d, int pirq, int vector,
                           struct physdev_map_pirq *map)
{
    int ret = 0;
    int old_vector, old_pirq;

    if ( d == NULL )
        return -EINVAL;

    ASSERT(spin_is_locked(&d->arch.irq_lock));

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( pirq < 0 || pirq >= NR_PIRQS || vector < 0 || vector >= NR_VECTORS )
    {
        gdprintk(XENLOG_G_ERR,
                 "invalid pirq %x or vector %x\n", pirq, vector);
        return -EINVAL;
    }

    old_vector = d->arch.pirq_vector[pirq];
    old_pirq = d->arch.vector_pirq[vector];

    if ( (old_vector && (old_vector != vector) ) ||
         (old_pirq && (old_pirq != pirq)) )
    {
        gdprintk(XENLOG_G_ERR, "remap pirq %x vector %x while not unmap\n",
                 pirq, vector);
        ret = -EINVAL;
        goto done;
    }

    ret = irq_permit_access(d, pirq);
    if ( ret )
    {
        gdprintk(XENLOG_G_ERR, "add irq permit access %x failed\n", pirq);
        ret = -EINVAL;
        goto done;
    }

    if ( map && MAP_PIRQ_TYPE_MSI == map->type )
    {
        irq_desc_t         *desc;
        unsigned long flags;

        desc = &irq_desc[vector];

        spin_lock_irqsave(&desc->lock, flags);
        if ( desc->handler != &no_irq_type )
            gdprintk(XENLOG_G_ERR, "Map vector %x to msi while it is in use\n",
                     vector);
        desc->handler = &pci_msi_type;
        spin_unlock_irqrestore(&desc->lock, flags);

        ret = pci_enable_msi(map->msi_info.bus,
		                     map->msi_info.devfn, vector,
							 map->msi_info.entry_nr,
							 map->msi_info.msi);
        if ( ret )
            goto done;
    }

    d->arch.pirq_vector[pirq] = vector;
    d->arch.vector_pirq[vector] = pirq;

done:
    return ret;
}

/*
 * The pirq should has been unbound before this call
 */
static int unmap_domain_pirq(struct domain *d, int pirq)
{
    int ret = 0;
    int vector;

    if ( d == NULL || pirq < 0 || pirq > NR_PIRQS )
        return -EINVAL;

    if ( !IS_PRIV(current->domain) )
        return -EINVAL;

    ASSERT(spin_is_locked(&d->arch.irq_lock));

    vector = d->arch.pirq_vector[pirq];

    if ( !vector )
    {
        gdprintk(XENLOG_G_ERR, "domain %X: pirq %x not mapped still\n",
                 d->domain_id, pirq);
        ret = -EINVAL;
    }
    else
    {
        unsigned long flags;
        irq_desc_t *desc;

        desc = &irq_desc[vector];
        if ( desc->msi_desc )
            pci_disable_msi(vector);

        spin_lock_irqsave(&desc->lock, flags);
        if ( desc->handler == &pci_msi_type )
        {
            /* MSI is not shared, so should be released already */
            BUG_ON(desc->status & IRQ_GUEST);
            irq_desc[vector].handler = &no_irq_type;
        }
        spin_unlock_irqrestore(&desc->lock, flags);

        d->arch.pirq_vector[pirq] = d->arch.vector_pirq[vector] = 0;
    }

    ret = irq_deny_access(d, pirq);

    if ( ret )
        gdprintk(XENLOG_G_ERR, "deny irq %x access failed\n", pirq);

    return ret;
}

extern int msi_irq_enable;
static int physdev_map_pirq(struct physdev_map_pirq *map)
{
    struct domain *d;
    int vector, pirq, ret = 0;
    unsigned long flags;

    /* if msi_irq_enable is not enabled,map always success */
    if ( !msi_irq_enable )
        return 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( !map )
        return -EINVAL;

    if ( map->domid == DOMID_SELF )
        d = rcu_lock_domain(current->domain);
    else
        d = rcu_lock_domain_by_id(map->domid);

    if ( d == NULL )
    {
        ret = -ESRCH;
        goto free_domain;
    }

    switch ( map->type )
    {
        case MAP_PIRQ_TYPE_GSI:
            if ( map->index >= NR_IRQS )
            {
                ret = -EINVAL;
                gdprintk(XENLOG_G_ERR,
                         "map invalid irq %x\n", map->index);
                goto free_domain;
            }
            vector = IO_APIC_VECTOR(map->index);
            if ( !vector )
            {
                ret = -EINVAL;
                gdprintk(XENLOG_G_ERR,
                         "map irq with no vector %x\n", map->index);
                goto free_domain;
            }
            break;
        case MAP_PIRQ_TYPE_MSI:
            vector = map->index;
			if ( vector == -1 )
				vector = assign_irq_vector(AUTO_ASSIGN);

            if ( vector < 0 || vector >= NR_VECTORS )
            {
                ret = -EINVAL;
                gdprintk(XENLOG_G_ERR,
                         "map_pirq with wrong vector %x\n", map->index);
                goto free_domain;
            }
            break;
        default:
            ret = -EINVAL;
            gdprintk(XENLOG_G_ERR, "wrong map_pirq type %x\n", map->type);
            goto free_domain;
            break;
    }

    spin_lock_irqsave(&d->arch.irq_lock, flags);
    if ( map->pirq == -1 )
    {
        if ( d->arch.vector_pirq[vector] )
        {
            gdprintk(XENLOG_G_ERR, "%x %x mapped already%x\n",
                                    map->index, map->pirq,
                                    d->arch.vector_pirq[vector]);
            pirq = d->arch.vector_pirq[vector];
        }
        else
        {
            pirq = get_free_pirq(d, map->type, map->index);
            if ( pirq < 0 )
            {
                ret = pirq;
                gdprintk(XENLOG_G_ERR, "No free pirq\n");
                goto done;
            }
        }
    }
    else
    {
        if ( d->arch.vector_pirq[vector] &&
             d->arch.vector_pirq[vector] != map->pirq )
        {
            gdprintk(XENLOG_G_ERR, "%x conflict with %x\n",
              map->index, map->pirq);
            ret = -EEXIST;
            goto done;
        }
        else
            pirq = map->pirq;
    }


    ret = map_domain_pirq(d, pirq, vector, map);

    if ( !ret )
        map->pirq = pirq;
done:
    spin_unlock_irqrestore(&d->arch.irq_lock, flags);
free_domain:
    rcu_unlock_domain(d);
    return ret;
}

static int physdev_unmap_pirq(struct physdev_unmap_pirq *unmap)
{
    struct domain *d;
    unsigned long flags;
    int ret;

    if ( !msi_irq_enable )
        return 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( !unmap )
        return -EINVAL;

    if ( unmap->domid == DOMID_SELF )
        d = rcu_lock_domain(current->domain);
    else
        d = rcu_lock_domain_by_id(unmap->domid);

    if ( d == NULL )
    {
        rcu_unlock_domain(d);
        return -ESRCH;
    }

    spin_lock_irqsave(&d->arch.irq_lock, flags);
    ret = unmap_domain_pirq(d, unmap->pirq);
    spin_unlock_irqrestore(&d->arch.irq_lock, flags);
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
        ret = pirq_guest_eoi(v->domain, eoi.irq);
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
        if ( (irq < 0) || (irq >= NR_IRQS) )
            break;
        irq_status_query.flags = 0;
        if ( pirq_acktype(v->domain, irq) != 0 )
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
        unsigned long flags;

        ret = -EFAULT;
        if ( copy_from_guest(&irq_op, arg, 1) != 0 )
            break;

        ret = -EPERM;
        if ( !IS_PRIV(v->domain) )
            break;

        ret = xsm_assign_vector(v->domain, irq_op.irq);
        if ( ret )
            break;

        irq = irq_op.irq;
        ret = -EINVAL;
        if ( ((irq < 0) && (irq != AUTO_ASSIGN)) || (irq >= NR_IRQS) )
            break;

        irq_op.vector = assign_irq_vector(irq);

        ret = 0;

        if ( msi_irq_enable )
        {
            spin_lock_irqsave(&dom0->arch.irq_lock, flags);
            if ( irq != AUTO_ASSIGN )
                ret = map_domain_pirq(dom0, irq_op.irq, irq_op.vector, NULL);
            spin_unlock_irqrestore(&dom0->arch.irq_lock, flags);
        }

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
        v->arch.iopl = set_iopl.iopl;
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
        v->arch.iobmp       = set_iobitmap.bitmap;
#else
        guest_from_compat_handle(v->arch.iobmp, set_iobitmap.bitmap);
#endif
        v->arch.iobmp_limit = set_iobitmap.nr_ports;
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
