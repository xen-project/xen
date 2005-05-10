
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/smpboot.h>
#include <public/xen.h>
#include <public/physdev.h>

extern int ioapic_guest_read(int apicid, int address, u32 *pval);
extern int ioapic_guest_write(int apicid, int address, u32 pval);

void physdev_modify_ioport_access_range(
    struct domain *d, int enable, int port, int num)
{
    int i;
    for ( i = port; i < (port + num); i++ )
        (enable ? clear_bit : set_bit)(i, d->arch.iobmp_mask);
}

void physdev_destroy_state(struct domain *d)
{
    xfree(d->arch.iobmp_mask);
    d->arch.iobmp_mask = NULL;
}

/* Check if a domain controls a device with IO memory within frame @pfn.
 * Returns: 1 if the domain should be allowed to map @pfn, 0 otherwise.  */
int domain_iomem_in_pfn(struct domain *p, unsigned long pfn)
{
    return 0;
}

/*
 * Demuxing hypercall.
 */
long do_physdev_op(physdev_op_t *uop)
{
    physdev_op_t op;
    long         ret;
    int          irq, vector;

    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
        return -EFAULT;

    switch ( op.cmd )
    {
    case PHYSDEVOP_IRQ_UNMASK_NOTIFY:
        ret = pirq_guest_unmask(current->domain);
        break;

    case PHYSDEVOP_IRQ_STATUS_QUERY:
        irq = op.u.irq_status_query.irq;
        ret = -EINVAL;
        if ( (irq < 0) || (irq >= NR_IRQS) )
            break;
        op.u.irq_status_query.flags = 0;
        /* Edge-triggered interrupts don't need an explicit unmask downcall. */
        if ( strstr(irq_desc[irq].handler->typename, "edge") == NULL )
            op.u.irq_status_query.flags |= PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY;
        ret = 0;
        break;

    case PHYSDEVOP_APIC_READ:
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = ioapic_guest_read(
            op.u.apic_op.apic, op.u.apic_op.offset, &op.u.apic_op.value);
        break;

    case PHYSDEVOP_APIC_WRITE:
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = ioapic_guest_write(
            op.u.apic_op.apic, op.u.apic_op.offset, op.u.apic_op.value);
        break;

    case PHYSDEVOP_ASSIGN_VECTOR:
        if ( !IS_PRIV(current->domain) )
            return -EPERM;

        if ( (irq = op.u.irq_op.irq) >= NR_IRQS )
            return -EINVAL;
        
        op.u.irq_op.vector = vector = assign_irq_vector(irq);

        if ( use_pci_vector() && !platform_legacy_irq(irq) )
            set_intr_gate(vector, interrupt[vector]);
        else
            set_intr_gate(vector, interrupt[irq]);

        ret = 0;
        break;

    case PHYSDEVOP_SET_IOPL:
        ret = -EINVAL;
        if ( op.u.set_iopl.iopl > 3 )
            break;
        ret = 0;
        current->arch.iopl = op.u.set_iopl.iopl;
        break;

    case PHYSDEVOP_SET_IOBITMAP:
        ret = -EINVAL;
        if ( !access_ok(op.u.set_iobitmap.bitmap, IOBMP_BYTES) ||
             (op.u.set_iobitmap.nr_ports > 65536) )
            break;
        ret = 0;
        current->arch.iobmp       = (u8 *)op.u.set_iobitmap.bitmap;
        current->arch.iobmp_limit = op.u.set_iobitmap.nr_ports;
        break;
    default:
        ret = -EINVAL;
        break;
    }

    if ( copy_to_user(uop, &op, sizeof(op)) )
        ret = -EFAULT;

    return ret;
}

/* Domain 0 has read access to all devices. */
void physdev_init_dom0(struct domain *d)
{
    /* Access to all I/O ports. */
    d->arch.iobmp_mask = xmalloc_array(u8, IOBMP_BYTES);
    BUG_ON(d->arch.iobmp_mask == NULL);
    memset(d->arch.iobmp_mask, 0, IOBMP_BYTES);

    set_bit(DF_PHYSDEV, &d->flags);
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
