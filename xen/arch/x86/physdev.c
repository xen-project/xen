
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/current.h>
#include <asm/smpboot.h>
#include <public/xen.h>
#include <public/physdev.h>

extern int
ioapic_guest_read(
    unsigned long physbase, unsigned int reg, u32 *pval);
extern int
ioapic_guest_write(
    unsigned long physbase, unsigned int reg, u32 pval);

/*
 * Demuxing hypercall.
 */
long do_physdev_op(struct physdev_op *uop)
{
    struct physdev_op op;
    long ret;
    int  irq;

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
        if ( !strstr(irq_desc[irq_to_vector(irq)].handler->typename, "edge") )
            op.u.irq_status_query.flags |= PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY;
        ret = 0;
        break;

    case PHYSDEVOP_APIC_READ:
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = ioapic_guest_read(
            op.u.apic_op.apic_physbase,
            op.u.apic_op.reg,
            &op.u.apic_op.value);
        break;

    case PHYSDEVOP_APIC_WRITE:
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = ioapic_guest_write(
            op.u.apic_op.apic_physbase,
            op.u.apic_op.reg,
            op.u.apic_op.value);
        break;

    case PHYSDEVOP_ASSIGN_VECTOR:
        if ( !IS_PRIV(current->domain) )
            return -EPERM;

        if ( (irq = op.u.irq_op.irq) >= NR_IRQS )
            return -EINVAL;
        
        op.u.irq_op.vector = assign_irq_vector(irq);
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
        current->arch.iobmp       = op.u.set_iobitmap.bitmap;
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
