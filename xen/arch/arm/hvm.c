#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/sched.h>

#include <public/xen.h>
#include <public/hvm/params.h>
#include <public/hvm/hvm_op.h>

#include <asm/hypercall.h>

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE(void) arg)

{
    long rc = 0;

    switch ( op )
    {
    case HVMOP_set_param:
    case HVMOP_get_param:
    {
        struct xen_hvm_param a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        if ( a.index >= HVM_NR_PARAMS )
            return -EINVAL;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        if ( op == HVMOP_set_param )
        {
            d->arch.hvm_domain.params[a.index] = a.value;
        }
        else
        {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

        rcu_unlock_domain(d);
        break;
    }

    default:
    {
        printk("%s: Bad HVM op %ld.\n", __func__, op);
        rc = -ENOSYS;
        break;
    }
    }

    return rc;
}
