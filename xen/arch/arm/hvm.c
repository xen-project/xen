#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/sched.h>

#include <xsm/xsm.h>

#include <public/xen.h>
#include <public/hvm/params.h>
#include <public/hvm/hvm_op.h>

#include <asm/hypercall.h>

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) arg)

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

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail;

        if ( op == HVMOP_set_param )
        {
            d->arch.hvm_domain.params[a.index] = a.value;
        }
        else
        {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

    param_fail:
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
