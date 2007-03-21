/******************************************************************************
 * domain.c
 *
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <compat/vcpu.h>

int compat_vcpu_op(int cmd, int vcpuid, XEN_GUEST_HANDLE(void) arg)
{
    struct domain *d = current->domain;
    struct vcpu *v;
    long rc = 0;

    if ( (vcpuid < 0) || (vcpuid >= MAX_VIRT_CPUS) )
        return -EINVAL;

    if ( (v = d->vcpu[vcpuid]) == NULL )
        return -ENOENT;

    switch ( cmd )
    {
    case VCPUOP_initialise:
    {
        struct compat_vcpu_guest_context *cmp_ctxt;

        if ( (cmp_ctxt = xmalloc(struct compat_vcpu_guest_context)) == NULL )
        {
            rc = -ENOMEM;
            break;
        }

        if ( copy_from_guest(cmp_ctxt, arg, 1) )
        {
            xfree(cmp_ctxt);
            rc = -EFAULT;
            break;
        }

        LOCK_BIGLOCK(d);
        rc = -EEXIST;
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            rc = boot_vcpu(d, vcpuid, cmp_ctxt);
        UNLOCK_BIGLOCK(d);

        xfree(cmp_ctxt);
        break;
    }

    case VCPUOP_up:
    case VCPUOP_down:
    case VCPUOP_is_up:
    case VCPUOP_set_periodic_timer:
    case VCPUOP_stop_periodic_timer:
    case VCPUOP_set_singleshot_timer:
    case VCPUOP_stop_singleshot_timer:
        rc = do_vcpu_op(cmd, vcpuid, arg);
        break;

    case VCPUOP_get_runstate_info:
    {
        union {
            struct vcpu_runstate_info nat;
            struct compat_vcpu_runstate_info cmp;
        } runstate;

        vcpu_runstate_get(v, &runstate.nat);
        xlat_vcpu_runstate_info(&runstate.nat);
        if ( copy_to_guest(arg, &runstate.cmp, 1) )
            rc = -EFAULT;
        break;
    }

    default:
        rc = arch_compat_vcpu_op(cmd, v, arg);
        break;
    }

    return rc;
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
