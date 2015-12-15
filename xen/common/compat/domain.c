/******************************************************************************
 * domain.c
 *
 */

asm(".file \"" __FILE__ "\"");

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <compat/vcpu.h>
#include <compat/hvm/hvm_vcpu.h>

#define xen_vcpu_set_periodic_timer vcpu_set_periodic_timer
CHECK_vcpu_set_periodic_timer;
#undef xen_vcpu_set_periodic_timer

#define xen_vcpu_info vcpu_info
CHECK_SIZE_(struct, vcpu_info);
#undef xen_vcpu_info

#define xen_vcpu_register_vcpu_info vcpu_register_vcpu_info
CHECK_vcpu_register_vcpu_info;
#undef xen_vcpu_register_vcpu_info

#define xen_vcpu_hvm_context vcpu_hvm_context
#define xen_vcpu_hvm_x86_32 vcpu_hvm_x86_32
#define xen_vcpu_hvm_x86_64 vcpu_hvm_x86_64
CHECK_vcpu_hvm_context;
#undef xen_vcpu_hvm_x86_64
#undef xen_vcpu_hvm_x86_32
#undef xen_vcpu_hvm_context

int compat_vcpu_op(int cmd, unsigned int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d = current->domain;
    struct vcpu *v;
    int rc = 0;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
        return -ENOENT;

    switch ( cmd )
    {
    case VCPUOP_initialise:
    {
        if ( v->vcpu_info == &dummy_vcpu_info )
            return -EINVAL;

        if ( is_hvm_vcpu(v) )
        {
            struct vcpu_hvm_context ctxt;

            if ( copy_from_guest(&ctxt, arg, 1) )
                return -EFAULT;

            domain_lock(d);
            rc = v->is_initialised ? -EEXIST : arch_set_info_hvm_guest(v, &ctxt);
            domain_unlock(d);
        }
        else
        {
            struct compat_vcpu_guest_context *ctxt;

            if ( (ctxt = xmalloc(struct compat_vcpu_guest_context)) == NULL )
                return -ENOMEM;

            if ( copy_from_guest(ctxt, arg, 1) )
            {
                xfree(ctxt);
                return -EFAULT;
            }

            domain_lock(d);
            rc = v->is_initialised ? -EEXIST : arch_set_info_guest(v, ctxt);
            domain_unlock(d);

            xfree(ctxt);
        }

        if ( rc == -ERESTART )
            rc = hypercall_create_continuation(__HYPERVISOR_vcpu_op, "iuh",
                                               cmd, vcpuid, arg);

        break;
    }

    case VCPUOP_up:
    case VCPUOP_down:
    case VCPUOP_is_up:
    case VCPUOP_set_periodic_timer:
    case VCPUOP_stop_periodic_timer:
    case VCPUOP_stop_singleshot_timer:
    case VCPUOP_register_vcpu_info:
    case VCPUOP_send_nmi:
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

    case VCPUOP_set_singleshot_timer:
    {
        struct compat_vcpu_set_singleshot_timer cmp;
        struct vcpu_set_singleshot_timer *nat;

        if ( copy_from_guest(&cmp, arg, 1) )
            return -EFAULT;
        nat = COMPAT_ARG_XLAT_VIRT_BASE;
        XLAT_vcpu_set_singleshot_timer(nat, &cmp);
        rc = do_vcpu_op(cmd, vcpuid, guest_handle_from_ptr(nat, void));
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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
