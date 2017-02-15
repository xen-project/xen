/******************************************************************************
 * arch/x86/x86_64/domain.c
 *
 */

#include <xen/types.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <compat/vcpu.h>

#define xen_vcpu_get_physid vcpu_get_physid
CHECK_vcpu_get_physid;
#undef xen_vcpu_get_physid

int
arch_compat_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc = -ENOSYS;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    {
        struct compat_vcpu_register_runstate_memory_area area;
        struct compat_vcpu_runstate_info info;

        area.addr.p = 0;

        rc = -EFAULT;
        if ( copy_from_guest(&area.addr.h, arg, 1) )
            break;

        if ( area.addr.h.c != area.addr.p ||
             !compat_handle_okay(area.addr.h, 1) )
            break;

        rc = 0;
        guest_from_compat_handle(v->runstate_guest.compat, area.addr.h);

        if ( v == current )
        {
            XLAT_vcpu_runstate_info(&info, &v->runstate);
        }
        else
        {
            struct vcpu_runstate_info runstate;

            vcpu_runstate_get(v, &runstate);
            XLAT_vcpu_runstate_info(&info, &runstate);
        }
        __copy_to_guest(v->runstate_guest.compat, &info, 1);

        break;
    }

    case VCPUOP_get_physid:
        rc = arch_do_vcpu_op(cmd, v, arg);
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
