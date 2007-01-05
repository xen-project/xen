/******************************************************************************
 * arch/x86/x86_64/domain.c
 *
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/guest_access.h>
#include <asm/hypercall.h>
#include <compat/vcpu.h>

int
arch_compat_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE(void) arg)
{
    long rc = 0;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    {
        struct compat_vcpu_register_runstate_memory_area area;
        struct compat_vcpu_runstate_info info;

        rc = -EFAULT;
        if ( copy_from_guest(&area, arg, 1) )
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
            XLAT_vcpu_runstate_info(&info, &v->runstate);
        }
        __copy_to_guest(v->runstate_guest.compat, &info, 1);

        break;
    }

    default:
        rc = -ENOSYS;
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
