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

static void cf_check
runstate_area_populate(void *map, struct vcpu *v)
{
    if ( is_pv_vcpu(v) )
        v->arch.pv.need_update_runstate_area = false;

    v->runstate_guest_area_compat = true;

    if ( v == current )
    {
        struct compat_vcpu_runstate_info *info = map;

        XLAT_vcpu_runstate_info(info, &v->runstate);
    }
}

int
compat_vcpu_op(int cmd, unsigned int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc;
    struct domain *d = current->domain;
    struct vcpu *v;

    if ( (v = domain_vcpu(d, vcpuid)) == NULL )
        return -ENOENT;

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

    case VCPUOP_register_runstate_phys_area:
    {
        struct compat_vcpu_register_runstate_memory_area area;

        rc = -EFAULT;
        if ( copy_from_guest(&area.addr.p, arg, 1) )
            break;

        rc = map_guest_area(v, area.addr.p,
                            sizeof(struct compat_vcpu_runstate_info),
                            &v->runstate_guest_area,
                            runstate_area_populate);
        if ( rc == -ERESTART )
            rc = hypercall_create_continuation(__HYPERVISOR_vcpu_op, "iih",
                                               cmd, vcpuid, arg);

        break;
    }

    case VCPUOP_register_vcpu_time_memory_area:
    {
        struct compat_vcpu_register_time_memory_area area = { .addr.p = 0 };

        rc = -EFAULT;
        if ( copy_from_guest(&area.addr.h, arg, 1) )
            break;

        if ( area.addr.h.c != area.addr.p ||
             !compat_handle_okay(area.addr.h, 1) )
            break;

        rc = 0;
        guest_from_compat_handle(v->arch.time_info_guest, area.addr.h);

        force_update_vcpu_system_time(v);

        break;
    }

    case VCPUOP_send_nmi:
    case VCPUOP_get_physid:
    case VCPUOP_register_vcpu_time_phys_area:
        rc = do_vcpu_op(cmd, vcpuid, arg);
        break;

    default:
        rc = compat_common_vcpu_op(cmd, v, arg);
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
