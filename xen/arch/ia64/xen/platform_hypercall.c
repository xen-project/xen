/******************************************************************************
 * platform_hypercall.c
 * 
 * Hardware platform operations. Intended for use by domain-0 kernel.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/guest_access.h>
#include <xen/acpi.h>
#include <public/platform.h>
#include <acpi/cpufreq/processor_perf.h>

DEFINE_SPINLOCK(xenpf_lock);

extern int set_px_pminfo(uint32_t cpu, struct xen_processor_performance *perf);
extern long set_cx_pminfo(uint32_t cpu, struct xen_processor_power *power);

long do_platform_op(XEN_GUEST_HANDLE(xen_platform_op_t) u_xenpf_op)
{
    long ret = 0;
    struct xen_platform_op curop, *op = &curop;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_guest(op, u_xenpf_op, 1) )
        return -EFAULT;

    if ( op->interface_version != XENPF_INTERFACE_VERSION )
        return -EACCES;

    switch ( op->cmd )
    {
    case XENPF_set_processor_pminfo:
        spin_lock(&xenpf_lock);
        switch ( op->u.set_pminfo.type )
        {
        case XEN_PM_PX:
            if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_PX) )
            {
                ret = -ENOSYS;
                break;
            }
            ret = set_px_pminfo(op->u.set_pminfo.id,
                                &op->u.set_pminfo.u.perf);
            break;

        case XEN_PM_CX:
            /* Place holder for Cx */
            ret = -ENOSYS;
            break;

        default:
            ret = -EINVAL;
            break;
        }
        spin_unlock(&xenpf_lock);
        break;

    default:
        printk("Unknown platform hypercall op 0x%x\n", op->cmd);
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

