/******************************************************************************
 * Arch-specific sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <public/sysctl.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/processor.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xen/cpu.h>
#include <xsm/xsm.h>

#define get_xen_guest_handle(val, hnd)  do { val = (hnd).p; } while (0)

long cpu_up_helper(void *data)
{
    int cpu = (unsigned long)data;
    int ret = cpu_up(cpu);
    if ( ret == -EBUSY )
    {
        /* On EBUSY, flush RCU work and have one more go. */
        rcu_barrier();
        ret = cpu_up(cpu);
    }
    return ret;
}

long cpu_down_helper(void *data)
{
    int cpu = (unsigned long)data;
    int ret = cpu_down(cpu);
    if ( ret == -EBUSY )
    {
        /* On EBUSY, flush RCU work and have one more go. */
        rcu_barrier();
        ret = cpu_down(cpu);
    }
    return ret;
}

void arch_do_physinfo(xen_sysctl_physinfo_t *pi)
{
    memcpy(pi->hw_cap, boot_cpu_data.x86_capability,
           min(sizeof(pi->hw_cap), sizeof(boot_cpu_data.x86_capability)));
    if ( hvm_enabled )
        pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm;
    if ( iommu_enabled )
        pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm_directio;
}

long arch_do_sysctl(
    struct xen_sysctl *sysctl, XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl)
{
    long ret = 0;

    switch ( sysctl->cmd )
    {

    case XEN_SYSCTL_cpu_hotplug:
    {
        unsigned int cpu = sysctl->u.cpu_hotplug.cpu;

        switch ( sysctl->u.cpu_hotplug.op )
        {
        case XEN_SYSCTL_CPU_HOTPLUG_ONLINE:
            ret = xsm_resource_plug_core(XSM_HOOK);
            if ( ret )
                break;
            ret = continue_hypercall_on_cpu(
                0, cpu_up_helper, (void *)(unsigned long)cpu);
            break;
        case XEN_SYSCTL_CPU_HOTPLUG_OFFLINE:
            ret = xsm_resource_unplug_core(XSM_HOOK);
            if ( ret )
                break;
            ret = continue_hypercall_on_cpu(
                0, cpu_down_helper, (void *)(unsigned long)cpu);
            break;
        default:
            ret = -EINVAL;
            break;
        }
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
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
