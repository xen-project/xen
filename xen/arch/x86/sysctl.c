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
#include <asm/psr.h>

#define get_xen_guest_handle(val, hnd)  do { val = (hnd).p; } while (0)

struct l3_cache_info {
    int ret;
    unsigned long size;
};

static void l3_cache_get(void *arg)
{
    struct cpuid4_info info;
    struct l3_cache_info *l3_info = arg;

    l3_info->ret = cpuid4_cache_lookup(3, &info);
    if ( !l3_info->ret )
        l3_info->size = info.size / 1024; /* in KB unit */
}

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

    case XEN_SYSCTL_psr_cmt_op:
        if ( !psr_cmt_enabled() )
            return -ENODEV;

        if ( sysctl->u.psr_cmt_op.flags != 0 )
            return -EINVAL;

        switch ( sysctl->u.psr_cmt_op.cmd )
        {
        case XEN_SYSCTL_PSR_CMT_enabled:
            sysctl->u.psr_cmt_op.u.data =
                (psr_cmt->features & PSR_RESOURCE_TYPE_L3) &&
                (psr_cmt->l3.features & PSR_CMT_L3_OCCUPANCY);
            break;
        case XEN_SYSCTL_PSR_CMT_get_total_rmid:
            sysctl->u.psr_cmt_op.u.data = psr_cmt->rmid_max;
            break;
        case XEN_SYSCTL_PSR_CMT_get_l3_upscaling_factor:
            sysctl->u.psr_cmt_op.u.data = psr_cmt->l3.upscaling_factor;
            break;
        case XEN_SYSCTL_PSR_CMT_get_l3_cache_size:
        {
            struct l3_cache_info info;
            unsigned int cpu = sysctl->u.psr_cmt_op.u.l3_cache.cpu;

            if ( (cpu >= nr_cpu_ids) || !cpu_online(cpu) )
            {
                ret = -ENODEV;
                sysctl->u.psr_cmt_op.u.data = 0;
                break;
            }
            if ( cpu == smp_processor_id() )
                l3_cache_get(&info);
            else
                on_selected_cpus(cpumask_of(cpu), l3_cache_get, &info, 1);

            ret = info.ret;
            sysctl->u.psr_cmt_op.u.data = (ret ? 0 : info.size);
            break;
        }
        case XEN_SYSCTL_PSR_CMT_get_l3_event_mask:
            sysctl->u.psr_cmt_op.u.data = psr_cmt->l3.features;
            break;
        default:
            sysctl->u.psr_cmt_op.u.data = 0;
            ret = -ENOSYS;
            break;
        }

        if ( __copy_to_guest(u_sysctl, sysctl, 1) )
            ret = -EFAULT;

        break;

    case XEN_SYSCTL_psr_cat_op:
        switch ( sysctl->u.psr_cat_op.cmd )
        {
        case XEN_SYSCTL_PSR_CAT_get_l3_info:
            ret = psr_get_cat_l3_info(sysctl->u.psr_cat_op.target,
                                      &sysctl->u.psr_cat_op.u.l3_info.cbm_len,
                                      &sysctl->u.psr_cat_op.u.l3_info.cos_max);

            if ( !ret && __copy_field_to_guest(u_sysctl, sysctl, u.psr_cat_op) )
                ret = -EFAULT;

            break;
        default:
            ret = -EOPNOTSUPP;
            break;
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
