/******************************************************************************
 * sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/current.h>
#include <public/sysctl.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xsm/xsm.h>

extern long arch_do_sysctl(
    struct xen_sysctl *op, XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl);

long do_sysctl(XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    long ret = 0;
    struct xen_sysctl curop, *op = &curop;
    static DEFINE_SPINLOCK(sysctl_lock);

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_guest(op, u_sysctl, 1) )
        return -EFAULT;

    if ( op->interface_version != XEN_SYSCTL_INTERFACE_VERSION )
        return -EACCES;

    spin_lock(&sysctl_lock);

    switch ( op->cmd )
    {
    case XEN_SYSCTL_readconsole:
    {
        ret = xsm_readconsole(op->u.readconsole.clear);
        if ( ret )
            break;

        ret = read_console_ring(&op->u.readconsole);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_SYSCTL_tbuf_op:
    {
        ret = xsm_tbufcontrol();
        if ( ret )
            break;

        ret = tb_control(&op->u.tbuf_op);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;
    
    case XEN_SYSCTL_sched_id:
    {
        ret = xsm_sched_id();
        if ( ret )
            break;

        op->u.sched_id.sched_id = sched_id();
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
        else
            ret = 0;
    }
    break;

    case XEN_SYSCTL_getdomaininfolist:
    { 
        struct domain *d;
        struct xen_domctl_getdomaininfo info;
        u32 num_domains = 0;

        rcu_read_lock(&domlist_read_lock);

        for_each_domain ( d )
        {
            if ( d->domain_id < op->u.getdomaininfolist.first_domain )
                continue;
            if ( num_domains == op->u.getdomaininfolist.max_domains )
                break;

            ret = xsm_getdomaininfo(d);
            if ( ret )
                continue;

            getdomaininfo(d, &info);

            if ( copy_to_guest_offset(op->u.getdomaininfolist.buffer,
                                      num_domains, &info, 1) )
            {
                ret = -EFAULT;
                break;
            }
            
            num_domains++;
        }
        
        rcu_read_unlock(&domlist_read_lock);
        
        if ( ret != 0 )
            break;
        
        op->u.getdomaininfolist.num_domains = num_domains;

        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;

#ifdef PERF_COUNTERS
    case XEN_SYSCTL_perfc_op:
    {
        ret = xsm_perfcontrol();
        if ( ret )
            break;

        ret = perfc_control(&op->u.perfc_op);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;
#endif

    case XEN_SYSCTL_debug_keys:
    {
        char c;
        uint32_t i;

        for ( i = 0; i < op->u.debug_keys.nr_keys; i++ )
        {
            if ( copy_from_guest_offset(&c, op->u.debug_keys.keys, i, 1) )
                return -EFAULT;
            handle_keypress(c, guest_cpu_user_regs());
        }
    }
    break;

    case XEN_SYSCTL_getcpuinfo:
    {
        uint32_t i, nr_cpus;
        struct xen_sysctl_cpuinfo cpuinfo;
        struct vcpu *v;

        nr_cpus = min_t(uint32_t, op->u.getcpuinfo.max_cpus, NR_CPUS);

        for ( i = 0; i < nr_cpus; i++ )
        {
            /* Assume no holes in idle-vcpu map. */
            if ( (v = idle_vcpu[i]) == NULL )
                break;

            cpuinfo.idletime = v->runstate.time[RUNSTATE_running];
            if ( v->is_running )
                cpuinfo.idletime += NOW() - v->runstate.state_entry_time;

            ret = -EFAULT;
            if ( copy_to_guest_offset(op->u.getcpuinfo.info, i, &cpuinfo, 1) )
                goto out;
        }

        op->u.getcpuinfo.nr_cpus = i;
        ret = copy_to_guest(u_sysctl, op, 1) ? -EFAULT : 0;
    }
    break;

    case XEN_SYSCTL_availheap:
    { 
        op->u.availheap.avail_bytes = avail_domheap_pages_region(
            op->u.availheap.node,
            op->u.availheap.min_bitwidth,
            op->u.availheap.max_bitwidth);
        op->u.availheap.avail_bytes <<= PAGE_SHIFT;

        ret = copy_to_guest(u_sysctl, op, 1) ? -EFAULT : 0;
    }
    break;

    default:
        ret = arch_do_sysctl(op, u_sysctl);
        break;
    }

 out:
    spin_unlock(&sysctl_lock);

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
