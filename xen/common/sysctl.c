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
#include <xen/hypercall.h>
#include <public/sysctl.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xsm/xsm.h>
#include <xen/pmstat.h>

extern long arch_do_sysctl(
    struct xen_sysctl *op, XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl);
#ifdef LOCK_PROFILE
extern int spinlock_profile_control(xen_sysctl_lockprof_op_t *pc);
#endif

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

    /*
     * Trylock here avoids deadlock with an existing sysctl critical section
     * which might (for some current or future reason) want to synchronise
     * with this vcpu.
     */
    while ( !spin_trylock(&sysctl_lock) )
        if ( hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_sysctl, "h", u_sysctl);

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

#ifdef LOCK_PROFILE
    case XEN_SYSCTL_lockprof_op:
    {
        ret = spinlock_profile_control(&op->u.lockprof_op);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;
#endif
    case XEN_SYSCTL_debug_keys:
    {
        char c;
        uint32_t i;

        ret = xsm_debug_keys();
        if ( ret )
            break;

        ret = -EFAULT;
        for ( i = 0; i < op->u.debug_keys.nr_keys; i++ )
        {
            if ( copy_from_guest_offset(&c, op->u.debug_keys.keys, i, 1) )
                goto out;
            handle_keypress(c, guest_cpu_user_regs());
        }
        ret = 0;
    }
    break;

    case XEN_SYSCTL_getcpuinfo:
    {
        uint32_t i, nr_cpus;
        struct xen_sysctl_cpuinfo cpuinfo;

        nr_cpus = min_t(uint32_t, op->u.getcpuinfo.max_cpus, NR_CPUS);

        ret = xsm_getcpuinfo();
        if ( ret )
            break;

        for ( i = 0; i < nr_cpus; i++ )
        {
            cpuinfo.idletime = get_cpu_idle_time(i);

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
        ret = xsm_availheap();
        if ( ret )
            break;

        op->u.availheap.avail_bytes = avail_domheap_pages_region(
            op->u.availheap.node,
            op->u.availheap.min_bitwidth,
            op->u.availheap.max_bitwidth);
        op->u.availheap.avail_bytes <<= PAGE_SHIFT;

        ret = copy_to_guest(u_sysctl, op, 1) ? -EFAULT : 0;
    }
    break;

    case XEN_SYSCTL_get_pmstat:
    {
        ret = xsm_get_pmstat();
        if ( ret )
            break;

        ret = do_get_pm_info(&op->u.get_pmstat);
        if ( ret )
            break;

        if ( copy_to_guest(u_sysctl, op, 1) )
        {
            ret = -EFAULT;
            break;
        }
    }
    break;

    case XEN_SYSCTL_pm_op:
    {
        ret = xsm_pm_op();
        if ( ret )
            break;

        ret = do_pm_op(&op->u.pm_op);
        if ( ret && (ret != -EAGAIN) )
            break;

        if ( copy_to_guest(u_sysctl, op, 1) )
        {
            ret = -EFAULT;
            break;
        }
    }
    break;

    case XEN_SYSCTL_page_offline_op:
    {
        uint32_t *status, *ptr;
        unsigned long pfn;

        ptr = status = xmalloc_bytes( sizeof(uint32_t) *
                                (op->u.page_offline.end -
                                  op->u.page_offline.start + 1));
        if ( !status )
        {
            dprintk(XENLOG_WARNING, "Out of memory for page offline op\n");
            ret = -ENOMEM;
            break;
        }

        memset(status, PG_OFFLINE_INVALID, sizeof(uint32_t) *
                      (op->u.page_offline.end - op->u.page_offline.start + 1));

        for ( pfn = op->u.page_offline.start;
              pfn <= op->u.page_offline.end;
              pfn ++ )
        {
            switch ( op->u.page_offline.cmd )
            {
                /* Shall revert her if failed, or leave caller do it? */
                case sysctl_page_offline:
                    ret = offline_page(pfn, 0, ptr++);
                    break;
                case sysctl_page_online:
                    ret = online_page(pfn, ptr++);
                    break;
                case sysctl_query_page_offline:
                    ret = query_page_offline(pfn, ptr++);
                    break;
                default:
                    gdprintk(XENLOG_WARNING, "invalid page offline op %x\n",
                            op->u.page_offline.cmd);
                    ret = -EINVAL;
                    break;
            }

            if (ret)
                break;
        }

        if ( copy_to_guest(
            op->u.page_offline.status, status,
            op->u.page_offline.end - op->u.page_offline.start + 1) )
        {
            ret = -EFAULT;
            break;
        }

        xfree(status);
    }
    break;

    case XEN_SYSCTL_cpupool_op:
    {
        ret = cpupool_do_sysctl(&op->u.cpupool_op);
        if ( (ret == 0) && copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_SYSCTL_scheduler_op:
    {
        ret = sched_adjust_global(&op->u.scheduler_op);
        if ( (ret == 0) && copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
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
