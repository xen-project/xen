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

long do_sysctl(XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl)
{
    long ret = 0;
    int copyback = -1;
    struct xen_sysctl curop, *op = &curop;
    static DEFINE_SPINLOCK(sysctl_lock);

    if ( copy_from_guest(op, u_sysctl, 1) )
        return -EFAULT;

    if ( op->interface_version != XEN_SYSCTL_INTERFACE_VERSION )
        return -EACCES;

    ret = xsm_sysctl(XSM_PRIV, op->cmd);
    if ( ret )
        return ret;

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
        ret = xsm_readconsole(XSM_HOOK, op->u.readconsole.clear);
        if ( ret )
            break;

        ret = read_console_ring(&op->u.readconsole);
        break;

    case XEN_SYSCTL_tbuf_op:
        ret = tb_control(&op->u.tbuf_op);
        break;
    
    case XEN_SYSCTL_sched_id:
        op->u.sched_id.sched_id = sched_id();
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

            ret = xsm_getdomaininfo(XSM_HOOK, d);
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
    }
    break;

#ifdef PERF_COUNTERS
    case XEN_SYSCTL_perfc_op:
        ret = perfc_control(&op->u.perfc_op);
        break;
#endif

#ifdef LOCK_PROFILE
    case XEN_SYSCTL_lockprof_op:
        ret = spinlock_profile_control(&op->u.lockprof_op);
        break;
#endif
    case XEN_SYSCTL_debug_keys:
    {
        char c;
        uint32_t i;

        ret = -EFAULT;
        for ( i = 0; i < op->u.debug_keys.nr_keys; i++ )
        {
            if ( copy_from_guest_offset(&c, op->u.debug_keys.keys, i, 1) )
                goto out;
            handle_keypress(c, guest_cpu_user_regs());
        }
        ret = 0;
        copyback = 0;
    }
    break;

    case XEN_SYSCTL_getcpuinfo:
    {
        uint32_t i, nr_cpus;
        struct xen_sysctl_cpuinfo cpuinfo;

        nr_cpus = min(op->u.getcpuinfo.max_cpus, nr_cpu_ids);

        ret = -EFAULT;
        for ( i = 0; i < nr_cpus; i++ )
        {
            cpuinfo.idletime = get_cpu_idle_time(i);

            if ( copy_to_guest_offset(op->u.getcpuinfo.info, i, &cpuinfo, 1) )
                goto out;
        }

        op->u.getcpuinfo.nr_cpus = i;
        ret = 0;
    }
    break;

    case XEN_SYSCTL_availheap:
        op->u.availheap.avail_bytes = avail_domheap_pages_region(
            op->u.availheap.node,
            op->u.availheap.min_bitwidth,
            op->u.availheap.max_bitwidth);
        op->u.availheap.avail_bytes <<= PAGE_SHIFT;
        break;

#ifdef HAS_ACPI
    case XEN_SYSCTL_get_pmstat:
        ret = do_get_pm_info(&op->u.get_pmstat);
        break;

    case XEN_SYSCTL_pm_op:
        ret = do_pm_op(&op->u.pm_op);
        if ( ret == -EAGAIN )
            copyback = 1;
        break;
#endif

    case XEN_SYSCTL_page_offline_op:
    {
        uint32_t *status, *ptr;
        unsigned long pfn;

        ret = xsm_page_offline(XSM_HOOK, op->u.page_offline.cmd);
        if ( ret )
            break;

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
        copyback = 0;
    }
    break;

    case XEN_SYSCTL_cpupool_op:
        ret = cpupool_do_sysctl(&op->u.cpupool_op);
        break;

    case XEN_SYSCTL_scheduler_op:
        ret = sched_adjust_global(&op->u.scheduler_op);
        break;

    default:
        ret = arch_do_sysctl(op, u_sysctl);
        copyback = 0;
        break;
    }

 out:
    spin_unlock(&sysctl_lock);

    if ( copyback && (!ret || copyback > 0) &&
         __copy_to_guest(u_sysctl, op, 1) )
        ret = -EFAULT;

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
