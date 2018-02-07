/******************************************************************************
 * sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/tmem.h>
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
#include <xen/livepatch.h>
#include <xen/coverage.h>

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
        struct xen_domctl_getdomaininfo info = { 0 };
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

#ifdef CONFIG_PERF_COUNTERS
    case XEN_SYSCTL_perfc_op:
        ret = perfc_control(&op->u.perfc_op);
        break;
#endif

#ifdef CONFIG_LOCK_PROFILE
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
        struct xen_sysctl_cpuinfo cpuinfo = { 0 };

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

#if defined (CONFIG_ACPI) && defined (CONFIG_HAS_CPUFREQ)
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
            ret = -EFAULT;

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

    case XEN_SYSCTL_physinfo:
    {
        struct xen_sysctl_physinfo *pi = &op->u.physinfo;

        memset(pi, 0, sizeof(*pi));
        pi->threads_per_core =
            cpumask_weight(per_cpu(cpu_sibling_mask, 0));
        pi->cores_per_socket =
            cpumask_weight(per_cpu(cpu_core_mask, 0)) / pi->threads_per_core;
        pi->nr_cpus = num_online_cpus();
        pi->nr_nodes = num_online_nodes();
        pi->max_node_id = MAX_NUMNODES-1;
        pi->max_cpu_id = nr_cpu_ids - 1;
        pi->total_pages = total_pages;
        /* Protected by lock */
        get_outstanding_claims(&pi->free_pages, &pi->outstanding_pages);
        pi->scrub_pages = 0;
        pi->cpu_khz = cpu_khz;
        pi->max_mfn = get_upper_mfn_bound();
        arch_do_physinfo(pi);

        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_SYSCTL_numainfo:
    {
        unsigned int i, j, num_nodes;
        struct xen_sysctl_numainfo *ni = &op->u.numainfo;
        bool_t do_meminfo = !guest_handle_is_null(ni->meminfo);
        bool_t do_distance = !guest_handle_is_null(ni->distance);

        num_nodes = last_node(node_online_map) + 1;

        if ( do_meminfo || do_distance )
        {
            struct xen_sysctl_meminfo meminfo = { };

            if ( num_nodes > ni->num_nodes )
                num_nodes = ni->num_nodes;
            for ( i = 0; i < num_nodes; ++i )
            {
                static uint32_t distance[MAX_NUMNODES];

                if ( do_meminfo )
                {
                    if ( node_online(i) )
                    {
                        meminfo.memsize = node_spanned_pages(i) << PAGE_SHIFT;
                        meminfo.memfree = avail_node_heap_pages(i) << PAGE_SHIFT;
                    }
                    else
                        meminfo.memsize = meminfo.memfree = XEN_INVALID_MEM_SZ;

                    if ( copy_to_guest_offset(ni->meminfo, i, &meminfo, 1) )
                    {
                        ret = -EFAULT;
                        break;
                    }
                }

                if ( do_distance )
                {
                    for ( j = 0; j < num_nodes; j++ )
                    {
                        distance[j] = __node_distance(i, j);
                        if ( distance[j] == NUMA_NO_DISTANCE )
                            distance[j] = XEN_INVALID_NODE_DIST;
                    }

                    if ( copy_to_guest_offset(ni->distance, i * num_nodes,
                                              distance, num_nodes) )
                    {
                        ret = -EFAULT;
                        break;
                    }
                }
            }
        }
        else
            i = num_nodes;

        if ( !ret && (ni->num_nodes != i) )
        {
            ni->num_nodes = i;
            if ( __copy_field_to_guest(u_sysctl, op,
                                       u.numainfo.num_nodes) )
            {
                ret = -EFAULT;
                break;
            }
        }
    }
    break;

    case XEN_SYSCTL_cputopoinfo:
    {
        unsigned int i, num_cpus;
        struct xen_sysctl_cputopoinfo *ti = &op->u.cputopoinfo;

        num_cpus = cpumask_last(&cpu_online_map) + 1;
        if ( !guest_handle_is_null(ti->cputopo) )
        {
            struct xen_sysctl_cputopo cputopo = { };

            if ( num_cpus > ti->num_cpus )
                num_cpus = ti->num_cpus;
            for ( i = 0; i < num_cpus; ++i )
            {
                if ( cpu_present(i) )
                {
                    cputopo.core = cpu_to_core(i);
                    cputopo.socket = cpu_to_socket(i);
                    cputopo.node = cpu_to_node(i);
                    if ( cputopo.node == NUMA_NO_NODE )
                        cputopo.node = XEN_INVALID_NODE_ID;
                }
                else
                {
                    cputopo.core = XEN_INVALID_CORE_ID;
                    cputopo.socket = XEN_INVALID_SOCKET_ID;
                    cputopo.node = XEN_INVALID_NODE_ID;
                }

                if ( copy_to_guest_offset(ti->cputopo, i, &cputopo, 1) )
                {
                    ret = -EFAULT;
                    break;
                }
            }
        }
        else
            i = num_cpus;

        if ( !ret && (ti->num_cpus != i) )
        {
            ti->num_cpus = i;
            if ( __copy_field_to_guest(u_sysctl, op,
                                       u.cputopoinfo.num_cpus) )
            {
                ret = -EFAULT;
                break;
            }
        }
    }
    break;

    case XEN_SYSCTL_coverage_op:
        ret = sysctl_cov_op(&op->u.coverage_op);
        copyback = 1;
        break;

#ifdef CONFIG_HAS_PCI
    case XEN_SYSCTL_pcitopoinfo:
    {
        struct xen_sysctl_pcitopoinfo *ti = &op->u.pcitopoinfo;
        unsigned int i = 0;

        if ( guest_handle_is_null(ti->devs) ||
             guest_handle_is_null(ti->nodes) )
        {
            ret = -EINVAL;
            break;
        }

        while ( i < ti->num_devs )
        {
            physdev_pci_device_t dev;
            uint32_t node;
            const struct pci_dev *pdev;

            if ( copy_from_guest_offset(&dev, ti->devs, i, 1) )
            {
                ret = -EFAULT;
                break;
            }

            pcidevs_lock();
            pdev = pci_get_pdev(dev.seg, dev.bus, dev.devfn);
            if ( !pdev )
                node = XEN_INVALID_DEV;
            else if ( pdev->node == NUMA_NO_NODE )
                node = XEN_INVALID_NODE_ID;
            else
                node = pdev->node;
            pcidevs_unlock();

            if ( copy_to_guest_offset(ti->nodes, i, &node, 1) )
            {
                ret = -EFAULT;
                break;
            }

            if ( (++i > 0x3f) && hypercall_preempt_check() )
                break;
        }

        if ( !ret && (ti->num_devs != i) )
        {
            ti->num_devs = i;
            if ( __copy_field_to_guest(u_sysctl, op, u.pcitopoinfo.num_devs) )
                ret = -EFAULT;
        }
        break;
    }
#endif

    case XEN_SYSCTL_tmem_op:
        ret = tmem_control(&op->u.tmem_op);
        break;

    case XEN_SYSCTL_livepatch_op:
        ret = livepatch_op(&op->u.livepatch);
        if ( ret != -ENOSYS && ret != -EOPNOTSUPP )
            copyback = 1;
        break;

    case XEN_SYSCTL_set_parameter:
    {
#define XEN_SET_PARAMETER_MAX_SIZE 1023
        char *params;

        if ( op->u.set_parameter.pad[0] || op->u.set_parameter.pad[1] ||
             op->u.set_parameter.pad[2] )
        {
            ret = -EINVAL;
            break;
        }
        if ( op->u.set_parameter.size > XEN_SET_PARAMETER_MAX_SIZE )
        {
            ret = -E2BIG;
            break;
        }
        params = xmalloc_bytes(op->u.set_parameter.size + 1);
        if ( !params )
        {
            ret = -ENOMEM;
            break;
        }
        if ( copy_from_guest(params, op->u.set_parameter.params,
                             op->u.set_parameter.size) )
            ret = -EFAULT;
        else
        {
            params[op->u.set_parameter.size] = 0;
            ret = runtime_parse(params);
        }

        xfree(params);

        break;
    }

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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
