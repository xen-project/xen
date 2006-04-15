/******************************************************************************
 * dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
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
#include <asm/current.h>
#include <public/dom0_ops.h>
#include <public/sched_ctl.h>
#include <acm/acm_hooks.h>

extern long arch_do_dom0_op(
    struct dom0_op *op, GUEST_HANDLE(dom0_op_t) u_dom0_op);
extern void arch_getdomaininfo_ctxt(
    struct vcpu *, struct vcpu_guest_context *);

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return 1;

    put_domain(d);
    return 0;
}

static void getdomaininfo(struct domain *d, dom0_getdomaininfo_t *info)
{
    struct vcpu   *v;
    u64 cpu_time = 0;
    int flags = DOMFLAGS_BLOCKED;
    struct vcpu_runstate_info runstate;
    
    info->domain = d->domain_id;
    info->nr_online_vcpus = 0;
    
    /* 
     * - domain is marked as blocked only if all its vcpus are blocked
     * - domain is marked as running if any of its vcpus is running
     */
    for_each_vcpu ( d, v ) {
        vcpu_runstate_get(v, &runstate);
        cpu_time += runstate.time[RUNSTATE_running];
        info->max_vcpu_id = v->vcpu_id;
        if ( !test_bit(_VCPUF_down, &v->vcpu_flags) )
        {
            if ( !(v->vcpu_flags & VCPUF_blocked) )
                flags &= ~DOMFLAGS_BLOCKED;
            if ( v->vcpu_flags & VCPUF_running )
                flags |= DOMFLAGS_RUNNING;
            info->nr_online_vcpus++;
        }
    }
    
    info->cpu_time = cpu_time;
    
    info->flags = flags |
        ((d->domain_flags & DOMF_dying)      ? DOMFLAGS_DYING    : 0) |
        ((d->domain_flags & DOMF_shutdown)   ? DOMFLAGS_SHUTDOWN : 0) |
        ((d->domain_flags & DOMF_ctrl_pause) ? DOMFLAGS_PAUSED   : 0) |
        d->shutdown_code << DOMFLAGS_SHUTDOWNSHIFT;

    if (d->ssid != NULL)
        info->ssidref = ((struct acm_ssid_domain *)d->ssid)->ssidref;
    else    
        info->ssidref = ACM_DEFAULT_SSID;
    
    info->tot_pages         = d->tot_pages;
    info->max_pages         = d->max_pages;
    info->shared_info_frame = __pa(d->shared_info) >> PAGE_SHIFT;

    memcpy(info->handle, d->handle, sizeof(xen_domain_handle_t));
}

long do_dom0_op(GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    long ret = 0;
    struct dom0_op curop, *op = &curop;
    void *ssid = NULL; /* save security ptr between pre and post/fail hooks */
    static spinlock_t dom0_lock = SPIN_LOCK_UNLOCKED;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_guest(op, u_dom0_op, 1) )
        return -EFAULT;

    if ( op->interface_version != DOM0_INTERFACE_VERSION )
        return -EACCES;

    if ( acm_pre_dom0_op(op, &ssid) )
        return -EPERM;

    spin_lock(&dom0_lock);

    switch ( op->cmd )
    {

    case DOM0_SETVCPUCONTEXT:
    {
        struct domain *d = find_domain_by_id(op->u.setvcpucontext.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = set_info_guest(d, &op->u.setvcpucontext);
            put_domain(d);
        }
    }
    break;

    case DOM0_PAUSEDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.pausedomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_pause_by_systemcontroller(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_UNPAUSEDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.unpausedomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( (d != current->domain) && 
                 test_bit(_VCPUF_initialised, &d->vcpu[0]->vcpu_flags) )
            {
                domain_unpause_by_systemcontroller(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_CREATEDOMAIN:
    {
        struct domain *d;
        unsigned int   pro;
        domid_t        dom;
        struct vcpu   *v;
        unsigned int   i, cnt[NR_CPUS] = { 0 };
        cpumask_t      cpu_exclude_map;
        static domid_t rover = 0;

        /*
         * Running the domain 0 kernel in ring 0 is not compatible
         * with multiple guests.
         */
        if ( supervisor_mode_kernel )
            return -EINVAL;

        dom = op->u.createdomain.domain;
        if ( (dom > 0) && (dom < DOMID_FIRST_RESERVED) )
        {
            ret = -EINVAL;
            if ( !is_free_domid(dom) )
                break;
        }
        else
        {
            for ( dom = rover + 1; dom != rover; dom++ )
            {
                if ( dom == DOMID_FIRST_RESERVED )
                    dom = 0;
                if ( is_free_domid(dom) )
                    break;
            }

            ret = -ENOMEM;
            if ( dom == rover )
                break;

            rover = dom;
        }

        /* Do an initial CPU placement. Pick the least-populated CPU. */
        read_lock(&domlist_lock);
        for_each_domain ( d )
            for_each_vcpu ( d, v )
                if ( !test_bit(_VCPUF_down, &v->vcpu_flags) )
                    cnt[v->processor]++;
        read_unlock(&domlist_lock);
        
        /*
         * If we're on a HT system, we only auto-allocate to a non-primary HT.
         * We favour high numbered CPUs in the event of a tie.
         */
        pro = first_cpu(cpu_sibling_map[0]);
        if ( cpus_weight(cpu_sibling_map[0]) > 1 )
            pro = next_cpu(pro, cpu_sibling_map[0]);
        cpu_exclude_map = cpu_sibling_map[0];
        for_each_online_cpu ( i )
        {
            if ( cpu_isset(i, cpu_exclude_map) )
                continue;
            if ( (i == first_cpu(cpu_sibling_map[i])) &&
                 (cpus_weight(cpu_sibling_map[i]) > 1) )
                continue;
            cpus_or(cpu_exclude_map, cpu_exclude_map, cpu_sibling_map[i]);
            if ( cnt[i] <= cnt[pro] )
                pro = i;
        }

        ret = -ENOMEM;
        if ( (d = domain_create(dom, pro)) == NULL )
            break;

        memcpy(d->handle, op->u.createdomain.handle,
               sizeof(xen_domain_handle_t));

        ret = 0;

        op->u.createdomain.domain = d->domain_id;
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    case DOM0_MAX_VCPUS:
    {
        struct domain *d;
        unsigned int i, max = op->u.max_vcpus.max, cpu;

        ret = -EINVAL;
        if ( max > MAX_VIRT_CPUS )
            break;

        ret = -ESRCH;
        if ( (d = find_domain_by_id(op->u.max_vcpus.domain)) == NULL )
            break;

        /*
         * Can only create new VCPUs while the domain is not fully constructed
         * (and hence not runnable). Xen needs auditing for races before
         * removing this check.
         */
        ret = -EINVAL;
        if ( test_bit(_VCPUF_initialised, &d->vcpu[0]->vcpu_flags) )
            goto maxvcpu_out;

        /* We cannot reduce maximum VCPUs. */
        ret = -EINVAL;
        if ( (max != MAX_VIRT_CPUS) && (d->vcpu[max] != NULL) )
            goto maxvcpu_out;

        ret = -ENOMEM;
        for ( i = 0; i < max; i++ )
        {
            if ( d->vcpu[i] == NULL )
            {
                cpu = (d->vcpu[i-1]->processor + 1) % num_online_cpus();
                if ( alloc_vcpu(d, i, cpu) == NULL )
                    goto maxvcpu_out;
            }
        }

        ret = 0;

    maxvcpu_out:
        put_domain(d);
    }
    break;

    case DOM0_DESTROYDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.destroydomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_kill(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_SETVCPUAFFINITY:
    {
        domid_t dom = op->u.setvcpuaffinity.domain;
        struct domain *d = find_domain_by_id(dom);
        struct vcpu *v;
        cpumask_t new_affinity;

        if ( d == NULL )
        {
            ret = -ESRCH;            
            break;
        }
        
        if ( (op->u.setvcpuaffinity.vcpu >= MAX_VIRT_CPUS) ||
             !d->vcpu[op->u.setvcpuaffinity.vcpu] )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }

        v = d->vcpu[op->u.setvcpuaffinity.vcpu];
        if ( v == NULL )
        {
            ret = -ESRCH;
            put_domain(d);
            break;
        }

        if ( v == current )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }

        new_affinity = v->cpu_affinity;
        memcpy(cpus_addr(new_affinity),
               &op->u.setvcpuaffinity.cpumap,
               min((int)(BITS_TO_LONGS(NR_CPUS) * sizeof(long)),
                   (int)sizeof(op->u.setvcpuaffinity.cpumap)));

        ret = vcpu_set_affinity(v, &new_affinity);

        put_domain(d);
    }
    break;

    case DOM0_SCHEDCTL:
    {
        ret = sched_ctl(&op->u.schedctl);
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    case DOM0_ADJUSTDOM:
    {
        ret = sched_adjdom(&op->u.adjustdom);
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    case DOM0_GETDOMAININFO:
    { 
        struct domain *d;
        domid_t dom;

        dom = op->u.getdomaininfo.domain;
        if ( dom == DOMID_SELF )
            dom = current->domain->domain_id;

        read_lock(&domlist_lock);

        for_each_domain ( d )
        {
            if ( d->domain_id >= dom )
                break;
        }

        if ( (d == NULL) || !get_domain(d) )
        {
            read_unlock(&domlist_lock);
            ret = -ESRCH;
            break;
        }

        read_unlock(&domlist_lock);

        getdomaininfo(d, &op->u.getdomaininfo);

        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;

        put_domain(d);
    }
    break;

    case DOM0_GETDOMAININFOLIST:
    { 
        struct domain *d;
        dom0_getdomaininfo_t info;
        u32 num_domains = 0;

        read_lock(&domlist_lock);

        for_each_domain ( d )
        {
            if ( d->domain_id < op->u.getdomaininfolist.first_domain )
                continue;
            if ( num_domains == op->u.getdomaininfolist.max_domains )
                break;
            if ( (d == NULL) || !get_domain(d) )
            {
                ret = -ESRCH;
                break;
            }

            getdomaininfo(d, &info);

            put_domain(d);

            if ( copy_to_guest_offset(op->u.getdomaininfolist.buffer,
                                      num_domains, &info, 1) )
            {
                ret = -EFAULT;
                break;
            }
            
            num_domains++;
        }
        
        read_unlock(&domlist_lock);
        
        if ( ret != 0 )
            break;
        
        op->u.getdomaininfolist.num_domains = num_domains;

        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    case DOM0_GETVCPUCONTEXT:
    { 
        struct vcpu_guest_context *c;
        struct domain             *d;
        struct vcpu               *v;

        ret = -ESRCH;
        if ( (d = find_domain_by_id(op->u.getvcpucontext.domain)) == NULL )
            break;

        ret = -EINVAL;
        if ( op->u.getvcpucontext.vcpu >= MAX_VIRT_CPUS )
            goto getvcpucontext_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.getvcpucontext.vcpu]) == NULL )
            goto getvcpucontext_out;

        ret = -ENODATA;
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            goto getvcpucontext_out;

        ret = -ENOMEM;
        if ( (c = xmalloc(struct vcpu_guest_context)) == NULL )
            goto getvcpucontext_out;

        if ( v != current )
            vcpu_pause(v);

        arch_getdomaininfo_ctxt(v,c);
        ret = 0;

        if ( v != current )
            vcpu_unpause(v);

        if ( copy_to_guest(op->u.getvcpucontext.ctxt, c, 1) )
            ret = -EFAULT;

        xfree(c);

        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;

    getvcpucontext_out:
        put_domain(d);
    }
    break;

    case DOM0_GETVCPUINFO:
    { 
        struct domain *d;
        struct vcpu   *v;
        struct vcpu_runstate_info runstate;

        ret = -ESRCH;
        if ( (d = find_domain_by_id(op->u.getvcpuinfo.domain)) == NULL )
            break;

        ret = -EINVAL;
        if ( op->u.getvcpuinfo.vcpu >= MAX_VIRT_CPUS )
            goto getvcpuinfo_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.getvcpuinfo.vcpu]) == NULL )
            goto getvcpuinfo_out;

        vcpu_runstate_get(v, &runstate);

        op->u.getvcpuinfo.online   = !test_bit(_VCPUF_down, &v->vcpu_flags);
        op->u.getvcpuinfo.blocked  = test_bit(_VCPUF_blocked, &v->vcpu_flags);
        op->u.getvcpuinfo.running  = test_bit(_VCPUF_running, &v->vcpu_flags);
        op->u.getvcpuinfo.cpu_time = runstate.time[RUNSTATE_running];
        op->u.getvcpuinfo.cpu      = v->processor;
        op->u.getvcpuinfo.cpumap   = 0;
        memcpy(&op->u.getvcpuinfo.cpumap,
               cpus_addr(v->cpu_affinity),
               min((int)(BITS_TO_LONGS(NR_CPUS) * sizeof(long)),
                   (int)sizeof(op->u.getvcpuinfo.cpumap)));
        ret = 0;

        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;

    getvcpuinfo_out:
        put_domain(d);
    }
    break;

    case DOM0_SETTIME:
    {
        do_settime(op->u.settime.secs, 
                   op->u.settime.nsecs, 
                   op->u.settime.system_time);
        ret = 0;
    }
    break;

    case DOM0_TBUFCONTROL:
    {
        ret = tb_control(&op->u.tbufcontrol);
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;
    
    case DOM0_READCONSOLE:
    {
        ret = read_console_ring(
            op->u.readconsole.buffer, 
            &op->u.readconsole.count,
            op->u.readconsole.clear); 
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    case DOM0_SCHED_ID:
    {
        op->u.sched_id.sched_id = sched_id();
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
        else
            ret = 0;
    }
    break;

    case DOM0_SETDOMAINMAXMEM:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.setdomainmaxmem.domain);
        if ( d != NULL )
        {
            unsigned long new_max;
            new_max = op->u.setdomainmaxmem.max_memkb >> (PAGE_SHIFT-10);
            if (new_max < d->tot_pages) 
                ret = -EINVAL;
            else 
            {  
                d->max_pages = new_max;
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_SETDOMAINHANDLE:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.setdomainhandle.domain);
        if ( d != NULL )
        {
            memcpy(d->handle, op->u.setdomainhandle.handle,
                   sizeof(xen_domain_handle_t));
            put_domain(d);
            ret = 0;
        }
    }
    break;

    case DOM0_SETDEBUGGING:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.setdebugging.domain);
        if ( d != NULL )
        {
            if ( op->u.setdebugging.enable )
                set_bit(_DOMF_debugging, &d->domain_flags);
            else
                clear_bit(_DOMF_debugging, &d->domain_flags);
            put_domain(d);
            ret = 0;
        }
    }
    break;

    case DOM0_IRQ_PERMISSION:
    {
        struct domain *d;
        unsigned int pirq = op->u.irq_permission.pirq;

        ret = -EINVAL;
        if ( pirq >= NR_PIRQS )
            break;

        ret = -ESRCH;
        d = find_domain_by_id(op->u.irq_permission.domain);
        if ( d == NULL )
            break;

        if ( op->u.irq_permission.allow_access )
            ret = irq_permit_access(d, pirq);
        else
            ret = irq_deny_access(d, pirq);

        put_domain(d);
    }
    break;

    case DOM0_IOMEM_PERMISSION:
    {
        struct domain *d;
        unsigned long mfn = op->u.iomem_permission.first_mfn;
        unsigned long nr_mfns = op->u.iomem_permission.nr_mfns;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        ret = -ESRCH;
        d = find_domain_by_id(op->u.iomem_permission.domain);
        if ( d == NULL )
            break;

        if ( op->u.iomem_permission.allow_access )
            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
        else
            ret = iomem_deny_access(d, mfn, mfn + nr_mfns - 1);

        put_domain(d);
    }
    break;

#ifdef PERF_COUNTERS
    case DOM0_PERFCCONTROL:
    {
        extern int perfc_control(dom0_perfccontrol_t *);
        ret = perfc_control(&op->u.perfccontrol);
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;
#endif

    default:
        ret = arch_do_dom0_op(op, u_dom0_op);
        break;
    }

    spin_unlock(&dom0_lock);

    if (!ret)
        acm_post_dom0_op(op, ssid);
    else
        acm_fail_dom0_op(op, ssid);

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
