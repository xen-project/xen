/******************************************************************************
 * domctl.c
 * 
 * Domain management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K A Fraser
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
#include <xen/rcupdate.h>
#include <xen/guest_access.h>
#include <xen/bitmap.h>
#include <xen/shadow.h>
#include <asm/current.h>
#include <public/domctl.h>
#include <acm/acm_hooks.h>

extern long arch_do_domctl(
    struct xen_domctl *op, XEN_GUEST_HANDLE(xen_domctl_t) u_domctl);

void cpumask_to_xenctl_cpumap(
    struct xenctl_cpumap *xenctl_cpumap, cpumask_t *cpumask)
{
    unsigned int guest_bytes, copy_bytes, i;
    uint8_t zero = 0;
    uint8_t bytemap[(NR_CPUS + 7) / 8];

    if ( guest_handle_is_null(xenctl_cpumap->bitmap) )
        return;

    guest_bytes = (xenctl_cpumap->nr_cpus + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, sizeof(bytemap));

    bitmap_long_to_byte(bytemap, cpus_addr(*cpumask), NR_CPUS);

    copy_to_guest(xenctl_cpumap->bitmap, &bytemap[0], copy_bytes);

    for ( i = copy_bytes; i < guest_bytes; i++ )
        copy_to_guest_offset(xenctl_cpumap->bitmap, i, &zero, 1);
}

void xenctl_cpumap_to_cpumask(
    cpumask_t *cpumask, struct xenctl_cpumap *xenctl_cpumap)
{
    unsigned int guest_bytes, copy_bytes;
    uint8_t bytemap[(NR_CPUS + 7) / 8];

    guest_bytes = (xenctl_cpumap->nr_cpus + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, sizeof(bytemap));

    cpus_clear(*cpumask);

    if ( guest_handle_is_null(xenctl_cpumap->bitmap) )
        return;

    copy_from_guest(&bytemap[0], xenctl_cpumap->bitmap, copy_bytes);

    bitmap_byte_to_long(cpus_addr(*cpumask), bytemap, NR_CPUS);
}

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = rcu_lock_domain_by_id(dom)) == NULL )
        return 1;

    rcu_unlock_domain(d);
    return 0;
}

void getdomaininfo(struct domain *d, struct xen_domctl_getdomaininfo *info)
{
    struct vcpu   *v;
    u64 cpu_time = 0;
    int flags = XEN_DOMINF_blocked;
    struct vcpu_runstate_info runstate;
    
    info->domain = d->domain_id;
    info->nr_online_vcpus = 0;
    
    /* 
     * - domain is marked as blocked only if all its vcpus are blocked
     * - domain is marked as running if any of its vcpus is running
     */
    for_each_vcpu ( d, v )
    {
        vcpu_runstate_get(v, &runstate);
        cpu_time += runstate.time[RUNSTATE_running];
        info->max_vcpu_id = v->vcpu_id;
        if ( !test_bit(_VPF_down, &v->pause_flags) )
        {
            if ( !(v->pause_flags & VPF_blocked) )
                flags &= ~XEN_DOMINF_blocked;
            if ( v->is_running )
                flags |= XEN_DOMINF_running;
            info->nr_online_vcpus++;
        }
    }

    info->cpu_time = cpu_time;

    info->flags = flags |
        (d->is_dying                ? XEN_DOMINF_dying    : 0) |
        (d->is_shut_down            ? XEN_DOMINF_shutdown : 0) |
        (d->is_paused_by_controller ? XEN_DOMINF_paused   : 0) |
        d->shutdown_code << XEN_DOMINF_shutdownshift;

    if ( is_hvm_domain(d) )
        info->flags |= XEN_DOMINF_hvm_guest;

    if ( d->ssid != NULL )
        info->ssidref = ((struct acm_ssid_domain *)d->ssid)->ssidref;
    else    
        info->ssidref = ACM_DEFAULT_SSID;
    
    info->tot_pages         = d->tot_pages;
    info->max_pages         = d->max_pages;
    info->shared_info_frame = mfn_to_gmfn(d, __pa(d->shared_info)>>PAGE_SHIFT);

    memcpy(info->handle, d->handle, sizeof(xen_domain_handle_t));
}

static unsigned int default_vcpu0_location(void)
{
    struct domain *d;
    struct vcpu   *v;
    unsigned int   i, cpu, cnt[NR_CPUS] = { 0 };
    cpumask_t      cpu_exclude_map;

    /* Do an initial CPU placement. Pick the least-populated CPU. */
    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
        for_each_vcpu ( d, v )
        if ( !test_bit(_VPF_down, &v->pause_flags) )
            cnt[v->processor]++;
    rcu_read_unlock(&domlist_read_lock);

    /*
     * If we're on a HT system, we only auto-allocate to a non-primary HT. We 
     * favour high numbered CPUs in the event of a tie.
     */
    cpu = first_cpu(cpu_sibling_map[0]);
    if ( cpus_weight(cpu_sibling_map[0]) > 1 )
        cpu = next_cpu(cpu, cpu_sibling_map[0]);
    cpu_exclude_map = cpu_sibling_map[0];
    for_each_online_cpu ( i )
    {
        if ( cpu_isset(i, cpu_exclude_map) )
            continue;
        if ( (i == first_cpu(cpu_sibling_map[i])) &&
             (cpus_weight(cpu_sibling_map[i]) > 1) )
            continue;
        cpus_or(cpu_exclude_map, cpu_exclude_map, cpu_sibling_map[i]);
        if ( cnt[i] <= cnt[cpu] )
            cpu = i;
    }

    return cpu;
}

long do_domctl(XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    long ret = 0;
    struct xen_domctl curop, *op = &curop;
    static DEFINE_SPINLOCK(domctl_lock);

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_guest(op, u_domctl, 1) )
        return -EFAULT;

    if ( op->interface_version != XEN_DOMCTL_INTERFACE_VERSION )
        return -EACCES;

    spin_lock(&domctl_lock);

    switch ( op->cmd )
    {

    case XEN_DOMCTL_setvcpucontext:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);
        vcpu_guest_context_u c = { .nat = NULL };
        unsigned int vcpu = op->u.vcpucontext.vcpu;
        struct vcpu *v;

        ret = -ESRCH;
        if ( d == NULL )
            break;

        ret = -EINVAL;
        if ( (vcpu >= MAX_VIRT_CPUS) || ((v = d->vcpu[vcpu]) == NULL) )
            goto svc_out;

        if ( guest_handle_is_null(op->u.vcpucontext.ctxt) )
        {
            ret = vcpu_reset(v);
            goto svc_out;
        }

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = xmalloc(struct vcpu_guest_context)) == NULL )
            goto svc_out;

        if ( !IS_COMPAT(v->domain) )
            ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
#ifdef CONFIG_COMPAT
        else
            ret = copy_from_guest(c.cmp,
                                  guest_handle_cast(op->u.vcpucontext.ctxt,
                                                    void), 1);
#endif
        ret = ret ? -EFAULT : 0;

        if ( ret == 0 )
        {
            domain_pause(d);
            ret = arch_set_info_guest(v, c);
            domain_unpause(d);
        }

    svc_out:
        xfree(c.nat);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_pausedomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_pause_by_systemcontroller(d);
                ret = 0;
            }
            rcu_unlock_domain(d);
        }
    }
    break;

    case XEN_DOMCTL_unpausedomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);

        ret = -ESRCH;
        if ( d == NULL )
            break;

        domain_unpause_by_systemcontroller(d);
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_resumedomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);

        ret = -ESRCH;
        if ( d == NULL )
            break;

        domain_resume(d);
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_createdomain:
    {
        struct domain *d;
        domid_t        dom;
        static domid_t rover = 0;
        unsigned int domcr_flags;

        ret = -EINVAL;
        if ( supervisor_mode_kernel ||
             (op->u.createdomain.flags & ~XEN_DOMCTL_CDF_hvm_guest) )
            break;

        dom = op->domain;
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

        domcr_flags = 0;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_hvm_guest )
            domcr_flags |= DOMCRF_hvm;

        ret = -ENOMEM;
        d = domain_create(dom, domcr_flags, op->u.createdomain.ssidref);
        if ( d == NULL )
            break;

        ret = 0;

        memcpy(d->handle, op->u.createdomain.handle,
               sizeof(xen_domain_handle_t));

        op->domain = d->domain_id;
        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_max_vcpus:
    {
        struct domain *d;
        unsigned int i, max = op->u.max_vcpus.max, cpu;

        ret = -EINVAL;
        if ( max > MAX_VIRT_CPUS )
            break;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        /* Needed, for example, to ensure writable p.t. state is synced. */
        domain_pause(d);

        /* We cannot reduce maximum VCPUs. */
        ret = -EINVAL;
        if ( (max != MAX_VIRT_CPUS) && (d->vcpu[max] != NULL) )
            goto maxvcpu_out;

        ret = -ENOMEM;
        for ( i = 0; i < max; i++ )
        {
            if ( d->vcpu[i] != NULL )
                continue;

            cpu = (i == 0) ?
                default_vcpu0_location() :
                (d->vcpu[i-1]->processor + 1) % num_online_cpus();

            if ( alloc_vcpu(d, i, cpu) == NULL )
                goto maxvcpu_out;
        }

        ret = 0;

    maxvcpu_out:
        domain_unpause(d);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_destroydomain:
    {
        struct domain *d = rcu_lock_domain_by_id(op->domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_kill(d);
                ret = 0;
            }
            rcu_unlock_domain(d);
        }
    }
    break;

    case XEN_DOMCTL_setvcpuaffinity:
    case XEN_DOMCTL_getvcpuaffinity:
    {
        domid_t dom = op->domain;
        struct domain *d = rcu_lock_domain_by_id(dom);
        struct vcpu *v;
        cpumask_t new_affinity;

        ret = -ESRCH;
        if ( d == NULL )
            break;

        ret = -EINVAL;
        if ( op->u.vcpuaffinity.vcpu >= MAX_VIRT_CPUS )
            goto vcpuaffinity_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.vcpuaffinity.vcpu]) == NULL )
            goto vcpuaffinity_out;

        if ( op->cmd == XEN_DOMCTL_setvcpuaffinity )
        {
            xenctl_cpumap_to_cpumask(
                &new_affinity, &op->u.vcpuaffinity.cpumap);
            ret = vcpu_set_affinity(v, &new_affinity);
        }
        else
        {
            cpumask_to_xenctl_cpumap(
                &op->u.vcpuaffinity.cpumap, &v->cpu_affinity);
            ret = 0;
        }

    vcpuaffinity_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_scheduler_op:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = sched_adjust(d, &op->u.scheduler_op);
        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_getdomaininfo:
    { 
        struct domain *d;
        domid_t dom;

        dom = op->domain;
        if ( dom == DOMID_SELF )
            dom = current->domain->domain_id;

        rcu_read_lock(&domlist_read_lock);

        for_each_domain ( d )
        {
            if ( d->domain_id >= dom )
                break;
        }

        if ( d == NULL )
        {
            rcu_read_unlock(&domlist_read_lock);
            ret = -ESRCH;
            break;
        }

        getdomaininfo(d, &op->u.getdomaininfo);

        op->domain = op->u.getdomaininfo.domain;
        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;

        rcu_read_unlock(&domlist_read_lock);
    }
    break;

    case XEN_DOMCTL_getvcpucontext:
    { 
        vcpu_guest_context_u c = { .nat = NULL };
        struct domain       *d;
        struct vcpu         *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = -EINVAL;
        if ( op->u.vcpucontext.vcpu >= MAX_VIRT_CPUS )
            goto getvcpucontext_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.vcpucontext.vcpu]) == NULL )
            goto getvcpucontext_out;

        ret = -ENODATA;
        if ( !v->is_initialised )
            goto getvcpucontext_out;

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = xmalloc(struct vcpu_guest_context)) == NULL )
            goto getvcpucontext_out;

        if ( v != current )
            vcpu_pause(v);

        arch_get_info_guest(v, c);
        ret = 0;

        if ( v != current )
            vcpu_unpause(v);

        if ( !IS_COMPAT(v->domain) )
            ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
#ifdef CONFIG_COMPAT
        else
            ret = copy_to_guest(guest_handle_cast(op->u.vcpucontext.ctxt,
                                                  void), c.cmp, 1);
#endif

        if ( copy_to_guest(u_domctl, op, 1) || ret )
            ret = -EFAULT;

    getvcpucontext_out:
        xfree(c.nat);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_getvcpuinfo:
    { 
        struct domain *d;
        struct vcpu   *v;
        struct vcpu_runstate_info runstate;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(op->domain)) == NULL )
            break;

        ret = -EINVAL;
        if ( op->u.getvcpuinfo.vcpu >= MAX_VIRT_CPUS )
            goto getvcpuinfo_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.getvcpuinfo.vcpu]) == NULL )
            goto getvcpuinfo_out;

        vcpu_runstate_get(v, &runstate);

        op->u.getvcpuinfo.online   = !test_bit(_VPF_down, &v->pause_flags);
        op->u.getvcpuinfo.blocked  = test_bit(_VPF_blocked, &v->pause_flags);
        op->u.getvcpuinfo.running  = v->is_running;
        op->u.getvcpuinfo.cpu_time = runstate.time[RUNSTATE_running];
        op->u.getvcpuinfo.cpu      = v->processor;
        ret = 0;

        if ( copy_to_guest(u_domctl, op, 1) )
            ret = -EFAULT;

    getvcpuinfo_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_max_mem:
    {
        struct domain *d;
        unsigned long new_max;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        ret = -EINVAL;
        new_max = op->u.max_mem.max_memkb >> (PAGE_SHIFT-10);

        spin_lock(&d->page_alloc_lock);
        if ( new_max >= d->tot_pages )
        {
            ret = guest_physmap_max_mem_pages(d, new_max);
            if ( ret != 0 )
                break;
            d->max_pages = new_max;
            ret = 0;
        }
        spin_unlock(&d->page_alloc_lock);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_setdomainhandle:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        memcpy(d->handle, op->u.setdomainhandle.handle,
               sizeof(xen_domain_handle_t));
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_setdebugging:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        domain_pause(d);
        d->debugger_attached = !!op->u.setdebugging.enable;
        domain_unpause(d); /* causes guest to latch new status */
        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_irq_permission:
    {
        struct domain *d;
        unsigned int pirq = op->u.irq_permission.pirq;

        ret = -EINVAL;
        if ( pirq >= NR_IRQS )
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        if ( op->u.irq_permission.allow_access )
            ret = irq_permit_access(d, pirq);
        else
            ret = irq_deny_access(d, pirq);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_iomem_permission:
    {
        struct domain *d;
        unsigned long mfn = op->u.iomem_permission.first_mfn;
        unsigned long nr_mfns = op->u.iomem_permission.nr_mfns;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            break;

        if ( op->u.iomem_permission.allow_access )
            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
        else
            ret = iomem_deny_access(d, mfn, mfn + nr_mfns - 1);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_settimeoffset:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(op->domain);
        if ( d != NULL )
        {
            d->time_offset_seconds = op->u.settimeoffset.time_offset_seconds;
            rcu_unlock_domain(d);
            ret = 0;
        }
    }
    break;

    default:
        ret = arch_do_domctl(op, u_domctl);
        break;
    }

    spin_unlock(&domctl_lock);

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
