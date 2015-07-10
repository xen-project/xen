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
#include <xen/err.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/rcupdate.h>
#include <xen/guest_access.h>
#include <xen/bitmap.h>
#include <xen/paging.h>
#include <xen/hypercall.h>
#include <xen/vm_event.h>
#include <asm/current.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/p2m.h>
#include <asm/monitor.h>
#include <public/domctl.h>
#include <xsm/xsm.h>

static DEFINE_SPINLOCK(domctl_lock);
DEFINE_SPINLOCK(vcpu_alloc_lock);

static int bitmap_to_xenctl_bitmap(struct xenctl_bitmap *xenctl_bitmap,
                                   const unsigned long *bitmap,
                                   unsigned int nbits)
{
    unsigned int guest_bytes, copy_bytes, i;
    uint8_t zero = 0;
    int err = 0;
    uint8_t *bytemap = xmalloc_array(uint8_t, (nbits + 7) / 8);

    if ( !bytemap )
        return -ENOMEM;

    guest_bytes = (xenctl_bitmap->nr_bits + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, (nbits + 7) / 8);

    bitmap_long_to_byte(bytemap, bitmap, nbits);

    if ( copy_bytes != 0 )
        if ( copy_to_guest(xenctl_bitmap->bitmap, bytemap, copy_bytes) )
            err = -EFAULT;

    for ( i = copy_bytes; !err && i < guest_bytes; i++ )
        if ( copy_to_guest_offset(xenctl_bitmap->bitmap, i, &zero, 1) )
            err = -EFAULT;

    xfree(bytemap);

    return err;
}

static int xenctl_bitmap_to_bitmap(unsigned long *bitmap,
                                   const struct xenctl_bitmap *xenctl_bitmap,
                                   unsigned int nbits)
{
    unsigned int guest_bytes, copy_bytes;
    int err = 0;
    uint8_t *bytemap = xzalloc_array(uint8_t, (nbits + 7) / 8);

    if ( !bytemap )
        return -ENOMEM;

    guest_bytes = (xenctl_bitmap->nr_bits + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, (nbits + 7) / 8);

    if ( copy_bytes != 0 )
    {
        if ( copy_from_guest(bytemap, xenctl_bitmap->bitmap, copy_bytes) )
            err = -EFAULT;
        if ( (xenctl_bitmap->nr_bits & 7) && (guest_bytes == copy_bytes) )
            bytemap[guest_bytes-1] &= ~(0xff << (xenctl_bitmap->nr_bits & 7));
    }

    if ( !err )
        bitmap_byte_to_long(bitmap, bytemap, nbits);

    xfree(bytemap);

    return err;
}

int cpumask_to_xenctl_bitmap(struct xenctl_bitmap *xenctl_cpumap,
                             const cpumask_t *cpumask)
{
    return bitmap_to_xenctl_bitmap(xenctl_cpumap, cpumask_bits(cpumask),
                                   nr_cpu_ids);
}

int xenctl_bitmap_to_cpumask(cpumask_var_t *cpumask,
                             const struct xenctl_bitmap *xenctl_cpumap)
{
    int err = 0;

    if ( alloc_cpumask_var(cpumask) ) {
        err = xenctl_bitmap_to_bitmap(cpumask_bits(*cpumask), xenctl_cpumap,
                                      nr_cpu_ids);
        /* In case of error, cleanup is up to us, as the caller won't care! */
        if ( err )
            free_cpumask_var(*cpumask);
    }
    else
        err = -ENOMEM;

    return err;
}

static int nodemask_to_xenctl_bitmap(struct xenctl_bitmap *xenctl_nodemap,
                                     const nodemask_t *nodemask)
{
    return bitmap_to_xenctl_bitmap(xenctl_nodemap, nodes_addr(*nodemask),
                                   MAX_NUMNODES);
}

static int xenctl_bitmap_to_nodemask(nodemask_t *nodemask,
                                     const struct xenctl_bitmap *xenctl_nodemap)
{
    return xenctl_bitmap_to_bitmap(nodes_addr(*nodemask), xenctl_nodemap,
                                   MAX_NUMNODES);
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
    struct vcpu *v;
    u64 cpu_time = 0;
    int flags = XEN_DOMINF_blocked;
    struct vcpu_runstate_info runstate;

    info->domain = d->domain_id;
    info->max_vcpu_id = XEN_INVALID_MAX_VCPU_ID;
    info->nr_online_vcpus = 0;
    info->ssidref = 0;

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

    info->flags = (info->nr_online_vcpus ? flags : 0) |
        ((d->is_dying == DOMDYING_dead) ? XEN_DOMINF_dying    : 0) |
        (d->is_shut_down                ? XEN_DOMINF_shutdown : 0) |
        (d->controller_pause_count > 0  ? XEN_DOMINF_paused   : 0) |
        (d->debugger_attached           ? XEN_DOMINF_debugged : 0) |
        d->shutdown_code << XEN_DOMINF_shutdownshift;

    switch ( d->guest_type )
    {
    case guest_type_hvm:
        info->flags |= XEN_DOMINF_hvm_guest;
        break;
    case guest_type_pvh:
        info->flags |= XEN_DOMINF_pvh_guest;
        break;
    default:
        break;
    }

    xsm_security_domaininfo(d, info);

    info->tot_pages         = d->tot_pages;
    info->max_pages         = d->max_pages;
    info->outstanding_pages = d->outstanding_pages;
    info->shr_pages         = atomic_read(&d->shr_pages);
    info->paged_pages       = atomic_read(&d->paged_pages);
    info->shared_info_frame = mfn_to_gmfn(d, virt_to_mfn(d->shared_info));
    BUG_ON(SHARED_M2P(info->shared_info_frame));

    info->cpupool = d->cpupool ? d->cpupool->cpupool_id : CPUPOOLID_NONE;

    memcpy(info->handle, d->handle, sizeof(xen_domain_handle_t));
}

static unsigned int default_vcpu0_location(cpumask_t *online)
{
    struct domain *d;
    struct vcpu   *v;
    unsigned int   i, cpu, nr_cpus, *cnt;
    cpumask_t      cpu_exclude_map;

    /* Do an initial CPU placement. Pick the least-populated CPU. */
    nr_cpus = cpumask_last(&cpu_online_map) + 1;
    cnt = xzalloc_array(unsigned int, nr_cpus);
    if ( cnt )
    {
        rcu_read_lock(&domlist_read_lock);
        for_each_domain ( d )
            for_each_vcpu ( d, v )
                if ( !test_bit(_VPF_down, &v->pause_flags)
                     && ((cpu = v->processor) < nr_cpus) )
                    cnt[cpu]++;
        rcu_read_unlock(&domlist_read_lock);
    }

    /*
     * If we're on a HT system, we only auto-allocate to a non-primary HT. We
     * favour high numbered CPUs in the event of a tie.
     */
    cpumask_copy(&cpu_exclude_map, per_cpu(cpu_sibling_mask, 0));
    cpu = cpumask_first(&cpu_exclude_map);
    i = cpumask_next(cpu, &cpu_exclude_map);
    if ( i < nr_cpu_ids )
        cpu = i;
    for_each_cpu(i, online)
    {
        if ( cpumask_test_cpu(i, &cpu_exclude_map) )
            continue;
        if ( (i == cpumask_first(per_cpu(cpu_sibling_mask, i))) &&
             (cpumask_next(i, per_cpu(cpu_sibling_mask, i)) < nr_cpu_ids) )
            continue;
        cpumask_or(&cpu_exclude_map, &cpu_exclude_map,
                   per_cpu(cpu_sibling_mask, i));
        if ( !cnt || cnt[i] <= cnt[cpu] )
            cpu = i;
    }

    xfree(cnt);

    return cpu;
}

bool_t domctl_lock_acquire(void)
{
    /*
     * Caller may try to pause its own VCPUs. We must prevent deadlock
     * against other non-domctl routines which try to do the same.
     */
    if ( !spin_trylock(&current->domain->hypercall_deadlock_mutex) )
        return 0;

    /*
     * Trylock here is paranoia if we have multiple privileged domains. Then
     * we could have one domain trying to pause another which is spinning
     * on domctl_lock -- results in deadlock.
     */
    if ( spin_trylock(&domctl_lock) )
        return 1;

    spin_unlock(&current->domain->hypercall_deadlock_mutex);
    return 0;
}

void domctl_lock_release(void)
{
    spin_unlock(&domctl_lock);
    spin_unlock(&current->domain->hypercall_deadlock_mutex);
}

static inline
int vcpuaffinity_params_invalid(const xen_domctl_vcpuaffinity_t *vcpuaff)
{
    return vcpuaff->flags == 0 ||
           ((vcpuaff->flags & XEN_VCPUAFFINITY_HARD) &&
            guest_handle_is_null(vcpuaff->cpumap_hard.bitmap)) ||
           ((vcpuaff->flags & XEN_VCPUAFFINITY_SOFT) &&
            guest_handle_is_null(vcpuaff->cpumap_soft.bitmap));
}

void vnuma_destroy(struct vnuma_info *vnuma)
{
    if ( vnuma )
    {
        xfree(vnuma->vmemrange);
        xfree(vnuma->vcpu_to_vnode);
        xfree(vnuma->vdistance);
        xfree(vnuma->vnode_to_pnode);
        xfree(vnuma);
    }
}

/*
 * Allocates memory for vNUMA, **vnuma should be NULL.
 * Caller has to make sure that domain has max_pages
 * and number of vcpus set for domain.
 * Verifies that single allocation does not exceed
 * PAGE_SIZE.
 */
static struct vnuma_info *vnuma_alloc(unsigned int nr_vnodes,
                                      unsigned int nr_ranges,
                                      unsigned int nr_vcpus)
{

    struct vnuma_info *vnuma;

    /*
     * Check if any of the allocations are bigger than PAGE_SIZE.
     * See XSA-77.
     */
    if ( nr_vnodes * nr_vnodes > (PAGE_SIZE / sizeof(*vnuma->vdistance)) ||
         nr_ranges > (PAGE_SIZE / sizeof(*vnuma->vmemrange)) )
        return ERR_PTR(-EINVAL);

    /*
     * If allocations become larger then PAGE_SIZE, these allocations
     * should be split into PAGE_SIZE allocations due to XSA-77.
     */
    vnuma = xmalloc(struct vnuma_info);
    if ( !vnuma )
        return ERR_PTR(-ENOMEM);

    vnuma->vdistance = xmalloc_array(unsigned int, nr_vnodes * nr_vnodes);
    vnuma->vcpu_to_vnode = xmalloc_array(unsigned int, nr_vcpus);
    vnuma->vnode_to_pnode = xmalloc_array(nodeid_t, nr_vnodes);
    vnuma->vmemrange = xmalloc_array(xen_vmemrange_t, nr_ranges);

    if ( vnuma->vdistance == NULL || vnuma->vmemrange == NULL ||
         vnuma->vcpu_to_vnode == NULL || vnuma->vnode_to_pnode == NULL )
    {
        vnuma_destroy(vnuma);
        return ERR_PTR(-ENOMEM);
    }

    return vnuma;
}

/*
 * Construct vNUMA topology form uinfo.
 */
static struct vnuma_info *vnuma_init(const struct xen_domctl_vnuma *uinfo,
                                     const struct domain *d)
{
    unsigned int i, nr_vnodes;
    int ret = -EINVAL;
    struct vnuma_info *info;

    nr_vnodes = uinfo->nr_vnodes;

    if ( nr_vnodes == 0 || uinfo->nr_vcpus != d->max_vcpus || uinfo->pad != 0 )
        return ERR_PTR(ret);

    info = vnuma_alloc(nr_vnodes, uinfo->nr_vmemranges, d->max_vcpus);
    if ( IS_ERR(info) )
        return info;

    ret = -EFAULT;

    if ( copy_from_guest(info->vdistance, uinfo->vdistance,
                         nr_vnodes * nr_vnodes) )
        goto vnuma_fail;

    if ( copy_from_guest(info->vmemrange, uinfo->vmemrange,
                         uinfo->nr_vmemranges) )
        goto vnuma_fail;

    if ( copy_from_guest(info->vcpu_to_vnode, uinfo->vcpu_to_vnode,
                         d->max_vcpus) )
        goto vnuma_fail;

    ret = -E2BIG;
    for ( i = 0; i < d->max_vcpus; ++i )
        if ( info->vcpu_to_vnode[i] >= nr_vnodes )
            goto vnuma_fail;

    for ( i = 0; i < nr_vnodes; ++i )
    {
        unsigned int pnode;

        ret = -EFAULT;
        if ( copy_from_guest_offset(&pnode, uinfo->vnode_to_pnode, i, 1) )
            goto vnuma_fail;
        ret = -E2BIG;
        if ( pnode >= MAX_NUMNODES )
            goto vnuma_fail;
        info->vnode_to_pnode[i] = pnode;
    }

    info->nr_vnodes = nr_vnodes;
    info->nr_vmemranges = uinfo->nr_vmemranges;

    /* Check that vmemranges flags are zero. */
    ret = -EINVAL;
    for ( i = 0; i < info->nr_vmemranges; i++ )
        if ( info->vmemrange[i].flags != 0 )
            goto vnuma_fail;

    return info;

 vnuma_fail:
    vnuma_destroy(info);
    return ERR_PTR(ret);
}

long do_domctl(XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    long ret = 0;
    bool_t copyback = 0;
    struct xen_domctl curop, *op = &curop;
    struct domain *d;

    if ( copy_from_guest(op, u_domctl, 1) )
        return -EFAULT;

    if ( op->interface_version != XEN_DOMCTL_INTERFACE_VERSION )
        return -EACCES;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_createdomain:
    case XEN_DOMCTL_getdomaininfo:
    case XEN_DOMCTL_test_assign_device:
    case XEN_DOMCTL_gdbsx_guestmemio:
        d = NULL;
        break;
    default:
        d = rcu_lock_domain_by_id(op->domain);
        if ( d == NULL )
            return -ESRCH;
    }

    ret = xsm_domctl(XSM_OTHER, d, op->cmd);
    if ( ret )
        goto domctl_out_unlock_domonly;

    if ( !domctl_lock_acquire() )
    {
        if ( d )
            rcu_unlock_domain(d);
        return hypercall_create_continuation(
            __HYPERVISOR_domctl, "h", u_domctl);
    }

    switch ( op->cmd )
    {

    case XEN_DOMCTL_setvcpucontext:
    {
        vcpu_guest_context_u c = { .nat = NULL };
        unsigned int vcpu = op->u.vcpucontext.vcpu;
        struct vcpu *v;

        ret = -EINVAL;
        if ( (d == current->domain) || /* no domain_pause() */
             (vcpu >= d->max_vcpus) || ((v = d->vcpu[vcpu]) == NULL) )
            break;

        if ( guest_handle_is_null(op->u.vcpucontext.ctxt) )
        {
            ret = vcpu_reset(v);
            if ( ret == -ERESTART )
                ret = hypercall_create_continuation(
                          __HYPERVISOR_domctl, "h", u_domctl);
            break;
        }

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = alloc_vcpu_guest_context()) == NULL )
            break;

#ifdef CONFIG_COMPAT
        if ( !is_pv_32bit_domain(d) )
            ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
        else
            ret = copy_from_guest(c.cmp,
                                  guest_handle_cast(op->u.vcpucontext.ctxt,
                                                    void), 1);
#else
        ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
#endif
        ret = ret ? -EFAULT : 0;

        if ( ret == 0 )
        {
            domain_pause(d);
            ret = arch_set_info_guest(v, c);
            domain_unpause(d);

            if ( ret == -ERESTART )
                ret = hypercall_create_continuation(
                          __HYPERVISOR_domctl, "h", u_domctl);
        }

        free_vcpu_guest_context(c.nat);
        break;
    }

    case XEN_DOMCTL_pausedomain:
        ret = -EINVAL;
        if ( d != current->domain )
            ret = domain_pause_by_systemcontroller(d);
        break;

    case XEN_DOMCTL_unpausedomain:
        ret = domain_unpause_by_systemcontroller(d);
        break;

    case XEN_DOMCTL_resumedomain:
        if ( d == current->domain ) /* no domain_pause() */
            ret = -EINVAL;
        else
            domain_resume(d);
        break;

    case XEN_DOMCTL_createdomain:
    {
        domid_t        dom;
        static domid_t rover = 0;
        unsigned int domcr_flags;

        ret = -EINVAL;
        if ( (op->u.createdomain.flags &
             ~(XEN_DOMCTL_CDF_hvm_guest
               | XEN_DOMCTL_CDF_pvh_guest
               | XEN_DOMCTL_CDF_hap
               | XEN_DOMCTL_CDF_s3_integrity
               | XEN_DOMCTL_CDF_oos_off)) )
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
                    dom = 1;
                if ( is_free_domid(dom) )
                    break;
            }

            ret = -ENOMEM;
            if ( dom == rover )
                break;

            rover = dom;
        }

        if ( (op->u.createdomain.flags & XEN_DOMCTL_CDF_hvm_guest)
             && (op->u.createdomain.flags & XEN_DOMCTL_CDF_pvh_guest) )
            return -EINVAL;

        domcr_flags = 0;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_hvm_guest )
            domcr_flags |= DOMCRF_hvm;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_pvh_guest )
            domcr_flags |= DOMCRF_pvh;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_hap )
            domcr_flags |= DOMCRF_hap;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_s3_integrity )
            domcr_flags |= DOMCRF_s3_integrity;
        if ( op->u.createdomain.flags & XEN_DOMCTL_CDF_oos_off )
            domcr_flags |= DOMCRF_oos_off;

        d = domain_create(dom, domcr_flags, op->u.createdomain.ssidref,
                          &op->u.createdomain.config);
        if ( IS_ERR(d) )
        {
            ret = PTR_ERR(d);
            d = NULL;
            break;
        }

        ret = 0;

        memcpy(d->handle, op->u.createdomain.handle,
               sizeof(xen_domain_handle_t));

        op->domain = d->domain_id;
        copyback = 1;
        d = NULL;
        break;
    }

    case XEN_DOMCTL_max_vcpus:
    {
        unsigned int i, max = op->u.max_vcpus.max, cpu;
        cpumask_t *online;

        ret = -EINVAL;
        if ( (d == current->domain) || /* no domain_pause() */
             (max > domain_max_vcpus(d)) )
            break;

        /* Until Xenoprof can dynamically grow its vcpu-s array... */
        if ( d->xenoprof )
        {
            ret = -EAGAIN;
            break;
        }

        /* Needed, for example, to ensure writable p.t. state is synced. */
        domain_pause(d);

        /*
         * Certain operations (e.g. CPU microcode updates) modify data which is
         * used during VCPU allocation/initialization
         */
        while ( !spin_trylock(&vcpu_alloc_lock) )
        {
            if ( hypercall_preempt_check() )
            {
                ret =  hypercall_create_continuation(
                    __HYPERVISOR_domctl, "h", u_domctl);
                goto maxvcpu_out_novcpulock;
            }
        }

        /* We cannot reduce maximum VCPUs. */
        ret = -EINVAL;
        if ( (max < d->max_vcpus) && (d->vcpu[max] != NULL) )
            goto maxvcpu_out;

        /*
         * For now don't allow increasing the vcpu count from a non-zero
         * value: This code and all readers of d->vcpu would otherwise need
         * to be converted to use RCU, but at present there's no tools side
         * code path that would issue such a request.
         */
        ret = -EBUSY;
        if ( (d->max_vcpus > 0) && (max > d->max_vcpus) )
            goto maxvcpu_out;

        ret = -ENOMEM;
        online = cpupool_online_cpumask(d->cpupool);
        if ( max > d->max_vcpus )
        {
            struct vcpu **vcpus;

            BUG_ON(d->vcpu != NULL);
            BUG_ON(d->max_vcpus != 0);

            if ( (vcpus = xzalloc_array(struct vcpu *, max)) == NULL )
                goto maxvcpu_out;

            /* Install vcpu array /then/ update max_vcpus. */
            d->vcpu = vcpus;
            smp_wmb();
            d->max_vcpus = max;
        }

        for ( i = 0; i < max; i++ )
        {
            if ( d->vcpu[i] != NULL )
                continue;

            cpu = (i == 0) ?
                default_vcpu0_location(online) :
                cpumask_cycle(d->vcpu[i-1]->processor, online);

            if ( alloc_vcpu(d, i, cpu) == NULL )
                goto maxvcpu_out;
        }

        ret = 0;

    maxvcpu_out:
        spin_unlock(&vcpu_alloc_lock);

    maxvcpu_out_novcpulock:
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_destroydomain:
        ret = domain_kill(d);
        if ( ret == -ERESTART )
            ret = hypercall_create_continuation(
                __HYPERVISOR_domctl, "h", u_domctl);
        break;

    case XEN_DOMCTL_setnodeaffinity:
    {
        nodemask_t new_affinity;

        ret = xenctl_bitmap_to_nodemask(&new_affinity,
                                        &op->u.nodeaffinity.nodemap);
        if ( !ret )
            ret = domain_set_node_affinity(d, &new_affinity);
        break;
    }

    case XEN_DOMCTL_getnodeaffinity:
        ret = nodemask_to_xenctl_bitmap(&op->u.nodeaffinity.nodemap,
                                        &d->node_affinity);
        break;

    case XEN_DOMCTL_setvcpuaffinity:
    case XEN_DOMCTL_getvcpuaffinity:
    {
        struct vcpu *v;
        xen_domctl_vcpuaffinity_t *vcpuaff = &op->u.vcpuaffinity;

        ret = -EINVAL;
        if ( vcpuaff->vcpu >= d->max_vcpus )
            break;

        ret = -ESRCH;
        if ( (v = d->vcpu[vcpuaff->vcpu]) == NULL )
            break;

        ret = -EINVAL;
        if ( vcpuaffinity_params_invalid(vcpuaff) )
            break;

        if ( op->cmd == XEN_DOMCTL_setvcpuaffinity )
        {
            cpumask_var_t new_affinity, old_affinity;
            cpumask_t *online = cpupool_online_cpumask(v->domain->cpupool);;

            /*
             * We want to be able to restore hard affinity if we are trying
             * setting both and changing soft affinity (which happens later,
             * when hard affinity has been succesfully chaged already) fails.
             */
            if ( !alloc_cpumask_var(&old_affinity) )
            {
                ret = -ENOMEM;
                break;
            }
            cpumask_copy(old_affinity, v->cpu_hard_affinity);

            if ( !alloc_cpumask_var(&new_affinity) )
            {
                free_cpumask_var(old_affinity);
                ret = -ENOMEM;
                break;
            }

            /*
             * We both set a new affinity and report back to the caller what
             * the scheduler will be effectively using.
             */
            if ( vcpuaff->flags & XEN_VCPUAFFINITY_HARD )
            {
                ret = xenctl_bitmap_to_bitmap(cpumask_bits(new_affinity),
                                              &vcpuaff->cpumap_hard,
                                              nr_cpu_ids);
                if ( !ret )
                    ret = vcpu_set_hard_affinity(v, new_affinity);
                if ( ret )
                    goto setvcpuaffinity_out;

                /*
                 * For hard affinity, what we return is the intersection of
                 * cpupool's online mask and the new hard affinity.
                 */
                cpumask_and(new_affinity, online, v->cpu_hard_affinity);
                ret = cpumask_to_xenctl_bitmap(&vcpuaff->cpumap_hard,
                                               new_affinity);
            }
            if ( vcpuaff->flags & XEN_VCPUAFFINITY_SOFT )
            {
                ret = xenctl_bitmap_to_bitmap(cpumask_bits(new_affinity),
                                              &vcpuaff->cpumap_soft,
                                              nr_cpu_ids);
                if ( !ret)
                    ret = vcpu_set_soft_affinity(v, new_affinity);
                if ( ret )
                {
                    /*
                     * Since we're returning error, the caller expects nothing
                     * happened, so we rollback the changes to hard affinity
                     * (if any).
                     */
                    if ( vcpuaff->flags & XEN_VCPUAFFINITY_HARD )
                        vcpu_set_hard_affinity(v, old_affinity);
                    goto setvcpuaffinity_out;
                }

                /*
                 * For soft affinity, we return the intersection between the
                 * new soft affinity, the cpupool's online map and the (new)
                 * hard affinity.
                 */
                cpumask_and(new_affinity, new_affinity, online);
                cpumask_and(new_affinity, new_affinity, v->cpu_hard_affinity);
                ret = cpumask_to_xenctl_bitmap(&vcpuaff->cpumap_soft,
                                               new_affinity);
            }

 setvcpuaffinity_out:
            free_cpumask_var(new_affinity);
            free_cpumask_var(old_affinity);
        }
        else
        {
            if ( vcpuaff->flags & XEN_VCPUAFFINITY_HARD )
                ret = cpumask_to_xenctl_bitmap(&vcpuaff->cpumap_hard,
                                               v->cpu_hard_affinity);
            if ( vcpuaff->flags & XEN_VCPUAFFINITY_SOFT )
                ret = cpumask_to_xenctl_bitmap(&vcpuaff->cpumap_soft,
                                               v->cpu_soft_affinity);
        }
        break;
    }

    case XEN_DOMCTL_scheduler_op:
        ret = sched_adjust(d, &op->u.scheduler_op);
        copyback = 1;
        break;

    case XEN_DOMCTL_getdomaininfo:
    {
        domid_t dom = op->domain;

        rcu_read_lock(&domlist_read_lock);

        for_each_domain ( d )
            if ( d->domain_id >= dom )
                break;

        ret = -ESRCH;
        if ( d == NULL )
            goto getdomaininfo_out;

        ret = xsm_getdomaininfo(XSM_HOOK, d);
        if ( ret )
            goto getdomaininfo_out;

        getdomaininfo(d, &op->u.getdomaininfo);

        op->domain = op->u.getdomaininfo.domain;
        copyback = 1;

    getdomaininfo_out:
        rcu_read_unlock(&domlist_read_lock);
        d = NULL;
        break;
    }

    case XEN_DOMCTL_getvcpucontext:
    {
        vcpu_guest_context_u c = { .nat = NULL };
        struct vcpu         *v;

        ret = -EINVAL;
        if ( op->u.vcpucontext.vcpu >= d->max_vcpus ||
             (v = d->vcpu[op->u.vcpucontext.vcpu]) == NULL ||
             v == current ) /* no vcpu_pause() */
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

        vcpu_pause(v);

        arch_get_info_guest(v, c);
        ret = 0;

        vcpu_unpause(v);

#ifdef CONFIG_COMPAT
        if ( !is_pv_32bit_domain(d) )
            ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
        else
            ret = copy_to_guest(guest_handle_cast(op->u.vcpucontext.ctxt,
                                                  void), c.cmp, 1);
#else
        ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
#endif

        if ( ret )
            ret = -EFAULT;
        copyback = 1;

    getvcpucontext_out:
        xfree(c.nat);
        break;
    }

    case XEN_DOMCTL_getvcpuinfo:
    {
        struct vcpu   *v;
        struct vcpu_runstate_info runstate;

        ret = -EINVAL;
        if ( op->u.getvcpuinfo.vcpu >= d->max_vcpus )
            break;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.getvcpuinfo.vcpu]) == NULL )
            break;

        vcpu_runstate_get(v, &runstate);

        op->u.getvcpuinfo.online   = !test_bit(_VPF_down, &v->pause_flags);
        op->u.getvcpuinfo.blocked  = test_bit(_VPF_blocked, &v->pause_flags);
        op->u.getvcpuinfo.running  = v->is_running;
        op->u.getvcpuinfo.cpu_time = runstate.time[RUNSTATE_running];
        op->u.getvcpuinfo.cpu      = v->processor;
        ret = 0;
        copyback = 1;
        break;
    }

    case XEN_DOMCTL_max_mem:
    {
        uint64_t new_max = op->u.max_mem.max_memkb >> (PAGE_SHIFT - 10);

        spin_lock(&d->page_alloc_lock);
        /*
         * NB. We removed a check that new_max >= current tot_pages; this means
         * that the domain will now be allowed to "ratchet" down to new_max. In
         * the meantime, while tot > max, all new allocations are disallowed.
         */
        d->max_pages = min(new_max, (uint64_t)(typeof(d->max_pages))-1);
        spin_unlock(&d->page_alloc_lock);
        break;
    }

    case XEN_DOMCTL_setdomainhandle:
        memcpy(d->handle, op->u.setdomainhandle.handle,
               sizeof(xen_domain_handle_t));
        break;

    case XEN_DOMCTL_setdebugging:
        if ( unlikely(d == current->domain) ) /* no domain_pause() */
            ret = -EINVAL;
        else
        {
            domain_pause(d);
            d->debugger_attached = !!op->u.setdebugging.enable;
            domain_unpause(d); /* causes guest to latch new status */
        }
        break;

    case XEN_DOMCTL_irq_permission:
    {
        unsigned int pirq = op->u.irq_permission.pirq, irq;
        int allow = op->u.irq_permission.allow_access;

        if ( pirq >= current->domain->nr_pirqs )
        {
            ret = -EINVAL;
            break;
        }
        irq = pirq_access_permitted(current->domain, pirq);
        if ( !irq || xsm_irq_permission(XSM_HOOK, d, irq, allow) )
            ret = -EPERM;
        else if ( allow )
            ret = irq_permit_access(d, irq);
        else
            ret = irq_deny_access(d, irq);
        break;
    }

    case XEN_DOMCTL_iomem_permission:
    {
        unsigned long mfn = op->u.iomem_permission.first_mfn;
        unsigned long nr_mfns = op->u.iomem_permission.nr_mfns;
        int allow = op->u.iomem_permission.allow_access;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        if ( !iomem_access_permitted(current->domain,
                                     mfn, mfn + nr_mfns - 1) ||
             xsm_iomem_permission(XSM_HOOK, d, mfn, mfn + nr_mfns - 1, allow) )
            ret = -EPERM;
        else if ( allow )
            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
        else
            ret = iomem_deny_access(d, mfn, mfn + nr_mfns - 1);
        if ( !ret )
            memory_type_changed(d);
        break;
    }

    case XEN_DOMCTL_memory_mapping:
    {
        unsigned long gfn = op->u.memory_mapping.first_gfn;
        unsigned long mfn = op->u.memory_mapping.first_mfn;
        unsigned long nr_mfns = op->u.memory_mapping.nr_mfns;
        unsigned long mfn_end = mfn + nr_mfns - 1;
        int add = op->u.memory_mapping.add_mapping;

        ret = -EINVAL;
        if ( mfn_end < mfn || /* wrap? */
             ((mfn | mfn_end) >> (paddr_bits - PAGE_SHIFT)) ||
             (gfn + nr_mfns - 1) < gfn ) /* wrap? */
            break;

        ret = -E2BIG;
        /* Must break hypercall up as this could take a while. */
        if ( nr_mfns > 64 )
            break;

        ret = -EPERM;
        if ( !iomem_access_permitted(current->domain, mfn, mfn_end) ||
             !iomem_access_permitted(d, mfn, mfn_end) )
            break;

        ret = xsm_iomem_mapping(XSM_HOOK, d, mfn, mfn_end, add);
        if ( ret )
            break;

        if ( add )
        {
            printk(XENLOG_G_INFO
                   "memory_map:add: dom%d gfn=%lx mfn=%lx nr=%lx\n",
                   d->domain_id, gfn, mfn, nr_mfns);

            ret = map_mmio_regions(d, gfn, nr_mfns, mfn);
            if ( ret )
                printk(XENLOG_G_WARNING
                       "memory_map:fail: dom%d gfn=%lx mfn=%lx nr=%lx ret:%ld\n",
                       d->domain_id, gfn, mfn, nr_mfns, ret);
        }
        else
        {
            printk(XENLOG_G_INFO
                   "memory_map:remove: dom%d gfn=%lx mfn=%lx nr=%lx\n",
                   d->domain_id, gfn, mfn, nr_mfns);

            ret = unmap_mmio_regions(d, gfn, nr_mfns, mfn);
            if ( ret && is_hardware_domain(current->domain) )
                printk(XENLOG_ERR
                       "memory_map: error %ld removing dom%d access to [%lx,%lx]\n",
                       ret, d->domain_id, mfn, mfn_end);
        }
        /* Do this unconditionally to cover errors on above failure paths. */
        memory_type_changed(d);
        break;
    }

    case XEN_DOMCTL_settimeoffset:
        domain_set_time_offset(d, op->u.settimeoffset.time_offset_seconds);
        break;

    case XEN_DOMCTL_set_target:
    {
        struct domain *e;

        ret = -ESRCH;
        e = get_domain_by_id(op->u.set_target.target);
        if ( e == NULL )
            break;

        ret = -EINVAL;
        if ( (d == e) || (d->target != NULL) )
        {
            put_domain(e);
            break;
        }

        ret = xsm_set_target(XSM_HOOK, d, e);
        if ( ret ) {
            put_domain(e);
            break;
        }

        /* Hold reference on @e until we destroy @d. */
        d->target = e;
        break;
    }

    case XEN_DOMCTL_subscribe:
        d->suspend_evtchn = op->u.subscribe.port;
        break;

    case XEN_DOMCTL_vm_event_op:
        ret = vm_event_domctl(d, &op->u.vm_event_op,
                              guest_handle_cast(u_domctl, void));
        copyback = 1;
        break;

    case XEN_DOMCTL_disable_migrate:
        d->disable_migrate = op->u.disable_migrate.disable;
        break;

#ifdef HAS_MEM_ACCESS
    case XEN_DOMCTL_set_access_required:
        if ( unlikely(current->domain == d) )
            ret = -EPERM;
        else
            p2m_get_hostp2m(d)->access_required =
                op->u.access_required.access_required;
        break;
#endif

    case XEN_DOMCTL_set_virq_handler:
        ret = set_global_virq_handler(d, op->u.set_virq_handler.virq);
        break;

    case XEN_DOMCTL_set_max_evtchn:
        d->max_evtchn_port = min_t(unsigned int,
                                   op->u.set_max_evtchn.max_port,
                                   INT_MAX);
        break;

    case XEN_DOMCTL_setvnumainfo:
    {
        struct vnuma_info *vnuma;

        vnuma = vnuma_init(&op->u.vnuma, d);
        if ( IS_ERR(vnuma) )
        {
            ret = PTR_ERR(vnuma);
            break;
        }

        /* overwrite vnuma topology for domain. */
        write_lock(&d->vnuma_rwlock);
        vnuma_destroy(d->vnuma);
        d->vnuma = vnuma;
        write_unlock(&d->vnuma_rwlock);

        break;
    }

    case XEN_DOMCTL_monitor_op:
        ret = -EPERM;
        if ( current->domain == d )
            break;

        ret = monitor_domctl(d, &op->u.monitor_op);
        if ( !ret )
            copyback = 1;
        break;

    default:
        ret = arch_do_domctl(op, d, u_domctl);
        break;
    }

    domctl_lock_release();

 domctl_out_unlock_domonly:
    if ( d )
        rcu_unlock_domain(d);

    if ( copyback && __copy_to_guest(u_domctl, op, 1) )
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
