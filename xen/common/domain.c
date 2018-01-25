/******************************************************************************
 * domain.c
 * 
 * Generic domain-handling functions.
 */

#include <xen/compat.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/err.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/domain.h>
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/vm_event.h>
#include <xen/time.h>
#include <xen/console.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/domain_page.h>
#include <xen/rangeset.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/delay.h>
#include <xen/shutdown.h>
#include <xen/percpu.h>
#include <xen/multicall.h>
#include <xen/rcupdate.h>
#include <xen/wait.h>
#include <xen/grant_table.h>
#include <xen/xenoprof.h>
#include <xen/irq.h>
#include <asm/debugger.h>
#include <asm/p2m.h>
#include <asm/processor.h>
#include <public/sched.h>
#include <public/sysctl.h>
#include <public/vcpu.h>
#include <xsm/xsm.h>
#include <xen/trace.h>
#include <xen/tmem.h>
#include <asm/setup.h>

#ifdef CONFIG_X86
#include <asm/guest.h>
#endif

/* Linux config option: propageted to domain0 */
/* xen_processor_pmbits: xen control Cx, Px, ... */
unsigned int xen_processor_pmbits = XEN_PROCESSOR_PM_PX;

/* opt_dom0_vcpus_pin: If true, dom0 VCPUs are pinned. */
bool_t opt_dom0_vcpus_pin;
boolean_param("dom0_vcpus_pin", opt_dom0_vcpus_pin);

/* Protect updates/reads (resp.) of domain_list and domain_hash. */
DEFINE_SPINLOCK(domlist_update_lock);
DEFINE_RCU_READ_LOCK(domlist_read_lock);

#define DOMAIN_HASH_SIZE 256
#define DOMAIN_HASH(_id) ((int)(_id)&(DOMAIN_HASH_SIZE-1))
static struct domain *domain_hash[DOMAIN_HASH_SIZE];
struct domain *domain_list;

struct domain *hardware_domain __read_mostly;

#ifdef CONFIG_LATE_HWDOM
domid_t hardware_domid __read_mostly;
integer_param("hardware_dom", hardware_domid);
#endif

struct vcpu *idle_vcpu[NR_CPUS] __read_mostly;

vcpu_info_t dummy_vcpu_info;

static void __domain_finalise_shutdown(struct domain *d)
{
    struct vcpu *v;

    BUG_ON(!spin_is_locked(&d->shutdown_lock));

    if ( d->is_shut_down )
        return;

    for_each_vcpu ( d, v )
        if ( !v->paused_for_shutdown )
            return;

    d->is_shut_down = 1;
    if ( (d->shutdown_code == SHUTDOWN_suspend) && d->suspend_evtchn )
        evtchn_send(d, d->suspend_evtchn);
    else
        send_global_virq(VIRQ_DOM_EXC);
}

static void vcpu_check_shutdown(struct vcpu *v)
{
    struct domain *d = v->domain;

    spin_lock(&d->shutdown_lock);

    if ( d->is_shutting_down )
    {
        if ( !v->paused_for_shutdown )
            vcpu_pause_nosync(v);
        v->paused_for_shutdown = 1;
        v->defer_shutdown = 0;
        __domain_finalise_shutdown(d);
    }

    spin_unlock(&d->shutdown_lock);
}

static void vcpu_info_reset(struct vcpu *v)
{
    struct domain *d = v->domain;

    v->vcpu_info = ((v->vcpu_id < XEN_LEGACY_MAX_VCPUS)
                    ? (vcpu_info_t *)&shared_info(d, vcpu_info[v->vcpu_id])
                    : &dummy_vcpu_info);
    v->vcpu_info_mfn = INVALID_MFN;
}

struct vcpu *alloc_vcpu(
    struct domain *d, unsigned int vcpu_id, unsigned int cpu_id)
{
    struct vcpu *v;

    BUG_ON((!is_idle_domain(d) || vcpu_id) && d->vcpu[vcpu_id]);

    if ( (v = alloc_vcpu_struct()) == NULL )
        return NULL;

    v->domain = d;
    v->vcpu_id = vcpu_id;
    v->dirty_cpu = VCPU_CPU_CLEAN;

    spin_lock_init(&v->virq_lock);

    tasklet_init(&v->continue_hypercall_tasklet, NULL, 0);

    grant_table_init_vcpu(v);

    if ( !zalloc_cpumask_var(&v->cpu_hard_affinity) ||
         !zalloc_cpumask_var(&v->cpu_hard_affinity_tmp) ||
         !zalloc_cpumask_var(&v->cpu_hard_affinity_saved) ||
         !zalloc_cpumask_var(&v->cpu_soft_affinity) )
        goto fail_free;

    if ( is_idle_domain(d) )
    {
        v->runstate.state = RUNSTATE_running;
    }
    else
    {
        v->runstate.state = RUNSTATE_offline;        
        v->runstate.state_entry_time = NOW();
        set_bit(_VPF_down, &v->pause_flags);
        vcpu_info_reset(v);
        init_waitqueue_vcpu(v);
    }

    if ( sched_init_vcpu(v, cpu_id) != 0 )
        goto fail_wq;

    if ( vcpu_initialise(v) != 0 )
    {
        sched_destroy_vcpu(v);
 fail_wq:
        destroy_waitqueue_vcpu(v);
 fail_free:
        free_cpumask_var(v->cpu_hard_affinity);
        free_cpumask_var(v->cpu_hard_affinity_tmp);
        free_cpumask_var(v->cpu_hard_affinity_saved);
        free_cpumask_var(v->cpu_soft_affinity);
        free_vcpu_struct(v);
        return NULL;
    }

    d->vcpu[vcpu_id] = v;
    if ( vcpu_id != 0 )
    {
        int prev_id = v->vcpu_id - 1;
        while ( (prev_id >= 0) && (d->vcpu[prev_id] == NULL) )
            prev_id--;
        BUG_ON(prev_id < 0);
        v->next_in_list = d->vcpu[prev_id]->next_in_list;
        d->vcpu[prev_id]->next_in_list = v;
    }

    /* Must be called after making new vcpu visible to for_each_vcpu(). */
    vcpu_check_shutdown(v);

    if ( !is_idle_domain(d) )
        domain_update_node_affinity(d);

    return v;
}

static int late_hwdom_init(struct domain *d)
{
#ifdef CONFIG_LATE_HWDOM
    struct domain *dom0;
    int rv;

    if ( d != hardware_domain || d->domain_id == 0 )
        return 0;

    rv = xsm_init_hardware_domain(XSM_HOOK, d);
    if ( rv )
        return rv;

    printk("Initialising hardware domain %d\n", hardware_domid);

    dom0 = rcu_lock_domain_by_id(0);
    ASSERT(dom0 != NULL);
    /*
     * Hardware resource ranges for domain 0 have been set up from
     * various sources intended to restrict the hardware domain's
     * access.  Apply these ranges to the actual hardware domain.
     *
     * Because the lists are being swapped, a side effect of this
     * operation is that Domain 0's rangesets are cleared.  Since
     * domain 0 should not be accessing the hardware when it constructs
     * a hardware domain, this should not be a problem.  Both lists
     * may be modified after this hypercall returns if a more complex
     * device model is desired.
     */
    rangeset_swap(d->irq_caps, dom0->irq_caps);
    rangeset_swap(d->iomem_caps, dom0->iomem_caps);
#ifdef CONFIG_X86
    rangeset_swap(d->arch.ioport_caps, dom0->arch.ioport_caps);
    setup_io_bitmap(d);
    setup_io_bitmap(dom0);
#endif

    rcu_unlock_domain(dom0);

    iommu_hwdom_init(d);

    return rv;
#else
    return 0;
#endif
}

static unsigned int __read_mostly extra_hwdom_irqs;
static unsigned int __read_mostly extra_domU_irqs = 32;

static int __init parse_extra_guest_irqs(const char *s)
{
    if ( isdigit(*s) )
        extra_domU_irqs = simple_strtoul(s, &s, 0);
    if ( *s == ',' && isdigit(*++s) )
        extra_hwdom_irqs = simple_strtoul(s, &s, 0);

    return *s ? -EINVAL : 0;
}
custom_param("extra_guest_irqs", parse_extra_guest_irqs);

struct domain *domain_create(domid_t domid, unsigned int domcr_flags,
                             uint32_t ssidref,
                             struct xen_arch_domainconfig *config)
{
    struct domain *d, **pd, *old_hwdom = NULL;
    enum { INIT_xsm = 1u<<0, INIT_watchdog = 1u<<1, INIT_rangeset = 1u<<2,
           INIT_evtchn = 1u<<3, INIT_gnttab = 1u<<4, INIT_arch = 1u<<5 };
    int err, init_status = 0;
    int poolid = CPUPOOLID_NONE;

    if ( (d = alloc_domain_struct()) == NULL )
        return ERR_PTR(-ENOMEM);

    d->domain_id = domid;

    TRACE_1D(TRC_DOM0_DOM_ADD, d->domain_id);

    lock_profile_register_struct(LOCKPROF_TYPE_PERDOM, d, domid, "Domain");

    if ( (err = xsm_alloc_security_domain(d)) != 0 )
        goto fail;
    init_status |= INIT_xsm;

    watchdog_domain_init(d);
    init_status |= INIT_watchdog;

    atomic_set(&d->refcnt, 1);
    spin_lock_init_prof(d, domain_lock);
    spin_lock_init_prof(d, page_alloc_lock);
    spin_lock_init(&d->hypercall_deadlock_mutex);
    INIT_PAGE_LIST_HEAD(&d->page_list);
    INIT_PAGE_LIST_HEAD(&d->xenpage_list);

    spin_lock_init(&d->node_affinity_lock);
    d->node_affinity = NODE_MASK_ALL;
    d->auto_node_affinity = 1;

    spin_lock_init(&d->shutdown_lock);
    d->shutdown_code = SHUTDOWN_CODE_INVALID;

    spin_lock_init(&d->pbuf_lock);

    rwlock_init(&d->vnuma_rwlock);

    err = -ENOMEM;
    if ( !zalloc_cpumask_var(&d->dirty_cpumask) )
        goto fail;

    if ( domcr_flags & DOMCRF_hvm )
        d->guest_type = guest_type_hvm;
    else
        d->guest_type = guest_type_pv;

    if ( domid == 0 || domid == hardware_domid )
    {
        if ( hardware_domid < 0 || hardware_domid >= DOMID_FIRST_RESERVED )
            panic("The value of hardware_dom must be a valid domain ID");
        d->is_pinned = opt_dom0_vcpus_pin;
        d->disable_migrate = 1;
        old_hwdom = hardware_domain;
        hardware_domain = d;
    }

    if ( domcr_flags & DOMCRF_xs_domain )
    {
        d->is_xenstore = 1;
        d->disable_migrate = 1;
    }

    rangeset_domain_initialise(d);
    init_status |= INIT_rangeset;

    d->iomem_caps = rangeset_new(d, "I/O Memory", RANGESETF_prettyprint_hex);
    d->irq_caps   = rangeset_new(d, "Interrupts", 0);
    if ( (d->iomem_caps == NULL) || (d->irq_caps == NULL) )
        goto fail;

    if ( domcr_flags & DOMCRF_dummy )
        return d;

    if ( !is_idle_domain(d) )
    {
        if ( (err = xsm_domain_create(XSM_HOOK, d, ssidref)) != 0 )
            goto fail;

        d->controller_pause_count = 1;
        atomic_inc(&d->pause_count);

        if ( !is_hardware_domain(d) )
            d->nr_pirqs = nr_static_irqs + extra_domU_irqs;
        else
            d->nr_pirqs = extra_hwdom_irqs ? nr_static_irqs + extra_hwdom_irqs
                                           : arch_hwdom_irqs(domid);
        if ( d->nr_pirqs > nr_irqs )
            d->nr_pirqs = nr_irqs;

        radix_tree_init(&d->pirq_tree);

        if ( (err = evtchn_init(d)) != 0 )
            goto fail;
        init_status |= INIT_evtchn;

        if ( (err = grant_table_create(d)) != 0 )
            goto fail;
        init_status |= INIT_gnttab;

        poolid = 0;

        err = -ENOMEM;

        d->pbuf = xzalloc_array(char, DOMAIN_PBUF_SIZE);
        if ( !d->pbuf )
            goto fail;
    }

    if ( (err = arch_domain_create(d, domcr_flags, config)) != 0 )
        goto fail;
    init_status |= INIT_arch;

    if ( (err = sched_init_domain(d, poolid)) != 0 )
        goto fail;

    if ( (err = late_hwdom_init(d)) != 0 )
        goto fail;

    if ( !is_idle_domain(d) )
    {
        spin_lock(&domlist_update_lock);
        pd = &domain_list; /* NB. domain_list maintained in order of domid. */
        for ( pd = &domain_list; *pd != NULL; pd = &(*pd)->next_in_list )
            if ( (*pd)->domain_id > d->domain_id )
                break;
        d->next_in_list = *pd;
        d->next_in_hashbucket = domain_hash[DOMAIN_HASH(domid)];
        rcu_assign_pointer(*pd, d);
        rcu_assign_pointer(domain_hash[DOMAIN_HASH(domid)], d);
        spin_unlock(&domlist_update_lock);
    }

    return d;

 fail:
    d->is_dying = DOMDYING_dead;
    if ( hardware_domain == d )
        hardware_domain = old_hwdom;
    atomic_set(&d->refcnt, DOMAIN_DESTROYED);
    xfree(d->pbuf);
    if ( init_status & INIT_arch )
        arch_domain_destroy(d);
    if ( init_status & INIT_gnttab )
        grant_table_destroy(d);
    if ( init_status & INIT_evtchn )
    {
        evtchn_destroy(d);
        evtchn_destroy_final(d);
        radix_tree_destroy(&d->pirq_tree, free_pirq_struct);
    }
    if ( init_status & INIT_rangeset )
        rangeset_domain_destroy(d);
    if ( init_status & INIT_watchdog )
        watchdog_domain_destroy(d);
    if ( init_status & INIT_xsm )
        xsm_free_security_domain(d);
    free_cpumask_var(d->dirty_cpumask);
    free_domain_struct(d);
    return ERR_PTR(err);
}


void domain_update_node_affinity(struct domain *d)
{
    cpumask_var_t dom_cpumask, dom_cpumask_soft;
    cpumask_t *dom_affinity;
    const cpumask_t *online;
    struct vcpu *v;
    unsigned int cpu;

    /* Do we have vcpus already? If not, no need to update node-affinity. */
    if ( !d->vcpu || !d->vcpu[0] )
        return;

    if ( !zalloc_cpumask_var(&dom_cpumask) )
        return;
    if ( !zalloc_cpumask_var(&dom_cpumask_soft) )
    {
        free_cpumask_var(dom_cpumask);
        return;
    }

    online = cpupool_domain_cpumask(d);

    spin_lock(&d->node_affinity_lock);

    /*
     * If d->auto_node_affinity is true, let's compute the domain's
     * node-affinity and update d->node_affinity accordingly. if false,
     * just leave d->auto_node_affinity alone.
     */
    if ( d->auto_node_affinity )
    {
        /*
         * We want the narrowest possible set of pcpus (to get the narowest
         * possible set of nodes). What we need is the cpumask of where the
         * domain can run (the union of the hard affinity of all its vcpus),
         * and the full mask of where it would prefer to run (the union of
         * the soft affinity of all its various vcpus). Let's build them.
         */
        for_each_vcpu ( d, v )
        {
            cpumask_or(dom_cpumask, dom_cpumask, v->cpu_hard_affinity);
            cpumask_or(dom_cpumask_soft, dom_cpumask_soft,
                       v->cpu_soft_affinity);
        }
        /* Filter out non-online cpus */
        cpumask_and(dom_cpumask, dom_cpumask, online);
        ASSERT(!cpumask_empty(dom_cpumask));
        /* And compute the intersection between hard, online and soft */
        cpumask_and(dom_cpumask_soft, dom_cpumask_soft, dom_cpumask);

        /*
         * If not empty, the intersection of hard, soft and online is the
         * narrowest set we want. If empty, we fall back to hard&online.
         */
        dom_affinity = cpumask_empty(dom_cpumask_soft) ?
                           dom_cpumask : dom_cpumask_soft;

        nodes_clear(d->node_affinity);
        for_each_cpu ( cpu, dom_affinity )
            node_set(cpu_to_node(cpu), d->node_affinity);
    }

    spin_unlock(&d->node_affinity_lock);

    free_cpumask_var(dom_cpumask_soft);
    free_cpumask_var(dom_cpumask);
}


int domain_set_node_affinity(struct domain *d, const nodemask_t *affinity)
{
    /* Being affine with no nodes is just wrong */
    if ( nodes_empty(*affinity) )
        return -EINVAL;

    spin_lock(&d->node_affinity_lock);

    /*
     * Being/becoming explicitly affine to all nodes is not particularly
     * useful. Let's take it as the `reset node affinity` command.
     */
    if ( nodes_full(*affinity) )
    {
        d->auto_node_affinity = 1;
        goto out;
    }

    d->auto_node_affinity = 0;
    d->node_affinity = *affinity;

out:
    spin_unlock(&d->node_affinity_lock);

    domain_update_node_affinity(d);

    return 0;
}


struct domain *get_domain_by_id(domid_t dom)
{
    struct domain *d;

    rcu_read_lock(&domlist_read_lock);

    for ( d = rcu_dereference(domain_hash[DOMAIN_HASH(dom)]);
          d != NULL;
          d = rcu_dereference(d->next_in_hashbucket) )
    {
        if ( d->domain_id == dom )
        {
            if ( unlikely(!get_domain(d)) )
                d = NULL;
            break;
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    return d;
}


struct domain *rcu_lock_domain_by_id(domid_t dom)
{
    struct domain *d = NULL;

    rcu_read_lock(&domlist_read_lock);

    for ( d = rcu_dereference(domain_hash[DOMAIN_HASH(dom)]);
          d != NULL;
          d = rcu_dereference(d->next_in_hashbucket) )
    {
        if ( d->domain_id == dom )
        {
            rcu_lock_domain(d);
            break;
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    return d;
}

struct domain *rcu_lock_domain_by_any_id(domid_t dom)
{
    if ( dom == DOMID_SELF )
        return rcu_lock_current_domain();
    return rcu_lock_domain_by_id(dom);
}

int rcu_lock_remote_domain_by_id(domid_t dom, struct domain **d)
{
    if ( (*d = rcu_lock_domain_by_id(dom)) == NULL )
        return -ESRCH;

    if ( *d == current->domain )
    {
        rcu_unlock_domain(*d);
        return -EPERM;
    }

    return 0;
}

int rcu_lock_live_remote_domain_by_id(domid_t dom, struct domain **d)
{
    int rv;
    rv = rcu_lock_remote_domain_by_id(dom, d);
    if ( rv )
        return rv;
    if ( (*d)->is_dying )
    {
        rcu_unlock_domain(*d);
        return -EINVAL;
    }

    return 0;
}

int domain_kill(struct domain *d)
{
    int rc = 0;
    struct vcpu *v;

    if ( d == current->domain )
        return -EINVAL;

    /* Protected by d->domain_lock. */
    switch ( d->is_dying )
    {
    case DOMDYING_alive:
        domain_unlock(d);
        domain_pause(d);
        domain_lock(d);
        /*
         * With the domain lock dropped, d->is_dying may have changed. Call
         * ourselves recursively if so, which is safe as then we won't come
         * back here.
         */
        if ( d->is_dying != DOMDYING_alive )
            return domain_kill(d);
        d->is_dying = DOMDYING_dying;
        evtchn_destroy(d);
        gnttab_release_mappings(d);
        tmem_destroy(d->tmem_client);
        vnuma_destroy(d->vnuma);
        domain_set_outstanding_pages(d, 0);
        d->tmem_client = NULL;
        /* fallthrough */
    case DOMDYING_dying:
        rc = domain_relinquish_resources(d);
        if ( rc != 0 )
            break;
        if ( cpupool_move_domain(d, cpupool0) )
            return -ERESTART;
        for_each_vcpu ( d, v )
            unmap_vcpu_info(v);
        d->is_dying = DOMDYING_dead;
        /* Mem event cleanup has to go here because the rings 
         * have to be put before we call put_domain. */
        vm_event_cleanup(d);
        put_domain(d);
        send_global_virq(VIRQ_DOM_EXC);
        /* fallthrough */
    case DOMDYING_dead:
        break;
    }

    return rc;
}


void __domain_crash(struct domain *d)
{
    if ( d->is_shutting_down )
    {
        /* Print nothing: the domain is already shutting down. */
    }
    else if ( d == current->domain )
    {
        printk("Domain %d (vcpu#%d) crashed on cpu#%d:\n",
               d->domain_id, current->vcpu_id, smp_processor_id());
        show_execution_state(guest_cpu_user_regs());
    }
    else
    {
        printk("Domain %d reported crashed by domain %d on cpu#%d:\n",
               d->domain_id, current->domain->domain_id, smp_processor_id());
    }

    domain_shutdown(d, SHUTDOWN_crash);
}


void __domain_crash_synchronous(void)
{
    __domain_crash(current->domain);

    vcpu_end_shutdown_deferral(current);

    for ( ; ; )
        do_softirq();
}


int domain_shutdown(struct domain *d, u8 reason)
{
    struct vcpu *v;

#ifdef CONFIG_X86
    if ( pv_shim )
        return pv_shim_shutdown(reason);
#endif

    spin_lock(&d->shutdown_lock);

    if ( d->shutdown_code == SHUTDOWN_CODE_INVALID )
        d->shutdown_code = reason;
    reason = d->shutdown_code;

    if ( is_hardware_domain(d) )
        hwdom_shutdown(reason);

    if ( d->is_shutting_down )
    {
        spin_unlock(&d->shutdown_lock);
        return 0;
    }

    d->is_shutting_down = 1;

    smp_mb(); /* set shutdown status /then/ check for per-cpu deferrals */

    for_each_vcpu ( d, v )
    {
        if ( reason == SHUTDOWN_crash )
            v->defer_shutdown = 0;
        else if ( v->defer_shutdown )
            continue;
        vcpu_pause_nosync(v);
        v->paused_for_shutdown = 1;
    }

    arch_domain_shutdown(d);

    __domain_finalise_shutdown(d);

    spin_unlock(&d->shutdown_lock);

    return 0;
}

void domain_resume(struct domain *d)
{
    struct vcpu *v;

    /*
     * Some code paths assume that shutdown status does not get reset under
     * their feet (e.g., some assertions make this assumption).
     */
    domain_pause(d);

    spin_lock(&d->shutdown_lock);

    d->is_shutting_down = d->is_shut_down = 0;
    d->shutdown_code = SHUTDOWN_CODE_INVALID;

    for_each_vcpu ( d, v )
    {
        if ( v->paused_for_shutdown )
            vcpu_unpause(v);
        v->paused_for_shutdown = 0;
    }

    spin_unlock(&d->shutdown_lock);

    domain_unpause(d);
}

int vcpu_start_shutdown_deferral(struct vcpu *v)
{
    if ( v->defer_shutdown )
        return 1;

    v->defer_shutdown = 1;
    smp_mb(); /* set deferral status /then/ check for shutdown */
    if ( unlikely(v->domain->is_shutting_down) )
        vcpu_check_shutdown(v);

    return v->defer_shutdown;
}

void vcpu_end_shutdown_deferral(struct vcpu *v)
{
    v->defer_shutdown = 0;
    smp_mb(); /* clear deferral status /then/ check for shutdown */
    if ( unlikely(v->domain->is_shutting_down) )
        vcpu_check_shutdown(v);
}

#ifdef CONFIG_HAS_GDBSX
void domain_pause_for_debugger(void)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;

    domain_pause_by_systemcontroller_nosync(d);

    /* if gdbsx active, we just need to pause the domain */
    if ( curr->arch.gdbsx_vcpu_event == 0 )
        send_global_virq(VIRQ_DEBUGGER);
}
#endif

/* Complete domain destroy after RCU readers are not holding old references. */
static void complete_domain_destroy(struct rcu_head *head)
{
    struct domain *d = container_of(head, struct domain, rcu);
    struct vcpu *v;
    int i;

    /*
     * Flush all state for the vCPU previously having run on the current CPU.
     * This is in particular relevant for x86 HVM ones on VMX, so that this
     * flushing of state won't happen from the TLB flush IPI handler behind
     * the back of a vmx_vmcs_enter() / vmx_vmcs_exit() section.
     */
    sync_local_execstate();

    for ( i = d->max_vcpus - 1; i >= 0; i-- )
    {
        if ( (v = d->vcpu[i]) == NULL )
            continue;
        tasklet_kill(&v->continue_hypercall_tasklet);
        vcpu_destroy(v);
        sched_destroy_vcpu(v);
        destroy_waitqueue_vcpu(v);
    }

    grant_table_destroy(d);

    arch_domain_destroy(d);

    watchdog_domain_destroy(d);

    rangeset_domain_destroy(d);

    sched_destroy_domain(d);

    /* Free page used by xen oprofile buffer. */
#ifdef CONFIG_XENOPROF
    free_xenoprof_pages(d);
#endif

#ifdef CONFIG_HAS_MEM_PAGING
    xfree(d->vm_event_paging);
#endif
    xfree(d->vm_event_monitor);
#ifdef CONFIG_HAS_MEM_SHARING
    xfree(d->vm_event_share);
#endif

    xfree(d->pbuf);

    for ( i = d->max_vcpus - 1; i >= 0; i-- )
        if ( (v = d->vcpu[i]) != NULL )
        {
            free_cpumask_var(v->cpu_hard_affinity);
            free_cpumask_var(v->cpu_hard_affinity_tmp);
            free_cpumask_var(v->cpu_hard_affinity_saved);
            free_cpumask_var(v->cpu_soft_affinity);
            free_vcpu_struct(v);
        }

    if ( d->target != NULL )
        put_domain(d->target);

    evtchn_destroy_final(d);

    radix_tree_destroy(&d->pirq_tree, free_pirq_struct);

    xsm_free_security_domain(d);
    free_cpumask_var(d->dirty_cpumask);
    xfree(d->vcpu);
    free_domain_struct(d);

    send_global_virq(VIRQ_DOM_EXC);
}

/* Release resources belonging to task @p. */
void domain_destroy(struct domain *d)
{
    struct domain **pd;

    BUG_ON(!d->is_dying);

    /* May be already destroyed, or get_domain() can race us. */
    if ( atomic_cmpxchg(&d->refcnt, 0, DOMAIN_DESTROYED) != 0 )
        return;

    TRACE_1D(TRC_DOM0_DOM_REM, d->domain_id);

    /* Delete from task list and task hashtable. */
    spin_lock(&domlist_update_lock);
    pd = &domain_list;
    while ( *pd != d ) 
        pd = &(*pd)->next_in_list;
    rcu_assign_pointer(*pd, d->next_in_list);
    pd = &domain_hash[DOMAIN_HASH(d->domain_id)];
    while ( *pd != d ) 
        pd = &(*pd)->next_in_hashbucket;
    rcu_assign_pointer(*pd, d->next_in_hashbucket);
    spin_unlock(&domlist_update_lock);

    /* Schedule RCU asynchronous completion of domain destroy. */
    call_rcu(&d->rcu, complete_domain_destroy);
}

void vcpu_pause(struct vcpu *v)
{
    ASSERT(v != current);
    atomic_inc(&v->pause_count);
    vcpu_sleep_sync(v);
}

void vcpu_pause_nosync(struct vcpu *v)
{
    atomic_inc(&v->pause_count);
    vcpu_sleep_nosync(v);
}

void vcpu_unpause(struct vcpu *v)
{
    if ( atomic_dec_and_test(&v->pause_count) )
        vcpu_wake(v);
}

int vcpu_pause_by_systemcontroller(struct vcpu *v)
{
    int old, new, prev = v->controller_pause_count;

    do
    {
        old = prev;
        new = old + 1;

        if ( new > 255 )
            return -EOVERFLOW;

        prev = cmpxchg(&v->controller_pause_count, old, new);
    } while ( prev != old );

    vcpu_pause(v);

    return 0;
}

int vcpu_unpause_by_systemcontroller(struct vcpu *v)
{
    int old, new, prev = v->controller_pause_count;

    do
    {
        old = prev;
        new = old - 1;

        if ( new < 0 )
            return -EINVAL;

        prev = cmpxchg(&v->controller_pause_count, old, new);
    } while ( prev != old );

    vcpu_unpause(v);

    return 0;
}

static void do_domain_pause(struct domain *d,
                            void (*sleep_fn)(struct vcpu *v))
{
    struct vcpu *v;

    atomic_inc(&d->pause_count);

    for_each_vcpu( d, v )
        sleep_fn(v);

    arch_domain_pause(d);
}

void domain_pause(struct domain *d)
{
    ASSERT(d != current->domain);
    do_domain_pause(d, vcpu_sleep_sync);
}

void domain_pause_nosync(struct domain *d)
{
    do_domain_pause(d, vcpu_sleep_nosync);
}

void domain_unpause(struct domain *d)
{
    struct vcpu *v;

    arch_domain_unpause(d);

    if ( atomic_dec_and_test(&d->pause_count) )
        for_each_vcpu( d, v )
            vcpu_wake(v);
}

int __domain_pause_by_systemcontroller(struct domain *d,
                                       void (*pause_fn)(struct domain *d))
{
    int old, new, prev = d->controller_pause_count;

    do
    {
        old = prev;
        new = old + 1;

        /*
         * Limit the toolstack pause count to an arbitrary 255 to prevent the
         * toolstack overflowing d->pause_count with many repeated hypercalls.
         */
        if ( new > 255 )
            return -EOVERFLOW;

        prev = cmpxchg(&d->controller_pause_count, old, new);
    } while ( prev != old );

    pause_fn(d);

    return 0;
}

int domain_unpause_by_systemcontroller(struct domain *d)
{
    int old, new, prev = d->controller_pause_count;

    do
    {
        old = prev;
        new = old - 1;

        if ( new < 0 )
            return -EINVAL;

        prev = cmpxchg(&d->controller_pause_count, old, new);
    } while ( prev != old );

    /*
     * d->controller_pause_count is initialised to 1, and the toolstack is
     * responsible for making one unpause hypercall when it wishes the guest
     * to start running.
     *
     * All other toolstack operations should make a pair of pause/unpause
     * calls and rely on the reference counting here.
     *
     * Creation is considered finished when the controller reference count
     * first drops to 0.
     */
    if ( new == 0 )
        d->creation_finished = true;

    domain_unpause(d);

    return 0;
}

void domain_pause_except_self(struct domain *d)
{
    struct vcpu *v, *curr = current;

    if ( curr->domain == d )
    {
        for_each_vcpu( d, v )
            if ( likely(v != curr) )
                vcpu_pause(v);
    }
    else
        domain_pause(d);
}

void domain_unpause_except_self(struct domain *d)
{
    struct vcpu *v, *curr = current;

    if ( curr->domain == d )
    {
        for_each_vcpu( d, v )
            if ( likely(v != curr) )
                vcpu_unpause(v);
    }
    else
        domain_unpause(d);
}

int domain_soft_reset(struct domain *d)
{
    struct vcpu *v;
    int rc;

    spin_lock(&d->shutdown_lock);
    for_each_vcpu ( d, v )
        if ( !v->paused_for_shutdown )
        {
            spin_unlock(&d->shutdown_lock);
            return -EINVAL;
        }
    spin_unlock(&d->shutdown_lock);

    rc = evtchn_reset(d);
    if ( rc )
        return rc;

    grant_table_warn_active_grants(d);

    for_each_vcpu ( d, v )
    {
        set_xen_guest_handle(runstate_guest(v), NULL);
        unmap_vcpu_info(v);
    }

    rc = arch_domain_soft_reset(d);
    if ( !rc )
        domain_resume(d);
    else
        domain_crash(d);

    return rc;
}

int vcpu_reset(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    vcpu_pause(v);
    domain_lock(d);

    set_bit(_VPF_in_reset, &v->pause_flags);
    rc = arch_vcpu_reset(v);
    if ( rc )
        goto out_unlock;

    set_bit(_VPF_down, &v->pause_flags);

    clear_bit(v->vcpu_id, d->poll_mask);
    v->poll_evtchn = 0;

    v->fpu_initialised = 0;
    v->fpu_dirtied     = 0;
    v->is_initialised  = 0;
#ifdef VCPU_TRAP_LAST
    v->async_exception_mask = 0;
    memset(v->async_exception_state, 0, sizeof(v->async_exception_state));
#endif
    cpumask_clear(v->cpu_hard_affinity_tmp);
    clear_bit(_VPF_blocked, &v->pause_flags);
    clear_bit(_VPF_in_reset, &v->pause_flags);

 out_unlock:
    domain_unlock(v->domain);
    vcpu_unpause(v);

    return rc;
}

/*
 * Map a guest page in and point the vcpu_info pointer at it.  This
 * makes sure that the vcpu_info is always pointing at a valid piece
 * of memory, and it sets a pending event to make sure that a pending
 * event doesn't get missed.
 */
int map_vcpu_info(struct vcpu *v, unsigned long gfn, unsigned offset)
{
    struct domain *d = v->domain;
    void *mapping;
    vcpu_info_t *new_info;
    struct page_info *page;
    int i;

    if ( offset > (PAGE_SIZE - sizeof(vcpu_info_t)) )
        return -EINVAL;

    if ( !mfn_eq(v->vcpu_info_mfn, INVALID_MFN) )
        return -EINVAL;

    /* Run this command on yourself or on other offline VCPUS. */
    if ( (v != current) && !(v->pause_flags & VPF_down) )
        return -EINVAL;

    page = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !page )
        return -EINVAL;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return -EINVAL;
    }

    mapping = __map_domain_page_global(page);
    if ( mapping == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    new_info = (vcpu_info_t *)(mapping + offset);

    if ( v->vcpu_info == &dummy_vcpu_info )
    {
        memset(new_info, 0, sizeof(*new_info));
#ifdef XEN_HAVE_PV_UPCALL_MASK
        __vcpu_info(v, new_info, evtchn_upcall_mask) = 1;
#endif
    }
    else
    {
        memcpy(new_info, v->vcpu_info, sizeof(*new_info));
    }

    v->vcpu_info = new_info;
    v->vcpu_info_mfn = _mfn(page_to_mfn(page));

    /* Set new vcpu_info pointer /before/ setting pending flags. */
    smp_wmb();

    /*
     * Mark everything as being pending just to make sure nothing gets
     * lost.  The domain will get a spurious event, but it can cope.
     */
    vcpu_info(v, evtchn_upcall_pending) = 1;
    for ( i = 0; i < BITS_PER_EVTCHN_WORD(d); i++ )
        set_bit(i, &vcpu_info(v, evtchn_pending_sel));
    arch_evtchn_inject(v);

    return 0;
}

/*
 * Unmap the vcpu info page if the guest decided to place it somewhere
 * else. This is used from domain_kill() and domain_soft_reset().
 */
void unmap_vcpu_info(struct vcpu *v)
{
    mfn_t mfn = v->vcpu_info_mfn;

    if ( mfn_eq(mfn, INVALID_MFN) )
        return;

    unmap_domain_page_global((void *)
                             ((unsigned long)v->vcpu_info & PAGE_MASK));

    vcpu_info_reset(v); /* NB: Clobbers v->vcpu_info_mfn */

    put_page_and_type(mfn_to_page(mfn_x(mfn)));
}

int default_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct vcpu_guest_context *ctxt;
    struct domain *d = v->domain;
    int rc;

    if ( (ctxt = alloc_vcpu_guest_context()) == NULL )
        return -ENOMEM;

    if ( copy_from_guest(ctxt, arg, 1) )
    {
        free_vcpu_guest_context(ctxt);
        return -EFAULT;
    }

    domain_lock(d);
    rc = v->is_initialised ? -EEXIST : arch_set_info_guest(v, ctxt);
    domain_unlock(d);

    free_vcpu_guest_context(ctxt);

    return rc;
}

long do_vcpu_op(int cmd, unsigned int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d = current->domain;
    struct vcpu *v;
    long rc = 0;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
        return -ENOENT;

    switch ( cmd )
    {
    case VCPUOP_initialise:
        if ( v->vcpu_info == &dummy_vcpu_info )
            return -EINVAL;

        rc = arch_initialise_vcpu(v, arg);
        if ( rc == -ERESTART )
            rc = hypercall_create_continuation(__HYPERVISOR_vcpu_op, "iuh",
                                               cmd, vcpuid, arg);

        break;

    case VCPUOP_up:
#ifdef CONFIG_X86
        if ( pv_shim )
            rc = continue_hypercall_on_cpu(0, pv_shim_cpu_up, v);
        else
#endif
        {
            bool wake = false;

            domain_lock(d);
            if ( !v->is_initialised )
                rc = -EINVAL;
            else
                wake = test_and_clear_bit(_VPF_down, &v->pause_flags);
            domain_unlock(d);
            if ( wake )
                vcpu_wake(v);
        }

        break;

    case VCPUOP_down:
#ifdef CONFIG_X86
        if ( pv_shim )
            rc = continue_hypercall_on_cpu(0, pv_shim_cpu_down, v);
        else
#endif
            if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
                vcpu_sleep_nosync(v);

        break;

    case VCPUOP_is_up:
        rc = !(v->pause_flags & VPF_down);
        break;

    case VCPUOP_get_runstate_info:
    {
        struct vcpu_runstate_info runstate;
        vcpu_runstate_get(v, &runstate);
        if ( copy_to_guest(arg, &runstate, 1) )
            rc = -EFAULT;
        break;
    }

    case VCPUOP_set_periodic_timer:
    {
        struct vcpu_set_periodic_timer set;

        if ( copy_from_guest(&set, arg, 1) )
            return -EFAULT;

        if ( set.period_ns < MILLISECS(1) )
            return -EINVAL;

        if ( set.period_ns > STIME_DELTA_MAX )
            return -EINVAL;

        v->periodic_period = set.period_ns;
        vcpu_force_reschedule(v);

        break;
    }

    case VCPUOP_stop_periodic_timer:
        v->periodic_period = 0;
        vcpu_force_reschedule(v);
        break;

    case VCPUOP_set_singleshot_timer:
    {
        struct vcpu_set_singleshot_timer set;

        if ( v != current )
            return -EINVAL;

        if ( copy_from_guest(&set, arg, 1) )
            return -EFAULT;

        if ( (set.flags & VCPU_SSHOTTMR_future) &&
             (set.timeout_abs_ns < NOW()) )
            return -ETIME;

        migrate_timer(&v->singleshot_timer, smp_processor_id());
        set_timer(&v->singleshot_timer, set.timeout_abs_ns);

        break;
    }

    case VCPUOP_stop_singleshot_timer:
        if ( v != current )
            return -EINVAL;

        stop_timer(&v->singleshot_timer);

        break;

    case VCPUOP_register_vcpu_info:
    {
        struct vcpu_register_vcpu_info info;

        rc = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) )
            break;

        domain_lock(d);
        rc = map_vcpu_info(v, info.mfn, info.offset);
        domain_unlock(d);

        break;
    }

    case VCPUOP_register_runstate_memory_area:
    {
        struct vcpu_register_runstate_memory_area area;
        struct vcpu_runstate_info runstate;

        rc = -EFAULT;
        if ( copy_from_guest(&area, arg, 1) )
            break;

        if ( !guest_handle_okay(area.addr.h, 1) )
            break;

        rc = 0;
        runstate_guest(v) = area.addr.h;

        if ( v == current )
        {
            __copy_to_guest(runstate_guest(v), &v->runstate, 1);
        }
        else
        {
            vcpu_runstate_get(v, &runstate);
            __copy_to_guest(runstate_guest(v), &runstate, 1);
        }

        break;
    }

#ifdef VCPU_TRAP_NMI
    case VCPUOP_send_nmi:
        if ( !guest_handle_is_null(arg) )
            return -EINVAL;

        if ( !test_and_set_bool(v->nmi_pending) )
            vcpu_kick(v);

        break;
#endif

    default:
        rc = arch_do_vcpu_op(cmd, v, arg);
        break;
    }

    return rc;
}

#ifdef VM_ASSIST_VALID
long vm_assist(struct domain *p, unsigned int cmd, unsigned int type,
               unsigned long valid)
{
    if ( type >= BITS_PER_LONG || !test_bit(type, &valid) )
        return -EINVAL;

    switch ( cmd )
    {
    case VMASST_CMD_enable:
        set_bit(type, &p->vm_assist);
        return 0;
    case VMASST_CMD_disable:
        clear_bit(type, &p->vm_assist);
        return 0;
    }

    return -ENOSYS;
}
#endif

struct pirq *pirq_get_info(struct domain *d, int pirq)
{
    struct pirq *info = pirq_info(d, pirq);

    if ( !info && (info = alloc_pirq_struct(d)) != NULL )
    {
        info->pirq = pirq;
        if ( radix_tree_insert(&d->pirq_tree, pirq, info) )
        {
            free_pirq_struct(info);
            info = NULL;
        }
    }

    return info;
}

static void _free_pirq_struct(struct rcu_head *head)
{
    xfree(container_of(head, struct pirq, rcu_head));
}

void free_pirq_struct(void *ptr)
{
    struct pirq *pirq = ptr;

    call_rcu(&pirq->rcu_head, _free_pirq_struct);
}

struct migrate_info {
    long (*func)(void *data);
    void *data;
    struct vcpu *vcpu;
    unsigned int cpu;
    unsigned int nest;
};

static DEFINE_PER_CPU(struct migrate_info *, continue_info);

static void continue_hypercall_tasklet_handler(unsigned long _info)
{
    struct migrate_info *info = (struct migrate_info *)_info;
    struct vcpu *v = info->vcpu;

    /* Wait for vcpu to sleep so that we can access its register state. */
    vcpu_sleep_sync(v);

    this_cpu(continue_info) = info;
    return_reg(v) = (info->cpu == smp_processor_id())
        ? info->func(info->data) : -EINVAL;
    this_cpu(continue_info) = NULL;

    if ( info->nest-- == 0 )
    {
        xfree(info);
        vcpu_unpause(v);
        put_domain(v->domain);
    }
}

int continue_hypercall_on_cpu(
    unsigned int cpu, long (*func)(void *data), void *data)
{
    struct migrate_info *info;

    if ( (cpu >= nr_cpu_ids) || !cpu_online(cpu) )
        return -EINVAL;

    info = this_cpu(continue_info);
    if ( info == NULL )
    {
        struct vcpu *curr = current;

        info = xmalloc(struct migrate_info);
        if ( info == NULL )
            return -ENOMEM;

        info->vcpu = curr;
        info->nest = 0;

        tasklet_kill(
            &curr->continue_hypercall_tasklet);
        tasklet_init(
            &curr->continue_hypercall_tasklet,
            continue_hypercall_tasklet_handler,
            (unsigned long)info);

        get_knownalive_domain(curr->domain);
        vcpu_pause_nosync(curr);
    }
    else
    {
        BUG_ON(info->nest != 0);
        info->nest++;
    }

    info->func = func;
    info->data = data;
    info->cpu  = cpu;

    tasklet_schedule_on_cpu(&info->vcpu->continue_hypercall_tasklet, cpu);

    /* Dummy return value will be overwritten by tasklet. */
    return 0;
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
