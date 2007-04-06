/******************************************************************************
 * domain.c
 * 
 * Generic domain-handling functions.
 */

#include <xen/config.h>
#include <xen/compat.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/console.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/rangeset.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/delay.h>
#include <xen/shutdown.h>
#include <xen/percpu.h>
#include <xen/multicall.h>
#include <xen/rcupdate.h>
#include <asm/debugger.h>
#include <public/sched.h>
#include <public/vcpu.h>

/* Protect updates/reads (resp.) of domain_list and domain_hash. */
DEFINE_SPINLOCK(domlist_update_lock);
DEFINE_RCU_READ_LOCK(domlist_read_lock);

#define DOMAIN_HASH_SIZE 256
#define DOMAIN_HASH(_id) ((int)(_id)&(DOMAIN_HASH_SIZE-1))
static struct domain *domain_hash[DOMAIN_HASH_SIZE];
struct domain *domain_list;

struct domain *dom0;

struct vcpu *idle_vcpu[NR_CPUS] __read_mostly;

int current_domain_id(void)
{
    return current->domain->domain_id;
}

struct domain *alloc_domain(domid_t domid)
{
    struct domain *d;

    if ( (d = xmalloc(struct domain)) == NULL )
        return NULL;

    memset(d, 0, sizeof(*d));
    d->domain_id = domid;
    atomic_set(&d->refcnt, 1);
    spin_lock_init(&d->big_lock);
    spin_lock_init(&d->page_alloc_lock);
    spin_lock_init(&d->shutdown_lock);
    INIT_LIST_HEAD(&d->page_list);
    INIT_LIST_HEAD(&d->xenpage_list);

    return d;
}

void free_domain(struct domain *d)
{
    struct vcpu *v;
    int i;

    for ( i = MAX_VIRT_CPUS-1; i >= 0; i-- )
    {
        if ( (v = d->vcpu[i]) == NULL )
            continue;
        vcpu_destroy(v);
        sched_destroy_vcpu(v);
        free_vcpu_struct(v);
    }

    sched_destroy_domain(d);
    xfree(d);
}

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

    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);

    send_guest_global_virq(dom0, VIRQ_DOM_EXC);
}

static void vcpu_check_shutdown(struct vcpu *v)
{
    struct domain *d = v->domain;

    spin_lock(&d->shutdown_lock);

    if ( d->is_shutting_down )
    {
        if ( !v->paused_for_shutdown )
            atomic_inc(&v->pause_count);
        v->paused_for_shutdown = 1;
        v->defer_shutdown = 0;
        __domain_finalise_shutdown(d);
    }

    spin_unlock(&d->shutdown_lock);
}

struct vcpu *alloc_vcpu(
    struct domain *d, unsigned int vcpu_id, unsigned int cpu_id)
{
    struct vcpu *v;

    BUG_ON(d->vcpu[vcpu_id] != NULL);

    if ( (v = alloc_vcpu_struct()) == NULL )
        return NULL;

    v->domain = d;
    v->vcpu_id = vcpu_id;

    v->runstate.state = is_idle_vcpu(v) ? RUNSTATE_running : RUNSTATE_offline;
    v->runstate.state_entry_time = NOW();

    if ( !is_idle_domain(d) )
    {
        set_bit(_VPF_down, &v->pause_flags);
        v->vcpu_info = shared_info_addr(d, vcpu_info[vcpu_id]);
    }

    if ( sched_init_vcpu(v, cpu_id) != 0 )
    {
        free_vcpu_struct(v);
        return NULL;
    }

    if ( vcpu_initialise(v) != 0 )
    {
        sched_destroy_vcpu(v);
        free_vcpu_struct(v);
        return NULL;
    }

    d->vcpu[vcpu_id] = v;
    if ( vcpu_id != 0 )
        d->vcpu[v->vcpu_id-1]->next_in_list = v;

    /* Must be called after making new vcpu visible to for_each_vcpu(). */
    vcpu_check_shutdown(v);

    return v;
}

struct vcpu *alloc_idle_vcpu(unsigned int cpu_id)
{
    struct domain *d;
    struct vcpu *v;
    unsigned int vcpu_id = cpu_id % MAX_VIRT_CPUS;

    if ( (v = idle_vcpu[cpu_id]) != NULL )
        return v;

    d = (vcpu_id == 0) ?
        domain_create(IDLE_DOMAIN_ID, 0) :
        idle_vcpu[cpu_id - vcpu_id]->domain;
    BUG_ON(d == NULL);

    v = alloc_vcpu(d, vcpu_id, cpu_id);
    idle_vcpu[cpu_id] = v;

    return v;
}

struct domain *domain_create(domid_t domid, unsigned int domcr_flags)
{
    struct domain *d, **pd;

    if ( (d = alloc_domain(domid)) == NULL )
        return NULL;

    if ( domcr_flags & DOMCRF_hvm )
        d->is_hvm = 1;

    rangeset_domain_initialise(d);

    if ( !is_idle_domain(d) )
    {
        d->is_paused_by_controller = 1;
        atomic_inc(&d->pause_count);

        if ( evtchn_init(d) != 0 )
            goto fail1;

        if ( grant_table_create(d) != 0 )
            goto fail2;
    }

    if ( arch_domain_create(d) != 0 )
        goto fail3;

    d->iomem_caps = rangeset_new(d, "I/O Memory", RANGESETF_prettyprint_hex);
    d->irq_caps   = rangeset_new(d, "Interrupts", 0);
    if ( (d->iomem_caps == NULL) || (d->irq_caps == NULL) )
        goto fail4;

    if ( sched_init_domain(d) != 0 )
        goto fail4;

    if ( !is_idle_domain(d) )
    {
        spin_lock(&domlist_update_lock);
        pd = &domain_list; /* NB. domain_list maintained in order of domid. */
        for ( pd = &domain_list; *pd != NULL; pd = &(*pd)->next_in_list )
            if ( (*pd)->domain_id > d->domain_id )
                break;
        d->next_in_list = *pd;
        d->next_in_hashbucket = domain_hash[DOMAIN_HASH(domid)];
        /* Two rcu assignments are not atomic 
         * Readers may see inconsistent domlist and hash table
         * That is OK as long as each RCU reader-side critical section uses
         * only one or them  */
        rcu_assign_pointer(*pd, d);
        rcu_assign_pointer(domain_hash[DOMAIN_HASH(domid)], d);
        spin_unlock(&domlist_update_lock);
    }

    return d;

 fail4:
    arch_domain_destroy(d);
 fail3:
    if ( !is_idle_domain(d) )
        grant_table_destroy(d);
 fail2:
    if ( !is_idle_domain(d) )
        evtchn_destroy(d);
 fail1:
    rangeset_domain_destroy(d);
    free_domain(d);
    return NULL;
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
    struct domain *d;

    rcu_read_lock(&domlist_read_lock);

    for ( d = rcu_dereference(domain_hash[DOMAIN_HASH(dom)]);
          d != NULL;
          d = rcu_dereference(d->next_in_hashbucket) )
    {
        if ( d->domain_id == dom )
            return d;
    }

    rcu_read_unlock(&domlist_read_lock);

    return NULL;
}


void domain_kill(struct domain *d)
{
    domain_pause(d);

    /* Already dying? Then bail. */
    if ( test_and_set_bool(d->is_dying) )
    {
        domain_unpause(d);
        return;
    }

    /* Tear down state /after/ setting the dying flag. */
    smp_wmb();

    gnttab_release_mappings(d);
    domain_relinquish_resources(d);
    put_domain(d);

    /* Kick page scrubbing after domain_relinquish_resources(). */
    page_scrub_kick();

    send_guest_global_virq(dom0, VIRQ_DOM_EXC);
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

    /*
     * Flush multicall state before dying if a multicall is in progress.
     * This shouldn't be necessary, but some architectures are calling
     * domain_crash_synchronous() when they really shouldn't (i.e., from
     * within hypercall context).
     */
    if ( this_cpu(mc_state).flags != 0 )
    {
        dprintk(XENLOG_ERR,
                "FIXME: synchronous domain crash during a multicall!\n");
        this_cpu(mc_state).flags = 0;
    }

    for ( ; ; )
        do_softirq();
}


void domain_shutdown(struct domain *d, u8 reason)
{
    struct vcpu *v;

    if ( d->domain_id == 0 )
        dom0_shutdown(reason);

    spin_lock(&d->shutdown_lock);

    if ( d->is_shutting_down )
    {
        spin_unlock(&d->shutdown_lock);
        return;
    }

    d->is_shutting_down = 1;
    d->shutdown_code = reason;

    smp_mb(); /* set shutdown status /then/ check for per-cpu deferrals */

    for_each_vcpu ( d, v )
    {
        if ( v->defer_shutdown )
            continue;
        atomic_inc(&v->pause_count);
        v->paused_for_shutdown = 1;
    }

    __domain_finalise_shutdown(d);

    spin_unlock(&d->shutdown_lock);
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

void domain_pause_for_debugger(void)
{
    struct domain *d = current->domain;
    struct vcpu *v;

    atomic_inc(&d->pause_count);
    if ( test_and_set_bool(d->is_paused_by_controller) )
        domain_unpause(d); /* race-free atomic_dec(&d->pause_count) */

    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);

    send_guest_global_virq(dom0, VIRQ_DEBUGGER);
}

/* Complete domain destroy after RCU readers are not holding old references. */
static void complete_domain_destroy(struct rcu_head *head)
{
    struct domain *d = container_of(head, struct domain, rcu);

    rangeset_domain_destroy(d);

    evtchn_destroy(d);
    grant_table_destroy(d);

    arch_domain_destroy(d);

    free_domain(d);

    send_guest_global_virq(dom0, VIRQ_DOM_EXC);
}

/* Release resources belonging to task @p. */
void domain_destroy(struct domain *d)
{
    struct domain **pd;
    atomic_t      old, new;

    BUG_ON(!d->is_dying);

    /* May be already destroyed, or get_domain() can race us. */
    _atomic_set(old, 0);
    _atomic_set(new, DOMAIN_DESTROYED);
    old = atomic_compareandswap(old, new, &d->refcnt);
    if ( _atomic_read(old) != 0 )
        return;

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

void domain_pause(struct domain *d)
{
    struct vcpu *v;

    ASSERT(d != current->domain);

    atomic_inc(&d->pause_count);

    for_each_vcpu( d, v )
        vcpu_sleep_sync(v);
}

void domain_unpause(struct domain *d)
{
    struct vcpu *v;

    if ( atomic_dec_and_test(&d->pause_count) )
        for_each_vcpu( d, v )
            vcpu_wake(v);
}

void domain_pause_by_systemcontroller(struct domain *d)
{
    domain_pause(d);
    if ( test_and_set_bool(d->is_paused_by_controller) )
        domain_unpause(d);
}

void domain_unpause_by_systemcontroller(struct domain *d)
{
    if ( test_and_clear_bool(d->is_paused_by_controller) )
        domain_unpause(d);
}

int boot_vcpu(struct domain *d, int vcpuid, vcpu_guest_context_u ctxt)
{
    struct vcpu *v = d->vcpu[vcpuid];

    BUG_ON(v->is_initialised);

    return arch_set_info_guest(v, ctxt);
}

int vcpu_reset(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    domain_pause(d);
    LOCK_BIGLOCK(d);

    rc = arch_vcpu_reset(v);
    if ( rc != 0 )
        goto out;

    set_bit(_VPF_down, &v->pause_flags);

    v->fpu_initialised = 0;
    v->fpu_dirtied     = 0;
    v->is_polling      = 0;
    v->is_initialised  = 0;
    v->nmi_pending     = 0;
    v->nmi_masked      = 0;
    clear_bit(_VPF_blocked, &v->pause_flags);

 out:
    UNLOCK_BIGLOCK(v->domain);
    domain_unpause(d);

    return rc;
}


long do_vcpu_op(int cmd, int vcpuid, XEN_GUEST_HANDLE(void) arg)
{
    struct domain *d = current->domain;
    struct vcpu *v;
    struct vcpu_guest_context *ctxt;
    long rc = 0;

    if ( (vcpuid < 0) || (vcpuid >= MAX_VIRT_CPUS) )
        return -EINVAL;

    if ( (v = d->vcpu[vcpuid]) == NULL )
        return -ENOENT;

    switch ( cmd )
    {
    case VCPUOP_initialise:
        if ( (ctxt = xmalloc(struct vcpu_guest_context)) == NULL )
            return -ENOMEM;

        if ( copy_from_guest(ctxt, arg, 1) )
        {
            xfree(ctxt);
            return -EFAULT;
        }

        LOCK_BIGLOCK(d);
        rc = -EEXIST;
        if ( !v->is_initialised )
            rc = boot_vcpu(d, vcpuid, ctxt);
        UNLOCK_BIGLOCK(d);

        xfree(ctxt);
        break;

    case VCPUOP_up:
        if ( !v->is_initialised )
            return -EINVAL;

        if ( test_and_clear_bit(_VPF_down, &v->pause_flags) )
            vcpu_wake(v);

        break;

    case VCPUOP_down:
        if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
            vcpu_sleep_nosync(v);
        break;

    case VCPUOP_is_up:
        rc = !test_bit(_VPF_down, &v->pause_flags);
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

        v->periodic_period = set.period_ns;
        vcpu_force_reschedule(v);

        break;
    }

    case VCPUOP_stop_periodic_timer:
    {
        v->periodic_period = 0;
        vcpu_force_reschedule(v);
        break;
    }

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

        if ( v->singleshot_timer.cpu != smp_processor_id() )
        {
            stop_timer(&v->singleshot_timer);
            v->singleshot_timer.cpu = smp_processor_id();
        }

        set_timer(&v->singleshot_timer, set.timeout_abs_ns);

        break;
    }

    case VCPUOP_stop_singleshot_timer:
    {
        if ( v != current )
            return -EINVAL;

        stop_timer(&v->singleshot_timer);
        break;
    }

    default:
        rc = arch_do_vcpu_op(cmd, v, arg);
        break;
    }

    return rc;
}

long vm_assist(struct domain *p, unsigned int cmd, unsigned int type)
{
    if ( type > MAX_VMASST_TYPE )
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
