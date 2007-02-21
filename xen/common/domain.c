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
    spin_lock_init(&d->pause_lock);
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

struct vcpu *alloc_vcpu(
    struct domain *d, unsigned int vcpu_id, unsigned int cpu_id)
{
    struct vcpu *v;

    BUG_ON(d->vcpu[vcpu_id] != NULL);

    if ( (v = alloc_vcpu_struct()) == NULL )
        return NULL;

    v->domain = d;
    v->vcpu_id = vcpu_id;
    v->vcpu_info = shared_info_addr(d, vcpu_info[vcpu_id]);
    spin_lock_init(&v->pause_lock);

    v->runstate.state = is_idle_vcpu(v) ? RUNSTATE_running : RUNSTATE_offline;
    v->runstate.state_entry_time = NOW();

    if ( (vcpu_id != 0) && !is_idle_domain(d) )
        set_bit(_VCPUF_down, &v->vcpu_flags);

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
        set_bit(_DOMF_ctrl_pause, &d->domain_flags);
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
    d = rcu_dereference(domain_hash[DOMAIN_HASH(dom)]);
    while ( d != NULL )
    {
        if ( d->domain_id == dom )
        {
            if ( unlikely(!get_domain(d)) )
                d = NULL;
            break;
        }
        d = rcu_dereference(d->next_in_hashbucket);
    }
    rcu_read_unlock(&domlist_read_lock);

    return d;
}


void domain_kill(struct domain *d)
{
    domain_pause(d);

    if ( test_and_set_bit(_DOMF_dying, &d->domain_flags) )
        return;

    gnttab_release_mappings(d);
    domain_relinquish_resources(d);
    put_domain(d);

    send_guest_global_virq(dom0, VIRQ_DOM_EXC);
}


void __domain_crash(struct domain *d)
{
    if ( test_bit(_DOMF_shutdown, &d->domain_flags) )
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

    if ( !test_and_set_bit(_DOMF_shutdown, &d->domain_flags) )
        d->shutdown_code = reason;

    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);

    send_guest_global_virq(dom0, VIRQ_DOM_EXC);
}


void domain_pause_for_debugger(void)
{
    struct domain *d = current->domain;
    struct vcpu *v;

    set_bit(_DOMF_ctrl_pause, &d->domain_flags);

    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);

    send_guest_global_virq(dom0, VIRQ_DEBUGGER);
}

/* Complete domain destroy after RCU readers are not holding 
   old references */
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

    BUG_ON(!test_bit(_DOMF_dying, &d->domain_flags));

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

    /* schedule RCU asynchronous completion of domain destroy */
    call_rcu(&d->rcu, complete_domain_destroy);
}

static void vcpu_pause_setup(struct vcpu *v)
{
    spin_lock(&v->pause_lock);
    if ( v->pause_count++ == 0 )
        set_bit(_VCPUF_paused, &v->vcpu_flags);
    spin_unlock(&v->pause_lock);
}

void vcpu_pause(struct vcpu *v)
{
    ASSERT(v != current);
    vcpu_pause_setup(v);
    vcpu_sleep_sync(v);
}

void vcpu_pause_nosync(struct vcpu *v)
{
    vcpu_pause_setup(v);
    vcpu_sleep_nosync(v);
}

void vcpu_unpause(struct vcpu *v)
{
    int wake;

    ASSERT(v != current);

    spin_lock(&v->pause_lock);
    wake = (--v->pause_count == 0);
    if ( wake )
        clear_bit(_VCPUF_paused, &v->vcpu_flags);
    spin_unlock(&v->pause_lock);

    if ( wake )
        vcpu_wake(v);
}

void domain_pause(struct domain *d)
{
    struct vcpu *v;

    ASSERT(d != current->domain);

    spin_lock(&d->pause_lock);
    if ( d->pause_count++ == 0 )
        set_bit(_DOMF_paused, &d->domain_flags);
    spin_unlock(&d->pause_lock);

    for_each_vcpu( d, v )
        vcpu_sleep_sync(v);
}

void domain_unpause(struct domain *d)
{
    struct vcpu *v;
    int wake;

    ASSERT(d != current->domain);

    spin_lock(&d->pause_lock);
    wake = (--d->pause_count == 0);
    if ( wake )
        clear_bit(_DOMF_paused, &d->domain_flags);
    spin_unlock(&d->pause_lock);

    if ( wake )
        for_each_vcpu( d, v )
            vcpu_wake(v);
}

void domain_pause_by_systemcontroller(struct domain *d)
{
    struct vcpu *v;

    BUG_ON(current->domain == d);

    if ( !test_and_set_bit(_DOMF_ctrl_pause, &d->domain_flags) )
    {
        for_each_vcpu ( d, v )
            vcpu_sleep_sync(v);
    }
}

void domain_unpause_by_systemcontroller(struct domain *d)
{
    struct vcpu *v;

    if ( test_and_clear_bit(_DOMF_ctrl_pause, &d->domain_flags) )
    {
        for_each_vcpu ( d, v )
            vcpu_wake(v);
    }
}

int boot_vcpu(struct domain *d, int vcpuid, vcpu_guest_context_u ctxt)
{
    struct vcpu *v = d->vcpu[vcpuid];

    BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));

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

    set_bit(_VCPUF_down, &v->vcpu_flags);

    clear_bit(_VCPUF_fpu_initialised, &v->vcpu_flags);
    clear_bit(_VCPUF_fpu_dirtied, &v->vcpu_flags);
    clear_bit(_VCPUF_blocked, &v->vcpu_flags);
    clear_bit(_VCPUF_initialised, &v->vcpu_flags);
    clear_bit(_VCPUF_nmi_pending, &v->vcpu_flags);
    clear_bit(_VCPUF_nmi_masked, &v->vcpu_flags);
    clear_bit(_VCPUF_polling, &v->vcpu_flags);

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
        {
            rc = -ENOMEM;
            break;
        }

        if ( copy_from_guest(ctxt, arg, 1) )
        {
            xfree(ctxt);
            rc = -EFAULT;
            break;
        }

        LOCK_BIGLOCK(d);
        rc = -EEXIST;
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            rc = boot_vcpu(d, vcpuid, ctxt);
        UNLOCK_BIGLOCK(d);

        xfree(ctxt);
        break;

    case VCPUOP_up:
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            rc = -EINVAL;
        else if ( test_and_clear_bit(_VCPUF_down, &v->vcpu_flags) )
            vcpu_wake(v);
        break;

    case VCPUOP_down:
        if ( !test_and_set_bit(_VCPUF_down, &v->vcpu_flags) )
            vcpu_sleep_nosync(v);
        break;

    case VCPUOP_is_up:
        rc = !test_bit(_VCPUF_down, &v->vcpu_flags);
        break;

    case VCPUOP_get_runstate_info:
    {
        struct vcpu_runstate_info runstate;
        vcpu_runstate_get(v, &runstate);
        if ( copy_to_guest(arg, &runstate, 1) )
            rc = -EFAULT;
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
