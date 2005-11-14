/******************************************************************************
 * domain.c
 * 
 * Generic domain-handling functions.
 */

#include <xen/config.h>
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
#include <asm/debugger.h>
#include <public/dom0_ops.h>
#include <public/sched.h>
#include <public/vcpu.h>

/* Both these structures are protected by the domlist_lock. */
rwlock_t domlist_lock = RW_LOCK_UNLOCKED;
struct domain *domain_hash[DOMAIN_HASH_SIZE];
struct domain *domain_list;

struct domain *dom0;

struct domain *do_createdomain(domid_t dom_id, unsigned int cpu)
{
    struct domain *d, **pd;
    struct vcpu *v;

    if ( (d = alloc_domain()) == NULL )
        return NULL;

    d->domain_id = dom_id;

    atomic_set(&d->refcnt, 1);

    spin_lock_init(&d->big_lock);
    spin_lock_init(&d->page_alloc_lock);
    INIT_LIST_HEAD(&d->page_list);
    INIT_LIST_HEAD(&d->xenpage_list);

    if ( d->domain_id == IDLE_DOMAIN_ID )
        set_bit(_DOMF_idle_domain, &d->domain_flags);
    else
        set_bit(_DOMF_ctrl_pause, &d->domain_flags);

    if ( !is_idle_task(d) &&
         ((evtchn_init(d) != 0) || (grant_table_create(d) != 0)) )
    {
        evtchn_destroy(d);
        free_domain(d);
        return NULL;
    }
    
    if ( (v = alloc_vcpu(d, 0, cpu)) == NULL )
    {
        grant_table_destroy(d);
        evtchn_destroy(d);
        free_domain(d);
        return NULL;
    }

    arch_do_createdomain(v);
    
    if ( !is_idle_task(d) )
    {
        write_lock(&domlist_lock);
        pd = &domain_list; /* NB. domain_list maintained in order of dom_id. */
        for ( pd = &domain_list; *pd != NULL; pd = &(*pd)->next_in_list )
            if ( (*pd)->domain_id > d->domain_id )
                break;
        d->next_in_list = *pd;
        *pd = d;
        d->next_in_hashbucket = domain_hash[DOMAIN_HASH(dom_id)];
        domain_hash[DOMAIN_HASH(dom_id)] = d;
        write_unlock(&domlist_lock);
    }

    return d;
}


struct domain *find_domain_by_id(domid_t dom)
{
    struct domain *d;

    read_lock(&domlist_lock);
    d = domain_hash[DOMAIN_HASH(dom)];
    while ( d != NULL )
    {
        if ( d->domain_id == dom )
        {
            if ( unlikely(!get_domain(d)) )
                d = NULL;
            break;
        }
        d = d->next_in_hashbucket;
    }
    read_unlock(&domlist_lock);

    return d;
}


void domain_kill(struct domain *d)
{
    struct vcpu *v;

    domain_pause(d);
    if ( !test_and_set_bit(_DOMF_dying, &d->domain_flags) )
    {
        for_each_vcpu(d, v)
            sched_rem_domain(v);
        domain_relinquish_resources(d);
        put_domain(d);

        send_guest_virq(dom0->vcpu[0], VIRQ_DOM_EXC);
    }
}


void domain_crash(struct domain *d)
{
    if ( d == current->domain )
    {
        printk("Domain %d (vcpu#%d) crashed on cpu#%d:\n",
               d->domain_id, current->vcpu_id, smp_processor_id());
        show_registers(guest_cpu_user_regs());
    }
    else
    {
        printk("Domain %d reported crashed by domain %d on cpu#%d:\n",
               d->domain_id, current->domain->domain_id, smp_processor_id());
    }

    domain_shutdown(d, SHUTDOWN_crash);
}


void domain_crash_synchronous(void)
{
    domain_crash(current->domain);
    for ( ; ; )
        do_softirq();
}


static struct domain *domain_shuttingdown[NR_CPUS];

static void domain_shutdown_finalise(void)
{
    struct domain *d;
    struct vcpu *v;

    d = domain_shuttingdown[smp_processor_id()];
    domain_shuttingdown[smp_processor_id()] = NULL;

    BUG_ON(d == NULL);
    BUG_ON(d == current->domain);
    BUG_ON(!test_bit(_DOMF_shuttingdown, &d->domain_flags));
    BUG_ON(test_bit(_DOMF_shutdown, &d->domain_flags));

    /* Make sure that every vcpu is descheduled before we finalise. */
    for_each_vcpu ( d, v )
        vcpu_sleep_sync(v);
    BUG_ON(!cpus_empty(d->cpumask));

    sync_pagetable_state(d);

    set_bit(_DOMF_shutdown, &d->domain_flags);
    clear_bit(_DOMF_shuttingdown, &d->domain_flags);

    send_guest_virq(dom0->vcpu[0], VIRQ_DOM_EXC);
}

static __init int domain_shutdown_finaliser_init(void)
{
    open_softirq(DOMAIN_SHUTDOWN_FINALISE_SOFTIRQ, domain_shutdown_finalise);
    return 0;
}
__initcall(domain_shutdown_finaliser_init);


void domain_shutdown(struct domain *d, u8 reason)
{
    struct vcpu *v;

    if ( d->domain_id == 0 )
    {
        extern void machine_restart(char *);
        extern void machine_halt(void);

        debugger_trap_immediate();

        if ( reason == SHUTDOWN_poweroff ) 
        {
            printk("Domain 0 halted: halting machine.\n");
            machine_halt();
        }
        else
        {
            printk("Domain 0 shutdown: rebooting machine.\n");
            machine_restart(0);
        }
    }

    /* Mark the domain as shutting down. */
    d->shutdown_code = reason;
    if ( !test_and_set_bit(_DOMF_shuttingdown, &d->domain_flags) )
    {
        /* This vcpu won the race to finalise the shutdown. */
        domain_shuttingdown[smp_processor_id()] = d;
        raise_softirq(DOMAIN_SHUTDOWN_FINALISE_SOFTIRQ);
    }

    /* Put every vcpu to sleep, but don't wait (avoids inter-vcpu deadlock). */
    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);
}


void domain_pause_for_debugger(void)
{
    struct domain *d = current->domain;
    struct vcpu *v;

    /*
     * NOTE: This does not synchronously pause the domain. The debugger
     * must issue a PAUSEDOMAIN command to ensure that all execution
     * has ceased and guest state is committed to memory.
     */
    set_bit(_DOMF_ctrl_pause, &d->domain_flags);
    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);

    send_guest_virq(dom0->vcpu[0], VIRQ_DEBUGGER);
}


/* Release resources belonging to task @p. */
void domain_destruct(struct domain *d)
{
    struct domain **pd;
    atomic_t      old, new;

    BUG_ON(!test_bit(_DOMF_dying, &d->domain_flags));

    /* May be already destructed, or get_domain() can race us. */
    _atomic_set(old, 0);
    _atomic_set(new, DOMAIN_DESTRUCTED);
    old = atomic_compareandswap(old, new, &d->refcnt);
    if ( _atomic_read(old) != 0 )
        return;

    /* Delete from task list and task hashtable. */
    write_lock(&domlist_lock);
    pd = &domain_list;
    while ( *pd != d ) 
        pd = &(*pd)->next_in_list;
    *pd = d->next_in_list;
    pd = &domain_hash[DOMAIN_HASH(d->domain_id)];
    while ( *pd != d ) 
        pd = &(*pd)->next_in_hashbucket;
    *pd = d->next_in_hashbucket;
    write_unlock(&domlist_lock);

    evtchn_destroy(d);
    grant_table_destroy(d);

    free_perdomain_pt(d);
    free_xenheap_page(d->shared_info);

    free_domain(d);

    send_guest_virq(dom0->vcpu[0], VIRQ_DOM_EXC);
}

void vcpu_pause(struct vcpu *v)
{
    BUG_ON(v == current);
    atomic_inc(&v->pausecnt);
    vcpu_sleep_sync(v);
}

void domain_pause(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu( d, v )
    {
        BUG_ON(v == current);
        atomic_inc(&v->pausecnt);
        vcpu_sleep_sync(v);
    }

    sync_pagetable_state(d);
}

void vcpu_unpause(struct vcpu *v)
{
    BUG_ON(v == current);
    if ( atomic_dec_and_test(&v->pausecnt) )
        vcpu_wake(v);
}

void domain_unpause(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu( d, v )
        vcpu_unpause(v);
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

    sync_pagetable_state(d);
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


/*
 * set_info_guest is used for final setup, launching, and state modification 
 * of domains other than domain 0. ie. the domains that are being built by 
 * the userspace dom0 domain builder.
 */
int set_info_guest(struct domain *d, dom0_setdomaininfo_t *setdomaininfo)
{
    int rc = 0;
    struct vcpu_guest_context *c = NULL;
    unsigned long vcpu = setdomaininfo->vcpu;
    struct vcpu *v; 

    if ( (vcpu >= MAX_VIRT_CPUS) || ((v = d->vcpu[vcpu]) == NULL) )
        return -EINVAL;
    
    if ( !test_bit(_DOMF_ctrl_pause, &d->domain_flags) )
        return -EINVAL;

    if ( (c = xmalloc(struct vcpu_guest_context)) == NULL )
        return -ENOMEM;

    rc = -EFAULT;
    if ( copy_from_user(c, setdomaininfo->ctxt, sizeof(*c)) == 0 )
        rc = arch_set_info_guest(v, c);

    xfree(c);
    return rc;
}

int boot_vcpu(struct domain *d, int vcpuid, struct vcpu_guest_context *ctxt) 
{
    struct vcpu *v = d->vcpu[vcpuid];
    int rc;

    BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));

    if ( (rc = arch_set_info_guest(v, ctxt)) != 0 )
        return rc;

    return rc;
}

long do_vcpu_op(int cmd, int vcpuid, void *arg)
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

        if ( copy_from_user(ctxt, arg, sizeof(*ctxt)) )
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
        if ( test_and_clear_bit(_VCPUF_down, &v->vcpu_flags) )
            vcpu_wake(v);
        break;

    case VCPUOP_down:
        if ( !test_and_set_bit(_VCPUF_down, &v->vcpu_flags) )
            vcpu_sleep_nosync(v);
        break;

    case VCPUOP_is_up:
        rc = !test_bit(_VCPUF_down, &v->vcpu_flags);
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
