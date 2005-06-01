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
#include <public/dom0_ops.h>
#include <asm/domain_page.h>
#include <asm/debugger.h>

/* Both these structures are protected by the domlist_lock. */
rwlock_t domlist_lock = RW_LOCK_UNLOCKED;
struct domain *domain_hash[DOMAIN_HASH_SIZE];
struct domain *domain_list;

struct domain *dom0;

struct domain *do_createdomain(domid_t dom_id, unsigned int cpu)
{
    struct domain *d, **pd;
    struct exec_domain *ed;

    if ( (d = alloc_domain_struct()) == NULL )
        return NULL;

    ed = d->exec_domain[0];

    atomic_set(&d->refcnt, 1);
    atomic_set(&ed->pausecnt, 0);

    d->domain_id   = dom_id;
    ed->processor  = cpu;
 
    spin_lock_init(&d->time_lock);

    spin_lock_init(&d->big_lock);

    spin_lock_init(&d->page_alloc_lock);
    INIT_LIST_HEAD(&d->page_list);
    INIT_LIST_HEAD(&d->xenpage_list);

    if ( d->domain_id == IDLE_DOMAIN_ID )
        set_bit(_DOMF_idle_domain, &d->domain_flags);

    if ( !is_idle_task(d) &&
         ((init_event_channels(d) != 0) || (grant_table_create(d) != 0)) )
    {
        destroy_event_channels(d);
        free_domain_struct(d);
        return NULL;
    }
    
    arch_do_createdomain(ed);
    
    sched_add_domain(ed);

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
    struct exec_domain *ed;

    domain_pause(d);
    if ( !test_and_set_bit(_DOMF_dying, &d->domain_flags) )
    {
        for_each_exec_domain(d, ed)
            sched_rem_domain(ed);
        domain_relinquish_resources(d);
        put_domain(d);
    }
}


void domain_crash(void)
{
    struct domain *d = current->domain;

    if ( d->domain_id == 0 )
    {
        show_registers(guest_cpu_user_regs());
        panic("Domain 0 crashed!\n");
    }

#ifndef NDEBUG
    show_registers(guest_cpu_user_regs());
#endif

    domain_shutdown(SHUTDOWN_crash);
}


void domain_crash_synchronous(void)
{
    domain_crash();
    for ( ; ; )
        do_softirq();
}


static struct domain *domain_shuttingdown[NR_CPUS];

static void domain_shutdown_finalise(void)
{
    struct domain *d;
    struct exec_domain *ed;

    d = domain_shuttingdown[smp_processor_id()];
    domain_shuttingdown[smp_processor_id()] = NULL;

    BUG_ON(d == NULL);
    BUG_ON(d == current->domain);
    BUG_ON(!test_bit(_DOMF_shuttingdown, &d->domain_flags));
    BUG_ON(test_bit(_DOMF_shutdown, &d->domain_flags));

    /* Make sure that every vcpu is descheduled before we finalise. */
    for_each_exec_domain ( d, ed )
        while ( test_bit(_VCPUF_running, &ed->vcpu_flags) )
            cpu_relax();

    sync_lazy_execstate_cpuset(d->cpuset);
    BUG_ON(d->cpuset != 0);

    sync_pagetable_state(d);

    set_bit(_DOMF_shutdown, &d->domain_flags);
    clear_bit(_DOMF_shuttingdown, &d->domain_flags);

    send_guest_virq(dom0->exec_domain[0], VIRQ_DOM_EXC);
}

static __init int domain_shutdown_finaliser_init(void)
{
    open_softirq(DOMAIN_SHUTDOWN_FINALISE_SOFTIRQ, domain_shutdown_finalise);
    return 0;
}
__initcall(domain_shutdown_finaliser_init);


void domain_shutdown(u8 reason)
{
    struct domain *d = current->domain;
    struct exec_domain *ed;

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
    for_each_exec_domain ( d, ed )
        domain_sleep_nosync(ed);
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

    destroy_event_channels(d);
    grant_table_destroy(d);

    free_perdomain_pt(d);
    free_xenheap_page((unsigned long)d->shared_info);

    free_domain_struct(d);

    send_guest_virq(dom0->exec_domain[0], VIRQ_DOM_EXC);
}

void exec_domain_pause(struct exec_domain *ed)
{
    BUG_ON(ed == current);
    atomic_inc(&ed->pausecnt);
    domain_sleep_sync(ed);
}

void domain_pause(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain( d, ed )
    {
        BUG_ON(ed == current);
        atomic_inc(&ed->pausecnt);
        domain_sleep_sync(ed);
    }
}

void exec_domain_unpause(struct exec_domain *ed)
{
    BUG_ON(ed == current);
    if ( atomic_dec_and_test(&ed->pausecnt) )
        domain_wake(ed);
}

void domain_unpause(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain( d, ed )
        exec_domain_unpause(ed);
}

void domain_pause_by_systemcontroller(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain ( d, ed )
    {
        BUG_ON(ed == current);
        if ( !test_and_set_bit(_VCPUF_ctrl_pause, &ed->vcpu_flags) )
            domain_sleep_sync(ed);
    }
}

void domain_unpause_by_systemcontroller(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain ( d, ed )
    {
        if ( test_and_clear_bit(_VCPUF_ctrl_pause, &ed->vcpu_flags) )
            domain_wake(ed);
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
    struct exec_domain *ed; 

    if ( (vcpu >= MAX_VIRT_CPUS) || ((ed = d->exec_domain[vcpu]) == NULL) )
        return -EINVAL;
    
    if (test_bit(_DOMF_constructed, &d->domain_flags) && 
        !test_bit(_VCPUF_ctrl_pause, &ed->vcpu_flags))
        return -EINVAL;

    if ( (c = xmalloc(struct vcpu_guest_context)) == NULL )
        return -ENOMEM;

    if ( copy_from_user(c, setdomaininfo->ctxt, sizeof(*c)) )
    {
        rc = -EFAULT;
        goto out;
    }
    
    if ( (rc = arch_set_info_guest(ed, c)) != 0 )
        goto out;

    set_bit(_DOMF_constructed, &d->domain_flags);

 out:    
    xfree(c);
    return rc;
}

/*
 * final_setup_guest is used for final setup and launching of domains other
 * than domain 0. ie. the domains that are being built by the userspace dom0
 * domain builder.
 */
long do_boot_vcpu(unsigned long vcpu, struct vcpu_guest_context *ctxt) 
{
    struct domain *d = current->domain;
    struct exec_domain *ed;
    int rc = 0;
    struct vcpu_guest_context *c;

    if ( (vcpu >= MAX_VIRT_CPUS) || (d->exec_domain[vcpu] != NULL) )
        return -EINVAL;

    if ( alloc_exec_domain_struct(d, vcpu) == NULL )
        return -ENOMEM;

    if ( (c = xmalloc(struct vcpu_guest_context)) == NULL )
    {
        rc = -ENOMEM;
        goto out;
    }

    if ( copy_from_user(c, ctxt, sizeof(*c)) )
    {
        rc = -EFAULT;
        goto out;
    }

    ed = d->exec_domain[vcpu];

    atomic_set(&ed->pausecnt, 0);
    ed->cpumap = CPUMAP_RUNANYWHERE;

    memcpy(&ed->arch, &idle0_exec_domain.arch, sizeof(ed->arch));

    arch_do_boot_vcpu(ed);

    if ( (rc = arch_set_info_guest(ed, c)) != 0 )
        goto out;

    sched_add_domain(ed);

    /* domain_unpause_by_systemcontroller */
    if ( test_and_clear_bit(_VCPUF_ctrl_pause, &ed->vcpu_flags) )
        domain_wake(ed);

    xfree(c);
    return 0;

 out:
    xfree(c);
    arch_free_exec_domain_struct(d->exec_domain[vcpu]);
    d->exec_domain[vcpu] = NULL;
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
