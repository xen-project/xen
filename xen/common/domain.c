/******************************************************************************
 * domain.c
 * 
 * Generic domain-handling functions.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/sched.h>
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

    if ( (d->domain_id != IDLE_DOMAIN_ID) &&
         ((init_event_channels(d) != 0) || (grant_table_create(d) != 0)) )
    {
        destroy_event_channels(d);
        free_domain_struct(d);
        return NULL;
    }
    
    arch_do_createdomain(ed);
    
    sched_add_domain(ed);

    if ( d->domain_id != IDLE_DOMAIN_ID )
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
        BUG();

    set_bit(_DOMF_crashed, &d->domain_flags);

    send_guest_virq(dom0->exec_domain[0], VIRQ_DOM_EXC);

    raise_softirq(SCHEDULE_SOFTIRQ);
}


void domain_crash_synchronous(void)
{
    domain_crash();
    for ( ; ; )
        do_softirq();
}


void domain_shutdown(u8 reason)
{
    struct domain *d = current->domain;

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

    if ( (d->shutdown_code = reason) == SHUTDOWN_crash )
        set_bit(_DOMF_crashed, &d->domain_flags);
    else
        set_bit(_DOMF_shutdown, &d->domain_flags);

    send_guest_virq(dom0->exec_domain[0], VIRQ_DOM_EXC);

    raise_softirq(SCHEDULE_SOFTIRQ);
}


/* Release resources belonging to task @p. */
void domain_destruct(struct domain *d)
{
    struct domain **pd;
    atomic_t      old, new;

    if ( !test_bit(_DOMF_dying, &d->domain_flags) )
        BUG();

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
    unsigned long vcpu = setdomaininfo->exec_domain;
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
