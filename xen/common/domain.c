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
#include <asm/shadow.h>
#include <public/dom0_ops.h>
#include <asm/domain_page.h>

/* Both these structures are protected by the domlist_lock. */
rwlock_t domlist_lock = RW_LOCK_UNLOCKED;
struct domain *domain_hash[DOMAIN_HASH_SIZE];
struct domain *domain_list;

struct domain *do_createdomain(domid_t dom_id, unsigned int cpu)
{
    struct domain *d, **pd;
    struct exec_domain *ed;

    if ( (d = alloc_domain_struct()) == NULL )
        return NULL;

    ed = d->exec_domain[0];

    atomic_set(&d->refcnt, 1);
    atomic_set(&ed->pausecnt, 0);

    shadow_lock_init(ed);

    d->id          = dom_id;
    ed->processor   = cpu;
    d->create_time = NOW();
 
    memcpy(&ed->thread, &idle0_exec_domain.thread, sizeof(ed->thread));

    spin_lock_init(&d->time_lock);

    spin_lock_init(&d->big_lock);

    spin_lock_init(&d->page_alloc_lock);
    INIT_LIST_HEAD(&d->page_list);
    INIT_LIST_HEAD(&d->xenpage_list);

    /* Per-domain PCI-device list. */
    spin_lock_init(&d->pcidev_lock);
    INIT_LIST_HEAD(&d->pcidev_list);

    if ( d->id != IDLE_DOMAIN_ID )
    {
        if ( (init_event_channels(d) != 0) || (grant_table_create(d) != 0) )
        {
            destroy_event_channels(d);
            free_domain_struct(d);
            return NULL;
        }

        arch_do_createdomain(ed);

        sched_add_domain(ed);

        write_lock(&domlist_lock);
        pd = &domain_list; /* NB. domain_list maintained in order of dom_id. */
        for ( pd = &domain_list; *pd != NULL; pd = &(*pd)->next_list )
            if ( (*pd)->id > d->id )
                break;
        d->next_list = *pd;
        *pd = d;
        d->next_hash = domain_hash[DOMAIN_HASH(dom_id)];
        domain_hash[DOMAIN_HASH(dom_id)] = d;
        write_unlock(&domlist_lock);
    }
    else
    {
        sched_add_domain(ed);
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
        if ( d->id == dom )
        {
            if ( unlikely(!get_domain(d)) )
                d = NULL;
            break;
        }
        d = d->next_hash;
    }
    read_unlock(&domlist_lock);

    return d;
}


/* Return the most recently created domain. */
struct domain *find_last_domain(void)
{
    struct domain *d, *dlast;

    read_lock(&domlist_lock);
    dlast = domain_list;
    d = dlast->next_list;
    while ( d != NULL )
    {
        if ( d->create_time > dlast->create_time )
            dlast = d;
        d = d->next_list;
    }
    if ( !get_domain(dlast) )
        dlast = NULL;
    read_unlock(&domlist_lock);

    return dlast;
}


void domain_kill(struct domain *d)
{
    domain_pause(d);
    if ( !test_and_set_bit(DF_DYING, &d->d_flags) )
    {
        sched_rem_domain(d);
        domain_relinquish_memory(d);
        put_domain(d);
    }
}


void domain_crash(void)
{
    struct domain *d = current->domain;

    if ( d->id == 0 )
        BUG();

    set_bit(DF_CRASHED, &d->d_flags);

    send_guest_virq(dom0->exec_domain[0], VIRQ_DOM_EXC);
    
    __enter_scheduler();
    BUG();
}

void domain_shutdown(u8 reason)
{
    struct domain *d = current->domain;

    if ( d->id == 0 )
    {
        extern void machine_restart(char *);
        extern void machine_halt(void);

        if ( reason == 0 ) 
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

    d->shutdown_code = reason;
    set_bit(DF_SHUTDOWN, &d->d_flags);

    send_guest_virq(dom0->exec_domain[0], VIRQ_DOM_EXC);

    __enter_scheduler();
}

unsigned int alloc_new_dom_mem(struct domain *d, unsigned int kbytes)
{
    unsigned int alloc_pfns, nr_pages;
    struct pfn_info *page;

    nr_pages = (kbytes + ((PAGE_SIZE-1)>>10)) >> (PAGE_SHIFT - 10);
    d->max_pages = nr_pages; /* this can now be controlled independently */

    /* Grow the allocation if necessary. */
    for ( alloc_pfns = d->tot_pages; alloc_pfns < nr_pages; alloc_pfns++ )
    {
        if ( unlikely((page = alloc_domheap_page(d)) == NULL) )
        {
            domain_relinquish_memory(d);
            return -ENOMEM;
        }

        /* initialise to machine_to_phys_mapping table to likely pfn */
        machine_to_phys_mapping[page-frame_table] = alloc_pfns;
    }

    return 0;
}
 

/* Release resources belonging to task @p. */
void domain_destruct(struct domain *d)
{
    struct domain **pd;
    atomic_t      old, new;

    if ( !test_bit(DF_DYING, &d->d_flags) )
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
        pd = &(*pd)->next_list;
    *pd = d->next_list;
    pd = &domain_hash[DOMAIN_HASH(d->id)];
    while ( *pd != d ) 
        pd = &(*pd)->next_hash;
    *pd = d->next_hash;
    write_unlock(&domlist_lock);

    destroy_event_channels(d);
    grant_table_destroy(d);

    free_perdomain_pt(d);
    free_xenheap_page((unsigned long)d->shared_info);

    free_domain_struct(d);
}


/*
 * final_setup_guestos is used for final setup and launching of domains other
 * than domain 0. ie. the domains that are being built by the userspace dom0
 * domain builder.
 */
int final_setup_guestos(struct domain *p, dom0_builddomain_t *builddomain)
{
    int rc = 0;
    full_execution_context_t *c;

    if ( (c = xmalloc(sizeof(*c))) == NULL )
        return -ENOMEM;

    if ( test_bit(DF_CONSTRUCTED, &p->d_flags) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( copy_from_user(c, builddomain->ctxt, sizeof(*c)) )
    {
        rc = -EFAULT;
        goto out;
    }
    
    if ( (rc = arch_final_setup_guestos(p->exec_domain[0],c)) != 0 )
        goto out;

    /* Set up the shared info structure. */
    update_dom_time(p);

    set_bit(DF_CONSTRUCTED, &p->d_flags);

 out:    
    if ( c != NULL )
        xfree(c);
    return rc;
}

extern xmem_cache_t *exec_domain_struct_cachep;

/*
 * final_setup_guestos is used for final setup and launching of domains other
 * than domain 0. ie. the domains that are being built by the userspace dom0
 * domain builder.
 */
long do_boot_vcpu(unsigned long vcpu, full_execution_context_t *ctxt) 
{
    struct domain *d = current->domain;
    struct exec_domain *ed;
    int rc = 0;
    full_execution_context_t *c;

    if ( d->exec_domain[vcpu] != NULL )
        return EINVAL;

    if ( alloc_exec_domain_struct(d, vcpu) == NULL )
        return -ENOMEM;

    if ( (c = xmalloc(sizeof(*c))) == NULL )
    {
        rc = -ENOMEM;
        goto out;
    }

    if ( copy_from_user(c, ctxt, sizeof(*c)) )
    {
        rc = -EFAULT;
        goto out;
    }

    printk("do_boot_vcpu for dom %d vcpu %ld\n", d->id, vcpu);

    ed = d->exec_domain[vcpu];

    atomic_set(&ed->pausecnt, 0);
    shadow_lock_init(ed);

    memcpy(&ed->thread, &idle0_exec_domain.thread, sizeof(ed->thread));

    /* arch_do_createdomain */
    ed->mm.perdomain_ptes = d->mm_perdomain_pt + (ed->eid << PDPT_VCPU_SHIFT);

    sched_add_domain(ed);

    if ( (rc = arch_final_setup_guestos(ed, c)) != 0 )
        goto out;

    /* Set up the shared info structure. */
    update_dom_time(d);

    /* domain_unpause_by_systemcontroller */
    if ( test_and_clear_bit(EDF_CTRLPAUSE, &ed->ed_flags) )
        domain_wake(ed);

    xfree(c);
    return 0;

 out:
    if ( c != NULL )
        xfree(c);
    xmem_cache_free(exec_domain_struct_cachep, d->exec_domain[vcpu]);
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
        if (vm_assist_info[type].enable)
            (*vm_assist_info[type].enable)(p);
        return 0;
    case VMASST_CMD_disable:
        clear_bit(type, &p->vm_assist);
        if (vm_assist_info[type].disable)
            (*vm_assist_info[type].disable)(p);
        return 0;
    }

    return -ENOSYS;
}
