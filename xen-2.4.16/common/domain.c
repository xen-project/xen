
#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/mm.h>
#include <xeno/skbuff.h>
#include <xeno/interrupt.h>
#include <xeno/delay.h>
#include <xeno/event.h>
#include <xeno/dom0_ops.h>
#include <asm/io.h>

#include <asm/msr.h>
#include <xeno/multiboot.h>

#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED)
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED|_PAGE_DIRTY)

extern int nr_mods;
extern module_t *mod;
extern unsigned char *cmdline;

rwlock_t tasklist_lock __cacheline_aligned = RW_LOCK_UNLOCKED;

schedule_data_t schedule_data[NR_CPUS];

int wake_up(struct task_struct *p)
{
    unsigned long flags;
    int ret = 0;
    spin_lock_irqsave(&schedule_data[p->processor].lock, flags);
    if ( __task_on_runqueue(p) ) goto out;
    p->state = TASK_RUNNING;
    __add_to_runqueue(p);
    ret = 1;

 out:
    spin_unlock_irqrestore(&schedule_data[p->processor].lock, flags);
    return ret;
}


struct task_struct *do_newdomain(void)
{
    int retval;
    struct task_struct *p = NULL;
    unsigned long flags;

    retval = -ENOMEM;
    p = alloc_task_struct();
    if (!p) goto newdomain_out;
    memset(p, 0, sizeof(*p));
    p->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(p->shared_info, 0, sizeof(shared_info_t));

    p->addr_limit = USER_DS;
    p->state      = TASK_UNINTERRUPTIBLE;
    p->active_mm  = &p->mm;
    p->num_net_vifs = 0;

    /*
     * KAF: Passing in newdomain struct to this function is gross!
     * Therefore, for now we just allocate the single blk_ring
     * before the multiople net_rings :-)
     */
    p->blk_ring_base = (blk_ring_t *)(p->shared_info + 1);
    p->net_ring_base = (net_ring_t *)(p->blk_ring_base + 1);
    p->pg_head = p->tot_pages = 0;
    write_lock_irqsave(&tasklist_lock, flags);
    SET_LINKS(p);
    write_unlock_irqrestore(&tasklist_lock, flags);

 newdomain_out:
    return(p);
}


void reschedule(struct task_struct *p)
{
    int cpu = p->processor;
    struct task_struct *curr;
    unsigned long flags;

    if ( p->has_cpu ) return;

    spin_lock_irqsave(&schedule_data[cpu].lock, flags);
    curr = schedule_data[cpu].curr;
    if ( is_idle_task(curr) ) 
    {
        set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);
        spin_unlock_irqrestore(&schedule_data[cpu].lock, flags);
#ifdef CONFIG_SMP
        if ( cpu != smp_processor_id() ) smp_send_event_check_cpu(cpu);
#endif
    }
    else
    {
        spin_unlock_irqrestore(&schedule_data[cpu].lock, flags);
    }
}


static void process_timeout(unsigned long __data)
{
    struct task_struct * p = (struct task_struct *) __data;
    wake_up(p);
}

long schedule_timeout(long timeout)
{
    struct timer_list timer;
    unsigned long expire;
    
    switch (timeout)
    {
    case MAX_SCHEDULE_TIMEOUT:
        /*
         * These two special cases are useful to be comfortable in the caller.
         * Nothing more. We could take MAX_SCHEDULE_TIMEOUT from one of the
         * negative value but I' d like to return a valid offset (>=0) to allow
         * the caller to do everything it want with the retval.
         */
        schedule();
        goto out;
    default:
        /*
         * Another bit of PARANOID. Note that the retval will be 0 since no
         * piece of kernel is supposed to do a check for a negative retval of
         * schedule_timeout() (since it should never happens anyway). You just
         * have the printk() that will tell you if something is gone wrong and
         * where.
         */
        if (timeout < 0)
        {
            printk(KERN_ERR "schedule_timeout: wrong timeout "
                   "value %lx from %p\n", timeout,
                   __builtin_return_address(0));
            current->state = TASK_RUNNING;
            goto out;
        }
    }
    
    expire = timeout + jiffies;
    
    init_timer(&timer);
    timer.expires = expire;
    timer.data = (unsigned long) current;
    timer.function = process_timeout;
    
    add_timer(&timer);
    schedule();
    del_timer_sync(&timer);
    
    timeout = expire - jiffies;
    
 out:
    return timeout < 0 ? 0 : timeout;
}


long do_yield(void)
{
    current->state = TASK_INTERRUPTIBLE;
    schedule();
    return 0;
}

/* Get a pointer to the specified domain.  Consider replacing this
 * with a hash lookup later.
 *
 * Also, kill_other_domain should call this instead of scanning on its own.
 */
struct task_struct *find_domain_by_id(unsigned int dom)
{
    struct task_struct *p = &idle0_task;

    read_lock_irq(&tasklist_lock);
    do {
        if ( (p->domain == dom) ) {
            read_unlock_irq(&tasklist_lock);
            return (p);
        }
    } while ( (p = p->next_task) != &idle0_task );
    read_unlock_irq(&tasklist_lock);

    return 0;
}


void kill_domain_with_errmsg(const char *err)
{
    printk("DOM%d FATAL ERROR: %s\n", 
           current->domain, err);
    kill_domain();
}


/* Kill the currently executing domain. */
void kill_domain(void)
{
    if ( current->domain == 0 )
    {
        extern void machine_restart(char *);
        printk("Domain 0 killed: rebooting machine!\n");
        machine_restart(0);
    }

    printk("Killing domain %d\n", current->domain);
    current->state = TASK_DYING;
    schedule();
    BUG(); /* never get here */
}


long kill_other_domain(unsigned int dom)
{
    struct task_struct *p = &idle0_task;
    unsigned long cpu_mask = 0;
    long ret = -ESRCH;

    read_lock_irq(&tasklist_lock);
    do {
        if ( p->domain == dom )
        {
            cpu_mask = mark_guest_event(p, _EVENT_DIE);
            ret = 0;
            break;
        }
    }
    while ( (p = p->next_task) != &idle0_task );
    read_unlock_irq(&tasklist_lock);

    hyp_event_notify(cpu_mask);

    return ret;
}


/* Release resources belonging to task @p. */
void release_task(struct task_struct *p)
{
    ASSERT(!__task_on_runqueue(p));
    ASSERT(p->state == TASK_DYING);
    ASSERT(!p->has_cpu);
    write_lock_irq(&tasklist_lock);
    REMOVE_LINKS(p);
    write_unlock_irq(&tasklist_lock);

    /*
     * Safe! Only queue skbuffs with tasklist_lock held.
     * Only access shared_info with tasklist_lock held.
     * And free_task_struct() only releases if refcnt == 0.
     */
    while ( p->num_net_vifs )
    {
        destroy_net_vif(p);
    }
    free_page((unsigned long)p->shared_info);
    free_task_struct(p);
}


asmlinkage void schedule(void)
{
    struct task_struct *prev, *next;
    struct list_head *tmp;
    int this_cpu;

 need_resched_back:
    prev = current;
    this_cpu = prev->processor;

    spin_lock_irq(&schedule_data[this_cpu].lock);

    ASSERT(!in_interrupt());
    ASSERT(__task_on_runqueue(prev));

    if ( !prev->counter )
    {
        prev->counter = 2;
        __move_last_runqueue(prev);
    }

    switch ( prev->state )
    {
    case TASK_INTERRUPTIBLE:
        if ( signal_pending(prev) )
        {
            prev->state = TASK_RUNNING;
            break;
        }
    default:
        __del_from_runqueue(prev);
    case TASK_RUNNING:;
    }
    clear_bit(_HYP_EVENT_NEED_RESCHED, &prev->hyp_events);

    /* Round-robin, skipping idle where possible. */
    next = NULL;
    list_for_each(tmp, &schedule_data[smp_processor_id()].runqueue) {
        next = list_entry(tmp, struct task_struct, run_list);
        if ( next->domain != IDLE_DOMAIN_ID ) break;
    }

    prev->has_cpu = 0;
    next->has_cpu = 1;

    schedule_data[this_cpu].prev = prev;
    schedule_data[this_cpu].curr = next;

    spin_unlock_irq(&schedule_data[this_cpu].lock);

    if ( unlikely(prev == next) )
    {
        /* We won't go through the normal tail, so do this by hand */
        prev->policy &= ~SCHED_YIELD;
        goto same_process;
    }

    prepare_to_switch();
    switch_to(prev, next);
    prev = schedule_data[this_cpu].prev;
    
    prev->policy &= ~SCHED_YIELD;
    if ( prev->state == TASK_DYING ) release_task(prev);

 same_process:
    if ( test_bit(_HYP_EVENT_NEED_RESCHED, &current->hyp_events) )
        goto need_resched_back;
    return;
}


unsigned int alloc_new_dom_mem(struct task_struct *p, unsigned int kbytes)
{

    struct list_head *temp;
    struct pfn_info *pf, *pf_head;
    unsigned int alloc_pfns;
    unsigned int req_pages;

    /* how many pages do we need to alloc? */
    req_pages = kbytes >> (PAGE_SHIFT - 10);

    /* is there enough mem to serve the request? */   
    if(req_pages > free_pfns)
        return -1;
    
    /* allocate pages and build a thread through frame_table */
    temp = free_list.next;
    printk("bd240 debug: DOM%d requesting %d pages\n", p->domain, req_pages);

    /* allocate first page */
    pf = list_entry(temp, struct pfn_info, list);
    pf->flags |= p->domain;
    temp = temp->next;
    list_del(&pf->list);
    pf->next = pf->prev = p->pg_head = (pf - frame_table);
    free_pfns--;
    pf_head = pf;

    /* allocate the rest */
    for(alloc_pfns = req_pages - 1; alloc_pfns; alloc_pfns--){
        pf = list_entry(temp, struct pfn_info, list);
        pf->flags |= p->domain;
        temp = temp->next;
        list_del(&pf->list);

        pf->next = p->pg_head;
        pf->prev = pf_head->prev;
        (frame_table + pf_head->prev)->next = (pf - frame_table);
        pf_head->prev = (pf - frame_table);

        free_pfns--;
    }
    
    p->tot_pages = req_pages;

    return 0;
}

int final_setup_guestos(struct task_struct * p, dom_meminfo_t * meminfo)
{
    l2_pgentry_t * l2tab;
    l1_pgentry_t * l1tab;
    start_info_t * virt_startinfo_addr;
    unsigned long virt_stack_addr;
    unsigned long long time;
    net_ring_t *net_ring;
    char *dst;    // temporary
    int i;        // temporary

    /* entries 0xe0000000 onwards in page table must contain hypervisor
     * mem mappings - set them up.
     */
    l2tab = (l2_pgentry_t *)__va(meminfo->l2_pgt_addr);
    memcpy(l2tab + DOMAIN_ENTRIES_PER_L2_PAGETABLE, 
        ((l2_pgentry_t *)idle0_pg_table) + DOMAIN_ENTRIES_PER_L2_PAGETABLE, 
        (ENTRIES_PER_L2_PAGETABLE - DOMAIN_ENTRIES_PER_L2_PAGETABLE) * sizeof(l2_pgentry_t));
    p->mm.pagetable = mk_pagetable((unsigned long)l2tab);

    /* map in the shared info structure */
    l2tab = pagetable_ptr(p->mm.pagetable) + l2_table_offset(meminfo->virt_shinfo_addr);
    l1tab = l2_pgentry_to_l1(*l2tab) + l1_table_offset(meminfo->virt_shinfo_addr);
    *l1tab = mk_l1_pgentry(__pa(p->shared_info) | L1_PROT);

    /* set up the shared info structure */
    rdtscll(time);
    p->shared_info->wall_time    = time;
    p->shared_info->domain_time  = time;
    p->shared_info->ticks_per_ms = ticks_per_usec * 1000;

    /* we pass start info struct to guest os as function parameter on stack */
    virt_startinfo_addr = (start_info_t *)meminfo->virt_startinfo_addr;
    virt_stack_addr = (unsigned long)virt_startinfo_addr;       

    /* we need to populate start_info struct within the context of the
     * new domain. thus, temporarely install its pagetables.
     */
    __cli();
    __asm__ __volatile__ (
        "mov %%eax, %%cr3"
        : : "a" (__pa(pagetable_ptr(p->mm.pagetable))));

    memset(virt_startinfo_addr, 0, sizeof(virt_startinfo_addr));
    virt_startinfo_addr->nr_pages = p->tot_pages;
    virt_startinfo_addr->shared_info = (shared_info_t *)meminfo->virt_shinfo_addr;
    virt_startinfo_addr->pt_base = meminfo->virt_load_addr + 
                    ((p->tot_pages - 1) << PAGE_SHIFT);

    /* now, this is just temprorary before we switch to pseudo phys
     * addressing. this works only for contiguous chunks of memory!!!
     */
    virt_startinfo_addr->phys_base = p->pg_head << PAGE_SHIFT;
    
    /* Add virtual network interfaces and point to them in startinfo. */
    while (meminfo->num_vifs-- > 0) {
        net_ring = create_net_vif(p->domain);
        if (!net_ring) panic("no network ring!\n");
    }
    virt_startinfo_addr->net_rings = p->net_ring_base;
    virt_startinfo_addr->num_net_rings = p->num_net_vifs;

    /* Add block io interface */
    virt_startinfo_addr->blk_ring = p->blk_ring_base;

    /* i do not think this has to be done any more, temporary */
    /* We tell OS about any modules we were given. */
    if ( nr_mods > 1 )
    {
        virt_startinfo_addr->mod_start = 
            (mod[1].mod_start-mod[0].mod_start-12) + meminfo->virt_load_addr;
        virt_startinfo_addr->mod_len = 
            mod[nr_mods-1].mod_end - mod[1].mod_start;
    }

    /* temporary, meminfo->cmd_line just needs to be copied info start info */
    dst = virt_startinfo_addr->cmd_line;
    if ( mod[0].string )
    {
        char *modline = (char *)__va(mod[0].string);
        for ( i = 0; i < 255; i++ )
        {
            if ( modline[i] == '\0' ) break;
            *dst++ = modline[i];
        }
    }
    *dst = '\0';

    if ( opt_nfsroot )
    {
        unsigned char boot[150];
        unsigned char ipbase[20], nfsserv[20], gateway[20], netmask[20];
        unsigned char nfsroot[70];
        snprintf(nfsroot, 70, opt_nfsroot, p->domain); 
        snprintf(boot, 200,
                " root=/dev/nfs ip=%s:%s:%s:%s::eth0:off nfsroot=%s",
                 quad_to_str(opt_ipbase + p->domain, ipbase),
                 quad_to_str(opt_nfsserv, nfsserv),
                 quad_to_str(opt_gateway, gateway),
                 quad_to_str(opt_netmask, netmask),
                 nfsroot);
        strcpy(dst, boot);
    }

    /* Reinstate the caller's page tables. */
    __asm__ __volatile__ (
        "mov %%eax,%%cr3"
        : : "a" (__pa(pagetable_ptr(current->mm.pagetable))));    
    __sti();

    new_thread(p, 
               (unsigned long)meminfo->virt_load_addr, 
               (unsigned long)virt_stack_addr, 
               (unsigned long)virt_startinfo_addr);

    return 0;
}
     
/*
 * Initial load map:
 *  start_address:
 *     OS image
 *      ....
 *  stack_start:
 *  start_info:
 *      <one page>
 *  page tables:
 *      <enough pages>
 *  end_address:
 *  shared_info:
 *      <one page>
 */
#define MB_PER_DOMAIN 16
int setup_guestos(struct task_struct *p, dom0_newdomain_t *params)
{
#define ALLOC_PAGE_FROM_DOMAIN() \
  ({ alloc_address -= PAGE_SIZE; __va(alloc_address); })
    char *src, *dst;
    int i, dom = p->domain;
    unsigned long start_address = MAX_MONITOR_ADDRESS;
    unsigned long cur_address, end_address, alloc_address, vaddr;
    unsigned long virt_load_address, virt_stack_address, virt_shinfo_address;
    unsigned long virt_ftable_start_addr = 0, virt_ftable_end_addr;
    unsigned long ft_mapping = (unsigned long)frame_table;
    unsigned int ft_size = 0;
    start_info_t  *virt_startinfo_address;
    unsigned long long time;
    l2_pgentry_t *l2tab;
    l1_pgentry_t *l1tab = NULL;
    struct pfn_info *page = NULL;
    net_ring_t *net_ring;
    blk_ring_t *blk_ring;

    if ( strncmp(__va(mod[0].mod_start), "XenoGues", 8) )
    {
        printk("DOM%d: Invalid guest OS image\n", dom);
        return -1;
    }

    virt_load_address = *(unsigned long *)__va(mod[0].mod_start + 8);
    if ( (virt_load_address & (PAGE_SIZE-1)) )
    {
        printk("DOM%d: Guest OS load address not page-aligned (%08lx)\n",
               dom, virt_load_address);
        return -1;
    }

    if ( alloc_new_dom_mem(p, params->memory_kb) ) return -ENOMEM;

    /* temporary, *_address have to be reimplemented in another way
     * as we can no longer expect contiguous addr space
     */
    start_address = p->pg_head << PAGE_SHIFT; 
    alloc_address = end_address = start_address + (p->tot_pages << PAGE_SHIFT);

    /* start_address += (dom * MB_PER_DOMAIN) << 20; */ /* MB -> bytes */
    /* alloc_address = end_address = start_address + (MB_PER_DOMAIN << 20); */

    if ( (mod[nr_mods-1].mod_end-mod[0].mod_start) > 
         ((end_address-start_address)>>1) )
    {
        printk("DOM%d: Guest OS image is too large\n"
               "       (%luMB is greater than %luMB limit for a\n"
               "        %luMB address space)\n",
               dom, (mod[nr_mods-1].mod_end-mod[0].mod_start)>>20,
               (end_address-start_address)>>21,
               (end_address-start_address)>>20);
        /* XXX Should release memory from alloc_new_dom_mem here XXX */
        return -1;
    }

    /* Set up initial mappings. */
    printk("DOM%d: Mapping physmem %08lx -> %08lx (%luMB)\n", dom,
           start_address, end_address, (end_address-start_address)>>20);
    printk("DOM%d: Guest OS virtual load address is %08lx\n", dom,
           virt_load_address);
    
    l2tab = (l2_pgentry_t *)ALLOC_PAGE_FROM_DOMAIN();
    memcpy(l2tab, idle0_pg_table, sizeof(idle0_pg_table));
    memset(l2tab, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE*sizeof(l2_pgentry_t));
    p->mm.pagetable = mk_pagetable((unsigned long)l2tab);

    /*
     * NB. The upper limit on this loop does one extra page. This is to
     * make sure a pte exists when we want to map the shared_info struct.
     */

    /* bd240: not only one extra page but one + num of pages required for
     * frame_table if domain 0 is in question. this ugly for loop 
     * condition is going to change once domain building is moved out
     * of hypervisor.
     */

    if(dom == 0)
        ft_size = frame_table_size; 

    l2tab = pagetable_ptr(p->mm.pagetable) +
        l2_table_offset(virt_load_address);    
    for ( cur_address  = start_address;
          cur_address != (end_address + PAGE_SIZE + ft_size);
          cur_address += PAGE_SIZE )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1tab = (l1_pgentry_t *)ALLOC_PAGE_FROM_DOMAIN();
            clear_page(l1tab);
            l1tab += l1_table_offset(
                virt_load_address + cur_address - start_address);
            *l2tab++ = mk_l2_pgentry(__pa(l1tab)|L2_PROT);
        }
        *l1tab++ = mk_l1_pgentry(cur_address|L1_PROT);
        
        /* New domain doesn't own shared_info page, or frame_table. */
        if ( cur_address < end_address )
        {
            page = frame_table + (cur_address >> PAGE_SHIFT);
            page->flags = dom | PGT_writeable_page;
            page->type_count = page->tot_count = 1;
        }
    }
    
    /* Pages that are part of page tables must be read-only. */
    vaddr = virt_load_address + alloc_address - start_address;
    l2tab = pagetable_ptr(p->mm.pagetable) + l2_table_offset(vaddr);
    l1tab = l2_pgentry_to_l1(*l2tab++) + l1_table_offset(vaddr);
    for ( cur_address  = alloc_address;
          cur_address != end_address;
          cur_address += PAGE_SIZE )
    {
        *l1tab++ = mk_l1_pgentry(l1_pgentry_val(*l1tab) & ~_PAGE_RW);
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
            l1tab = l2_pgentry_to_l1(*l2tab++);
        page = frame_table + (cur_address >> PAGE_SHIFT);
        page->flags = dom | PGT_l1_page_table;
        page->tot_count++;
    }
    page->flags = dom | PGT_l2_page_table;

    /* Map in the the shared info structure. */
    virt_shinfo_address = end_address - start_address + virt_load_address;
    l2tab = pagetable_ptr(p->mm.pagetable) +
        l2_table_offset(virt_shinfo_address);
    l1tab = l2_pgentry_to_l1(*l2tab) +
        l1_table_offset(virt_shinfo_address);
    *l1tab = mk_l1_pgentry(__pa(p->shared_info)|L1_PROT);

    /* Set up shared info area. */
    rdtscll(time);
    p->shared_info->wall_time    = time;
    p->shared_info->domain_time  = time;
    p->shared_info->ticks_per_ms = ticks_per_usec * 1000;

    /* for DOM0, setup mapping of frame table */
    if ( dom == 0 )
    {
        virt_ftable_start_addr = virt_shinfo_address + PAGE_SIZE;
        virt_ftable_end_addr = virt_ftable_start_addr + frame_table_size;
        for(cur_address = virt_ftable_start_addr;
            cur_address < virt_ftable_end_addr;
            cur_address += PAGE_SIZE)
        {
            l2tab = pagetable_ptr(p->mm.pagetable) + l2_table_offset(cur_address);
            l1tab = l2_pgentry_to_l1(*l2tab) + l1_table_offset(cur_address); 
            *l1tab = mk_l1_pgentry(__pa(ft_mapping)|L1_PROT);
            ft_mapping += PAGE_SIZE;
        }
    }

    virt_startinfo_address = (start_info_t *)
        (alloc_address - start_address - PAGE_SIZE + virt_load_address);
    virt_stack_address  = (unsigned long)virt_startinfo_address;

    /* Install the new page tables. */
    __cli();
    __asm__ __volatile__ (
        "mov %%eax,%%cr3"
        : : "a" (__pa(pagetable_ptr(p->mm.pagetable))));

    /* Copy the guest OS image. */
    src = (char *)__va(mod[0].mod_start + 12);
    dst = (char *)virt_load_address;
    while ( src < (char *)__va(mod[nr_mods-1].mod_end) ) *dst++ = *src++;

    /* Set up start info area. */
    memset(virt_startinfo_address, 0, sizeof(*virt_startinfo_address));
    virt_startinfo_address->nr_pages = (end_address-start_address)>>PAGE_SHIFT;
    virt_startinfo_address->shared_info = 
        (shared_info_t *)virt_shinfo_address;
    virt_startinfo_address->pt_base = 
        end_address - PAGE_SIZE - start_address + virt_load_address;
    virt_startinfo_address->phys_base = start_address;
    /* NB. Next field will be NULL if dom != 0. */
    virt_startinfo_address->frame_table = virt_ftable_start_addr;
    virt_startinfo_address->frame_table_len = ft_size;
    virt_startinfo_address->frame_table_pa = __pa(frame_table);

    /* Add virtual network interfaces and point to them in startinfo. */
    while (params->num_vifs-- > 0) {
        net_ring = create_net_vif(dom);
        if (!net_ring) panic("no network ring!\n");
    }

/* XXX SMH: horrible hack to convert hypervisor VAs in SHIP to guest VAs  */
#define SHIP2GUEST(_x) (virt_shinfo_address | (((unsigned long)(_x)) & 0xFFF))

    virt_startinfo_address->net_rings = 
	(net_ring_t *)SHIP2GUEST(p->net_ring_base); 
    virt_startinfo_address->num_net_rings = p->num_net_vifs;

    /* Add block io interface */
    virt_startinfo_address->blk_ring = 
	(blk_ring_t *)SHIP2GUEST(p->blk_ring_base); 


    /* We tell OS about any modules we were given. */
    if ( nr_mods > 1 )
    {
        virt_startinfo_address->mod_start = 
            (mod[1].mod_start-mod[0].mod_start-12) + virt_load_address;
        virt_startinfo_address->mod_len = 
            mod[nr_mods-1].mod_end - mod[1].mod_start;
    }

    dst = virt_startinfo_address->cmd_line;
    if ( mod[0].string )
    {
        char *modline = (char *)__va(mod[0].string);
        for ( i = 0; i < 255; i++ )
        {
            if ( modline[i] == '\0' ) break;
            *dst++ = modline[i];
        }
    }
    *dst = '\0';

    if ( opt_nfsroot )
    {
        unsigned char boot[150];
        unsigned char ipbase[20], nfsserv[20], gateway[20], netmask[20];
        unsigned char nfsroot[70];
        snprintf(nfsroot, 70, opt_nfsroot, dom); 
        snprintf(boot, 200,
                " root=/dev/nfs ip=%s:%s:%s:%s::eth0:off nfsroot=%s",
                 quad_to_str(opt_ipbase + dom, ipbase),
                 quad_to_str(opt_nfsserv, nfsserv),
                 quad_to_str(opt_gateway, gateway),
                 quad_to_str(opt_netmask, netmask),
                 nfsroot);
        strcpy(dst, boot);
    }

    /* Reinstate the caller's page tables. */
    __asm__ __volatile__ (
        "mov %%eax,%%cr3"
        : : "a" (__pa(pagetable_ptr(current->mm.pagetable))));    
    __sti();

    new_thread(p, 
               (unsigned long)virt_load_address, 
               (unsigned long)virt_stack_address, 
               (unsigned long)virt_startinfo_address);

    return 0;
}


void __init domain_init(void)
{
    int i;
    for ( i = 0; i < NR_CPUS; i++ )
    {
        INIT_LIST_HEAD(&schedule_data[i].runqueue);
        spin_lock_init(&schedule_data[i].lock);
        schedule_data[i].prev = &idle0_task;
        schedule_data[i].curr = &idle0_task;
    }
}



#if 0
    unsigned long s = (mod[        0].mod_start + (PAGE_SIZE-1)) & PAGE_MASK;
    unsigned long e = (mod[nr_mods-1].mod_end   + (PAGE_SIZE-1)) & PAGE_MASK;
    while ( s != e ) 
    { 
        free_pages((unsigned long)__va(s), 0); 
        s += PAGE_SIZE;
    }
#endif

