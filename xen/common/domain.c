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
#include <xeno/time.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <asm/io.h>
#include <asm/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <xeno/blkdev.h>
#include <xeno/console.h>
#include <xeno/vbd.h>

#include <asm/i387.h>

/*
 * NB. No ring-3 access in initial guestOS pagetables. Note that we allow
 * ring-3 privileges in the page directories, so that the guestOS may later
 * decide to share a 4MB region with applications.
 */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

/* Both these structures are protected by the tasklist_lock. */
rwlock_t tasklist_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
struct task_struct *task_hash[TASK_HASH_SIZE];

struct task_struct *do_createdomain(unsigned int dom_id, unsigned int cpu)
{
    int retval;
    struct task_struct *p = NULL;
    unsigned long flags;

    retval = -ENOMEM;
    p = alloc_task_struct();
    if ( p == NULL ) return NULL;
    memset(p, 0, sizeof(*p));

    atomic_set(&p->refcnt, 1);

    p->domain    = dom_id;
    p->processor = cpu;

    sprintf(p->name, "Domain-%d", dom_id);

    spin_lock_init(&p->blk_ring_lock);
    spin_lock_init(&p->page_lock);
    spin_lock_init(&p->physdev_lock);

    p->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(p->shared_info, 0, PAGE_SIZE);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(p->shared_info), dom_id);

    p->mm.perdomain_pt = (l1_pgentry_t *)get_free_page(GFP_KERNEL);
    memset(p->mm.perdomain_pt, 0, PAGE_SIZE);

    init_blkdev_info(p);

    INIT_LIST_HEAD(&p->physdisk_aces);

    p->addr_limit = USER_DS;

    sched_add_domain(p);

    INIT_LIST_HEAD(&p->pg_head);
    p->max_pages = p->tot_pages = 0;
    write_lock_irqsave(&tasklist_lock, flags);
    SET_LINKS(p);
    p->next_hash = task_hash[TASK_HASH(dom_id)];
    task_hash[TASK_HASH(dom_id)] = p;
    write_unlock_irqrestore(&tasklist_lock, flags);

    return p;
}


struct task_struct *find_domain_by_id(unsigned int dom)
{
    struct task_struct *p;
    unsigned long flags;

    read_lock_irqsave(&tasklist_lock, flags);
    p = task_hash[TASK_HASH(dom)];
    while ( p != NULL )
    {
        if ( p->domain == dom )
        {
            get_task_struct(p);
            break;
        }
        p = p->next_hash;
    }
    read_unlock_irqrestore(&tasklist_lock, flags);

    return p;
}


void kill_domain_with_errmsg(const char *err)
{
    printk("DOM%d FATAL ERROR: %s\n", 
           current->domain, err);
    kill_domain();
}


void __kill_domain(struct task_struct *p)
{
    int i;
    struct task_struct **pp;
    unsigned long flags;

    if ( p->domain == 0 )
    {
        extern void machine_restart(char *);
        printk("Domain 0 killed: rebooting machine!\n");
        machine_restart(0);
    }

    /* Only allow the domain to be destroyed once. */
    if ( !sched_rem_domain(p) )
        return;

    printk("Killing domain %d\n", p->domain);

    unlink_blkdev_info(p);

#if 0
    for ( i = 0; i < XEN_MAX_VBDS; i++ )
	xen_vbd_delete(p, i);
#endif

    for ( i = 0; i < MAX_DOMAIN_VIFS; i++ )
        unlink_net_vif(p->net_vif_list[i]);

    /*
     * Note this means that find_domain_by_id may fail, even when the caller
     * holds a reference to the domain being queried. Take care!
     */
    write_lock_irqsave(&tasklist_lock, flags);
    REMOVE_LINKS(p);
    pp = &task_hash[TASK_HASH(p->domain)];
    while ( *pp != p ) *pp = (*pp)->next_hash;
    *pp = p->next_hash;
    write_unlock_irqrestore(&tasklist_lock, flags);

    if ( p == current )
    {
        __enter_scheduler();
        BUG(); /* never get here */
    }
    else
    {
        put_task_struct(p);
    }
}


void kill_domain(void)
{
    __kill_domain(current);
}


long kill_other_domain(unsigned int dom, int force)
{
    struct task_struct *p;
    unsigned long cpu_mask = 0;

    p = find_domain_by_id(dom);
    if ( p == NULL ) return -ESRCH;

    if ( p->state == TASK_STOPPED )
    {
        __kill_domain(p);
    }
    else if ( force )
    {
        cpu_mask = mark_hyp_event(p, _HYP_EVENT_DIE);
        hyp_event_notify(cpu_mask);
    }
    else
    {
        cpu_mask = mark_guest_event(p, _EVENT_DIE);
        guest_event_notify(cpu_mask);
    }

    put_task_struct(p);
    return 0;
}

void stop_domain(void)
{
    memcpy(&current->shared_info->execution_context, 
           get_execution_context(), 
           sizeof(execution_context_t));
    unlazy_fpu(current);
    wmb(); /* All CPUs must see saved info in state TASK_STOPPED. */
    set_current_state(TASK_STOPPED);
    __enter_scheduler();
}

long stop_other_domain(unsigned int dom)
{
    unsigned long cpu_mask;
    struct task_struct *p;
    
    p = find_domain_by_id (dom);
    if ( p == NULL) return -ESRCH;
    
    if ( p->state != TASK_STOPPED )
    {
        cpu_mask = mark_guest_event(p, _EVENT_STOP);
        guest_event_notify(cpu_mask);
    }
    
    put_task_struct(p);
    return 0;
}

unsigned int alloc_new_dom_mem(struct task_struct *p, unsigned int kbytes)
{
    struct list_head *temp;
    struct pfn_info *pf;
    unsigned int alloc_pfns;
    unsigned int req_pages;
    unsigned long flags;

    /* how many pages do we need to alloc? */
    req_pages = kbytes >> (PAGE_SHIFT - 10);

    spin_lock_irqsave(&free_list_lock, flags);
    
    /* is there enough mem to serve the request? */   
    if ( (req_pages + (SLACK_DOMAIN_MEM_KILOBYTES >> (PAGE_SHIFT-10))) >
         free_pfns )
    {
        spin_unlock_irqrestore(&free_list_lock, flags);
        return -1;
    }

    /* allocate pages and build a thread through frame_table */
    temp = free_list.next;
    for ( alloc_pfns = 0; alloc_pfns < req_pages; alloc_pfns++ )
    {
        pf = list_entry(temp, struct pfn_info, list);
        pf->flags = p->domain;
        pf->type_count = pf->tot_count = 0;
        temp = temp->next;
        list_del(&pf->list);
        list_add_tail(&pf->list, &p->pg_head);
        free_pfns--;
        ASSERT(free_pfns != 0);
    }
   
    spin_unlock_irqrestore(&free_list_lock, flags);
    
    p->tot_pages = req_pages;

    /* TEMPORARY: max_pages should be explicitly specified. */
    p->max_pages = p->tot_pages;

    return 0;
}
 

void free_all_dom_mem(struct task_struct *p)
{
    struct list_head *ent;
    unsigned long flags;

    spin_lock_irqsave(&free_list_lock, flags);
    while ( (ent = p->pg_head.next) != &p->pg_head )
    {
        struct pfn_info *pf = list_entry(ent, struct pfn_info, list);
        pf->type_count = pf->tot_count = pf->flags = 0;
        ASSERT(ent->next->prev == ent);
        ASSERT(ent->prev->next == ent);
        list_del(ent);
        list_add(ent, &free_list);
        free_pfns++;
    }
    spin_unlock_irqrestore(&free_list_lock, flags);

    p->tot_pages = 0;
}


/* Release resources belonging to task @p. */
void release_task(struct task_struct *p)
{
    ASSERT(p->state == TASK_DYING);
    ASSERT(!p->has_cpu);

    printk("Releasing task %d\n", p->domain);

    /*
     * This frees up blkdev rings. Totally safe since blkdev ref counting
     * actually uses the task_struct refcnt.
     */
    destroy_blkdev_info(p);

#if 0
    /* Free up the physdisk access control info */
    destroy_physdisk_aces(p);
#endif

    /* Free all memory associated with this domain. */
    free_page((unsigned long)p->mm.perdomain_pt);
    UNSHARE_PFN(virt_to_page(p->shared_info));
    free_page((unsigned long)p->shared_info);
    free_all_dom_mem(p);

    kmem_cache_free(task_struct_cachep, p);
}


/*
 * final_setup_guestos is used for final setup and launching of domains other
 * than domain 0. ie. the domains that are being built by the userspace dom0
 * domain builder.
 */
int final_setup_guestos(struct task_struct *p, dom0_builddomain_t *builddomain)
{
    unsigned long phys_l2tab;
    int i;

    if ( (p->flags & PF_CONSTRUCTED) )
        return -EINVAL;
    
    p->flags &= ~PF_DONEFPUINIT;
    if ( builddomain->ctxt.flags & ECF_I387_VALID )
        p->flags |= PF_DONEFPUINIT;
    memcpy(&p->shared_info->execution_context,
           &builddomain->ctxt.i386_ctxt,
           sizeof(p->shared_info->execution_context));
    memcpy(&p->thread.i387,
           &builddomain->ctxt.i387_ctxt,
           sizeof(p->thread.i387));
    memcpy(p->thread.traps,
           &builddomain->ctxt.trap_ctxt,
           sizeof(p->thread.traps));
    SET_DEFAULT_FAST_TRAP(&p->thread);
    (void)set_fast_trap(p, builddomain->ctxt.fast_trap_idx);
    p->mm.ldt_base = builddomain->ctxt.ldt_base;
    p->mm.ldt_ents = builddomain->ctxt.ldt_ents;
    SET_GDT_ENTRIES(p, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(p, DEFAULT_GDT_ADDRESS);
    if ( builddomain->ctxt.gdt_ents != 0 )
        (void)set_gdt(p,
                      builddomain->ctxt.gdt_frames,
                      builddomain->ctxt.gdt_ents);
    p->thread.ss1  = builddomain->ctxt.ring1_ss;
    p->thread.esp1 = builddomain->ctxt.ring1_esp;
    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(p, i, builddomain->ctxt.debugreg[i]);
    p->event_selector    = builddomain->ctxt.event_callback_cs;
    p->event_address     = builddomain->ctxt.event_callback_eip;
    p->failsafe_selector = builddomain->ctxt.failsafe_callback_cs;
    p->failsafe_address  = builddomain->ctxt.failsafe_callback_eip;
    
    /* NB. Page base must already be pinned! */
    phys_l2tab = builddomain->ctxt.pt_base;
    p->mm.pagetable = mk_pagetable(phys_l2tab);
    get_page_type(&frame_table[phys_l2tab>>PAGE_SHIFT]);
    get_page_tot(&frame_table[phys_l2tab>>PAGE_SHIFT]);

    /* Set up the shared info structure. */
    update_dom_time(p->shared_info);

    /* Add virtual network interfaces and point to them in startinfo. */
    while ( builddomain->num_vifs-- > 0 )
        (void)create_net_vif(p->domain);

    p->flags |= PF_CONSTRUCTED;
    
    return 0;
}

static unsigned long alloc_page_from_domain(unsigned long * cur_addr, 
    unsigned long * index)
{
    unsigned long ret = *cur_addr;
    struct list_head *ent = frame_table[ret >> PAGE_SHIFT].list.prev;
    *cur_addr = list_entry(ent, struct pfn_info, list) - frame_table;
    *cur_addr <<= PAGE_SHIFT;
    (*index)--;    
    return ret;
}

/*
 * setup_guestos is used for building dom0 solely. other domains are built in
 * userspace dom0 and final setup is being done by final_setup_guestos.
 */
int setup_guestos(struct task_struct *p, dom0_createdomain_t *params, 
                  unsigned int num_vifs,
                  char *phy_data_start, unsigned long data_len, 
		  char *cmdline, unsigned long initrd_len)
{
    struct list_head *list_ent;
    char *src, *vsrc, *dst, *data_start;
    int i, dom = p->domain;
    unsigned long phys_l1tab, phys_l2tab;
    unsigned long cur_address, alloc_address;
    unsigned long virt_load_address, virt_stack_address;
    start_info_t  *virt_startinfo_address;
    unsigned long count;
    unsigned long alloc_index;
    l2_pgentry_t *l2tab, *l2start;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;
    struct pfn_info *page = NULL;

    /* Sanity! */
    if ( p->domain != 0 ) BUG();
    if ( (p->flags & PF_CONSTRUCTED) ) BUG();

    /*
     * This is all a bit grim. We've moved the modules to the "safe" physical 
     * memory region above MAP_DIRECTMAP_ADDRESS (48MB). Later in this 
     * routeine, we're going to copy it down into the region that's actually 
     * been allocated to domain 0. This is highly likely to be overlapping, so 
     * we use a forward copy.
     * 
     * MAP_DIRECTMAP_ADDRESS should be safe. The worst case is a machine with 
     * 4GB and lots of network/disk cards that allocate loads of buffers. 
     * We'll have to revist this if we ever support PAE (64GB).
     */

    data_start = map_domain_mem((unsigned long)phy_data_start);

    if ( strncmp(data_start, "XenoGues", 8) )
    {
        printk("DOM%d: Invalid guest OS image\n", dom);
        return -1;
    }

    virt_load_address = *(unsigned long *)(data_start + 8);
    if ( (virt_load_address & (PAGE_SIZE-1)) )
    {
        printk("DOM%d: Guest OS load address not page-aligned (%08lx)\n",
               dom, virt_load_address);
        return -1;
    }

    if ( alloc_new_dom_mem(p, params->memory_kb) ) return -ENOMEM;
    alloc_address = list_entry(p->pg_head.prev, struct pfn_info, list) -
        frame_table;
    alloc_address <<= PAGE_SHIFT;
    alloc_index = p->tot_pages;

    if ( data_len > (params->memory_kb << 9) )
    {
        printk("DOM%d: Guest OS image is too large\n"
               "       (%luMB is greater than %uMB limit for a\n"
               "        %uMB address space)\n",
               dom, data_len>>20,
               (params->memory_kb)>>11,
               (params->memory_kb)>>10);
        free_all_dom_mem(p);
        return -1;
    }

    printk("DOM%d: Guest OS virtual load address is %08lx\n", dom,
           virt_load_address);
    
    SET_GDT_ENTRIES(p, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(p, DEFAULT_GDT_ADDRESS);

    /*
     * We're basically forcing default RPLs to 1, so that our "what privilege
     * level are we returning to?" logic works.
     */
    p->failsafe_selector = FLAT_RING1_CS;
    p->event_selector    = FLAT_RING1_CS;
    p->thread.ss1        = FLAT_RING1_DS;
    for ( i = 0; i < 256; i++ ) 
        p->thread.traps[i].cs = FLAT_RING1_CS;

    /*
     * WARNING: The new domain must have its 'processor' field
     * filled in by now !!
     */
    phys_l2tab = alloc_page_from_domain(&alloc_address, &alloc_index);
    l2start = l2tab = map_domain_mem(phys_l2tab);
    memcpy(l2tab, &idle_pg_table[0], PAGE_SIZE);
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(p->mm.perdomain_pt) | __PAGE_HYPERVISOR);
    l2tab[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(phys_l2tab | __PAGE_HYPERVISOR);
    memset(l2tab, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE*sizeof(l2_pgentry_t));
    p->mm.pagetable = mk_pagetable(phys_l2tab);

    l2tab += l2_table_offset(virt_load_address);
    cur_address = list_entry(p->pg_head.next, struct pfn_info, list) -
        frame_table;
    cur_address <<= PAGE_SHIFT;
    for ( count = 0; count < p->tot_pages; count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            if ( l1tab != NULL ) unmap_domain_mem(l1start);
            phys_l1tab = alloc_page_from_domain(&alloc_address, &alloc_index);
            *l2tab++ = mk_l2_pgentry(phys_l1tab|L2_PROT);
            l1start = l1tab = map_domain_mem(phys_l1tab);
            clear_page(l1tab);
            l1tab += l1_table_offset(
                virt_load_address + (count << PAGE_SHIFT));
        }
        *l1tab++ = mk_l1_pgentry(cur_address|L1_PROT);
        
        page = frame_table + (cur_address >> PAGE_SHIFT);
        page->flags = dom | PGT_writeable_page | PG_need_flush;
        page->type_count = page->tot_count = 1;
        /* Set up the MPT entry. */
        machine_to_phys_mapping[cur_address >> PAGE_SHIFT] = count;

        list_ent = frame_table[cur_address >> PAGE_SHIFT].list.next;
        cur_address = list_entry(list_ent, struct pfn_info, list) -
            frame_table;
        cur_address <<= PAGE_SHIFT;
    }
    unmap_domain_mem(l1start);

    /* pages that are part of page tables must be read only */
    l2tab = l2start + l2_table_offset(virt_load_address + 
        (alloc_index << PAGE_SHIFT));
    l1start = l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
    l1tab += l1_table_offset(virt_load_address + (alloc_index << PAGE_SHIFT));
    l2tab++;
    for ( count = alloc_index; count < p->tot_pages; count++ ) 
    {
        *l1tab = mk_l1_pgentry(l1_pgentry_val(*l1tab) & ~_PAGE_RW);
        page = frame_table + l1_pgentry_to_pagenr(*l1tab);
        page->flags = dom | PGT_l1_page_table;
        page->tot_count++;
        l1tab++;
        if( !((unsigned long)l1tab & (PAGE_SIZE - 1)) )
        {
            unmap_domain_mem(l1start);
            l1start = l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
            l2tab++;
        }
    }
    page->type_count |= REFCNT_PIN_BIT;
    page->tot_count  |= REFCNT_PIN_BIT;
    page->flags = dom | PGT_l2_page_table;
    unmap_domain_mem(l1start);

    /* Set up shared info area. */
    update_dom_time(p->shared_info);
    p->shared_info->domain_time = 0;

    virt_startinfo_address = (start_info_t *)
        (virt_load_address + ((alloc_index - 1) << PAGE_SHIFT));
    virt_stack_address  = (unsigned long)virt_startinfo_address;
    
    unmap_domain_mem(l2start);

    /* Install the new page tables. */
    __cli();
    __write_cr3_counted(pagetable_val(p->mm.pagetable));

    /* Copy the guest OS image. */    
    src  = (char *)(phy_data_start + 12);
    vsrc = (char *)(data_start + 12); /* data_start invalid after first page*/
    dst  = (char *)virt_load_address;
    while ( src < (phy_data_start+data_len) )
    {
	*dst++ = *vsrc++;
	src++;
	if ( (((unsigned long)src) & (PAGE_SIZE-1)) == 0 )
        {
	    unmap_domain_mem( vsrc-1 );
	    vsrc = map_domain_mem( (unsigned long)src );
        }
    }
    unmap_domain_mem( vsrc );
    
    /* Set up start info area. */
    memset(virt_startinfo_address, 0, sizeof(*virt_startinfo_address));
    virt_startinfo_address->nr_pages = p->tot_pages;
    virt_startinfo_address->shared_info = virt_to_phys(p->shared_info);
    virt_startinfo_address->pt_base = virt_load_address + 
        ((p->tot_pages - 1) << PAGE_SHIFT); 

    virt_startinfo_address->dom_id = p->domain;
    virt_startinfo_address->flags  = 0;
    if ( IS_PRIV(p) )
    {
        virt_startinfo_address->flags |= SIF_PRIVILEGED;
        if ( CONSOLE_ISOWNER(p) )
            virt_startinfo_address->flags |= SIF_CONSOLE;
    }

    if ( initrd_len )
    {
	virt_startinfo_address->mod_start = (unsigned long)dst-initrd_len;
	virt_startinfo_address->mod_len   = initrd_len;
	printk("Initrd len 0x%lx, start at 0x%08lx\n",
	       virt_startinfo_address->mod_len, 
               virt_startinfo_address->mod_start);
    }

    /* Add virtual network interfaces and point to them in startinfo. */
    while ( num_vifs-- > 0 )
        (void)create_net_vif(dom);

    dst = virt_startinfo_address->cmd_line;
    if ( cmdline != NULL )
    {
        for ( i = 0; i < 255; i++ )
        {
            if ( cmdline[i] == '\0' ) break;
            *dst++ = cmdline[i];
        }
    }
    *dst = '\0';

    /* If this guy's getting the console we'd better let go. */
    if ( virt_startinfo_address->flags & SIF_CONSOLE )
    {
        /* NB. Should reset the console here. */
        opt_console = 0;
    }  


    /* Reinstate the caller's page tables. */
    __write_cr3_counted(pagetable_val(current->mm.pagetable));
    __sti();

    p->flags |= PF_CONSTRUCTED;

    new_thread(p, 
               (unsigned long)virt_load_address, 
               (unsigned long)virt_stack_address, 
               (unsigned long)virt_startinfo_address);

    return 0;
}


void __init domain_init(void)
{
    printk("Initialising domains\n");
}
