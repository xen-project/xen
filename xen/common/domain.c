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
    spin_lock_init(&p->event_channel_lock);

    p->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(p->shared_info, 0, PAGE_SIZE);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(p->shared_info), p);

    p->mm.perdomain_pt = (l1_pgentry_t *)get_free_page(GFP_KERNEL);
    memset(p->mm.perdomain_pt, 0, PAGE_SIZE);

    init_blkdev_info(p);

    p->addr_limit = USER_DS;

    sched_add_domain(p);

    spin_lock_init(&p->page_list_lock);
    INIT_LIST_HEAD(&p->page_list);
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
    
    if ( dom == 0 )
        return -EINVAL;

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

struct pfn_info *alloc_domain_page(struct task_struct *p)
{
    struct pfn_info *page = NULL;
    unsigned long flags, mask, pfn_stamp, cpu_stamp;
    int i;

    spin_lock_irqsave(&free_list_lock, flags);
    if ( likely(!list_empty(&free_list)) )
    {
        page = list_entry(free_list.next, struct pfn_info, list);
        list_del(&page->list);
        free_pfns--;
    }
    spin_unlock_irqrestore(&free_list_lock, flags);

    if ( unlikely(page == NULL) )
        return NULL;

    if ( (mask = page->u.cpu_mask) != 0 )
    {
        pfn_stamp = page->tlbflush_timestamp;
        for ( i = 0; (mask != 0) && (i < NR_CPUS); i++ )
        {
            if ( mask & (1<<i) )
            {
                cpu_stamp = tlbflush_time[i];
                if ( !NEED_FLUSH(cpu_stamp, pfn_stamp) )
                    mask &= ~(1<<i);
            }
        }

        if ( unlikely(mask != 0) )
        {
            /* In IRQ ctxt, flushing is best-effort only, to avoid deadlock. */
            if ( likely(!in_irq()) )
                flush_tlb_mask(mask);
            else if ( unlikely(!try_flush_tlb_mask(mask)) )
                goto free_and_exit;
            perfc_incrc(need_flush_tlb_flush);
        }
    }

    page->u.domain = p;
    page->type_and_flags = 0;
    if ( p != NULL )
    {
        if ( unlikely(in_irq()) )
            BUG();
        wmb(); /* Domain pointer must be visible before updating refcnt. */
        spin_lock(&p->page_list_lock);
        if ( unlikely(p->tot_pages >= p->max_pages) )
        {
            spin_unlock(&p->page_list_lock);
            goto free_and_exit;
        }
        list_add_tail(&page->list, &p->page_list);
        p->tot_pages++;
        page->count_and_flags = PGC_allocated | 1;
        spin_unlock(&p->page_list_lock);
    }

    return page;

 free_and_exit:
    spin_lock_irqsave(&free_list_lock, flags);
    list_add(&page->list, &free_list);
    free_pfns++;
    spin_unlock_irqrestore(&free_list_lock, flags);
    return NULL;
}

void free_domain_page(struct pfn_info *page)
{
    unsigned long flags;
    struct task_struct *p = page->u.domain;

    if ( unlikely(in_irq()) )
        BUG();

    if ( likely(!IS_XEN_HEAP_FRAME(page)) )
    {
        /*
         * No race with setting of zombie bit. If it wasn't set before the
         * last reference was dropped, then it can't be set now.
         */
        page->u.cpu_mask = 0;
        if ( !(page->count_and_flags & PGC_zombie) )
        {
            page->tlbflush_timestamp = tlbflush_clock;
            page->u.cpu_mask = 1 << p->processor;

            spin_lock(&p->page_list_lock);
            list_del(&page->list);
            p->tot_pages--;
            spin_unlock(&p->page_list_lock);
        }

        page->count_and_flags = 0;

        spin_lock_irqsave(&free_list_lock, flags);
        list_add(&page->list, &free_list);
        free_pfns++;
        spin_unlock_irqrestore(&free_list_lock, flags);
    }
    else
    {
        /*
         * No need for a TLB flush. Non-domain pages are always co-held by Xen,
         * and the Xen reference is not dropped until the domain is dead.
         * DOM0 may hold references, but it's trusted so no need to flush.
         */
        page->u.cpu_mask = 0;
        page->count_and_flags = 0;
        free_page((unsigned long)page_to_virt(page));
    }
}


void free_all_dom_mem(struct task_struct *p)
{
    struct list_head *ent, zombies;
    struct pfn_info *page;

    INIT_LIST_HEAD(&zombies);

    /* STEP 1. Drop the in-use reference to the page-table base. */
    put_page_and_type(&frame_table[pagetable_val(p->mm.pagetable) >>
                                  PAGE_SHIFT]);

    /* STEP 2. Zombify all pages on the domain's allocation list. */
    spin_lock(&p->page_list_lock);
    while ( (ent = p->page_list.next) != &p->page_list )
    {
        page = list_entry(ent, struct pfn_info, list);

        if ( unlikely(!get_page(page, p)) )
        {
            /*
             * Another CPU has dropped the last reference and is responsible 
             * for removing the page from this list. Wait for them to do so.
             */
            spin_unlock(&p->page_list_lock);
            while ( p->page_list.next == ent )
                barrier();
            spin_lock(&p->page_list_lock);
            continue;
        }

        set_bit(_PGC_zombie, &page->count_and_flags);

        list_del(&page->list);
        p->tot_pages--;

        list_add(&page->list, &zombies);
    }
    spin_unlock(&p->page_list_lock);

    /*
     * STEP 3. With the domain's list lock now released, we examine each zombie
     * page and drop references for guest-allocated and/or type-pinned pages.
     */
    while ( (ent = zombies.next) != &zombies )
    {
        page = list_entry(ent, struct pfn_info, list);

        list_del(&page->list);
        
        if ( test_and_clear_bit(_PGC_guest_pinned, &page->count_and_flags) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->count_and_flags) )
            put_page(page);

        put_page(page);
    }
}


unsigned int alloc_new_dom_mem(struct task_struct *p, unsigned int kbytes)
{
    unsigned int alloc_pfns, nr_pages;

    nr_pages = kbytes >> (PAGE_SHIFT - 10);

    /* TEMPORARY: max_pages should be explicitly specified. */
    p->max_pages = nr_pages;

    for ( alloc_pfns = 0; alloc_pfns < nr_pages; alloc_pfns++ )
    {
        if ( unlikely(alloc_domain_page(p) == NULL) ||
             unlikely(free_pfns < (SLACK_DOMAIN_MEM_KILOBYTES >> 
                                   (PAGE_SHIFT-10))) )
        {
            free_all_dom_mem(p);
            return -1;
        }
    }

    p->tot_pages = nr_pages;

    return 0;
}
 

/* Release resources belonging to task @p. */
void release_task(struct task_struct *p)
{
    extern void destroy_event_channels(struct task_struct *);

    ASSERT(p->state == TASK_DYING);
    ASSERT(!p->has_cpu);

    printk("Releasing task %d\n", p->domain);

    /*
     * This frees up blkdev rings and vbd-access lists. Totally safe since
     * blkdev ref counting actually uses the task_struct refcnt.
     */
    destroy_blkdev_info(p);

    /* Free all memory associated with this domain. */
    destroy_event_channels(p);
    free_page((unsigned long)p->mm.perdomain_pt);
    UNSHARE_PFN(virt_to_page(p->shared_info));
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
    
    phys_l2tab = builddomain->ctxt.pt_base;
    p->mm.pagetable = mk_pagetable(phys_l2tab);
    get_page_and_type(&frame_table[phys_l2tab>>PAGE_SHIFT], p, 
                      PGT_l2_page_table);

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

    extern void ide_probe_devices(xen_disk_info_t *);
    extern void scsi_probe_devices(xen_disk_info_t *);
    xen_disk_info_t xdi;
    xen_disk_t *xd;

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

    if ( alloc_new_dom_mem(p, params->memory_kb) )
    {
        printk("DOM%d: Not enough memory --- reduce dom0_mem ??\n", dom);
        return -ENOMEM;
    }

    alloc_address = list_entry(p->page_list.prev, struct pfn_info, list) -
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
    cur_address = list_entry(p->page_list.next, struct pfn_info, list) -
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
        
        page = &frame_table[cur_address >> PAGE_SHIFT];
        set_bit(_PGC_tlb_flush_on_type_change, &page->count_and_flags);
        if ( !get_page_and_type(page, p, PGT_writeable_page) )
            BUG();
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
        page->type_and_flags &= ~PGT_type_mask;
        page->type_and_flags |= PGT_l1_page_table;
        get_page(page, p); /* an extra ref because of readable mapping */
        l1tab++;
        if( !((unsigned long)l1tab & (PAGE_SIZE - 1)) )
        {
            unmap_domain_mem(l1start);
            l1start = l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
            l2tab++;
        }
    }
    /* Rewrite last L1 page to be a L2 page. */
    page->type_and_flags &= ~PGT_type_mask;
    page->type_and_flags |= PGT_l2_page_table;
    /* Get another ref to L2 page so that it can be pinned. */
    if ( !get_page_and_type(page, p, PGT_l2_page_table) )
        BUG();
    set_bit(_PGC_guest_pinned, &page->count_and_flags);
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
    write_cr3_counted(pagetable_val(p->mm.pagetable));

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
    write_cr3_counted(pagetable_val(current->mm.pagetable));
    __sti();

    /* DOM0 gets access to all real block devices. */
#define MAX_REAL_DISKS 256
    xd = kmalloc(MAX_REAL_DISKS * sizeof(xen_disk_t), GFP_KERNEL);
    xdi.max   = MAX_REAL_DISKS;
    xdi.count = 0;
    xdi.disks = xd;
    ide_probe_devices(&xdi);
    scsi_probe_devices(&xdi);
    for ( i = 0; i < xdi.count; i++ )
    {
        xen_extent_t e;
        e.device       = xd[i].device;
        e.start_sector = 0;
        e.nr_sectors   = xd[i].capacity;
        if ( (__vbd_create(p, xd[i].device, VBD_MODE_R|VBD_MODE_W, 
                           xd[i].info) != 0) ||
             (__vbd_grow(p, xd[i].device, &e) != 0) )
            BUG();
    }
    kfree(xd);

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
