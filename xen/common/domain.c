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
#include <xeno/dom0_ops.h>
#include <asm/io.h>
#include <asm/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <xeno/blkdev.h>

/*
 * NB. No ring-3 access in initial guestOS pagetables. Note that we allow
 * ring-3 privileges in the page directories, so that the guestOS may later
 * decide to share a 4MB region with applications.
 */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

rwlock_t tasklist_lock __cacheline_aligned = RW_LOCK_UNLOCKED;

/*
 * create a new domain
 */
struct task_struct *do_newdomain(unsigned int dom_id, unsigned int cpu)
{
    int retval;
    struct task_struct *p = NULL;
    unsigned long flags;

    retval = -ENOMEM;
    p = alloc_task_struct();
    if (!p) goto newdomain_out;
    memset(p, 0, sizeof(*p));

    atomic_set(&p->refcnt, 1);

    p->domain    = dom_id;
    p->processor = cpu;

    spin_lock_init(&p->blk_ring_lock);
    spin_lock_init(&p->page_lock);

    p->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(p->shared_info, 0, PAGE_SIZE);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(p->shared_info), dom_id);

    p->mm.perdomain_pt = (l1_pgentry_t *)get_free_page(GFP_KERNEL);
    memset(p->mm.perdomain_pt, 0, PAGE_SIZE);

    init_blkdev_info(p);

    SET_GDT_ENTRIES(p, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(p, DEFAULT_GDT_ADDRESS);

    p->addr_limit = USER_DS;
    p->active_mm  = &p->mm;
    p->num_net_vifs = 0;

    sched_add_domain(p);

    INIT_LIST_HEAD(&p->net_vifs);

    p->net_ring_base = (net_ring_t *)(p->shared_info + 1);
    INIT_LIST_HEAD(&p->pg_head);
    p->max_pages = p->tot_pages = 0;
    write_lock_irqsave(&tasklist_lock, flags);
    SET_LINKS(p);
    write_unlock_irqrestore(&tasklist_lock, flags);

 newdomain_out:
    return(p);
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
            get_task_struct(p); /* increment the refcnt for caller */
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
    struct list_head *ent;
    net_vif_t *vif;

    if ( current->domain == 0 )
    {
        extern void machine_restart(char *);
        printk("Domain 0 killed: rebooting machine!\n");
        machine_restart(0);
    }

    printk("Killing domain %d\n", current->domain);

    sched_rem_domain(current);

    unlink_blkdev_info(current);

    while ( (ent = current->net_vifs.next) != &current->net_vifs )
    {
        vif = list_entry(ent, net_vif_t, dom_list);
        unlink_net_vif(vif);
    }    
    
    schedule();
    BUG(); /* never get here */
}


long kill_other_domain(unsigned int dom, int force)
{
    struct task_struct *p;
    unsigned long cpu_mask = 0;

    p = find_domain_by_id(dom);
    if ( p == NULL ) return -ESRCH;

    if ( force )
    {
        cpu_mask = mark_hyp_event(p, _HYP_EVENT_DIE);
        hyp_event_notify(cpu_mask);
    }
    else
    {
        cpu_mask = mark_guest_event(p, _EVENT_DIE);
        guest_event_notify(cpu_mask);
    }

    free_task_struct(p);
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

    write_lock_irq(&tasklist_lock);
    REMOVE_LINKS(p);
    write_unlock_irq(&tasklist_lock);

    /*
     * This frees up blkdev rings. Totally safe since blkdev ref counting
     * actually uses the task_struct refcnt.
     */
    destroy_blkdev_info(p);

    /* Free all memory associated with this domain. */
    free_page((unsigned long)p->mm.perdomain_pt);
    UNSHARE_PFN(virt_to_page(p->shared_info));
    free_page((unsigned long)p->shared_info);
    free_all_dom_mem(p);
    free_pages((unsigned long)p, 1);
}


/* final_setup_guestos is used for final setup and launching of domains other
 * than domain 0. ie. the domains that are being built by the userspace dom0
 * domain builder.
 *
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

int final_setup_guestos(struct task_struct * p, dom_meminfo_t * meminfo)
{
    l2_pgentry_t * l2tab;
    l1_pgentry_t * l1tab;
    start_info_t * virt_startinfo_addr;
    unsigned long virt_stack_addr;
    unsigned long phys_l2tab;
    net_ring_t *net_ring;
    net_vif_t *net_vif;

    /* High entries in page table must contain hypervisor
     * mem mappings - set them up.
     */
    phys_l2tab = meminfo->l2_pgt_addr;
    l2tab = map_domain_mem(phys_l2tab); 
    memcpy(l2tab + DOMAIN_ENTRIES_PER_L2_PAGETABLE, 
        ((l2_pgentry_t *)idle_pg_table[p->processor]) + 
        DOMAIN_ENTRIES_PER_L2_PAGETABLE, 
        (ENTRIES_PER_L2_PAGETABLE - DOMAIN_ENTRIES_PER_L2_PAGETABLE) 
        * sizeof(l2_pgentry_t));
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] = 
        mk_l2_pgentry(__pa(p->mm.perdomain_pt) | __PAGE_HYPERVISOR);
    p->mm.pagetable = mk_pagetable(phys_l2tab);
    unmap_domain_mem(l2tab);

    /* map in the shared info structure */
    phys_l2tab = pagetable_val(p->mm.pagetable); 
    l2tab = map_domain_mem(phys_l2tab);
    l2tab += l2_table_offset(meminfo->virt_shinfo_addr);
    l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
    l1tab += l1_table_offset(meminfo->virt_shinfo_addr);
    *l1tab = mk_l1_pgentry(__pa(p->shared_info) | L1_PROT);
    unmap_domain_mem((void *)((unsigned long)l2tab & PAGE_MASK));
    unmap_domain_mem((void *)((unsigned long)l1tab & PAGE_MASK));

    /* set up the shared info structure */
    update_dom_time(p->shared_info);
    p->shared_info->cpu_freq     = cpu_freq;
    p->shared_info->domain_time  = 0;

    /* we pass start info struct to guest os as function parameter on stack */
    virt_startinfo_addr = (start_info_t *)meminfo->virt_startinfo_addr;
    virt_stack_addr = (unsigned long)virt_startinfo_addr;       

    /* we need to populate start_info struct within the context of the
     * new domain. thus, temporarely install its pagetables.
     */
    __cli();
    __asm__ __volatile__ ( 
        "mov %%eax,%%cr3" : : "a" (pagetable_val(p->mm.pagetable)));

    memset(virt_startinfo_addr, 0, sizeof(*virt_startinfo_addr));
    virt_startinfo_addr->nr_pages = p->tot_pages;
    virt_startinfo_addr->shared_info = (shared_info_t *)meminfo->virt_shinfo_addr;
    virt_startinfo_addr->pt_base = meminfo->virt_load_addr + 
                    ((p->tot_pages - 1) << PAGE_SHIFT);
    
    /* Add virtual network interfaces and point to them in startinfo. */
    while (meminfo->num_vifs-- > 0) {
        net_vif = create_net_vif(p->domain);
        net_ring = net_vif->net_ring;
        if (!net_ring) panic("no network ring!\n");
    }

/* XXX SMH: horrible hack to convert hypervisor VAs in SHIP to guest VAs  */
#define SH2G(_x) (meminfo->virt_shinfo_addr | (((unsigned long)(_x)) & 0xFFF))

    virt_startinfo_addr->net_rings = (net_ring_t *)SH2G(p->net_ring_base); 
    virt_startinfo_addr->num_net_rings = p->num_net_vifs;

    /* Add block io interface */
    virt_startinfo_addr->blk_ring = virt_to_phys(p->blk_ring_base);

    /* Copy the command line */
    strcpy(virt_startinfo_addr->cmd_line, meminfo->cmd_line);

    /* Reinstate the caller's page tables. */
    __asm__ __volatile__ (
        "mov %%eax,%%cr3" : : "a" (pagetable_val(current->mm.pagetable)));    
    __sti();
    
    new_thread(p, 
               (unsigned long)meminfo->virt_load_addr, 
               (unsigned long)virt_stack_addr, 
               (unsigned long)virt_startinfo_addr);

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

/* setup_guestos is used for building dom0 solely. other domains are built in
 * userspace dom0 and final setup is being done by final_setup_guestos.
 */
int setup_guestos(struct task_struct *p, dom0_newdomain_t *params, 
                  char *phy_data_start, unsigned long data_len, 
		  char *cmdline, unsigned long initrd_len)
{
    struct list_head *list_ent;
    char *src, *vsrc, *dst, *data_start;
    int i, dom = p->domain;
    unsigned long phys_l1tab, phys_l2tab;
    unsigned long cur_address, alloc_address;
    unsigned long virt_load_address, virt_stack_address, virt_shinfo_address;
    start_info_t  *virt_startinfo_address;
    unsigned long count;
    unsigned long alloc_index;
    l2_pgentry_t *l2tab, *l2start;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;
    struct pfn_info *page = NULL;
    net_ring_t *net_ring;
    net_vif_t *net_vif;

    /* Sanity! */
    if ( p->domain != 0 ) BUG();

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
    
    /*
     * WARNING: The new domain must have its 'processor' field
     * filled in by now !!
     */
    phys_l2tab = alloc_page_from_domain(&alloc_address, &alloc_index);
    l2start = l2tab = map_domain_mem(phys_l2tab);
    memcpy(l2tab, idle_pg_table[p->processor], PAGE_SIZE);
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(p->mm.perdomain_pt) | __PAGE_HYPERVISOR);
    memset(l2tab, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE*sizeof(l2_pgentry_t));
    p->mm.pagetable = mk_pagetable(phys_l2tab);

    /*
     * NB. The upper limit on this loop does one extra page. This is to make 
     * sure a pte exists when we want to map the shared_info struct.
     */

    l2tab += l2_table_offset(virt_load_address);
    cur_address = list_entry(p->pg_head.next, struct pfn_info, list) -
        frame_table;
    cur_address <<= PAGE_SHIFT;
    for ( count = 0; count < p->tot_pages + 1; count++ )
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
        
        if ( count < p->tot_pages )
        {
            page = frame_table + (cur_address >> PAGE_SHIFT);
            page->flags = dom | PGT_writeable_page | PG_need_flush;
            page->type_count = page->tot_count = 1;
            /* Set up the MPT entry. */
            machine_to_phys_mapping[cur_address >> PAGE_SHIFT] = count;
        }

        list_ent = frame_table[cur_address >> PAGE_SHIFT].list.next;
        cur_address = list_entry(list_ent, struct pfn_info, list) -
            frame_table;
        cur_address <<= PAGE_SHIFT;
    }
    unmap_domain_mem(l1start);

    /* pages that are part of page tables must be read only */
    cur_address = list_entry(p->pg_head.next, struct pfn_info, list) -
        frame_table;
    cur_address <<= PAGE_SHIFT;
    for ( count = 0; count < alloc_index; count++ ) 
    {
        list_ent = frame_table[cur_address >> PAGE_SHIFT].list.next;
        cur_address = list_entry(list_ent, struct pfn_info, list) -
            frame_table;
        cur_address <<= PAGE_SHIFT;
    }

    l2tab = l2start + l2_table_offset(virt_load_address + 
        (alloc_index << PAGE_SHIFT));
    l1start = l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
    l1tab += l1_table_offset(virt_load_address + (alloc_index << PAGE_SHIFT));
    l2tab++;
    for ( count = alloc_index; count < p->tot_pages; count++ ) 
    {
        *l1tab++ = mk_l1_pgentry(l1_pgentry_val(*l1tab) & ~_PAGE_RW);
        if( !((unsigned long)l1tab & (PAGE_SIZE - 1)) )
        {
            unmap_domain_mem(l1start);
            l1start = l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
            l2tab++;
        }
        page = frame_table + (cur_address >> PAGE_SHIFT);
        page->flags = dom | PGT_l1_page_table;
        page->tot_count++;
        
        list_ent = frame_table[cur_address >> PAGE_SHIFT].list.next;
        cur_address = list_entry(list_ent, struct pfn_info, list) -
            frame_table;
        cur_address <<= PAGE_SHIFT;
    }
    page->type_count |= REFCNT_PIN_BIT;
    page->tot_count  |= REFCNT_PIN_BIT;
    page->flags = dom | PGT_l2_page_table;
    unmap_domain_mem(l1start);

    /* Map in the the shared info structure. */
    virt_shinfo_address = virt_load_address + (p->tot_pages << PAGE_SHIFT); 
    l2tab = l2start + l2_table_offset(virt_shinfo_address);
    l1start = l1tab = map_domain_mem(l2_pgentry_to_phys(*l2tab));
    l1tab += l1_table_offset(virt_shinfo_address);
    *l1tab = mk_l1_pgentry(__pa(p->shared_info)|L1_PROT);
    unmap_domain_mem(l1start);

    /* Set up shared info area. */
    update_dom_time(p->shared_info);
    p->shared_info->cpu_freq     = cpu_freq;
    p->shared_info->domain_time  = 0;


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
    virt_startinfo_address->shared_info = 
        (shared_info_t *)virt_shinfo_address;
    virt_startinfo_address->pt_base = virt_load_address + 
        ((p->tot_pages - 1) << PAGE_SHIFT); 

    if ( initrd_len )
    {
	virt_startinfo_address->mod_start = (unsigned long)dst-initrd_len;
	virt_startinfo_address->mod_len   = initrd_len;
	printk("Initrd len 0x%lx, start at 0x%08lx\n",
	       virt_startinfo_address->mod_len, 
               virt_startinfo_address->mod_start);
    }

    /* Add virtual network interfaces and point to them in startinfo. */
    while (params->num_vifs-- > 0) {
        net_vif = create_net_vif(dom);
        net_ring = net_vif->net_ring;
        if (!net_ring) panic("no network ring!\n");
    }

/* XXX SMH: horrible hack to convert hypervisor VAs in SHIP to guest VAs  */
#define SHIP2GUEST(_x) (virt_shinfo_address | (((unsigned long)(_x)) & 0xFFF))

    virt_startinfo_address->net_rings = 
    (net_ring_t *)SHIP2GUEST(p->net_ring_base); 
    virt_startinfo_address->num_net_rings = p->num_net_vifs;

    /* Add block io interface */
    virt_startinfo_address->blk_ring = virt_to_phys(p->blk_ring_base); 

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

    /* Reinstate the caller's page tables. */
    __write_cr3_counted(pagetable_val(current->mm.pagetable));
    __sti();

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
