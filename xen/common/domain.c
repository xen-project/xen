#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/skbuff.h>
#include <xen/interrupt.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/shadow.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <asm/io.h>
#include <asm/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <xen/blkdev.h>
#include <xen/console.h>
#include <xen/vbd.h>
#include <asm/i387.h>
#include <xen/shadow.h>

#ifdef CONFIG_X86_64BITMODE
#define ELFSIZE 64
#else
#define ELFSIZE 32
#endif
#include <xen/elf.h>

#if !defined(CONFIG_X86_64BITMODE)
/* No ring-3 access in initial page tables. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#else
/* Allow ring-3 access in long mode as guest cannot use ring 1. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#endif
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L4_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

/* Both these structures are protected by the tasklist_lock. */
rwlock_t tasklist_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
struct task_struct *task_hash[TASK_HASH_SIZE];
struct task_struct *task_list;

struct task_struct *do_createdomain(domid_t dom_id, unsigned int cpu)
{
    char buf[100];
    struct task_struct *p, **pp;
    unsigned long flags;

    if ( (p = alloc_task_struct()) == NULL )
        return NULL;

    atomic_set(&p->refcnt, 1);

    spin_lock_init(&p->mm.shadow_lock);

    p->domain    = dom_id;
    p->processor = cpu;
    p->create_time = NOW();

    memcpy(&p->thread, &idle0_task.thread, sizeof(p->thread));

    if ( p->domain != IDLE_DOMAIN_ID )
    {
        if ( init_event_channels(p) != 0 )
        {
            free_task_struct(p);
            return NULL;
        }
        
        /* We use a large intermediate to avoid overflow in sprintf. */
        sprintf(buf, "Domain-%llu", dom_id);
        strncpy(p->name, buf, MAX_DOMAIN_NAME);
        p->name[MAX_DOMAIN_NAME-1] = '\0';

        spin_lock_init(&p->blk_ring_lock);

        p->addr_limit = USER_DS;
        
        spin_lock_init(&p->page_list_lock);
        INIT_LIST_HEAD(&p->page_list);
        p->max_pages = p->tot_pages = 0;

        p->shared_info = (void *)get_free_page(GFP_KERNEL);
        memset(p->shared_info, 0, PAGE_SIZE);
        SHARE_PFN_WITH_DOMAIN(virt_to_page(p->shared_info), p);
        
	machine_to_phys_mapping[virt_to_phys(p->shared_info) >> PAGE_SHIFT] =
	    0x80000000UL;  // set m2p table to magic marker (helps debug)

        p->mm.perdomain_pt = (l1_pgentry_t *)get_free_page(GFP_KERNEL);
        memset(p->mm.perdomain_pt, 0, PAGE_SIZE);
        
	machine_to_phys_mapping[virt_to_phys(p->mm.perdomain_pt) >> PAGE_SHIFT] =
	    0x0fffdeadUL;  // set m2p table to magic marker (helps debug)

        init_blkdev_info(p);
        
        /* Per-domain PCI-device list. */
        spin_lock_init(&p->pcidev_lock);
        INIT_LIST_HEAD(&p->pcidev_list);

        write_lock_irqsave(&tasklist_lock, flags);
        pp = &task_list; /* NB. task_list is maintained in order of dom_id. */
        for ( pp = &task_list; *pp != NULL; pp = &(*pp)->next_list )
            if ( (*pp)->domain > p->domain )
                break;
        p->next_list = *pp;
        *pp = p;
        p->next_hash = task_hash[TASK_HASH(dom_id)];
        task_hash[TASK_HASH(dom_id)] = p;
        write_unlock_irqrestore(&tasklist_lock, flags);
    }
    else
    {
        sprintf(p->name, "Idle-%d", cpu);
    }

    sched_add_domain(p);

    return p;
}


struct task_struct *find_domain_by_id(domid_t dom)
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


/* return the most recent domain created */
struct task_struct *find_last_domain(void)
{
    struct task_struct *p, *plast;
    unsigned long flags;

    read_lock_irqsave(&tasklist_lock, flags);
    plast = task_list;
    p = plast->next_list;
    while ( p != NULL )
    {
	if ( p->create_time > plast->create_time )
	    plast = p;
        p = p->next_list;
    }
    get_task_struct(plast);
    read_unlock_irqrestore(&tasklist_lock, flags);

    return plast;
}


void kill_domain_with_errmsg(const char *err)
{
    printk("DOM%llu FATAL ERROR: %s\n", current->domain, err);
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

    DPRINTK("Killing domain %llu\n", p->domain);

    unlink_blkdev_info(p);

    for ( i = 0; i < MAX_DOMAIN_VIFS; i++ )
        unlink_net_vif(p->net_vif_list[i]);

    destroy_event_channels(p);

    delete_all_domain_vfr_rules(p);

    /*
     * Note this means that find_domain_by_id may fail, even when the caller
     * holds a reference to the domain being queried. Take care!
     */
    write_lock_irqsave(&tasklist_lock, flags);
    pp = &task_list;                       /* Delete from task_list. */
    while ( *pp != p ) 
        pp = &(*pp)->next_list;
    *pp = p->next_list;
    pp = &task_hash[TASK_HASH(p->domain)]; /* Delete from task_hash. */
    while ( *pp != p ) 
        pp = &(*pp)->next_hash;
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


long kill_other_domain(domid_t dom, int force)
{
    struct task_struct *p;

    if ( (p = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    if ( p->state == TASK_STOPPED )
        __kill_domain(p);
    else if ( force )
        send_hyp_event(p, _HYP_EVENT_DIE);
    else
        send_guest_virq(p, VIRQ_DIE);

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

    /* OK, this is grim, but helps speed up live migrate. When a domain stops,
       kick Dom0 */
    {
	struct task_struct *p;
	guest_schedule_to_run( p = find_domain_by_id(0ULL) );
	put_task_struct(p);
    }

    __enter_scheduler();
}

long stop_other_domain(domid_t dom)
{
    struct task_struct *p;
    
    if ( dom == 0 )
        return -EINVAL;

    p = find_domain_by_id(dom);
    if ( p == NULL) return -ESRCH;
    
    if ( p->state != TASK_STOPPED )
        send_guest_virq(p, VIRQ_STOP);
    
    put_task_struct(p);
    return 0;
}

struct pfn_info *alloc_domain_page(struct task_struct *p)
{
    struct pfn_info *page = NULL;
    unsigned long flags, mask, pfn_stamp, cpu_stamp;
    int i;

#ifdef NO_DEVICES_IN_XEN
    ASSERT(!in_irq());
#else
    ASSERT((p == NULL) || !in_irq());
#endif

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
        for ( i = 0; (mask != 0) && (i < smp_num_cpus); i++ )
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
#ifdef NO_DEVICES_IN_XEN
            flush_tlb_mask(mask);
#else
            /* In IRQ ctxt, flushing is best-effort only, to avoid deadlock. */
            if ( likely(!in_irq()) )
                flush_tlb_mask(mask);
            else if ( unlikely(!try_flush_tlb_mask(mask)) )
                goto free_and_exit;
#endif
            perfc_incrc(need_flush_tlb_flush);
        }
    }

    page->u.domain = p;
    page->type_and_flags = 0;
    if ( p != NULL )
    {
        wmb(); /* Domain pointer must be visible before updating refcnt. */
        spin_lock(&p->page_list_lock);
        if ( unlikely(p->tot_pages >= p->max_pages) )
        {
            DPRINTK("Over-allocation for domain %llu: %u >= %u\n",
                    p->domain, p->tot_pages, p->max_pages);
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

    ASSERT(!in_irq());

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
	    if ( likely(p != NULL) )
	    {
                page->u.cpu_mask = 1 << p->processor;
                spin_lock(&p->page_list_lock);
		list_del(&page->list);
		p->tot_pages--;
		spin_unlock(&p->page_list_lock);
	    }
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
    unsigned long x, y;

    INIT_LIST_HEAD(&zombies);

    /*
     * If we're executing the idle task then we may still be running over the 
     * dead domain's page tables. We'd better fix that before freeing them!
     */
    if ( is_idle_task(current) )
        write_ptbase(&current->mm);

    /* Exit shadow mode before deconstructing final guest page table. */
    if ( p->mm.shadow_mode )
        shadow_mode_disable(p);

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

        /*
         * Forcibly invalidate base page tables at this point to break circular
         * 'linear page table' references. This is okay because MMU structures
         * are not shared across domains and this domain is now dead. Thus base
         * tables are not in use so a non-zero count means circular reference.
         */
        y = page->type_and_flags;
        do {
            x = y;
            if ( likely((x & (PGT_type_mask|PGT_validated)) != 
                        (PGT_base_page_table|PGT_validated)) )
                break;
            y = cmpxchg(&page->type_and_flags, x, x & ~PGT_validated);
            if ( likely(y == x) )
                free_page_type(page, PGT_base_page_table);
        }
        while ( unlikely(y != x) );

        put_page(page);
    }
}


unsigned int alloc_new_dom_mem(struct task_struct *p, unsigned int kbytes)
{
    unsigned int alloc_pfns, nr_pages;
    struct pfn_info *page;

    nr_pages = (kbytes + ((PAGE_SIZE-1)>>10)) >> (PAGE_SHIFT - 10);
    p->max_pages = nr_pages; /* this can now be controlled independently */

    /* grow the allocation if necessary */
    for ( alloc_pfns = p->tot_pages; alloc_pfns < nr_pages; alloc_pfns++ )
    {
        if ( unlikely((page=alloc_domain_page(p)) == NULL) ||
             unlikely(free_pfns < (SLACK_DOMAIN_MEM_KILOBYTES >> 
                                   (PAGE_SHIFT-10))) )
        {
            free_all_dom_mem(p);
            return -ENOMEM;
        }

	/* initialise to machine_to_phys_mapping table to likely pfn */
	machine_to_phys_mapping[page-frame_table] = alloc_pfns;

#ifndef NDEBUG
	{
	    // initialise with magic marker if in DEBUG mode
	    void * a = map_domain_mem( (page-frame_table)<<PAGE_SHIFT );
	    memset( a, 0x80 | (char) p->domain, PAGE_SIZE );
	    unmap_domain_mem( a );
	}
#endif

    }

    p->tot_pages = nr_pages;

    return 0;
}
 

/* Release resources belonging to task @p. */
void release_task(struct task_struct *p)
{
    ASSERT(p->state == TASK_DYING);
    ASSERT(!p->has_cpu);

    DPRINTK("Releasing task %llu\n", p->domain);

    /*
     * This frees up blkdev rings and vbd-access lists. Totally safe since
     * blkdev ref counting actually uses the task_struct refcnt.
     */
    destroy_blkdev_info(p);

    /* Free all memory associated with this domain. */
    free_page((unsigned long)p->mm.perdomain_pt);
    UNSHARE_PFN(virt_to_page(p->shared_info));
    free_all_dom_mem(p);

    free_task_struct(p);
}


/*
 * final_setup_guestos is used for final setup and launching of domains other
 * than domain 0. ie. the domains that are being built by the userspace dom0
 * domain builder.
 */
int final_setup_guestos(struct task_struct *p, dom0_builddomain_t *builddomain)
{
    unsigned long phys_basetab;
    int i, rc = 0;
    full_execution_context_t *c;

    if ( (c = kmalloc(sizeof(*c), GFP_KERNEL)) == NULL )
	return -ENOMEM;

    if ( test_bit(PF_CONSTRUCTED, &p->flags) )
    {
        rc = -EINVAL;
	goto out;
    }

    if ( copy_from_user(c, builddomain->ctxt, sizeof(*c)) )
    {
        rc = -EFAULT;
        goto out;
    }
    
    clear_bit(PF_DONEFPUINIT, &p->flags);
    if ( c->flags & ECF_I387_VALID )
        set_bit(PF_DONEFPUINIT, &p->flags);
    memcpy(&p->shared_info->execution_context,
           &c->cpu_ctxt,
           sizeof(p->shared_info->execution_context));
    memcpy(&p->thread.i387,
           &c->fpu_ctxt,
           sizeof(p->thread.i387));
    memcpy(p->thread.traps,
           &c->trap_ctxt,
           sizeof(p->thread.traps));
#ifdef ARCH_HAS_FAST_TRAP
    SET_DEFAULT_FAST_TRAP(&p->thread);
    (void)set_fast_trap(p, c->fast_trap_idx);
#endif
    p->mm.ldt_base = c->ldt_base;
    p->mm.ldt_ents = c->ldt_ents;
    SET_GDT_ENTRIES(p, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(p, DEFAULT_GDT_ADDRESS);
    if ( c->gdt_ents != 0 )
        (void)set_gdt(p,
                      c->gdt_frames,
                      c->gdt_ents);
    p->thread.guestos_ss = c->guestos_ss;
    p->thread.guestos_sp = c->guestos_esp;
    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(p, i, c->debugreg[i]);
    p->event_selector    = c->event_callback_cs;
    p->event_address     = c->event_callback_eip;
    p->failsafe_selector = c->failsafe_callback_cs;
    p->failsafe_address  = c->failsafe_callback_eip;
    
    phys_basetab = c->pt_base;
    p->mm.pagetable = mk_pagetable(phys_basetab);
    get_page_and_type(&frame_table[phys_basetab>>PAGE_SHIFT], p, 
                      PGT_base_page_table);

    /* Set up the shared info structure. */
    update_dom_time(p->shared_info);

    /* Add virtual network interfaces and point to them in startinfo. */
    while ( builddomain->num_vifs-- > 0 )
        (void)create_net_vif(p->domain);

    set_bit(PF_CONSTRUCTED, &p->flags);

out:    
    if (c) kfree(c);
    
    return rc;
}

static inline int is_loadable_phdr(Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

static int readelfimage_base_and_size(char *elfbase, 
                                      unsigned long elfsize,
                                      unsigned long *pkernstart,
                                      unsigned long *pkernend,
                                      unsigned long *pkernentry)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL;
    char *shstrtab, *guestinfo;
    int h;

    if ( !IS_ELF(*ehdr) )
    {
        printk("Kernel image does not have an ELF header.\n");
        return -EINVAL;
    }

    if ( (ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize)) > elfsize )
    {
	printk("ELF program headers extend beyond end of image.\n");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum * ehdr->e_shentsize)) > elfsize )
    {
	printk("ELF section headers extend beyond end of image.\n");
        return -EINVAL;
    }

    /* Find the section-header strings table. */
    if ( ehdr->e_shstrndx == SHN_UNDEF )
    {
        printk("ELF image has no section-header strings table (shstrtab).\n");
        return -EINVAL;
    }
    shdr = (Elf_Shdr *)(elfbase + ehdr->e_shoff + 
                        (ehdr->e_shstrndx*ehdr->e_shentsize));
    shstrtab = elfbase + shdr->sh_offset;
    
    /* Find the special '__xen_guest' section and check its contents. */
    for ( h = 0; h < ehdr->e_shnum; h++ )
    {
        shdr = (Elf_Shdr *)(elfbase + ehdr->e_shoff + (h*ehdr->e_shentsize));
        if ( strcmp(&shstrtab[shdr->sh_name], "__xen_guest") != 0 )
            continue;
        guestinfo = elfbase + shdr->sh_offset;
        printk("Xen-ELF header found: '%s'\n", guestinfo);
        if ( (strstr(guestinfo, "GUEST_OS=linux") == NULL) ||
             (strstr(guestinfo, "XEN_VER=1.3") == NULL) )
        {
            printk("ERROR: Xen will only load Linux built for Xen v1.3\n");
            return -EINVAL;
        }
        break;
    }
    if ( h == ehdr->e_shnum )
    {
        printk("Not a Xen-ELF image: '__xen_guest' section not found.\n");
        return -EINVAL;
    }

    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->p_vaddr < kernstart )
            kernstart = phdr->p_vaddr;
        if ( (phdr->p_vaddr + phdr->p_memsz) > kernend )
            kernend = phdr->p_vaddr + phdr->p_memsz;
    }

    if ( (kernstart > kernend) || 
         (ehdr->e_entry < kernstart) || 
         (ehdr->e_entry > kernend) )
    {
        printk("Malformed ELF image.\n");
        return -EINVAL;
    }

    *pkernstart = kernstart;
    *pkernend   = kernend;
    *pkernentry = ehdr->e_entry;

    return 0;
}

static int loadelfimage(char *elfbase)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    int h;
  
    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
	    continue;
        if ( phdr->p_filesz != 0 )
            memcpy((char *)phdr->p_vaddr, elfbase + phdr->p_offset, 
                   phdr->p_filesz);
        if ( phdr->p_memsz > phdr->p_filesz )
            memset((char *)phdr->p_vaddr + phdr->p_filesz, 0, 
                   phdr->p_memsz - phdr->p_filesz);
    }

    return 0;
}

int construct_dom0(struct task_struct *p, 
                   unsigned long alloc_start,
                   unsigned long alloc_end,
                   unsigned int num_vifs,
                   char *image_start, unsigned long image_len, 
                   char *initrd_start, unsigned long initrd_len,
                   char *cmdline)
{
    char *dst;
    int i, rc;
    unsigned long pfn, mfn;
    unsigned long nr_pages = (alloc_end - alloc_start) >> PAGE_SHIFT;
    unsigned long nr_pt_pages;
    unsigned long count;
    l2_pgentry_t *l2tab, *l2start;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;
    struct pfn_info *page = NULL;
    start_info_t *si;

    /*
     * This fully describes the memory layout of the initial domain. All 
     * *_start address are page-aligned, except v_start (and v_end) which are 
     * superpage-aligned.
     */
    unsigned long v_start;
    unsigned long vkern_start;
    unsigned long vkern_entry;
    unsigned long vkern_end;
    unsigned long vinitrd_start;
    unsigned long vinitrd_end;
    unsigned long vphysmap_start;
    unsigned long vphysmap_end;
    unsigned long vstartinfo_start;
    unsigned long vstartinfo_end;
    unsigned long vstack_start;
    unsigned long vstack_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_end;

    /* Machine address of next candidate page-table page. */
    unsigned long mpt_alloc;

    extern void physdev_init_dom0(struct task_struct *);

#ifndef NO_DEVICES_IN_XEN
    extern void ide_probe_devices(xen_disk_info_t *);
    extern void scsi_probe_devices(xen_disk_info_t *);
    extern void cciss_probe_devices(xen_disk_info_t *);
    xen_disk_info_t xdi;
    xen_disk_t *xd;
#endif

    /* Sanity! */
    if ( p->domain != 0 ) 
        BUG();
    if ( test_bit(PF_CONSTRUCTED, &p->flags) ) 
        BUG();

    printk("*** LOADING DOMAIN 0 ***\n");

    /*
     * This is all a bit grim. We've moved the modules to the "safe" physical 
     * memory region above MAP_DIRECTMAP_ADDRESS (48MB). Later in this 
     * routine we're going to copy it down into the region that's actually 
     * been allocated to domain 0. This is highly likely to be overlapping, so 
     * we use a forward copy.
     * 
     * MAP_DIRECTMAP_ADDRESS should be safe. The worst case is a machine with 
     * 4GB and lots of network/disk cards that allocate loads of buffers. 
     * We'll have to revisit this if we ever support PAE (64GB).
     */

    rc = readelfimage_base_and_size(image_start, image_len,
                                    &vkern_start, &vkern_end, &vkern_entry);
    if ( rc != 0 )
        return rc;

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        v_start          = vkern_start & ~((1<<22)-1);
        vinitrd_start    = round_pgup(vkern_end);
        vinitrd_end      = vinitrd_start + initrd_len;
        vphysmap_start   = round_pgup(vinitrd_end);
        vphysmap_end     = vphysmap_start + (nr_pages * sizeof(unsigned long));
        vpt_start        = round_pgup(vphysmap_end);
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstartinfo_start = vpt_end;
        vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
        vstack_start     = vstartinfo_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1<<22)-1) & ~((1<<22)-1);
        if ( (v_end - vstack_end) < (512 << 10) )
            v_end += 1 << 22; /* Add extra 4MB to get >= 512kB padding. */
        if ( (((v_end - v_start) >> L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
    }

    if ( (v_end - v_start) > (nr_pages * PAGE_SIZE) )
    {
        printk("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        return -ENOMEM;
    }

    printk("PHYSICAL MEMORY ARRANGEMENT:\n"
           " Kernel image:  %p->%p\n"
           " Initrd image:  %p->%p\n"
           " Dom0 alloc.:   %08lx->%08lx\n",
           image_start, image_start + image_len,
           initrd_start, initrd_start + initrd_len,
           alloc_start, alloc_end);
    printk("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %08lx->%08lx\n"
           " Init. ramdisk: %08lx->%08lx\n"
           " Phys-Mach map: %08lx->%08lx\n"
           " Page tables:   %08lx->%08lx\n"
           " Start info:    %08lx->%08lx\n"
           " Boot stack:    %08lx->%08lx\n"
           " TOTAL:         %08lx->%08lx\n",
           vkern_start, vkern_end, 
           vinitrd_start, vinitrd_end,
           vphysmap_start, vphysmap_end,
           vpt_start, vpt_end,
           vstartinfo_start, vstartinfo_end,
           vstack_start, vstack_end,
           v_start, v_end);
    printk(" ENTRY ADDRESS: %08lx\n", vkern_entry);

    /*
     * Protect the lowest 1GB of memory. We use a temporary mapping there
     * from which we copy the kernel and ramdisk images.
     */
    if ( v_start < (1<<30) )
    {
        printk("Initial loading isn't allowed to lowest 1GB of memory.\n");
        return -EINVAL;
    }

    /* Construct a frame-allocation list for the initial domain. */
    for ( pfn = (alloc_start>>PAGE_SHIFT); 
          pfn < (alloc_end>>PAGE_SHIFT); 
          pfn++ )
    {
        page = &frame_table[pfn];
        page->u.domain        = p;
        page->type_and_flags  = 0;
        page->count_and_flags = PGC_allocated | 1;
        list_add_tail(&page->list, &p->page_list);
        p->tot_pages++; p->max_pages++;
    }

    mpt_alloc = (vpt_start - v_start) + alloc_start;

    SET_GDT_ENTRIES(p, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(p, DEFAULT_GDT_ADDRESS);

    /*
     * We're basically forcing default RPLs to 1, so that our "what privilege
     * level are we returning to?" logic works.
     */
    p->failsafe_selector = FLAT_GUESTOS_CS;
    p->event_selector    = FLAT_GUESTOS_CS;
    p->thread.guestos_ss = FLAT_GUESTOS_DS;
    for ( i = 0; i < 256; i++ ) 
        p->thread.traps[i].cs = FLAT_GUESTOS_CS;

    /* WARNING: The new domain must have its 'processor' field filled in! */
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    memcpy(l2tab, &idle_pg_table[0], PAGE_SIZE);
    l2tab[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((unsigned long)l2start | __PAGE_HYPERVISOR);
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(p->mm.perdomain_pt) | __PAGE_HYPERVISOR);
    p->mm.pagetable = mk_pagetable((unsigned long)l2start);

    l2tab += l2_table_offset(v_start);
    mfn = alloc_start >> PAGE_SHIFT;
    for ( count = 0; count < ((v_end-v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1start = l1tab = (l1_pgentry_t *)mpt_alloc; 
            mpt_alloc += PAGE_SIZE;
            *l2tab++ = mk_l2_pgentry((unsigned long)l1start | L2_PROT);
            clear_page(l1tab);
        }
        *l1tab++ = mk_l1_pgentry((mfn << PAGE_SHIFT) | L1_PROT);
        
        page = &frame_table[mfn];
        set_bit(_PGC_tlb_flush_on_type_change, &page->count_and_flags);
        if ( !get_page_and_type(page, p, PGT_writeable_page) )
            BUG();

        mfn++;
    }

    /* Pages that are part of page tables must be read only. */
    l2tab = l2start + l2_table_offset(vpt_start);
    l1start = l1tab = (l1_pgentry_t *)l2_pgentry_to_phys(*l2tab);
    l1tab += l1_table_offset(vpt_start);
    l2tab++;
    for ( count = 0; count < nr_pt_pages; count++ ) 
    {
        *l1tab = mk_l1_pgentry(l1_pgentry_val(*l1tab) & ~_PAGE_RW);
        page = &frame_table[l1_pgentry_to_pagenr(*l1tab)];
        if ( count == 0 )
        {
            page->type_and_flags &= ~PGT_type_mask;
            page->type_and_flags |= PGT_l2_page_table;
            get_page(page, p); /* an extra ref because of readable mapping */
            /* Get another ref to L2 page so that it can be pinned. */
            if ( !get_page_and_type(page, p, PGT_l2_page_table) )
                BUG();
            set_bit(_PGC_guest_pinned, &page->count_and_flags);
        }
        else
        {
            page->type_and_flags &= ~PGT_type_mask;
            page->type_and_flags |= PGT_l1_page_table;
            get_page(page, p); /* an extra ref because of readable mapping */
        }
        l1tab++;
        if( !((unsigned long)l1tab & (PAGE_SIZE - 1)) )
            l1start = l1tab = (l1_pgentry_t *)l2_pgentry_to_phys(*l2tab);
    }

    /* Set up shared-info area. */
    update_dom_time(p->shared_info);
    p->shared_info->domain_time = 0;
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        p->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;

    /* Install the new page tables. */
    __cli();
    write_ptbase(&p->mm);

    /* Copy the OS image. */
    (void)loadelfimage(image_start);

    /* Copy the initial ramdisk. */
    if ( initrd_len != 0 )
        memcpy((void *)vinitrd_start, initrd_start, initrd_len);
    
    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    memset(si, 0, PAGE_SIZE);
    si->nr_pages     = p->tot_pages;
    si->shared_info  = virt_to_phys(p->shared_info);
    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    si->pt_base      = vpt_start;
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < p->tot_pages; pfn++ )
    {
        mfn = (alloc_start >> PAGE_SHIFT) + pfn;
        ((unsigned long *)vphysmap_start)[pfn] = mfn;
        machine_to_phys_mapping[mfn] = pfn;
    }

    if ( initrd_len != 0 )
    {
	si->mod_start = vinitrd_start;
	si->mod_len   = initrd_len;
	printk("Initrd len 0x%lx, start at 0x%08lx\n",
	       si->mod_len, si->mod_start);
    }

    dst = si->cmd_line;
    if ( cmdline != NULL )
    {
        for ( i = 0; i < 255; i++ )
        {
            if ( cmdline[i] == '\0' )
                break;
            *dst++ = cmdline[i];
        }
    }
    *dst = '\0';

    /* Reinstate the caller's page tables. */
    write_ptbase(&current->mm);
    __sti();

    /* Destroy low mappings - they were only for our convenience. */
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        if ( l2_pgentry_val(l2start[i]) & _PAGE_PSE )
            l2start[i] = mk_l2_pgentry(0);
    zap_low_mappings(); /* Do the same for the idle page tables. */
    
    /* Give up the VGA console if DOM0 is configured to grab it. */
    console_endboot(strstr(cmdline, "tty0") != NULL);

    /* Add virtual network interfaces. */
    while ( num_vifs-- > 0 )
        (void)create_net_vif(0);

#ifndef NO_DEVICES_IN_XEN
    /* DOM0 gets access to all real block devices. */
#define MAX_REAL_DISKS 256
    xd = kmalloc(MAX_REAL_DISKS * sizeof(xen_disk_t), GFP_KERNEL);
    xdi.max   = MAX_REAL_DISKS;
    xdi.count = 0;
    xdi.disks = xd;
    ide_probe_devices(&xdi);
    scsi_probe_devices(&xdi);
    cciss_probe_devices(&xdi);
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
#endif

    /* DOM0 gets access to everything. */
    physdev_init_dom0(p);

    set_bit(PF_CONSTRUCTED, &p->flags);

#if 0 /* XXXXX DO NOT CHECK IN ENABLED !!! (but useful for testing so leave) */
    shadow_mode_enable(&p->mm, SHM_test); 
#endif

    new_thread(p, vkern_entry, vstack_end, vstartinfo_start);

    return 0;
}


void __init domain_init(void)
{
    printk("Initialising domains\n");
}
