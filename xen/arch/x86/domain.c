/******************************************************************************
 * arch/x86/domain.c
 * 
 * x86-specific domain handling (e.g., register setup and context switching).
 */

/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <asm/ptrace.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/shadow.h>
#include <xen/console.h>
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

int hlt_counter;

void disable_hlt(void)
{
    hlt_counter++;
}

void enable_hlt(void)
{
    hlt_counter--;
}

/*
 * We use this if we don't have any better
 * idle routine..
 */
static void default_idle(void)
{
    if ( hlt_counter == 0 )
    {
        __cli();
        if ( !softirq_pending(smp_processor_id()) )
            safe_halt();
        else
            __sti();
    }
}

void continue_cpu_idle_loop(void)
{
    int cpu = smp_processor_id();
    for ( ; ; )
    {
        irq_stat[cpu].idle_timestamp = jiffies;
        while ( !softirq_pending(cpu) )
            default_idle();
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    /* Just some sanity to ensure that the scheduler is set up okay. */
    ASSERT(current->domain == IDLE_DOMAIN_ID);
    domain_unpause_by_systemcontroller(current);
    __enter_scheduler();

    /*
     * Declares CPU setup done to the boot processor.
     * Therefore memory barrier to ensure state is visible.
     */
    smp_mb();
    init_idle();

    continue_cpu_idle_loop();
}

static long no_idt[2];
static int reboot_mode;
int reboot_thru_bios = 0;

#ifdef CONFIG_SMP
int reboot_smp = 0;
static int reboot_cpu = -1;
/* shamelessly grabbed from lib/vsprintf.c for readability */
#define is_digit(c)	((c) >= '0' && (c) <= '9')
#endif


static inline void kb_wait(void)
{
    int i;

    for (i=0; i<0x10000; i++)
        if ((inb_p(0x64) & 0x02) == 0)
            break;
}


void machine_restart(char * __unused)
{
    extern int opt_noreboot;
#ifdef CONFIG_SMP
    int cpuid;
#endif
	
    if ( opt_noreboot )
    {
        printk("Reboot disabled on cmdline: require manual reset\n");
        for ( ; ; ) __asm__ __volatile__ ("hlt");
    }

#ifdef CONFIG_SMP
    cpuid = GET_APIC_ID(apic_read(APIC_ID));

    /* KAF: Need interrupts enabled for safe IPI. */
    __sti();

    if (reboot_smp) {

        /* check to see if reboot_cpu is valid 
           if its not, default to the BSP */
        if ((reboot_cpu == -1) ||  
            (reboot_cpu > (NR_CPUS -1))  || 
            !(phys_cpu_present_map & (1<<cpuid))) 
            reboot_cpu = boot_cpu_physical_apicid;

        reboot_smp = 0;  /* use this as a flag to only go through this once*/
        /* re-run this function on the other CPUs
           it will fall though this section since we have 
           cleared reboot_smp, and do the reboot if it is the
           correct CPU, otherwise it halts. */
        if (reboot_cpu != cpuid)
            smp_call_function((void *)machine_restart , NULL, 1, 0);
    }

    /* if reboot_cpu is still -1, then we want a tradional reboot, 
       and if we are not running on the reboot_cpu,, halt */
    if ((reboot_cpu != -1) && (cpuid != reboot_cpu)) {
        for (;;)
            __asm__ __volatile__ ("hlt");
    }
    /*
     * Stop all CPUs and turn off local APICs and the IO-APIC, so
     * other OSs see a clean IRQ state.
     */
    smp_send_stop();
    disable_IO_APIC();
#endif

    if(!reboot_thru_bios) {
        /* rebooting needs to touch the page at absolute addr 0 */
        *((unsigned short *)__va(0x472)) = reboot_mode;
        for (;;) {
            int i;
            for (i=0; i<100; i++) {
                kb_wait();
                udelay(50);
                outb(0xfe,0x64);         /* pulse reset low */
                udelay(50);
            }
            /* That didn't work - force a triple fault.. */
            __asm__ __volatile__("lidt %0": "=m" (no_idt));
            __asm__ __volatile__("int3");
        }
    }

    panic("Need to reinclude BIOS reboot code\n");
}


void __attribute__((noreturn)) __machine_halt(void *unused)
{
    for ( ; ; )
        __asm__ __volatile__ ( "cli; hlt" );
}

void machine_halt(void)
{
    smp_call_function(__machine_halt, NULL, 1, 1);
    __machine_halt(NULL);
}

void free_perdomain_pt(struct domain *d)
{
    free_xenheap_page((unsigned long)d->mm.perdomain_pt);
}

void arch_do_createdomain(struct domain *d)
{
    d->shared_info = (void *)alloc_xenheap_page();
    memset(d->shared_info, 0, PAGE_SIZE);
    d->shared_info->arch.mfn_to_pfn_start = 
	virt_to_phys(&machine_to_phys_mapping[0])>>PAGE_SHIFT;
    SHARE_PFN_WITH_DOMAIN(virt_to_page(d->shared_info), d);
    machine_to_phys_mapping[virt_to_phys(d->shared_info) >> 
                           PAGE_SHIFT] = INVALID_P2M_ENTRY;

    d->mm.perdomain_pt = (l1_pgentry_t *)alloc_xenheap_page();
    memset(d->mm.perdomain_pt, 0, PAGE_SIZE);
    machine_to_phys_mapping[virt_to_phys(d->mm.perdomain_pt) >> 
                           PAGE_SHIFT] = INVALID_P2M_ENTRY;
}

int arch_final_setup_guestos(struct domain *d, full_execution_context_t *c)
{
    unsigned long phys_basetab;
    int i, rc;

    clear_bit(DF_DONEFPUINIT, &d->flags);
    if ( c->flags & ECF_I387_VALID )
        set_bit(DF_DONEFPUINIT, &d->flags);

    memcpy(&d->shared_info->execution_context,
           &c->cpu_ctxt,
           sizeof(d->shared_info->execution_context));

    memcpy(&d->thread.i387,
           &c->fpu_ctxt,
           sizeof(d->thread.i387));

    memcpy(d->thread.traps,
           &c->trap_ctxt,
           sizeof(d->thread.traps));

#ifdef ARCH_HAS_FAST_TRAP
    SET_DEFAULT_FAST_TRAP(&d->thread);
    if ( (rc = (int)set_fast_trap(d, c->fast_trap_idx)) != 0 )
        return rc;
#endif

    d->mm.ldt_base = c->ldt_base;
    d->mm.ldt_ents = c->ldt_ents;

    d->thread.guestos_ss = c->guestos_ss;
    d->thread.guestos_sp = c->guestos_esp;

    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(d, i, c->debugreg[i]);

    d->event_selector    = c->event_callback_cs;
    d->event_address     = c->event_callback_eip;
    d->failsafe_selector = c->failsafe_callback_cs;
    d->failsafe_address  = c->failsafe_callback_eip;
    
    phys_basetab = c->pt_base;
    d->mm.pagetable = mk_pagetable(phys_basetab);
    if ( !get_page_and_type(&frame_table[phys_basetab>>PAGE_SHIFT], d, 
                            PGT_base_page_table) )
        return -EINVAL;

    /* Failure to set GDT is harmless. */
    SET_GDT_ENTRIES(d, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(d, DEFAULT_GDT_ADDRESS);
    if ( c->gdt_ents != 0 )
    {
        if ( (rc = (int)set_gdt(d, c->gdt_frames, c->gdt_ents)) != 0 )
        {
            put_page_and_type(&frame_table[phys_basetab>>PAGE_SHIFT]);
            return rc;
        }
    }

    return 0;
}

#if defined(__i386__)

void new_thread(struct domain *p,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
    execution_context_t *ec = &p->shared_info->execution_context;

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_RING1_DS
     *       CS:EIP = FLAT_RING1_CS:start_pc
     *       SS:ESP = FLAT_RING1_DS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     */
    ec->ds = ec->es = ec->fs = ec->gs = ec->ss = FLAT_RING1_DS;
    ec->cs = FLAT_RING1_CS;
    ec->eip = start_pc;
    ec->esp = start_stack;
    ec->esi = start_info;

    __save_flags(ec->eflags);
    ec->eflags |= X86_EFLAGS_IF;

    /* No fast trap at start of day. */
    SET_DEFAULT_FAST_TRAP(&p->thread);
}


/*
 * This special macro can be used to load a debugging register
 */
#define loaddebug(thread,register) \
		__asm__("movl %0,%%db" #register  \
			: /* no output */ \
			:"r" (thread->debugreg[register]))


void switch_to(struct domain *prev_p, struct domain *next_p)
{
    struct thread_struct *next = &next_p->thread;
    struct tss_struct *tss = init_tss + smp_processor_id();
    execution_context_t *stack_ec = get_execution_context();
    int i;
    
    __cli();

    /* Switch guest general-register state. */
    if ( !is_idle_task(prev_p) )
    {
        memcpy(&prev_p->shared_info->execution_context, 
               stack_ec, 
               sizeof(*stack_ec));
        unlazy_fpu(prev_p);
        CLEAR_FAST_TRAP(&prev_p->thread);
    }

    if ( !is_idle_task(next_p) )
    {
        memcpy(stack_ec,
               &next_p->shared_info->execution_context,
               sizeof(*stack_ec));

        /*
         * This is sufficient! If the descriptor DPL differs from CS RPL then 
         * we'll #GP. If DS, ES, FS, GS are DPL 0 then they'll be cleared 
         * automatically. If SS RPL or DPL differs from CS RPL then we'll #GP.
         */
        if ( (stack_ec->cs & 3) == 0 )
            stack_ec->cs = FLAT_RING1_CS;
        if ( (stack_ec->ss & 3) == 0 )
            stack_ec->ss = FLAT_RING1_DS;

        SET_FAST_TRAP(&next_p->thread);

        /* Switch the guest OS ring-1 stack. */
        tss->esp1 = next->guestos_sp;
        tss->ss1  = next->guestos_ss;

        /* Maybe switch the debug registers. */
        if ( unlikely(next->debugreg[7]) )
        {
            loaddebug(next, 0);
            loaddebug(next, 1);
            loaddebug(next, 2);
            loaddebug(next, 3);
            /* no 4 and 5 */
            loaddebug(next, 6);
            loaddebug(next, 7);
        }

        /* Switch page tables. */
        write_ptbase(&next_p->mm);
        tlb_clocktick();
    }

    if ( unlikely(prev_p->io_bitmap != NULL) || 
         unlikely(next_p->io_bitmap != NULL) )
    {
        if ( next_p->io_bitmap != NULL )
        {
            /* Copy in the appropriate parts of the IO bitmap.  We use the
             * selector to copy only the interesting parts of the bitmap. */

            u64 old_sel = ~0ULL; /* IO bitmap selector for previous task. */

            if ( prev_p->io_bitmap != NULL)
            {
                old_sel = prev_p->io_bitmap_sel;

                /* Replace any areas of the IO bitmap that had bits cleared. */
                for ( i = 0; i < sizeof(prev_p->io_bitmap_sel) * 8; i++ )
                    if ( !test_bit(i, &prev_p->io_bitmap_sel) )
                        memcpy(&tss->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                               &next_p->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                               IOBMP_SELBIT_LWORDS * sizeof(unsigned long));
            }

            /* Copy in any regions of the new task's bitmap that have bits
             * clear and we haven't already dealt with. */
            for ( i = 0; i < sizeof(prev_p->io_bitmap_sel) * 8; i++ )
            {
                if ( test_bit(i, &old_sel)
                     && !test_bit(i, &next_p->io_bitmap_sel) )
                    memcpy(&tss->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                           &next_p->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                           IOBMP_SELBIT_LWORDS * sizeof(unsigned long));
            }

            tss->bitmap = IO_BITMAP_OFFSET;

	}
        else
        {
            /* In this case, we're switching FROM a task with IO port access,
             * to a task that doesn't use the IO bitmap.  We set any TSS bits
             * that might have been cleared, ready for future use. */
            for ( i = 0; i < sizeof(prev_p->io_bitmap_sel) * 8; i++ )
                if ( !test_bit(i, &prev_p->io_bitmap_sel) )
                    memset(&tss->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                           0xFF, IOBMP_SELBIT_LWORDS * sizeof(unsigned long));

            /*
             * a bitmap offset pointing outside of the TSS limit
             * causes a nicely controllable SIGSEGV if a process
             * tries to use a port IO instruction. The first
             * sys_ioperm() call sets up the bitmap properly.
             */
            tss->bitmap = INVALID_IO_BITMAP_OFFSET;
	}
    }

    set_current(next_p);

    /* Switch GDT and LDT. */
    __asm__ __volatile__ ("lgdt %0" : "=m" (*next_p->mm.gdt));
    load_LDT(next_p);

    __sti();
}


/* XXX Currently the 'domain' field is ignored! XXX */
long do_iopl(domid_t domain, unsigned int new_io_pl)
{
    execution_context_t *ec = get_execution_context();
    ec->eflags = (ec->eflags & 0xffffcfff) | ((new_io_pl&3) << 12);
    return 0;
}

#endif


static void relinquish_list(struct domain *d, struct list_head *list)
{
    struct list_head *ent;
    struct pfn_info  *page;
    unsigned long     x, y;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    ent = list->next;
    while ( ent != list )
    {
        page = list_entry(ent, struct pfn_info, list);

        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
        {
            /* Couldn't get a reference -- someone is freeing this page. */
            ent = ent->next;
            continue;
        }

        if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
            put_page(page);

        /*
         * Forcibly invalidate base page tables at this point to break circular
         * 'linear page table' references. This is okay because MMU structures
         * are not shared across domains and this domain is now dead. Thus base
         * tables are not in use so a non-zero count means circular reference.
         */
        y = page->u.inuse.type_info;
        for ( ; ; )
        {
            x = y;
            if ( likely((x & (PGT_type_mask|PGT_validated)) != 
                        (PGT_base_page_table|PGT_validated)) )
                break;

            y = cmpxchg(&page->u.inuse.type_info, x, x & ~PGT_validated);
            if ( likely(y == x) )
            {
                free_page_type(page, PGT_base_page_table);
                break;
            }
        }

        /* Follow the list chain and /then/ potentially free the page. */
        ent = ent->next;
        put_page(page);
    }

    spin_unlock_recursive(&d->page_alloc_lock);
}


void domain_relinquish_memory(struct domain *d)
{
    audit_domain(d);

    /* Ensure that noone is running over the dead domain's page tables. */
    synchronise_pagetables(~0UL);

    /* Exit shadow mode before deconstructing final guest page table. */
    shadow_mode_disable(d);

    /* Drop the in-use reference to the page-table base. */
    if ( pagetable_val(d->mm.pagetable) != 0 )
        put_page_and_type(&frame_table[pagetable_val(d->mm.pagetable) >>
                                      PAGE_SHIFT]);

    /*
     * Relinquish GDT mappings. No need for explicit unmapping of the LDT as 
     * it automatically gets squashed when the guest's mappings go away.
     */
    destroy_gdt(d);

    /* Relinquish every page of memory. */
    relinquish_list(d, &d->xenpage_list);
    relinquish_list(d, &d->page_list);
}


int construct_dom0(struct domain *p, 
                   unsigned long alloc_start,
                   unsigned long alloc_end,
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
    struct domain_setup_info dsi;
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

    extern void physdev_init_dom0(struct domain *);

    /* Sanity! */
    if ( p->domain != 0 ) 
        BUG();
    if ( test_bit(DF_CONSTRUCTED, &p->flags) ) 
        BUG();

    memset(&dsi, 0, sizeof(struct domain_setup_info));

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

    rc = parseelfimage(image_start, image_len, &dsi);
    if ( rc != 0 )
        return rc;

    /* Set up domain options */
    if ( dsi.use_writable_pagetables )
        vm_assist(p, VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

    if ( (dsi.v_start & (PAGE_SIZE-1)) != 0 )
    {
        printk("Initial guest OS must load to a page boundary.\n");
        return -EINVAL;
    }

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    vinitrd_start    = round_pgup(dsi.v_kernend);
    vinitrd_end      = vinitrd_start + initrd_len;
    vphysmap_start   = round_pgup(vinitrd_end);
    vphysmap_end     = vphysmap_start + (nr_pages * sizeof(unsigned long));
    vpt_start        = round_pgup(vphysmap_end);
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstartinfo_start = vpt_end;
        vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
        vstack_start     = vstartinfo_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1<<22)-1) & ~((1<<22)-1);
        if ( (v_end - vstack_end) < (512 << 10) )
            v_end += 1 << 22; /* Add extra 4MB to get >= 512kB padding. */
        if ( (((v_end - dsi.v_start + ((1<<L2_PAGETABLE_SHIFT)-1)) >> 
               L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
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
           dsi.v_kernstart, dsi.v_kernend, 
           vinitrd_start, vinitrd_end,
           vphysmap_start, vphysmap_end,
           vpt_start, vpt_end,
           vstartinfo_start, vstartinfo_end,
           vstack_start, vstack_end,
           dsi.v_start, v_end);
    printk(" ENTRY ADDRESS: %08lx\n", dsi.v_kernentry);

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        printk("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-dsi.v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        return -ENOMEM;
    }

    /*
     * Protect the lowest 1GB of memory. We use a temporary mapping there
     * from which we copy the kernel and ramdisk images.
     */
    if ( dsi.v_start < (1<<30) )
    {
        printk("Initial loading isn't allowed to lowest 1GB of memory.\n");
        return -EINVAL;
    }

    /* Construct a frame-allocation list for the initial domain. */
    for ( mfn = (alloc_start>>PAGE_SHIFT); 
          mfn < (alloc_end>>PAGE_SHIFT); 
          mfn++ )
    {
        page = &frame_table[mfn];
        page->u.inuse.domain    = p;
        page->u.inuse.type_info = 0;
        page->count_info        = PGC_always_set | PGC_allocated | 1;
        list_add_tail(&page->list, &p->page_list);
        p->tot_pages++; p->max_pages++;
    }

    mpt_alloc = (vpt_start - dsi.v_start) + alloc_start;

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

    l2tab += l2_table_offset(dsi.v_start);
    mfn = alloc_start >> PAGE_SHIFT;
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1start = l1tab = (l1_pgentry_t *)mpt_alloc; 
            mpt_alloc += PAGE_SIZE;
            *l2tab++ = mk_l2_pgentry((unsigned long)l1start | L2_PROT);
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(dsi.v_start);
        }
        *l1tab++ = mk_l1_pgentry((mfn << PAGE_SHIFT) | L1_PROT);
        
        page = &frame_table[mfn];
        if ( !get_page_and_type(page, p, PGT_writable_page) )
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
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l2_page_table;
            get_page(page, p); /* an extra ref because of readable mapping */
            /* Get another ref to L2 page so that it can be pinned. */
            if ( !get_page_and_type(page, p, PGT_l2_page_table) )
                BUG();
            set_bit(_PGT_pinned, &page->u.inuse.type_info);
        }
        else
        {
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l1_page_table;
	    page->u.inuse.type_info |= 
		((dsi.v_start>>L2_PAGETABLE_SHIFT)+(count-1))<<PGT_va_shift;

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
        mfn = pfn + (alloc_start>>PAGE_SHIFT);
#ifndef NDEBUG
#define REVERSE_START ((v_end - dsi.v_start) >> PAGE_SHIFT)
        if ( pfn > REVERSE_START )
            mfn = (alloc_end>>PAGE_SHIFT) - (pfn - REVERSE_START);
#endif
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
    console_endboot(cmdline && strstr(cmdline, "tty0"));

    /* DOM0 gets access to everything. */
    physdev_init_dom0(p);

    set_bit(DF_CONSTRUCTED, &p->flags);

    new_thread(p, dsi.v_kernentry, vstack_end, vstartinfo_start);

#if 0 /* XXXXX DO NOT CHECK IN ENABLED !!! (but useful for testing so leave) */
    shadow_lock(&p->mm);
    shadow_mode_enable(p, SHM_test); 
    shadow_unlock(&p->mm);
#endif

    return 0;
}
