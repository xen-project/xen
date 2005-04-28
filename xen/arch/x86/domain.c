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
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/grant_table.h>
#include <asm/regs.h>
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
#include <asm/vmx.h>
#include <asm/vmx_vmcs.h>
#include <asm/msr.h>
#include <xen/kernel.h>
#include <public/io/ioreq.h>
#include <xen/multicall.h>

/* opt_noreboot: If true, machine will need manual reset on error. */
static int opt_noreboot = 0;
boolean_param("noreboot", opt_noreboot);

struct percpu_ctxt {
    struct exec_domain *curr_ed;
} __cacheline_aligned;
static struct percpu_ctxt percpu_ctxt[NR_CPUS];

static void default_idle(void)
{
    local_irq_disable();
    if ( !softirq_pending(smp_processor_id()) )
        safe_halt();
    else
        local_irq_enable();
}

static __attribute_used__ void idle_loop(void)
{
    int cpu = smp_processor_id();
    for ( ; ; )
    {
        irq_stat[cpu].idle_timestamp = jiffies;
        while ( !softirq_pending(cpu) )
        {
            page_scrub_schedule_work();
            default_idle();
        }
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    /* Just some sanity to ensure that the scheduler is set up okay. */
    ASSERT(current->domain->id == IDLE_DOMAIN_ID);
    percpu_ctxt[smp_processor_id()].curr_ed = current;
    set_bit(smp_processor_id(), &current->domain->cpuset);
    domain_unpause_by_systemcontroller(current->domain);
    raise_softirq(SCHEDULE_SOFTIRQ);
    do_softirq();

    /*
     * Declares CPU setup done to the boot processor.
     * Therefore memory barrier to ensure state is visible.
     */
    smp_mb();
    init_idle();

    idle_loop();
}

static long no_idt[2];
static int reboot_mode;

static inline void kb_wait(void)
{
    int i;

    for ( i = 0; i < 0x10000; i++ )
        if ( (inb_p(0x64) & 0x02) == 0 )
            break;
}

void machine_restart(char * __unused)
{
    int i;
	
    if ( opt_noreboot )
    {
        printk("Reboot disabled on cmdline: require manual reset\n");
        for ( ; ; )
            safe_halt();
    }

    local_irq_enable();

    /* Ensure we are the boot CPU. */
    if ( GET_APIC_ID(apic_read(APIC_ID)) != boot_cpu_physical_apicid )
    {
        smp_call_function((void *)machine_restart, NULL, 1, 0);
        for ( ; ; )
            safe_halt();
    }

    /*
     * Stop all CPUs and turn off local APICs and the IO-APIC, so
     * other OSs see a clean IRQ state.
     */
    smp_send_stop();
    disable_IO_APIC();

#ifdef CONFIG_VMX
    stop_vmx();
#endif

    /* Rebooting needs to touch the page at absolute address 0. */
    *((unsigned short *)__va(0x472)) = reboot_mode;

    for ( ; ; )
    {
        /* Pulse the keyboard reset line. */
        for ( i = 0; i < 100; i++ )
        {
            kb_wait();
            udelay(50);
            outb(0xfe,0x64); /* pulse reset low */
            udelay(50);
        }

        /* That didn't work - force a triple fault.. */
        __asm__ __volatile__("lidt %0": "=m" (no_idt));
        __asm__ __volatile__("int3");
    }
}


void __attribute__((noreturn)) __machine_halt(void *unused)
{
    for ( ; ; )
        safe_halt();
}

void machine_halt(void)
{
    watchdog_on = 0;
    smp_call_function(__machine_halt, NULL, 1, 0);
    __machine_halt(NULL);
}

void dump_pageframe_info(struct domain *d)
{
    struct pfn_info *page;

    if ( d->tot_pages < 10 )
    {
        list_for_each_entry ( page, &d->page_list, list )
        {
            printk("Page %p: caf=%08x, taf=%08x\n",
                   _p(page_to_phys(page)), page->count_info,
                   page->u.inuse.type_info);
        }
    }

    list_for_each_entry ( page, &d->xenpage_list, list )
    {
        printk("XenPage %p: caf=%08x, taf=%08x\n",
               _p(page_to_phys(page)), page->count_info,
               page->u.inuse.type_info);
    }

    
    page = virt_to_page(d->shared_info);
    printk("Shared_info@%p: caf=%08x, taf=%08x\n",
           _p(page_to_phys(page)), page->count_info,
           page->u.inuse.type_info);
}

struct exec_domain *arch_alloc_exec_domain_struct(void)
{
    return xmalloc(struct exec_domain);
}

void arch_free_exec_domain_struct(struct exec_domain *ed)
{
    xfree(ed);
}

void free_perdomain_pt(struct domain *d)
{
    free_xenheap_page((unsigned long)d->arch.mm_perdomain_pt);
#ifdef __x86_64__
    free_xenheap_page((unsigned long)d->arch.mm_perdomain_l2);
    free_xenheap_page((unsigned long)d->arch.mm_perdomain_l3);
#endif
}

static void continue_idle_task(struct exec_domain *ed)
{
    reset_stack_and_jump(idle_loop);
}

static void continue_nonidle_task(struct exec_domain *ed)
{
    reset_stack_and_jump(ret_from_intr);
}

void arch_do_createdomain(struct exec_domain *ed)
{
    struct domain *d = ed->domain;

    SET_DEFAULT_FAST_TRAP(&ed->arch);

    ed->arch.flags = TF_kernel_mode;

    if ( d->id == IDLE_DOMAIN_ID )
    {
        ed->arch.schedule_tail = continue_idle_task;
    }
    else
    {
        ed->arch.schedule_tail = continue_nonidle_task;

        d->shared_info = (void *)alloc_xenheap_page();
        memset(d->shared_info, 0, PAGE_SIZE);
        ed->vcpu_info = &d->shared_info->vcpu_data[ed->eid];
        SHARE_PFN_WITH_DOMAIN(virt_to_page(d->shared_info), d);
        machine_to_phys_mapping[virt_to_phys(d->shared_info) >> 
                               PAGE_SHIFT] = INVALID_M2P_ENTRY;

        d->arch.mm_perdomain_pt = (l1_pgentry_t *)alloc_xenheap_page();
        memset(d->arch.mm_perdomain_pt, 0, PAGE_SIZE);
        machine_to_phys_mapping[virt_to_phys(d->arch.mm_perdomain_pt) >> 
                               PAGE_SHIFT] = INVALID_M2P_ENTRY;
        ed->arch.perdomain_ptes = d->arch.mm_perdomain_pt;

        ed->arch.guest_vtable  = __linear_l2_table;
        ed->arch.shadow_vtable = __shadow_linear_l2_table;

#ifdef __x86_64__
        ed->arch.guest_vl3table = __linear_l3_table;
        ed->arch.guest_vl4table = __linear_l4_table;

        d->arch.mm_perdomain_l2 = (l2_pgentry_t *)alloc_xenheap_page();
        memset(d->arch.mm_perdomain_l2, 0, PAGE_SIZE);
        d->arch.mm_perdomain_l2[l2_table_offset(PERDOMAIN_VIRT_START)] = 
            l2e_create_phys(__pa(d->arch.mm_perdomain_pt),
                            __PAGE_HYPERVISOR);
        d->arch.mm_perdomain_l3 = (l3_pgentry_t *)alloc_xenheap_page();
        memset(d->arch.mm_perdomain_l3, 0, PAGE_SIZE);
        d->arch.mm_perdomain_l3[l3_table_offset(PERDOMAIN_VIRT_START)] = 
            l3e_create_phys(__pa(d->arch.mm_perdomain_l2),
                            __PAGE_HYPERVISOR);
#endif

        (void)ptwr_init(d);

        shadow_lock_init(d);        
        INIT_LIST_HEAD(&d->arch.free_shadow_frames);
    }
}

void arch_do_boot_vcpu(struct exec_domain *ed)
{
    struct domain *d = ed->domain;
    ed->arch.schedule_tail = d->exec_domain[0]->arch.schedule_tail;
    ed->arch.perdomain_ptes = 
        d->arch.mm_perdomain_pt + (ed->eid << PDPT_VCPU_SHIFT);
    ed->arch.flags = TF_kernel_mode;
}

#ifdef CONFIG_VMX
void arch_vmx_do_resume(struct exec_domain *ed) 
{
    u64 vmcs_phys_ptr = (u64) virt_to_phys(ed->arch.arch_vmx.vmcs);

    load_vmcs(&ed->arch.arch_vmx, vmcs_phys_ptr);
    vmx_do_resume(ed);
    reset_stack_and_jump(vmx_asm_do_resume);
}

void arch_vmx_do_launch(struct exec_domain *ed) 
{
    u64 vmcs_phys_ptr = (u64) virt_to_phys(ed->arch.arch_vmx.vmcs);

    load_vmcs(&ed->arch.arch_vmx, vmcs_phys_ptr);
    vmx_do_launch(ed);
    reset_stack_and_jump(vmx_asm_do_launch);
}

static int vmx_final_setup_guest(
    struct exec_domain *ed, struct vcpu_guest_context *ctxt)
{
    int error;
    struct cpu_user_regs *regs;
    struct vmcs_struct *vmcs;

    regs = &ctxt->user_regs;

    /*
     * Create a new VMCS
     */
    if (!(vmcs = alloc_vmcs())) {
        printk("Failed to create a new VMCS\n");
        return -ENOMEM;
    }

    memset(&ed->arch.arch_vmx, 0, sizeof (struct arch_vmx_struct));

    ed->arch.arch_vmx.vmcs = vmcs;
    error = construct_vmcs(
        &ed->arch.arch_vmx, regs, ctxt, VMCS_USE_HOST_ENV);
    if ( error < 0 )
    {
        printk("Failed to construct a new VMCS\n");
        goto out;
    }

    ed->arch.schedule_tail = arch_vmx_do_launch;
    clear_bit(VMX_CPU_STATE_PG_ENABLED, &ed->arch.arch_vmx.cpu_state);

#if defined (__i386)
    ed->arch.arch_vmx.vmx_platform.real_mode_data = 
        (unsigned long *) regs->esi;
#endif

    if (ed == ed->domain->exec_domain[0]) {
        /* 
         * Required to do this once per domain
         * XXX todo: add a seperate function to do these.
         */
        memset(&ed->domain->shared_info->evtchn_mask[0], 0xff, 
               sizeof(ed->domain->shared_info->evtchn_mask));
        clear_bit(IOPACKET_PORT, &ed->domain->shared_info->evtchn_mask[0]);

        /* Put the domain in shadow mode even though we're going to be using
         * the shared 1:1 page table initially. It shouldn't hurt */
        shadow_mode_enable(ed->domain, SHM_enable|SHM_translate|SHM_external);
    }

    return 0;

out:
    free_vmcs(vmcs);
    ed->arch.arch_vmx.vmcs = 0;
    return error;
}
#endif


/* This is called by arch_final_setup_guest and do_boot_vcpu */
int arch_set_info_guest(
    struct exec_domain *ed, struct vcpu_guest_context *c)
{
    struct domain *d = ed->domain;
    unsigned long phys_basetab;
    int i, rc;

    /*
     * This is sufficient! If the descriptor DPL differs from CS RPL then we'll
     * #GP. If DS, ES, FS, GS are DPL 0 then they'll be cleared automatically.
     * If SS RPL or DPL differs from CS RPL then we'll #GP.
     */
    if (!(c->flags & ECF_VMX_GUEST)) 
        if ( ((c->user_regs.cs & 3) == 0) ||
             ((c->user_regs.ss & 3) == 0) )
                return -EINVAL;

    clear_bit(EDF_DONEFPUINIT, &ed->ed_flags);
    if ( c->flags & ECF_I387_VALID )
        set_bit(EDF_DONEFPUINIT, &ed->ed_flags);

    ed->arch.flags &= ~TF_kernel_mode;
    if ( c->flags & ECF_IN_KERNEL )
        ed->arch.flags |= TF_kernel_mode;

    memcpy(&ed->arch.user_regs,
           &c->user_regs,
           sizeof(ed->arch.user_regs));

    memcpy(&ed->arch.i387,
           &c->fpu_ctxt,
           sizeof(ed->arch.i387));

    /* IOPL privileges are virtualised. */
    ed->arch.iopl = (ed->arch.user_regs.eflags >> 12) & 3;
    ed->arch.user_regs.eflags &= ~EF_IOPL;

    /* Clear IOPL for unprivileged domains. */
    if (!IS_PRIV(d))
        ed->arch.user_regs.eflags &= 0xffffcfff;

    if (test_bit(EDF_DONEINIT, &ed->ed_flags))
        return 0;

    memcpy(ed->arch.traps,
           &c->trap_ctxt,
           sizeof(ed->arch.traps));

    if ( (rc = (int)set_fast_trap(ed, c->fast_trap_idx)) != 0 )
        return rc;

    ed->arch.ldt_base = c->ldt_base;
    ed->arch.ldt_ents = c->ldt_ents;

    ed->arch.kernel_ss = c->kernel_ss;
    ed->arch.kernel_sp = c->kernel_esp;

    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(ed, i, c->debugreg[i]);

#if defined(__i386__)
    ed->arch.event_selector    = c->event_callback_cs;
    ed->arch.event_address     = c->event_callback_eip;
    ed->arch.failsafe_selector = c->failsafe_callback_cs;
    ed->arch.failsafe_address  = c->failsafe_callback_eip;
#elif defined(__x86_64__)
    ed->arch.event_address     = c->event_callback_eip;
    ed->arch.failsafe_address  = c->failsafe_callback_eip;
    ed->arch.syscall_address   = c->syscall_callback_eip;
#endif

    if ( ed->eid == 0 )
        d->vm_assist = c->vm_assist;

    phys_basetab = c->pt_base;
    ed->arch.guest_table = mk_pagetable(phys_basetab);

    if ( shadow_mode_enabled(d) )
    {
        if ( !get_page(&frame_table[phys_basetab>>PAGE_SHIFT], d) )
            return -EINVAL;
    }
    else
    {
        if ( !get_page_and_type(&frame_table[phys_basetab>>PAGE_SHIFT], d, 
                                PGT_base_page_table) )
            return -EINVAL;
    }

    /* Failure to set GDT is harmless. */
    SET_GDT_ENTRIES(ed, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(ed, DEFAULT_GDT_ADDRESS);
    if ( c->gdt_ents != 0 )
    {
        if ( (rc = (int)set_gdt(ed, c->gdt_frames, c->gdt_ents)) != 0 )
        {
            put_page_and_type(&frame_table[phys_basetab>>PAGE_SHIFT]);
            return rc;
        }
    }

#ifdef CONFIG_VMX
    if ( c->flags & ECF_VMX_GUEST )
    {
        int error;

        // VMX uses the initially provided page tables as the P2M map.
        //
        // XXX: This creates a security issue -- Xen can't necessarily
        //      trust the VMX domain builder.  Xen should validate this
        //      page table, and/or build the table itself, or ???
        //
        if ( !pagetable_val(d->arch.phys_table) )
            d->arch.phys_table = ed->arch.guest_table;

        if ( (error = vmx_final_setup_guest(ed, c)) )
            return error;
    }
#endif

    update_pagetables(ed);
    
    /* Don't redo final setup */
    set_bit(EDF_DONEINIT, &ed->ed_flags);

    return 0;
}


void new_thread(struct exec_domain *d,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
    struct cpu_user_regs *regs = &d->arch.user_regs;

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_KERNEL_DS
     *       CS:EIP = FLAT_KERNEL_CS:start_pc
     *       SS:ESP = FLAT_KERNEL_SS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     */
    regs->ds = regs->es = regs->fs = regs->gs = FLAT_KERNEL_DS;
    regs->ss = FLAT_KERNEL_SS;
    regs->cs = FLAT_KERNEL_CS;
    regs->eip = start_pc;
    regs->esp = start_stack;
    regs->esi = start_info;

    __save_flags(regs->eflags);
    regs->eflags |= X86_EFLAGS_IF;
}


#ifdef __x86_64__

void toggle_guest_mode(struct exec_domain *ed)
{
    ed->arch.flags ^= TF_kernel_mode;
    __asm__ __volatile__ ( "swapgs" );
    update_pagetables(ed);
    write_ptbase(ed);
}

#define loadsegment(seg,value) ({               \
    int __r = 1;                                \
    __asm__ __volatile__ (                      \
        "1: movl %k1,%%" #seg "\n2:\n"          \
        ".section .fixup,\"ax\"\n"              \
        "3: xorl %k0,%k0\n"                     \
        "   movl %k0,%%" #seg "\n"              \
        "   jmp 2b\n"                           \
        ".previous\n"                           \
        ".section __ex_table,\"a\"\n"           \
        "   .align 8\n"                         \
        "   .quad 1b,3b\n"                      \
        ".previous"                             \
        : "=r" (__r) : "r" (value), "0" (__r) );\
    __r; })

static void load_segments(struct exec_domain *p, struct exec_domain *n)
{
    int all_segs_okay = 1;

    /* Either selector != 0 ==> reload. */
    if ( unlikely(p->arch.user_regs.ds |
                  n->arch.user_regs.ds) )
        all_segs_okay &= loadsegment(ds, n->arch.user_regs.ds);

    /* Either selector != 0 ==> reload. */
    if ( unlikely(p->arch.user_regs.es |
                  n->arch.user_regs.es) )
        all_segs_okay &= loadsegment(es, n->arch.user_regs.es);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset FS_BASE if it was non-zero.
     */
    if ( unlikely(p->arch.user_regs.fs |
                  p->arch.user_regs.fs_base |
                  n->arch.user_regs.fs) )
    {
        all_segs_okay &= loadsegment(fs, n->arch.user_regs.fs);
        if ( p->arch.user_regs.fs ) /* != 0 selector kills fs_base */
            p->arch.user_regs.fs_base = 0;
    }

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset GS_BASE if it was non-zero.
     */
    if ( unlikely(p->arch.user_regs.gs |
                  p->arch.user_regs.gs_base_user |
                  n->arch.user_regs.gs) )
    {
        /* Reset GS_BASE with user %gs? */
        if ( p->arch.user_regs.gs || !n->arch.user_regs.gs_base_user )
            all_segs_okay &= loadsegment(gs, n->arch.user_regs.gs);
        if ( p->arch.user_regs.gs ) /* != 0 selector kills gs_base_user */
            p->arch.user_regs.gs_base_user = 0;
    }

    /* This can only be non-zero if selector is NULL. */
    if ( n->arch.user_regs.fs_base )
        wrmsr(MSR_FS_BASE,
              n->arch.user_regs.fs_base,
              n->arch.user_regs.fs_base>>32);

    /* Most kernels have non-zero GS base, so don't bother testing. */
    /* (This is also a serialising instruction, avoiding AMD erratum #88.) */
    wrmsr(MSR_SHADOW_GS_BASE,
          n->arch.user_regs.gs_base_kernel,
          n->arch.user_regs.gs_base_kernel>>32);

    /* This can only be non-zero if selector is NULL. */
    if ( n->arch.user_regs.gs_base_user )
        wrmsr(MSR_GS_BASE,
              n->arch.user_regs.gs_base_user,
              n->arch.user_regs.gs_base_user>>32);

    /* If in kernel mode then switch the GS bases around. */
    if ( n->arch.flags & TF_kernel_mode )
        __asm__ __volatile__ ( "swapgs" );

    if ( unlikely(!all_segs_okay) )
    {
        struct cpu_user_regs *regs = get_cpu_user_regs();
        unsigned long   *rsp =
            (n->arch.flags & TF_kernel_mode) ?
            (unsigned long *)regs->rsp : 
            (unsigned long *)n->arch.kernel_sp;

        if ( !(n->arch.flags & TF_kernel_mode) )
            toggle_guest_mode(n);
        else
            regs->cs &= ~3;

        if ( put_user(regs->ss,             rsp- 1) |
             put_user(regs->rsp,            rsp- 2) |
             put_user(regs->rflags,         rsp- 3) |
             put_user(regs->cs,             rsp- 4) |
             put_user(regs->rip,            rsp- 5) |
             put_user(n->arch.user_regs.gs, rsp- 6) |
             put_user(n->arch.user_regs.fs, rsp- 7) |
             put_user(n->arch.user_regs.es, rsp- 8) |
             put_user(n->arch.user_regs.ds, rsp- 9) |
             put_user(regs->r11,            rsp-10) |
             put_user(regs->rcx,            rsp-11) )
        {
            DPRINTK("Error while creating failsafe callback frame.\n");
            domain_crash();
        }

        regs->entry_vector  = TRAP_syscall;
        regs->rflags       &= 0xFFFCBEFFUL;
        regs->ss            = __GUEST_SS;
        regs->rsp           = (unsigned long)(rsp-11);
        regs->cs            = __GUEST_CS;
        regs->rip           = n->arch.failsafe_address;
    }
}

static void save_segments(struct exec_domain *p)
{
    __asm__ __volatile__ ( "movl %%ds,%0" : "=m" (p->arch.user_regs.ds) );
    __asm__ __volatile__ ( "movl %%es,%0" : "=m" (p->arch.user_regs.es) );
    __asm__ __volatile__ ( "movl %%fs,%0" : "=m" (p->arch.user_regs.fs) );
    __asm__ __volatile__ ( "movl %%gs,%0" : "=m" (p->arch.user_regs.gs) );
}

static void clear_segments(void)
{
    __asm__ __volatile__ (
        " movl %0,%%ds; "
        " movl %0,%%es; "
        " movl %0,%%fs; "
        " movl %0,%%gs; "
        ""safe_swapgs"  "
        " movl %0,%%gs"
        : : "r" (0) );
}

long do_switch_to_user(void)
{
    struct cpu_user_regs       *regs = get_cpu_user_regs();
    struct switch_to_user  stu;
    struct exec_domain    *ed = current;

    if ( unlikely(copy_from_user(&stu, (void *)regs->rsp, sizeof(stu))) ||
         unlikely(pagetable_val(ed->arch.guest_table_user) == 0) )
        return -EFAULT;

    toggle_guest_mode(ed);

    regs->rip    = stu.rip;
    regs->cs     = stu.cs | 3; /* force guest privilege */
    regs->rflags = stu.rflags;
    regs->rsp    = stu.rsp;
    regs->ss     = stu.ss | 3; /* force guest privilege */

    if ( !(stu.flags & ECF_IN_SYSCALL) )
    {
        regs->entry_vector = 0;
        regs->r11 = stu.r11;
        regs->rcx = stu.rcx;
    }
    
    /* Saved %rax gets written back to regs->rax in entry.S. */
    return stu.rax; 
}

#define switch_kernel_stack(_n,_c) ((void)0)

#elif defined(__i386__)

#define load_segments(_p, _n) ((void)0)
#define save_segments(_p)     ((void)0)
#define clear_segments()      ((void)0)

static inline void switch_kernel_stack(struct exec_domain *n, unsigned int cpu)
{
    struct tss_struct *tss = &init_tss[cpu];
    tss->esp1 = n->arch.kernel_sp;
    tss->ss1  = n->arch.kernel_ss;
}

#endif

#define loaddebug(_ed,_reg) \
	__asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_ed)->debugreg[_reg]))

static void __context_switch(void)
{
    struct cpu_user_regs *stack_ec = get_cpu_user_regs();
    unsigned int         cpu = smp_processor_id();
    struct exec_domain  *p = percpu_ctxt[cpu].curr_ed;
    struct exec_domain  *n = current;

    if ( !is_idle_task(p->domain) )
    {
        memcpy(&p->arch.user_regs,
               stack_ec, 
               CTXT_SWITCH_STACK_BYTES);
        unlazy_fpu(p);
        CLEAR_FAST_TRAP(&p->arch);
        save_segments(p);
    }

    if ( !is_idle_task(n->domain) )
    {
        memcpy(stack_ec,
               &n->arch.user_regs,
               CTXT_SWITCH_STACK_BYTES);

        /* Maybe switch the debug registers. */
        if ( unlikely(n->arch.debugreg[7]) )
        {
            loaddebug(&n->arch, 0);
            loaddebug(&n->arch, 1);
            loaddebug(&n->arch, 2);
            loaddebug(&n->arch, 3);
            /* no 4 and 5 */
            loaddebug(&n->arch, 6);
            loaddebug(&n->arch, 7);
        }

        if ( !VMX_DOMAIN(n) )
        {
            SET_FAST_TRAP(&n->arch);
            switch_kernel_stack(n, cpu);
        }
    }

    if ( p->domain != n->domain )
        set_bit(cpu, &n->domain->cpuset);

    write_ptbase(n);
    __asm__ __volatile__ ( "lgdt %0" : "=m" (*n->arch.gdt) );

    if ( p->domain != n->domain )
        clear_bit(cpu, &p->domain->cpuset);

    percpu_ctxt[cpu].curr_ed = n;
}


void context_switch(struct exec_domain *prev, struct exec_domain *next)
{
    struct exec_domain *realprev;

    local_irq_disable();

    set_current(next);

    if ( ((realprev = percpu_ctxt[smp_processor_id()].curr_ed) == next) || 
         is_idle_task(next->domain) )
    {
        local_irq_enable();
    }
    else
    {
        __context_switch();

        local_irq_enable();
        
        if ( !VMX_DOMAIN(next) )
        {
            load_LDT(next);
            load_segments(realprev, next);
        }
    }

    /*
     * We do this late on because it doesn't need to be protected by the
     * schedule_lock, and because we want this to be the very last use of
     * 'prev' (after this point, a dying domain's info structure may be freed
     * without warning). 
     */
    clear_bit(EDF_RUNNING, &prev->ed_flags);

    schedule_tail(next);

    BUG();
}

int __sync_lazy_execstate(void)
{
    if ( percpu_ctxt[smp_processor_id()].curr_ed == current )
        return 0;
    __context_switch();
    load_LDT(current);
    clear_segments();
    return 1;
}

void sync_lazy_execstate_cpuset(unsigned long cpuset)
{
    flush_tlb_mask(cpuset);
}

void sync_lazy_execstate_all(void)
{
    flush_tlb_all();
}

unsigned long __hypercall_create_continuation(
    unsigned int op, unsigned int nr_args, ...)
{
    struct mc_state *mcs = &mc_state[smp_processor_id()];
    struct cpu_user_regs *regs;
    unsigned int i;
    va_list args;

    va_start(args, nr_args);

    if ( test_bit(_MCSF_in_multicall, &mcs->flags) )
    {
        __set_bit(_MCSF_call_preempted, &mcs->flags);

        for ( i = 0; i < nr_args; i++ )
            mcs->call.args[i] = va_arg(args, unsigned long);
    }
    else
    {
        regs       = get_cpu_user_regs();
#if defined(__i386__)
        regs->eax  = op;
        regs->eip -= 2;  /* re-execute 'int 0x82' */
        
        for ( i = 0; i < nr_args; i++ )
        {
            switch ( i )
            {
            case 0: regs->ebx = va_arg(args, unsigned long); break;
            case 1: regs->ecx = va_arg(args, unsigned long); break;
            case 2: regs->edx = va_arg(args, unsigned long); break;
            case 3: regs->esi = va_arg(args, unsigned long); break;
            case 4: regs->edi = va_arg(args, unsigned long); break;
            case 5: regs->ebp = va_arg(args, unsigned long); break;
            }
        }
#elif defined(__x86_64__)
        regs->rax  = op;
        regs->rip -= 2;  /* re-execute 'syscall' */
        
        for ( i = 0; i < nr_args; i++ )
        {
            switch ( i )
            {
            case 0: regs->rdi = va_arg(args, unsigned long); break;
            case 1: regs->rsi = va_arg(args, unsigned long); break;
            case 2: regs->rdx = va_arg(args, unsigned long); break;
            case 3: regs->r10 = va_arg(args, unsigned long); break;
            case 4: regs->r8  = va_arg(args, unsigned long); break;
            case 5: regs->r9  = va_arg(args, unsigned long); break;
            }
        }
#endif
    }

    va_end(args);

    return op;
}

#ifdef CONFIG_VMX
static void vmx_relinquish_resources(struct exec_domain *ed)
{
    if ( !VMX_DOMAIN(ed) )
        return;

    BUG_ON(ed->arch.arch_vmx.vmcs == NULL);
    free_vmcs(ed->arch.arch_vmx.vmcs);
    ed->arch.arch_vmx.vmcs = 0;
    
    free_monitor_pagetable(ed);
    rem_ac_timer(&ed->arch.arch_vmx.vmx_platform.vmx_pit.pit_timer);
}
#else
#define vmx_relinquish_resources(_ed) ((void)0)
#endif

static void relinquish_memory(struct domain *d, struct list_head *list)
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

void domain_relinquish_resources(struct domain *d)
{
    struct exec_domain *ed;

    BUG_ON(d->cpuset != 0);

    ptwr_destroy(d);

    /* Release device mappings of other domains */
    gnttab_release_dev_mappings(d->grant_table);

    /* Drop the in-use references to page-table bases. */
    for_each_exec_domain ( d, ed )
    {
        if ( pagetable_val(ed->arch.guest_table) != 0 )
        {
            (shadow_mode_enabled(d) ? put_page : put_page_and_type)
                (&frame_table[pagetable_val(
                    ed->arch.guest_table) >> PAGE_SHIFT]);
            ed->arch.guest_table = mk_pagetable(0);
        }

        if ( pagetable_val(ed->arch.guest_table_user) != 0 )
        {
            (shadow_mode_enabled(d) ? put_page : put_page_and_type)
                (&frame_table[pagetable_val(
                    ed->arch.guest_table_user) >> PAGE_SHIFT]);
            ed->arch.guest_table_user = mk_pagetable(0);
        }

        vmx_relinquish_resources(ed);
    }

    shadow_mode_disable(d);

    /*
     * Relinquish GDT mappings. No need for explicit unmapping of the LDT as 
     * it automatically gets squashed when the guest's mappings go away.
     */
    for_each_exec_domain(d, ed)
        destroy_gdt(ed);

    /* Relinquish every page of memory. */
    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);
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
