/******************************************************************************
 * arch/x86/domain.c
 *
 * x86-specific domain handling (e.g., register setup and context switching).
 */

/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  Gareth Hughes <gareth@valinux.com>, May 2000
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
#include <xen/iocap.h>
#include <xen/kernel.h>
#include <xen/multicall.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/percpu.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <asm/shadow.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/msr.h>

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void paravirt_ctxt_switch_from(struct vcpu *v);
static void paravirt_ctxt_switch_to(struct vcpu *v);

static void continue_idle_domain(struct vcpu *v)
{
    reset_stack_and_jump(idle_loop);
}

static void continue_nonidle_domain(struct vcpu *v)
{
    reset_stack_and_jump(ret_from_intr);
}

static void default_idle(void)
{
    local_irq_disable();
    if ( !softirq_pending(smp_processor_id()) )
        safe_halt();
    else
        local_irq_enable();
}

void idle_loop(void)
{
    int cpu = smp_processor_id();

    for ( ; ; )
    {
        page_scrub_schedule_work();

        default_idle();

        if ( softirq_pending(cpu) )
            do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    cpu_set(smp_processor_id(), v->domain->domain_dirty_cpumask);
    cpu_set(smp_processor_id(), v->vcpu_dirty_cpumask);

    reset_stack_and_jump(idle_loop);
}

void dump_pageframe_info(struct domain *d)
{
    struct page_info *page;

    printk("Memory pages belonging to domain %u:\n", d->domain_id);

    if ( d->tot_pages >= 10 )
    {
        printk("    DomPage list too long to display\n");
    }
    else
    {
        list_for_each_entry ( page, &d->page_list, list )
        {
            printk("    DomPage %p: mfn=%p, caf=%08x, taf=%" PRtype_info "\n",
                   _p(page_to_maddr(page)), _p(page_to_mfn(page)),
                   page->count_info, page->u.inuse.type_info);
        }
    }

    list_for_each_entry ( page, &d->xenpage_list, list )
    {
        printk("    XenPage %p: mfn=%p, caf=%08x, taf=%" PRtype_info "\n",
               _p(page_to_maddr(page)), _p(page_to_mfn(page)),
               page->count_info, page->u.inuse.type_info);
    }
}

struct vcpu *alloc_vcpu_struct(struct domain *d, unsigned int vcpu_id)
{
    struct vcpu *v;

    if ( (v = xmalloc(struct vcpu)) == NULL )
        return NULL;

    memset(v, 0, sizeof(*v));

    v->arch.flags = TF_kernel_mode;

    v->arch.schedule_tail = is_idle_domain(d) ?
        continue_idle_domain : continue_nonidle_domain;

    v->arch.ctxt_switch_from = paravirt_ctxt_switch_from;
    v->arch.ctxt_switch_to   = paravirt_ctxt_switch_to;

    v->arch.perdomain_ptes =
        d->arch.mm_perdomain_pt + (vcpu_id << GDT_LDT_VCPU_SHIFT);

    v->arch.guest_vtable  = __linear_l2_table;
    v->arch.shadow_vtable = __shadow_linear_l2_table;
#if defined(__x86_64__)
    v->arch.guest_vl3table = __linear_l3_table;
    v->arch.guest_vl4table = __linear_l4_table;
#endif

    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    xfree(v);
}

int arch_domain_create(struct domain *d)
{
    l1_pgentry_t gdt_l1e;
    int vcpuid, pdpt_order, rc;
#ifdef __x86_64__
    int i;
#endif

    pdpt_order = get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(l1_pgentry_t));
    d->arch.mm_perdomain_pt = alloc_xenheap_pages(pdpt_order);
    if ( d->arch.mm_perdomain_pt == NULL )
        goto fail_nomem;
    memset(d->arch.mm_perdomain_pt, 0, PAGE_SIZE << pdpt_order);

    /*
     * Map Xen segments into every VCPU's GDT, irrespective of whether every
     * VCPU will actually be used. This avoids an NMI race during context
     * switch: if we take an interrupt after switching CR3 but before switching
     * GDT, and the old VCPU# is invalid in the new domain, we would otherwise
     * try to load CS from an invalid table.
     */
    gdt_l1e = l1e_from_page(virt_to_page(gdt_table), PAGE_HYPERVISOR);
    for ( vcpuid = 0; vcpuid < MAX_VIRT_CPUS; vcpuid++ )
        d->arch.mm_perdomain_pt[((vcpuid << GDT_LDT_VCPU_SHIFT) +
                                 FIRST_RESERVED_GDT_PAGE)] = gdt_l1e;

#if defined(__i386__)

    mapcache_init(d);

#else /* __x86_64__ */

    d->arch.mm_perdomain_l2 = alloc_xenheap_page();
    d->arch.mm_perdomain_l3 = alloc_xenheap_page();
    if ( (d->arch.mm_perdomain_l2 == NULL) ||
         (d->arch.mm_perdomain_l3 == NULL) )
        goto fail_nomem;

    memset(d->arch.mm_perdomain_l2, 0, PAGE_SIZE);
    for ( i = 0; i < (1 << pdpt_order); i++ )
        d->arch.mm_perdomain_l2[l2_table_offset(PERDOMAIN_VIRT_START)+i] =
            l2e_from_page(virt_to_page(d->arch.mm_perdomain_pt)+i,
                          __PAGE_HYPERVISOR);

    memset(d->arch.mm_perdomain_l3, 0, PAGE_SIZE);
    d->arch.mm_perdomain_l3[l3_table_offset(PERDOMAIN_VIRT_START)] =
        l3e_from_page(virt_to_page(d->arch.mm_perdomain_l2),
                            __PAGE_HYPERVISOR);

#endif /* __x86_64__ */

    shadow_lock_init(d);
    INIT_LIST_HEAD(&d->arch.free_shadow_frames);

    if ( !is_idle_domain(d) )
    {
        d->arch.ioport_caps = 
            rangeset_new(d, "I/O Ports", RANGESETF_prettyprint_hex);
        if ( d->arch.ioport_caps == NULL )
            goto fail_nomem;

        if ( (d->shared_info = alloc_xenheap_page()) == NULL )
            goto fail_nomem;

        if ( (rc = ptwr_init(d)) != 0 )
            goto fail_nomem;

        memset(d->shared_info, 0, PAGE_SIZE);
        share_xen_page_with_guest(
            virt_to_page(d->shared_info), d, XENSHARE_writable);
    }

    return 0;

 fail_nomem:
    free_xenheap_page(d->shared_info);
#ifdef __x86_64__
    free_xenheap_page(d->arch.mm_perdomain_l2);
    free_xenheap_page(d->arch.mm_perdomain_l3);
#endif
    free_xenheap_pages(d->arch.mm_perdomain_pt, pdpt_order);
    return -ENOMEM;
}

void arch_domain_destroy(struct domain *d)
{
    free_xenheap_pages(
        d->arch.mm_perdomain_pt,
        get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(l1_pgentry_t)));

#ifdef __x86_64__
    free_xenheap_page(d->arch.mm_perdomain_l2);
    free_xenheap_page(d->arch.mm_perdomain_l3);
#endif

    free_xenheap_page(d->shared_info);
}

/* This is called by arch_final_setup_guest and do_boot_vcpu */
int arch_set_info_guest(
    struct vcpu *v, struct vcpu_guest_context *c)
{
    struct domain *d = v->domain;
    unsigned long phys_basetab = INVALID_MFN;
    int i, rc;

    if ( !(c->flags & VGCF_HVM_GUEST) )
    {
        fixup_guest_stack_selector(c->user_regs.ss);
        fixup_guest_stack_selector(c->kernel_ss);
        fixup_guest_code_selector(c->user_regs.cs);

#ifdef __i386__
        fixup_guest_code_selector(c->event_callback_cs);
        fixup_guest_code_selector(c->failsafe_callback_cs);
#endif

        for ( i = 0; i < 256; i++ )
            fixup_guest_code_selector(c->trap_ctxt[i].cs);
    }
    else if ( !hvm_enabled )
      return -EINVAL;

    clear_bit(_VCPUF_fpu_initialised, &v->vcpu_flags);
    if ( c->flags & VGCF_I387_VALID )
        set_bit(_VCPUF_fpu_initialised, &v->vcpu_flags);

    v->arch.flags &= ~TF_kernel_mode;
    if ( (c->flags & VGCF_IN_KERNEL) || (c->flags & VGCF_HVM_GUEST) )
        v->arch.flags |= TF_kernel_mode;

    memcpy(&v->arch.guest_context, c, sizeof(*c));
    init_int80_direct_trap(v);

    if ( !(c->flags & VGCF_HVM_GUEST) )
    {
        /* IOPL privileges are virtualised. */
        v->arch.iopl = (v->arch.guest_context.user_regs.eflags >> 12) & 3;
        v->arch.guest_context.user_regs.eflags &= ~EF_IOPL;

        /* Ensure real hardware interrupts are enabled. */
        v->arch.guest_context.user_regs.eflags |= EF_IE;
    }
    else if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
    {
        hvm_load_cpu_guest_regs(v, &v->arch.guest_context.user_regs);
    }

    if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
        return 0;

    memset(v->arch.guest_context.debugreg, 0,
           sizeof(v->arch.guest_context.debugreg));
    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(v, i, c->debugreg[i]);

    if ( v->vcpu_id == 0 )
        d->vm_assist = c->vm_assist;

    if ( !(c->flags & VGCF_HVM_GUEST) )
    {
        phys_basetab = c->ctrlreg[3];
        phys_basetab =
            (gmfn_to_mfn(d, phys_basetab >> PAGE_SHIFT) << PAGE_SHIFT) |
            (phys_basetab & ~PAGE_MASK);

        v->arch.guest_table = mk_pagetable(phys_basetab);
    }

    if ( (rc = (int)set_gdt(v, c->gdt_frames, c->gdt_ents)) != 0 )
        return rc;

    if ( c->flags & VGCF_HVM_GUEST )
    {
        v->arch.guest_table = mk_pagetable(0);

        if ( !hvm_initialize_guest_resources(v) )
            return -EINVAL;
    }
    else if ( shadow_mode_refcounts(d) )
    {
        if ( !get_page(mfn_to_page(phys_basetab>>PAGE_SHIFT), d) )
        {
            destroy_gdt(v);
            return -EINVAL;
        }
    }
    else
    {
        if ( !get_page_and_type(mfn_to_page(phys_basetab>>PAGE_SHIFT), d,
                                PGT_base_page_table) )
        {
            destroy_gdt(v);
            return -EINVAL;
        }
    }

    update_pagetables(v);

    if ( v->vcpu_id == 0 )
        update_domain_wallclock_time(d);

    /* Don't redo final setup */
    set_bit(_VCPUF_initialised, &v->vcpu_flags);

    return 0;
}

long
arch_do_vcpu_op(
    int cmd, struct vcpu *v, GUEST_HANDLE(void) arg)
{
    long rc = 0;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    {
        struct vcpu_register_runstate_memory_area area;

        rc = -EINVAL;
        if ( v != current )
            break;

        rc = -EFAULT;
        if ( copy_from_guest(&area, arg, 1) )
            break;

        if ( !access_ok(area.addr.v, sizeof(*area.addr.v)) )
            break;

        rc = 0;
        v->runstate_guest = area.addr.v;
        __copy_to_user(v->runstate_guest, &v->runstate, sizeof(v->runstate));

        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

void new_thread(struct vcpu *d,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
    struct cpu_user_regs *regs = &d->arch.guest_context.user_regs;

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

/*
 * save_segments() writes a mask of segments which are dirty (non-zero),
 * allowing load_segments() to avoid some expensive segment loads and
 * MSR writes.
 */
static DEFINE_PER_CPU(unsigned int, dirty_segment_mask);
#define DIRTY_DS           0x01
#define DIRTY_ES           0x02
#define DIRTY_FS           0x04
#define DIRTY_GS           0x08
#define DIRTY_FS_BASE      0x10
#define DIRTY_GS_BASE_USER 0x20

static void load_segments(struct vcpu *n)
{
    struct vcpu_guest_context *nctxt = &n->arch.guest_context;
    int all_segs_okay = 1;
    unsigned int dirty_segment_mask, cpu = smp_processor_id();

    /* Load and clear the dirty segment mask. */
    dirty_segment_mask = per_cpu(dirty_segment_mask, cpu);
    per_cpu(dirty_segment_mask, cpu) = 0;

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_DS) | nctxt->user_regs.ds) )
        all_segs_okay &= loadsegment(ds, nctxt->user_regs.ds);

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_ES) | nctxt->user_regs.es) )
        all_segs_okay &= loadsegment(es, nctxt->user_regs.es);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset FS_BASE if it was non-zero.
     */
    if ( unlikely((dirty_segment_mask & (DIRTY_FS | DIRTY_FS_BASE)) |
                  nctxt->user_regs.fs) )
        all_segs_okay &= loadsegment(fs, nctxt->user_regs.fs);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset GS_BASE if it was non-zero.
     */
    if ( unlikely((dirty_segment_mask & (DIRTY_GS | DIRTY_GS_BASE_USER)) |
                  nctxt->user_regs.gs) )
    {
        /* Reset GS_BASE with user %gs? */
        if ( (dirty_segment_mask & DIRTY_GS) || !nctxt->gs_base_user )
            all_segs_okay &= loadsegment(gs, nctxt->user_regs.gs);
    }

    /* This can only be non-zero if selector is NULL. */
    if ( nctxt->fs_base )
        wrmsr(MSR_FS_BASE,
              nctxt->fs_base,
              nctxt->fs_base>>32);

    /* Most kernels have non-zero GS base, so don't bother testing. */
    /* (This is also a serialising instruction, avoiding AMD erratum #88.) */
    wrmsr(MSR_SHADOW_GS_BASE,
          nctxt->gs_base_kernel,
          nctxt->gs_base_kernel>>32);

    /* This can only be non-zero if selector is NULL. */
    if ( nctxt->gs_base_user )
        wrmsr(MSR_GS_BASE,
              nctxt->gs_base_user,
              nctxt->gs_base_user>>32);

    /* If in kernel mode then switch the GS bases around. */
    if ( n->arch.flags & TF_kernel_mode )
        __asm__ __volatile__ ( "swapgs" );

    if ( unlikely(!all_segs_okay) )
    {
        struct cpu_user_regs *regs = guest_cpu_user_regs();
        unsigned long   *rsp =
            (n->arch.flags & TF_kernel_mode) ?
            (unsigned long *)regs->rsp :
            (unsigned long *)nctxt->kernel_sp;

        if ( !(n->arch.flags & TF_kernel_mode) )
            toggle_guest_mode(n);
        else
            regs->cs &= ~3;

        if ( put_user(regs->ss,            rsp- 1) |
             put_user(regs->rsp,           rsp- 2) |
             put_user(regs->rflags,        rsp- 3) |
             put_user(regs->cs,            rsp- 4) |
             put_user(regs->rip,           rsp- 5) |
             put_user(nctxt->user_regs.gs, rsp- 6) |
             put_user(nctxt->user_regs.fs, rsp- 7) |
             put_user(nctxt->user_regs.es, rsp- 8) |
             put_user(nctxt->user_regs.ds, rsp- 9) |
             put_user(regs->r11,           rsp-10) |
             put_user(regs->rcx,           rsp-11) )
        {
            DPRINTK("Error while creating failsafe callback frame.\n");
            domain_crash(n->domain);
        }

        regs->entry_vector  = TRAP_syscall;
        regs->rflags       &= 0xFFFCBEFFUL;
        regs->ss            = __GUEST_SS;
        regs->rsp           = (unsigned long)(rsp-11);
        regs->cs            = __GUEST_CS;
        regs->rip           = nctxt->failsafe_callback_eip;
    }
}

static void save_segments(struct vcpu *v)
{
    struct vcpu_guest_context *ctxt = &v->arch.guest_context;
    struct cpu_user_regs      *regs = &ctxt->user_regs;
    unsigned int dirty_segment_mask = 0;

    regs->ds = read_segment_register(ds);
    regs->es = read_segment_register(es);
    regs->fs = read_segment_register(fs);
    regs->gs = read_segment_register(gs);

    if ( regs->ds )
        dirty_segment_mask |= DIRTY_DS;

    if ( regs->es )
        dirty_segment_mask |= DIRTY_ES;

    if ( regs->fs )
    {
        dirty_segment_mask |= DIRTY_FS;
        ctxt->fs_base = 0; /* != 0 selector kills fs_base */
    }
    else if ( ctxt->fs_base )
    {
        dirty_segment_mask |= DIRTY_FS_BASE;
    }

    if ( regs->gs )
    {
        dirty_segment_mask |= DIRTY_GS;
        ctxt->gs_base_user = 0; /* != 0 selector kills gs_base_user */
    }
    else if ( ctxt->gs_base_user )
    {
        dirty_segment_mask |= DIRTY_GS_BASE_USER;
    }

    this_cpu(dirty_segment_mask) = dirty_segment_mask;
}

#define switch_kernel_stack(v) ((void)0)

#elif defined(__i386__)

#define load_segments(n) ((void)0)
#define save_segments(p) ((void)0)

static inline void switch_kernel_stack(struct vcpu *v)
{
    struct tss_struct *tss = &init_tss[smp_processor_id()];
    tss->esp1 = v->arch.guest_context.kernel_sp;
    tss->ss1  = v->arch.guest_context.kernel_ss;
}

#endif /* __i386__ */

static void paravirt_ctxt_switch_from(struct vcpu *v)
{
    save_segments(v);
}

static void paravirt_ctxt_switch_to(struct vcpu *v)
{
    set_int80_direct_trap(v);
    switch_kernel_stack(v);
}

#define loaddebug(_v,_reg) \
    __asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_v)->debugreg[_reg]))

static void __context_switch(void)
{
    struct cpu_user_regs *stack_regs = guest_cpu_user_regs();
    unsigned int          cpu = smp_processor_id();
    struct vcpu          *p = per_cpu(curr_vcpu, cpu);
    struct vcpu          *n = current;

    ASSERT(p != n);
    ASSERT(cpus_empty(n->vcpu_dirty_cpumask));

    if ( !is_idle_vcpu(p) )
    {
        memcpy(&p->arch.guest_context.user_regs,
               stack_regs,
               CTXT_SWITCH_STACK_BYTES);
        unlazy_fpu(p);
        p->arch.ctxt_switch_from(p);
    }

    if ( !is_idle_vcpu(n) )
    {
        memcpy(stack_regs,
               &n->arch.guest_context.user_regs,
               CTXT_SWITCH_STACK_BYTES);

        /* Maybe switch the debug registers. */
        if ( unlikely(n->arch.guest_context.debugreg[7]) )
        {
            loaddebug(&n->arch.guest_context, 0);
            loaddebug(&n->arch.guest_context, 1);
            loaddebug(&n->arch.guest_context, 2);
            loaddebug(&n->arch.guest_context, 3);
            /* no 4 and 5 */
            loaddebug(&n->arch.guest_context, 6);
            loaddebug(&n->arch.guest_context, 7);
        }

        n->arch.ctxt_switch_to(n);
    }

    if ( p->domain != n->domain )
        cpu_set(cpu, n->domain->domain_dirty_cpumask);
    cpu_set(cpu, n->vcpu_dirty_cpumask);

    write_ptbase(n);

    if ( p->vcpu_id != n->vcpu_id )
    {
        char gdt_load[10];
        *(unsigned short *)(&gdt_load[0]) = LAST_RESERVED_GDT_BYTE;
        *(unsigned long  *)(&gdt_load[2]) = GDT_VIRT_START(n);
        __asm__ __volatile__ ( "lgdt %0" : "=m" (gdt_load) );
    }

    if ( p->domain != n->domain )
        cpu_clear(cpu, p->domain->domain_dirty_cpumask);
    cpu_clear(cpu, p->vcpu_dirty_cpumask);

    per_cpu(curr_vcpu, cpu) = n;
}


void context_switch(struct vcpu *prev, struct vcpu *next)
{
    unsigned int cpu = smp_processor_id();
    cpumask_t dirty_mask = next->vcpu_dirty_cpumask;

    ASSERT(local_irq_is_enabled());

    /* Allow at most one CPU at a time to be dirty. */
    ASSERT(cpus_weight(dirty_mask) <= 1);
    if ( unlikely(!cpu_isset(cpu, dirty_mask) && !cpus_empty(dirty_mask)) )
    {
        /* Other cpus call __sync_lazy_execstate from flush ipi handler. */
        if ( !cpus_empty(next->vcpu_dirty_cpumask) )
            flush_tlb_mask(next->vcpu_dirty_cpumask);
    }

    local_irq_disable();

    set_current(next);

    if ( (per_cpu(curr_vcpu, cpu) == next) || is_idle_vcpu(next) )
    {
        local_irq_enable();
    }
    else
    {
        __context_switch();

        /* Re-enable interrupts before restoring state which may fault. */
        local_irq_enable();

        if ( !hvm_guest(next) )
        {
            load_LDT(next);
            load_segments(next);
        }
    }

    context_saved(prev);

    /* Update per-VCPU guest runstate shared memory area (if registered). */
    if ( next->runstate_guest != NULL )
        __copy_to_user(next->runstate_guest, &next->runstate,
                       sizeof(next->runstate));

    schedule_tail(next);
    BUG();
}

void continue_running(struct vcpu *same)
{
    schedule_tail(same);
    BUG();
}

int __sync_lazy_execstate(void)
{
    unsigned long flags;
    int switch_required;

    local_irq_save(flags);

    switch_required = (this_cpu(curr_vcpu) != current);

    if ( switch_required )
        __context_switch();

    local_irq_restore(flags);

    return switch_required;
}

void sync_vcpu_execstate(struct vcpu *v)
{
    if ( cpu_isset(smp_processor_id(), v->vcpu_dirty_cpumask) )
        (void)__sync_lazy_execstate();

    /* Other cpus call __sync_lazy_execstate from flush ipi handler. */
    flush_tlb_mask(v->vcpu_dirty_cpumask);
}

#define next_arg(fmt, args) ({                                              \
    unsigned long __arg;                                                    \
    switch ( *(fmt)++ )                                                     \
    {                                                                       \
    case 'i': __arg = (unsigned long)va_arg(args, unsigned int);  break;    \
    case 'l': __arg = (unsigned long)va_arg(args, unsigned long); break;    \
    case 'h': __arg = (unsigned long)va_arg(args, void *);        break;    \
    default:  __arg = 0; BUG();                                             \
    }                                                                       \
    __arg;                                                                  \
})

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &mc_state[smp_processor_id()];
    struct cpu_user_regs *regs;
    const char *p = format;
    unsigned long arg;
    unsigned int i;
    va_list args;

    va_start(args, format);

    if ( test_bit(_MCSF_in_multicall, &mcs->flags) )
    {
        __set_bit(_MCSF_call_preempted, &mcs->flags);

        for ( i = 0; *p != '\0'; i++ )
            mcs->call.args[i] = next_arg(p, args);
    }
    else
    {
        regs       = guest_cpu_user_regs();
#if defined(__i386__)
        regs->eax  = op;

        if ( supervisor_mode_kernel )
            regs->eip &= ~31; /* re-execute entire hypercall entry stub */
        else
            regs->eip -= 2;   /* re-execute 'int 0x82' */

        for ( i = 0; *p != '\0'; i++ )
        {
            arg = next_arg(p, args);
            switch ( i )
            {
            case 0: regs->ebx = arg; break;
            case 1: regs->ecx = arg; break;
            case 2: regs->edx = arg; break;
            case 3: regs->esi = arg; break;
            case 4: regs->edi = arg; break;
            case 5: regs->ebp = arg; break;
            }
        }
#elif defined(__x86_64__)
        regs->rax  = op;
        regs->rip -= 2;  /* re-execute 'syscall' */

        for ( i = 0; *p != '\0'; i++ )
        {
            arg = next_arg(p, args);
            switch ( i )
            {
            case 0: regs->rdi = arg; break;
            case 1: regs->rsi = arg; break;
            case 2: regs->rdx = arg; break;
            case 3: regs->r10 = arg; break;
            case 4: regs->r8  = arg; break;
            case 5: regs->r9  = arg; break;
            }
        }
#endif
    }

    va_end(args);

    return op;
}

static void relinquish_memory(struct domain *d, struct list_head *list)
{
    struct list_head *ent;
    struct page_info  *page;
    unsigned long     x, y;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    ent = list->next;
    while ( ent != list )
    {
        page = list_entry(ent, struct page_info, list);

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
    struct vcpu *v;
    unsigned long pfn;

    BUG_ON(!cpus_empty(d->domain_dirty_cpumask));

    ptwr_destroy(d);

    /* Drop the in-use references to page-table bases. */
    for_each_vcpu ( d, v )
    {
        if ( (pfn = pagetable_get_pfn(v->arch.guest_table)) != 0 )
        {
            if ( !shadow_mode_refcounts(d) )
                put_page_type(mfn_to_page(pfn));
            put_page(mfn_to_page(pfn));

            v->arch.guest_table = mk_pagetable(0);
        }

        if ( (pfn = pagetable_get_pfn(v->arch.guest_table_user)) != 0 )
        {
            if ( !shadow_mode_refcounts(d) )
                put_page_type(mfn_to_page(pfn));
            put_page(mfn_to_page(pfn));

            v->arch.guest_table_user = mk_pagetable(0);
        }
    }

    if ( hvm_guest(d->vcpu[0]) )
        hvm_relinquish_guest_resources(d);

    shadow_mode_disable(d);

    /*
     * Relinquish GDT mappings. No need for explicit unmapping of the LDT as
     * it automatically gets squashed when the guest's mappings go away.
     */
    for_each_vcpu(d, v)
        destroy_gdt(v);

    /* Relinquish every page of memory. */
    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);

    /* Free page used by xen oprofile buffer */
    free_xenoprof_pages(d);

}

void arch_dump_domain_info(struct domain *d)
{
    if ( shadow_mode_enabled(d) )
    {
        printk("    shadow mode: ");
        if ( shadow_mode_refcounts(d) )
            printk("refcounts ");
        if ( shadow_mode_write_all(d) )
            printk("write_all ");
        if ( shadow_mode_log_dirty(d) )
            printk("log_dirty ");
        if ( shadow_mode_translate(d) )
            printk("translate ");
        if ( shadow_mode_external(d) )
            printk("external ");
        if ( shadow_mode_wr_pt_pte(d) )
            printk("wr_pt_pte ");
        printk("\n");
    }
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
