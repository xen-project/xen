
#include <xen/config.h>
#include <xen/version.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/shared.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

#include <public/callback.h>

static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];
    char debug = 'n';

#ifndef NDEBUG
    debug = 'y';
#endif

    printk("----[ Xen-%d.%d%s  x86_64  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           debug, print_tainted(taint_str));
}

void show_registers(struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    const char *context;

    if ( is_hvm_vcpu(current) && guest_mode(regs) )
    {
        context = "hvm";
        hvm_store_cpu_guest_regs(current, &fault_regs, fault_crs);
    }
    else
    {
        if ( guest_mode(regs) )
        {
            context = "guest";
            fault_crs[2] = arch_get_cr2(current);
        }
        else
        {
            context = "hypervisor";
            fault_crs[2] = read_cr2();
        }

        fault_crs[0] = read_cr0();
        fault_crs[3] = read_cr3();
        fault_crs[4] = read_cr4();
        fault_regs.ds = read_segment_register(ds);
        fault_regs.es = read_segment_register(es);
        fault_regs.fs = read_segment_register(fs);
        fault_regs.gs = read_segment_register(gs);
    }

    print_xen_info();
    printk("CPU:    %d\nRIP:    %04x:[<%016lx>]",
           smp_processor_id(), fault_regs.cs, fault_regs.rip);
    if ( !guest_mode(regs) )
        print_symbol(" %s", fault_regs.rip);
    printk("\nRFLAGS: %016lx   CONTEXT: %s\n", fault_regs.rflags, context);
    printk("rax: %016lx   rbx: %016lx   rcx: %016lx\n",
           fault_regs.rax, fault_regs.rbx, fault_regs.rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           fault_regs.rdx, fault_regs.rsi, fault_regs.rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           fault_regs.rbp, fault_regs.rsp, fault_regs.r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           fault_regs.r9,  fault_regs.r10, fault_regs.r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           fault_regs.r12, fault_regs.r13, fault_regs.r14);
    printk("r15: %016lx   cr0: %016lx   cr4: %016lx\n",
           fault_regs.r15, fault_crs[0], fault_crs[4]);
    printk("cr3: %016lx   cr2: %016lx\n", fault_crs[3], fault_crs[2]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           fault_regs.ds, fault_regs.es, fault_regs.fs,
           fault_regs.gs, fault_regs.ss, fault_regs.cs);
}

void show_page_walk(unsigned long addr)
{
    unsigned long pfn, mfn = read_cr3() >> PAGE_SHIFT;
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;

    printk("Pagetable walk from %016lx:\n", addr);

    l4t = mfn_to_virt(mfn);
    l4e = l4t[l4_table_offset(addr)];
    mfn = l4e_get_pfn(l4e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L4[0x%03lx] = %"PRIpte" %016lx\n",
           l4_table_offset(addr), l4e_get_intpte(l4e), pfn);
    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return;

    l3t = mfn_to_virt(mfn);
    l3e = l3t[l3_table_offset(addr)];
    mfn = l3e_get_pfn(l3e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L3[0x%03lx] = %"PRIpte" %016lx\n",
           l3_table_offset(addr), l3e_get_intpte(l3e), pfn);
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return;

    l2t = mfn_to_virt(mfn);
    l2e = l2t[l2_table_offset(addr)];
    mfn = l2e_get_pfn(l2e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L2[0x%03lx] = %"PRIpte" %016lx %s\n",
           l2_table_offset(addr), l2e_get_intpte(l2e), pfn,
           (l2e_get_flags(l2e) & _PAGE_PSE) ? "(PSE)" : "");
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) )
        return;

    l1t = mfn_to_virt(mfn);
    l1e = l1t[l1_table_offset(addr)];
    mfn = l1e_get_pfn(l1e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L1[0x%03lx] = %"PRIpte" %016lx\n",
           l1_table_offset(addr), l1e_get_intpte(l1e), pfn);
}

asmlinkage void double_fault(void);
asmlinkage void do_double_fault(struct cpu_user_regs *regs)
{
    unsigned int cpu, tr;

    asm ( "str %0" : "=r" (tr) );
    cpu = ((tr >> 3) - __FIRST_TSS_ENTRY) >> 2;

    watchdog_disable();

    console_force_unlock();

    /* Find information saved during fault and dump it to the console. */
    printk("*** DOUBLE FAULT ***\n");
    print_xen_info();
    printk("CPU:    %d\nRIP:    %04x:[<%016lx>]",
           cpu, regs->cs, regs->rip);
    print_symbol(" %s", regs->rip);
    printk("\nRFLAGS: %016lx\n", regs->rflags);
    printk("rax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, regs->rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           regs->r12, regs->r13, regs->r14);
    printk("r15: %016lx\n", regs->r15);
    show_stack_overflow(cpu, regs->rsp);

    panic("DOUBLE FAULT -- system shutdown\n");
}

void toggle_guest_mode(struct vcpu *v)
{
    if ( IS_COMPAT(v->domain) )
        return;
    v->arch.flags ^= TF_kernel_mode;
    __asm__ __volatile__ ( "swapgs" );
    update_cr3(v);
#ifdef USER_MAPPINGS_ARE_GLOBAL
    /* Don't flush user global mappings from the TLB. Don't tick TLB clock. */
    __asm__ __volatile__ ( "mov %0, %%cr3" : : "r" (v->arch.cr3) : "memory" );
#else
    write_ptbase(v);
#endif
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp,
                                 sizeof(iret_saved))) )
    {
        gdprintk(XENLOG_ERR, "Fault while reading IRET context from "
                "guest stack\n");
        goto exit_and_crash;
    }

    /* Returning to user mode? */
    if ( (iret_saved.cs & 3) == 3 )
    {
        if ( unlikely(pagetable_is_null(v->arch.guest_table_user)) )
        {
            gdprintk(XENLOG_ERR, "Guest switching to user mode with no "
                    "user page tables\n");
            goto exit_and_crash;
        }
        toggle_guest_mode(v);
    }

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = (iret_saved.rflags & ~(EF_IOPL|EF_VM)) | EF_IE;
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_in_syscall) )
    {
        regs->entry_vector = 0;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* No longer in NMI context. */
    current->nmi_masked = 0;

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(current, evtchn_upcall_mask) = !(iret_saved.rflags & EF_IE);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;

 exit_and_crash:
    gdprintk(XENLOG_ERR, "Fatal error\n");
    domain_crash(v->domain);
    return 0;
}

asmlinkage void syscall_enter(void);
asmlinkage void compat_hypercall(void);
asmlinkage void int80_direct_trap(void);
void __init percpu_traps_init(void)
{
    char *stack_bottom, *stack;
    int   cpu = smp_processor_id();

    if ( cpu == 0 )
    {
        /* Specify dedicated interrupt stacks for NMIs and double faults. */
        set_intr_gate(TRAP_double_fault, &double_fault);
        idt_table[TRAP_double_fault].a |= 1UL << 32; /* IST1 */
        idt_table[TRAP_nmi].a          |= 2UL << 32; /* IST2 */

#ifdef CONFIG_COMPAT
        /* The hypercall entry vector is only accessible from ring 1. */
        _set_gate(idt_table+HYPERCALL_VECTOR, 15, 1, &compat_hypercall);
        _set_gate(idt_table+0x80, 15, 3, &int80_direct_trap);
#endif
    }

    stack_bottom = (char *)get_stack_bottom();
    stack        = (char *)((unsigned long)stack_bottom & ~(STACK_SIZE - 1));

    /* Double-fault handler has its own per-CPU 2kB stack. */
    init_tss[cpu].ist[0] = (unsigned long)&stack[2048];

    /* NMI handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[1] = (unsigned long)&stack[3072];

    /*
     * Trampoline for SYSCALL entry from long mode.
     */

    /* Skip the NMI and DF stacks. */
    stack = &stack[3072];
    wrmsr(MSR_LSTAR, (unsigned long)stack, ((unsigned long)stack>>32));

    /* movq %rsp, saversp(%rip) */
    stack[0] = 0x48;
    stack[1] = 0x89;
    stack[2] = 0x25;
    *(u32 *)&stack[3] = (stack_bottom - &stack[7]) - 16;

    /* leaq saversp(%rip), %rsp */
    stack[7] = 0x48;
    stack[8] = 0x8d;
    stack[9] = 0x25;
    *(u32 *)&stack[10] = (stack_bottom - &stack[14]) - 16;

    /* pushq %r11 */
    stack[14] = 0x41;
    stack[15] = 0x53;

    /* pushq $FLAT_KERNEL_CS64 */
    stack[16] = 0x68;
    *(u32 *)&stack[17] = FLAT_KERNEL_CS64;

    /* jmp syscall_enter */
    stack[21] = 0xe9;
    *(u32 *)&stack[22] = (char *)syscall_enter - &stack[26];

    /*
     * Trampoline for SYSCALL entry from compatibility mode.
     */

    /* Skip the long-mode entry trampoline. */
    stack = &stack[26];
    wrmsr(MSR_CSTAR, (unsigned long)stack, ((unsigned long)stack>>32));

    /* movq %rsp, saversp(%rip) */
    stack[0] = 0x48;
    stack[1] = 0x89;
    stack[2] = 0x25;
    *(u32 *)&stack[3] = (stack_bottom - &stack[7]) - 16;

    /* leaq saversp(%rip), %rsp */
    stack[7] = 0x48;
    stack[8] = 0x8d;
    stack[9] = 0x25;
    *(u32 *)&stack[10] = (stack_bottom - &stack[14]) - 16;

    /* pushq %r11 */
    stack[14] = 0x41;
    stack[15] = 0x53;

    /* pushq $FLAT_KERNEL_CS32 */
    stack[16] = 0x68;
    *(u32 *)&stack[17] = FLAT_KERNEL_CS32;

    /* jmp syscall_enter */
    stack[21] = 0xe9;
    *(u32 *)&stack[22] = (char *)syscall_enter - &stack[26];

    /*
     * Common SYSCALL parameters.
     */

    wrmsr(MSR_STAR, 0, (FLAT_RING3_CS32<<16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, EF_VM|EF_RF|EF_NT|EF_DF|EF_IE|EF_TF, 0U);
}

void init_int80_direct_trap(struct vcpu *v)
{
    struct trap_info *ti = &v->arch.guest_context.trap_ctxt[0x80];
    struct trap_bounce *tb = &v->arch.int80_bounce;

    if ( !guest_gate_selector_okay(v->domain, ti->cs) )
         return;

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( null_trap_bounce(v, tb) )
        tb->flags = 0;
}

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.guest_context.event_callback_eip    = reg->address;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.guest_context.failsafe_callback_eip = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.guest_context.flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.guest_context.flags);
        break;

    case CALLBACKTYPE_syscall:
        v->arch.guest_context.syscall_callback_eip  = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_syscall_disables_events,
                    &v->arch.guest_context.flags);
        else
            clear_bit(_VGCF_syscall_disables_events,
                      &v->arch.guest_context.flags);
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long unregister_guest_callback(struct callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
    case CALLBACKTYPE_syscall:
        ret = -EINVAL;
        break;

    case CALLBACKTYPE_nmi:
        ret = unregister_guest_nmi_callback();
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}


long do_callback_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = event_address,
    };
    struct callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = failsafe_address,
    };
    struct callback_register syscall = {
        .type = CALLBACKTYPE_syscall,
        .address = syscall_address,
    };

    register_guest_callback(&event);
    register_guest_callback(&failsafe);
    register_guest_callback(&syscall);

    return 0;
}

static void hypercall_page_initialise_ring3_kernel(void *hypercall_page)
{
    char *p;
    int i;

    /* Fill in all the transfer points with template machine code. */
    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
        *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
        *(u8  *)(p+ 3) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 4) = i;
        *(u16 *)(p+ 8) = 0x050f;  /* syscall */
        *(u16 *)(p+10) = 0x5b41;  /* pop  %r11 */
        *(u8  *)(p+12) = 0x59;    /* pop  %rcx */
        *(u8  *)(p+13) = 0xc3;    /* ret */
    }

    /*
     * HYPERVISOR_iret is special because it doesn't return and expects a 
     * special stack frame. Guests jump at this transfer point instead of 
     * calling it.
     */
    p = (char *)(hypercall_page + (__HYPERVISOR_iret * 32));
    *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
    *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
    *(u8  *)(p+ 3) = 0x50;    /* push %rax */
    *(u8  *)(p+ 4) = 0xb8;    /* mov  $__HYPERVISOR_iret,%eax */
    *(u32 *)(p+ 5) = __HYPERVISOR_iret;
    *(u16 *)(p+ 9) = 0x050f;  /* syscall */
}

#include "compat/traps.c"

void hypercall_page_initialise(struct domain *d, void *hypercall_page)
{
    if ( is_hvm_domain(d) )
        hvm_hypercall_page_initialise(d, hypercall_page);
    else if ( !IS_COMPAT(d) )
        hypercall_page_initialise_ring3_kernel(hypercall_page);
    else
        hypercall_page_initialise_ring1_kernel(hypercall_page);
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
