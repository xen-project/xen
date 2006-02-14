
#include <xen/config.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <asm/shadow.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

void show_registers(struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    char taint_str[TAINT_STRING_MAX_LEN];
    const char *context;

    if ( HVM_DOMAIN(current) && GUEST_MODE(regs) )
    {
        context = "hvm";
        hvm_store_cpu_guest_regs(current, &fault_regs);
        hvm_store_cpu_guest_ctrl_regs(current, fault_crs);
    }
    else
    {
        context = GUEST_MODE(regs) ? "guest" : "hypervisor";
        fault_crs[0] = read_cr0();
        fault_crs[3] = read_cr3();
        fault_regs.ds = read_segment_register(ds);
        fault_regs.es = read_segment_register(es);
        fault_regs.fs = read_segment_register(fs);
        fault_regs.gs = read_segment_register(gs);
    }

    printk("----[ Xen-%d.%d%s    %s ]----\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           print_tainted(taint_str));
    printk("CPU:    %d\nRIP:    %04x:[<%016lx>]",
           smp_processor_id(), fault_regs.cs, fault_regs.rip);
    if ( !GUEST_MODE(regs) )
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
    printk("r15: %016lx   cr0: %016lx   cr3: %016lx\n",
           fault_regs.r15, fault_crs[0], fault_crs[3]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           fault_regs.ds, fault_regs.es, fault_regs.fs,
           fault_regs.gs, fault_regs.ss, fault_regs.cs);

    show_stack(regs);
}

void show_page_walk(unsigned long addr)
{
    unsigned long page = read_cr3();
    
    printk("Pagetable walk from %016lx:\n", addr);

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l4_table_offset(addr)];
    printk(" L4 = %016lx\n", page);
    if ( !(page & _PAGE_PRESENT) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l3_table_offset(addr)];
    printk("  L3 = %016lx\n", page);
    if ( !(page & _PAGE_PRESENT) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l2_table_offset(addr)];
    printk("   L2 = %016lx %s\n", page, (page & _PAGE_PSE) ? "(2MB)" : "");
    if ( !(page & _PAGE_PRESENT) || (page & _PAGE_PSE) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l1_table_offset(addr)];
    printk("    L1 = %016lx\n", page);
}

asmlinkage void double_fault(void);
asmlinkage void do_double_fault(struct cpu_user_regs *regs)
{
    watchdog_disable();

    console_force_unlock();

    /* Find information saved during fault and dump it to the console. */
    printk("************************************\n");
    show_registers(regs);
    printk("************************************\n");
    printk("CPU%d DOUBLE FAULT -- system shutdown\n", smp_processor_id());
    printk("System needs manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

void toggle_guest_mode(struct vcpu *v)
{
    v->arch.flags ^= TF_kernel_mode;
    __asm__ __volatile__ ( "swapgs" );
    update_pagetables(v);
    write_ptbase(v);
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp,
                                 sizeof(iret_saved))) )
        domain_crash_synchronous();

    /* Returning to user mode? */
    if ( (iret_saved.cs & 3) == 3 )
    {
        if ( unlikely(pagetable_get_paddr(v->arch.guest_table_user) == 0) )
            return -EFAULT;
        toggle_guest_mode(v);
    }

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = (iret_saved.rflags & ~(EF_IOPL|EF_VM)) | EF_IE;
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_IN_SYSCALL) )
    {
        regs->entry_vector = 0;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* No longer in NMI context. */
    clear_bit(_VCPUF_nmi_masked, &current->vcpu_flags);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;
}

asmlinkage void syscall_enter(void);
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
    }

    stack_bottom = (char *)get_stack_bottom();
    stack        = (char *)((unsigned long)stack_bottom & ~(STACK_SIZE - 1));

    /* Double-fault handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[0] = (unsigned long)&stack[1024];

    /* NMI handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[1] = (unsigned long)&stack[2048];

    /*
     * Trampoline for SYSCALL entry from long mode.
     */

    /* Skip the NMI and DF stacks. */
    stack = &stack[2048];
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

    /* pushq $__GUEST_CS64 */
    stack[16] = 0x68;
    *(u32 *)&stack[17] = __GUEST_CS64;

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

    /* pushq $__GUEST_CS32 */
    stack[16] = 0x68;
    *(u32 *)&stack[17] = __GUEST_CS32;

    /* jmp syscall_enter */
    stack[21] = 0xe9;
    *(u32 *)&stack[22] = (char *)syscall_enter - &stack[26];

    /*
     * Common SYSCALL parameters.
     */

    wrmsr(MSR_STAR, 0, (FLAT_RING3_CS32<<16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, EF_VM|EF_RF|EF_NT|EF_DF|EF_IE|EF_TF, 0U);
}

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct vcpu *d = current;

    d->arch.guest_context.event_callback_eip    = event_address;
    d->arch.guest_context.failsafe_callback_eip = failsafe_address;
    d->arch.guest_context.syscall_callback_eip  = syscall_address;

    return 0;
}

void hypercall_page_initialise(void *hypercall_page)
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
