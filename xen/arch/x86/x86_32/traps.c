
#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <asm/flushtlb.h>

#ifdef CONFIG_VMX
#include <asm/vmx.h>
#endif

/* All CPUs have their own IDT to allow set_fast_trap(). */
idt_entry_t *idt_tables[NR_CPUS] = { 0 };

static int kstack_depth_to_print = 8*20;

static inline int kernel_text_address(unsigned long addr)
{
    if (addr >= (unsigned long) &_stext &&
        addr <= (unsigned long) &_etext)
        return 1;
    return 0;

}

void show_guest_stack(void)
{
    int i;
    struct cpu_user_regs *regs = get_cpu_user_regs();
    unsigned long *stack = (unsigned long *)regs->esp;

    printk("Guest EIP is %08x\n   ", regs->eip);

    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n   ");
        printk("%08lx ", *stack++);
    }
    printk("\n");
    
}

void show_trace(unsigned long *esp)
{
    unsigned long *stack, addr;
    int i;

    printk("Call Trace from ESP=%p:\n   ", esp);
    stack = esp;
    i = 0;
    while (((long) stack & (STACK_SIZE-1)) != 0) {
        addr = *stack++;
        if (kernel_text_address(addr)) {
            if (i && ((i % 6) == 0))
                printk("\n   ");
            printk("[<%08lx>] ", addr);
            i++;
        }
    }
    printk("\n");
}

void show_stack(unsigned long *esp)
{
    unsigned long *stack;
    int i;

    printk("Stack trace from ESP=%p:\n   ", esp);

    stack = esp;
    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n   ");
        if ( kernel_text_address(*stack) )
            printk("[%08lx] ", *stack++);
        else
            printk("%08lx ", *stack++);
    }
    printk("\n");

    show_trace( esp );
}

void show_registers(struct cpu_user_regs *regs)
{
    unsigned long ss, ds, es, fs, gs, cs;
    unsigned long eip, esp, eflags;
    const char *context;

#ifdef CONFIG_VMX
    if ( VMX_DOMAIN(current) && (regs->eflags == 0) )
    {
        __vmread(GUEST_EIP, &eip);
        __vmread(GUEST_ESP, &esp);
        __vmread(GUEST_EFLAGS, &eflags);
        __vmread(GUEST_SS_SELECTOR, &ss);
        __vmread(GUEST_DS_SELECTOR, &ds);
        __vmread(GUEST_ES_SELECTOR, &es);
        __vmread(GUEST_FS_SELECTOR, &fs);
        __vmread(GUEST_GS_SELECTOR, &gs);
        __vmread(GUEST_CS_SELECTOR, &cs);
        context = "vmx guest";
    }
    else
#endif
    {
        eip = regs->eip;
        eflags = regs->eflags;

        if ( GUEST_MODE(regs) )
        {
            esp = regs->esp;
            ss  = regs->ss & 0xffff;
            ds  = regs->ds & 0xffff;
            es  = regs->es & 0xffff;
            fs  = regs->fs & 0xffff;
            gs  = regs->gs & 0xffff;
            cs  = regs->cs & 0xffff;
            context = "guest";
        }
        else
        {
            esp = (unsigned long)(&regs->esp);
            ss  = __HYPERVISOR_DS;
            ds  = __HYPERVISOR_DS;
            es  = __HYPERVISOR_DS;
            fs  = __HYPERVISOR_DS;
            gs  = __HYPERVISOR_DS;
            cs  = __HYPERVISOR_CS;
            
            context = "hypervisor";
        }
    }

    printk("CPU:    %d\nEIP:    %04lx:[<%08lx>]      \nEFLAGS: %08lx   "
           "CONTEXT: %s\n",
           smp_processor_id(), (unsigned long)0xffff & regs->cs,
           eip, eflags, context);
    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08lx\n",
           regs->esi, regs->edi, regs->ebp, esp);
    printk("ds: %04lx   es: %04lx   fs: %04lx   gs: %04lx   "
           "ss: %04lx   cs: %04lx\n",
           ds, es, fs, gs, ss, cs);

    show_stack((unsigned long *)&regs->esp);
    if ( GUEST_MODE(regs) )
        show_guest_stack();
} 

void show_page_walk(unsigned long addr)
{
    unsigned long page;

    if ( addr < PAGE_OFFSET )
        return;

    printk("Pagetable walk from %08lx:\n", addr);
    
    page = l2e_get_value(idle_pg_table[l2_table_offset(addr)]);
    printk(" L2 = %08lx %s\n", page, (page & _PAGE_PSE) ? "(4MB)" : "");
    if ( !(page & _PAGE_PRESENT) || (page & _PAGE_PSE) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l1_table_offset(addr)];
    printk("  L1 = %08lx\n", page);
}

#define DOUBLEFAULT_STACK_SIZE 1024
static struct tss_struct doublefault_tss;
static unsigned char doublefault_stack[DOUBLEFAULT_STACK_SIZE];

asmlinkage void do_double_fault(void)
{
    struct tss_struct *tss = &doublefault_tss;
    unsigned int cpu = ((tss->back_link>>3)-__FIRST_TSS_ENTRY)>>1;

    /* Disable the NMI watchdog. It's useless now. */
    watchdog_on = 0;

    console_force_unlock();

    /* Find information saved during fault and dump it to the console. */
    tss = &init_tss[cpu];
    printk("CPU:    %d\nEIP:    %04x:[<%08x>]      \nEFLAGS: %08x\n",
           cpu, tss->cs, tss->eip, tss->eflags);
    printk("CR3:    %08x\n", tss->__cr3);
    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           tss->eax, tss->ebx, tss->ecx, tss->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
           tss->esi, tss->edi, tss->ebp, tss->esp);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
           tss->ds, tss->es, tss->fs, tss->gs, tss->ss);
    printk("************************************\n");
    printk("CPU%d DOUBLE FAULT -- system shutdown\n", cpu);
    printk("System needs manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

BUILD_SMP_INTERRUPT(deferred_nmi, TRAP_deferred_nmi)
asmlinkage void smp_deferred_nmi(struct cpu_user_regs regs)
{
    asmlinkage void do_nmi(struct cpu_user_regs *, unsigned long);
    ack_APIC_irq();
    do_nmi(&regs, 0);
}

void __init percpu_traps_init(void)
{
    asmlinkage int hypercall(void);

    if ( smp_processor_id() != 0 )
        return;

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    /* The hypercall entry vector is only accessible from ring 1. */
    _set_gate(idt_table+HYPERCALL_VECTOR, 14, 1, &hypercall);

    set_intr_gate(TRAP_deferred_nmi, &deferred_nmi);

    /*
     * Make a separate task for double faults. This will get us debug output if
     * we blow the kernel stack.
     */
    struct tss_struct *tss = &doublefault_tss;
    memset(tss, 0, sizeof(*tss));
    tss->ds     = __HYPERVISOR_DS;
    tss->es     = __HYPERVISOR_DS;
    tss->ss     = __HYPERVISOR_DS;
    tss->esp    = (unsigned long)
        &doublefault_stack[DOUBLEFAULT_STACK_SIZE];
    tss->__cr3  = __pa(idle_pg_table);
    tss->cs     = __HYPERVISOR_CS;
    tss->eip    = (unsigned long)do_double_fault;
    tss->eflags = 2;
    tss->bitmap = IOBMP_INVALID_OFFSET;
    _set_tssldt_desc(gdt_table+__DOUBLEFAULT_TSS_ENTRY,
                     (unsigned long)tss, 235, 9);

    set_task_gate(TRAP_double_fault, __DOUBLEFAULT_TSS_ENTRY<<3);
}

long set_fast_trap(struct exec_domain *p, int idx)
{
    trap_info_t *ti;

    /* Index 0 is special: it disables fast traps. */
    if ( idx == 0 )
    {
        if ( p == current )
            CLEAR_FAST_TRAP(&p->arch);
        SET_DEFAULT_FAST_TRAP(&p->arch);
        return 0;
    }

    /* We only fast-trap vector 0x80 (used by Linux and the BSD variants). */
    if ( idx != 0x80 )
        return -1;

    ti = &p->arch.guest_context.trap_ctxt[idx];

    /*
     * We can't virtualise interrupt gates, as there's no way to get
     * the CPU to automatically clear the events_mask variable.
     */
    if ( TI_GET_IF(ti) )
        return -1;

    if ( p == current )
        CLEAR_FAST_TRAP(&p->arch);

    p->arch.guest_context.fast_trap_idx = idx;
    p->arch.fast_trap_desc.a = (ti->cs << 16) | (ti->address & 0xffff);
    p->arch.fast_trap_desc.b = 
        (ti->address & 0xffff0000) | 0x8f00 | (TI_GET_DPL(ti)&3)<<13;

    if ( p == current )
        SET_FAST_TRAP(&p->arch);

    return 0;
}


long do_set_fast_trap(int idx)
{
    return set_fast_trap(current, idx);
}

long do_set_callbacks(unsigned long event_selector,
                      unsigned long event_address,
                      unsigned long failsafe_selector,
                      unsigned long failsafe_address)
{
    struct exec_domain *d = current;

    if ( !VALID_CODESEL(event_selector) || !VALID_CODESEL(failsafe_selector) )
        return -EPERM;

    d->arch.guest_context.event_callback_cs     = event_selector;
    d->arch.guest_context.event_callback_eip    = event_address;
    d->arch.guest_context.failsafe_callback_cs  = failsafe_selector;
    d->arch.guest_context.failsafe_callback_eip = failsafe_address;

    return 0;
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
