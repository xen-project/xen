
#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <asm/msr.h>

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
    execution_context_t *ec = get_execution_context();
    unsigned long *stack = (unsigned long *)ec->rsp;
    printk("Guest RIP is %lx\n   ", ec->rip);

    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n    ");
            printk("%p ", *stack++);
    }
    printk("\n");
    
}

void show_trace(unsigned long *rsp)
{
    unsigned long *stack, addr;
    int i;

    printk("Call Trace from RSP=%p:\n   ", rsp);
    stack = rsp;
    i = 0;
    while (((long) stack & (STACK_SIZE-1)) != 0) {
        addr = *stack++;
        if (kernel_text_address(addr)) {
            if (i && ((i % 6) == 0))
                printk("\n   ");
            printk("[<%p>] ", addr);
            i++;
        }
    }
    printk("\n");
}

void show_stack(unsigned long *rsp)
{
    unsigned long *stack;
    int i;

    printk("Stack trace from RSP=%p:\n    ", rsp);

    stack = rsp;
    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n    ");
        if ( kernel_text_address(*stack) )
            printk("[%p] ", *stack++);
        else
            printk("%p ", *stack++);            
    }
    printk("\n");

    show_trace(rsp);
}

void show_registers(struct xen_regs *regs)
{
    printk("CPU:    %d\nEIP:    %04lx:[<%p>]      \nEFLAGS: %p\n",
           smp_processor_id(), 0xffff & regs->cs, regs->rip, regs->eflags);
    printk("rax: %p   rbx: %p   rcx: %p   rdx: %p\n",
           regs->rax, regs->rbx, regs->rcx, regs->rdx);
    printk("rsi: %p   rdi: %p   rbp: %p   rsp: %p\n",
           regs->rsi, regs->rdi, regs->rbp, regs->rsp);
    printk("r8:  %p   r9:  %p   r10: %p   r11: %p\n",
           regs->r8,  regs->r9,  regs->r10, regs->r11);
    printk("r12: %p   r13: %p   r14: %p   r15: %p\n",
           regs->r12, regs->r13, regs->r14, regs->r15);

    show_stack((unsigned long *)regs->rsp);
} 

void show_page_walk(unsigned long addr)
{
    unsigned long page = read_cr3();
    
    printk("Pagetable walk from %p:\n", addr);

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l4_table_offset(addr)];
    printk(" L4 = %p\n", page);
    if ( !(page & _PAGE_PRESENT) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l3_table_offset(addr)];
    printk("  L3 = %p\n", page);
    if ( !(page & _PAGE_PRESENT) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l2_table_offset(addr)];
    printk("   L2 = %p %s\n", page, (page & _PAGE_PSE) ? "(2MB)" : "");
    if ( !(page & _PAGE_PRESENT) || (page & _PAGE_PSE) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l1_table_offset(addr)];
    printk("    L1 = %p\n", page);
}

asmlinkage void double_fault(void);
asmlinkage void do_double_fault(struct xen_regs *regs)
{
    /* Disable the NMI watchdog. It's useless now. */
    watchdog_on = 0;

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

asmlinkage void syscall_enter(void);
void __init percpu_traps_init(void)
{
    char *stack_bottom, *stack;
    int   cpu = smp_processor_id();

    stack_bottom = (char *)get_stack_bottom();
    stack        = (char *)((unsigned long)stack_bottom & ~(STACK_SIZE - 1));

    /* Double-fault handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[0] = (unsigned long)&stack[1024];
    set_intr_gate(TRAP_double_fault, &double_fault);
    idt_tables[cpu][TRAP_double_fault].a |= 1UL << 32; /* IST1 */

    /* NMI handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[1] = (unsigned long)&stack[2048];
    idt_tables[cpu][TRAP_nmi].a          |= 2UL << 32; /* IST2 */

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

    /* jmp syscall_enter */
    stack[14] = 0xe9;
    *(u32 *)&stack[15] = (char *)syscall_enter - &stack[19];

    /*
     * Trampoline for SYSCALL entry from compatibility mode.
     */

    /* Skip the long-mode entry trampoline. */
    stack = &stack[19];
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

    /* jmp syscall_enter */
    stack[14] = 0xe9;
    *(u32 *)&stack[15] = (char *)syscall_enter - &stack[19];

    /*
     * Common SYSCALL parameters.
     */

    wrmsr(MSR_STAR, 0, (FLAT_RING3_CS32<<16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, ~EF_IE, 0U); /* disable interrupts */
}

void *decode_reg(struct xen_regs *regs, u8 b)
{
    switch ( b )
    {
    case  0: return &regs->rax;
    case  1: return &regs->rcx;
    case  2: return &regs->rdx;
    case  3: return &regs->rbx;
    case  4: return &regs->rsp;
    case  5: return &regs->rbp;
    case  6: return &regs->rsi;
    case  7: return &regs->rdi;
    case  8: return &regs->r8;
    case  9: return &regs->r9;
    case 10: return &regs->r10;
    case 11: return &regs->r11;
    case 12: return &regs->r12;
    case 13: return &regs->r13;
    case 14: return &regs->r14;
    case 15: return &regs->r15;
    }

    return NULL;
}
