
#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>

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
    printk("Guest RIP is %lx\n", ec->rip);

    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n       ");
            printk("%08lx ", *stack++);            
    }
    printk("\n");
    
}

void show_trace(unsigned long *rsp)
{
    unsigned long *stack, addr;
    int i;

    printk("Call Trace from RSP=%p: ", rsp);
    stack = rsp;
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

void show_stack(unsigned long *rsp)
{
    unsigned long *stack;
    int i;

    printk("Stack trace from RSP=%p:\n", rsp);

    stack = rsp;
    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n       ");
        if ( kernel_text_address(*stack) )
            printk("[%08lx] ", *stack++);
        else
            printk("%08lx ", *stack++);            
    }
    printk("\n");

    show_trace(rsp);
}

void show_registers(struct xen_regs *regs)
{
    printk("CPU:    %d\nEIP:    %04lx:[<%08lx>]      \nEFLAGS: %08lx\n",
           smp_processor_id(), 0xffff & regs->cs, regs->rip, regs->eflags);
    printk("rax: %08lx   rbx: %08lx   rcx: %08lx   rdx: %08lx\n",
           regs->rax, regs->rbx, regs->rcx, regs->rdx);
    printk("rsi: %08lx   rdi: %08lx   rbp: %08lx   rsp: %08lx   ss: %04x\n",
           regs->rsi, regs->rdi, regs->rbp, regs->rsp, regs->ss);
    printk("r8:  %08lx   r9:  %08lx   r10: %08lx   r11: %08lx\n",
           regs->r8,  regs->r9,  regs->r10, regs->r11);
    printk("r12: %08lx   r13: %08lx   r14: %08lx   r15: %08lx\n",
           regs->r12, regs->r13, regs->r14, regs->r15);

    show_stack((unsigned long *)regs->rsp);
} 

void __init doublefault_init(void)
{
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
