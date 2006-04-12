
#include <os.h>
#include <traps.h>
#include <hypervisor.h>
#include <mm.h>
#include <lib.h>
#include <sched.h>

/*
 * These are assembler stubs in entry.S.
 * They are the actual entry points for virtual exceptions.
 */
void divide_error(void);
void debug(void);
void int3(void);
void overflow(void);
void bounds(void);
void invalid_op(void);
void device_not_available(void);
void coprocessor_segment_overrun(void);
void invalid_TSS(void);
void segment_not_present(void);
void stack_segment(void);
void general_protection(void);
void page_fault(void);
void coprocessor_error(void);
void simd_coprocessor_error(void);
void alignment_check(void);
void spurious_interrupt_bug(void);
void machine_check(void);


void dump_regs(struct pt_regs *regs)
{
    printk("Thread: %s\n", current->name);
#ifdef __i386__    
    printk("EIP: %x, EFLAGS %x.\n", regs->eip, regs->eflags);
    printk("EBX: %08x ECX: %08x EDX: %08x\n",
	   regs->ebx, regs->ecx, regs->edx);
    printk("ESI: %08x EDI: %08x EBP: %08x EAX: %08x\n",
	   regs->esi, regs->edi, regs->ebp, regs->eax);
    printk("DS: %04x ES: %04x orig_eax: %08x, eip: %08x\n",
	   regs->xds, regs->xes, regs->orig_eax, regs->eip);
    printk("CS: %04x EFLAGS: %08x esp: %08x ss: %04x\n",
	   regs->xcs, regs->eflags, regs->esp, regs->xss);
#else
    printk("RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->rip);
    printk("\nRSP: %04lx:%016lx  EFLAGS: %08lx\n", 
           regs->ss, regs->rsp, regs->eflags);
    printk("RAX: %016lx RBX: %016lx RCX: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("RDX: %016lx RSI: %016lx RDI: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi); 
    printk("RBP: %016lx R08: %016lx R09: %016lx\n",
           regs->rbp, regs->r8, regs->r9); 
    printk("R10: %016lx R11: %016lx R12: %016lx\n",
           regs->r10, regs->r11, regs->r12); 
    printk("R13: %016lx R14: %016lx R15: %016lx\n",
           regs->r13, regs->r14, regs->r15); 
#endif
}

static void do_trap(int trapnr, char *str, struct pt_regs * regs, unsigned long error_code)
{
    printk("FATAL:  Unhandled Trap %d (%s), error code=0x%lx\n", trapnr, str, error_code);
    printk("Regs address %p\n", regs);
    dump_regs(regs);
    do_exit();
}

#define DO_ERROR(trapnr, str, name) \
void do_##name(struct pt_regs * regs, unsigned long error_code) \
{ \
	do_trap(trapnr, str, regs, error_code); \
}

#define DO_ERROR_INFO(trapnr, str, name, sicode, siaddr) \
void do_##name(struct pt_regs * regs, unsigned long error_code) \
{ \
	do_trap(trapnr, str, regs, error_code); \
}

DO_ERROR_INFO( 0, "divide error", divide_error, FPE_INTDIV, regs->eip)
DO_ERROR( 3, "int3", int3)
DO_ERROR( 4, "overflow", overflow)
DO_ERROR( 5, "bounds", bounds)
DO_ERROR_INFO( 6, "invalid operand", invalid_op, ILL_ILLOPN, regs->eip)
DO_ERROR( 7, "device not available", device_not_available)
DO_ERROR( 9, "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, "invalid TSS", invalid_TSS)
DO_ERROR(11, "segment not present", segment_not_present)
DO_ERROR(12, "stack segment", stack_segment)
DO_ERROR_INFO(17, "alignment check", alignment_check, BUS_ADRALN, 0)
DO_ERROR(18, "machine check", machine_check)

void page_walk(unsigned long virt_address)
{
        unsigned long *tab = (unsigned long *)start_info.pt_base;
        unsigned long addr = virt_address, page;
        printk("Pagetable walk from virt %lx, base %lx:\n", virt_address, start_info.pt_base);
    
#if defined(__x86_64__)
        page = tab[l4_table_offset(addr)];
        tab = to_virt(mfn_to_pfn(pte_to_mfn(page)) << PAGE_SHIFT);
        printk(" L4 = %p (%p)  [offset = %lx]\n", page, tab, l4_table_offset(addr));

        page = tab[l3_table_offset(addr)];
        tab = to_virt(mfn_to_pfn(pte_to_mfn(page)) << PAGE_SHIFT);
        printk("  L3 = %p (%p)  [offset = %lx]\n", page, tab, l3_table_offset(addr));
#endif
        page = tab[l2_table_offset(addr)];
        tab =  to_virt(mfn_to_pfn(pte_to_mfn(page)) << PAGE_SHIFT);
        printk("   L2 = %p (%p)  [offset = %lx]\n", page, tab, l2_table_offset(addr));
        
        page = tab[l1_table_offset(addr)];
        printk("    L1 = %p (%p)  [offset = %lx]\n", page, tab, l1_table_offset(addr));

}

#define read_cr2() \
        (HYPERVISOR_shared_info->vcpu_info[smp_processor_id()].arch.cr2)

void do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
    unsigned long addr = read_cr2();
    printk("Page fault at linear address %p, regs %p, code %lx\n", addr, regs,
	   error_code);
    dump_regs(regs);
    page_walk(addr);
    do_exit();
}

void do_general_protection(struct pt_regs *regs, long error_code)
{
#ifdef __i386__
    printk("GPF eip: %p, error_code=%lx\n", regs->eip, error_code);
#else    
    printk("GPF rip: %p, error_code=%lx\n", regs->rip, error_code);
#endif
    dump_regs(regs);
    do_exit();
}


void do_debug(struct pt_regs * regs)
{
    printk("Debug exception\n");
#define TF_MASK 0x100
    regs->eflags &= ~TF_MASK;
    dump_regs(regs);
    do_exit();
}

void do_coprocessor_error(struct pt_regs * regs)
{
    printk("Copro error\n");
    dump_regs(regs);
    do_exit();
}

void simd_math_error(void *eip)
{
    printk("SIMD error\n");
}

void do_simd_coprocessor_error(struct pt_regs * regs)
{
    printk("SIMD copro error\n");
}

void do_spurious_interrupt_bug(struct pt_regs * regs)
{
}

/*
 * Submit a virtual IDT to teh hypervisor. This consists of tuples
 * (interrupt vector, privilege ring, CS:EIP of handler).
 * The 'privilege ring' field specifies the least-privileged ring that
 * can trap to that vector using a software-interrupt instruction (INT).
 */
static trap_info_t trap_table[] = {
    {  0, 0, __KERNEL_CS, (unsigned long)divide_error                },
    {  1, 0, __KERNEL_CS, (unsigned long)debug                       },
    {  3, 3, __KERNEL_CS, (unsigned long)int3                        },
    {  4, 3, __KERNEL_CS, (unsigned long)overflow                    },
    {  5, 3, __KERNEL_CS, (unsigned long)bounds                      },
    {  6, 0, __KERNEL_CS, (unsigned long)invalid_op                  },
    {  7, 0, __KERNEL_CS, (unsigned long)device_not_available        },
    {  9, 0, __KERNEL_CS, (unsigned long)coprocessor_segment_overrun },
    { 10, 0, __KERNEL_CS, (unsigned long)invalid_TSS                 },
    { 11, 0, __KERNEL_CS, (unsigned long)segment_not_present         },
    { 12, 0, __KERNEL_CS, (unsigned long)stack_segment               },
    { 13, 0, __KERNEL_CS, (unsigned long)general_protection          },
    { 14, 0, __KERNEL_CS, (unsigned long)page_fault                  },
    { 15, 0, __KERNEL_CS, (unsigned long)spurious_interrupt_bug      },
    { 16, 0, __KERNEL_CS, (unsigned long)coprocessor_error           },
    { 17, 0, __KERNEL_CS, (unsigned long)alignment_check             },
    { 18, 0, __KERNEL_CS, (unsigned long)machine_check               },
    { 19, 0, __KERNEL_CS, (unsigned long)simd_coprocessor_error      },
    {  0, 0,           0, 0                           }
};
    


void trap_init(void)
{
    HYPERVISOR_set_trap_table(trap_table);    
}

