/******************************************************************************
 * arch/x86/traps.c
 * 
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/console.h>
#include <xen/shutdown.h>
#include <asm/regs.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/irq.h>
#include <xen/perfc.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/symbols.h>
#include <xen/iocap.h>
#include <xen/nmi.h>
#include <xen/version.h>
#include <xen/kexec.h>
#include <asm/paging.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/smp.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/debugger.h>
#include <asm/msr.h>
#include <asm/shared.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/vpt.h>

/*
 * opt_nmi: one of 'ignore', 'dom0', or 'fatal'.
 *  fatal:  Xen prints diagnostic message and then hangs.
 *  dom0:   The NMI is virtualised to DOM0.
 *  ignore: The NMI error is cleared and ignored.
 */
#ifdef NDEBUG
char opt_nmi[10] = "dom0";
#else
char opt_nmi[10] = "fatal";
#endif
string_param("nmi", opt_nmi);

/* Master table, used by all CPUs on x86/64, and by CPU0 on x86/32.*/
idt_entry_t idt_table[IDT_ENTRIES];

#define DECLARE_TRAP_HANDLER(_name)                     \
asmlinkage void _name(void);                            \
asmlinkage int do_ ## _name(struct cpu_user_regs *regs)

asmlinkage void nmi(void);
DECLARE_TRAP_HANDLER(divide_error);
DECLARE_TRAP_HANDLER(debug);
DECLARE_TRAP_HANDLER(int3);
DECLARE_TRAP_HANDLER(overflow);
DECLARE_TRAP_HANDLER(bounds);
DECLARE_TRAP_HANDLER(invalid_op);
DECLARE_TRAP_HANDLER(device_not_available);
DECLARE_TRAP_HANDLER(coprocessor_segment_overrun);
DECLARE_TRAP_HANDLER(invalid_TSS);
DECLARE_TRAP_HANDLER(segment_not_present);
DECLARE_TRAP_HANDLER(stack_segment);
DECLARE_TRAP_HANDLER(general_protection);
DECLARE_TRAP_HANDLER(page_fault);
DECLARE_TRAP_HANDLER(coprocessor_error);
DECLARE_TRAP_HANDLER(simd_coprocessor_error);
DECLARE_TRAP_HANDLER(alignment_check);
DECLARE_TRAP_HANDLER(spurious_interrupt_bug);
DECLARE_TRAP_HANDLER(machine_check);

long do_set_debugreg(int reg, unsigned long value);
unsigned long do_get_debugreg(int reg);

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

#ifdef CONFIG_X86_32
#define stack_words_per_line 8
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)&regs->esp)
#else
#define stack_words_per_line 4
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)regs->rsp)
#endif

static void show_guest_stack(struct cpu_user_regs *regs)
{
    int i;
    unsigned long *stack, addr;

    if ( is_hvm_vcpu(current) )
        return;

    if ( IS_COMPAT(container_of(regs, struct cpu_info, guest_cpu_user_regs)->current_vcpu->domain) )
    {
        compat_show_guest_stack(regs, debug_stack_lines);
        return;
    }

    if ( vm86_mode(regs) )
    {
        stack = (unsigned long *)((regs->ss << 4) + (regs->esp & 0xffff));
        printk("Guest stack trace from ss:sp = %04x:%04x (VM86)\n  ",
               regs->ss, (uint16_t)(regs->esp & 0xffff));
    }
    else
    {
        stack = (unsigned long *)regs->esp;
        printk("Guest stack trace from "__OP"sp=%p:\n  ", stack);
    }

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line); i++ )
    {
        if ( ((long)stack & (STACK_SIZE-BYTES_PER_LONG)) == 0 )
            break;
        if ( get_user(addr, stack) )
        {
            if ( i != 0 )
                printk("\n    ");
            printk("Fault while accessing guest memory.");
            i = 1;
            break;
        }
        if ( (i != 0) && ((i % stack_words_per_line) == 0) )
            printk("\n  ");
        printk(" %p", _p(addr));
        stack++;
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

#ifdef NDEBUG

static void show_trace(struct cpu_user_regs *regs)
{
    unsigned long *stack = ESP_BEFORE_EXCEPTION(regs), addr;

    printk("Xen call trace:\n   ");

    printk("[<%p>]", _p(regs->eip));
    print_symbol(" %s\n   ", regs->eip);

    while ( ((long)stack & (STACK_SIZE-BYTES_PER_LONG)) != 0 )
    {
        addr = *stack++;
        if ( is_kernel_text(addr) || is_kernel_inittext(addr) )
        {
            printk("[<%p>]", _p(addr));
            print_symbol(" %s\n   ", addr);
        }
    }

    printk("\n");
}

#else

static void show_trace(struct cpu_user_regs *regs)
{
    unsigned long *frame, next, addr, low, high;

    printk("Xen call trace:\n   ");

    printk("[<%p>]", _p(regs->eip));
    print_symbol(" %s\n   ", regs->eip);

    /* Bounds for range of valid frame pointer. */
    low  = (unsigned long)(ESP_BEFORE_EXCEPTION(regs) - 2);
    high = (low & ~(STACK_SIZE - 1)) + 
        (STACK_SIZE - sizeof(struct cpu_info) - 2*sizeof(unsigned long));

    /* The initial frame pointer. */
    next = regs->ebp;

    for ( ; ; )
    {
        /* Valid frame pointer? */
        if ( (next < low) || (next >= high) )
        {
            /*
             * Exception stack frames have a different layout, denoted by an
             * inverted frame pointer.
             */
            next = ~next;
            if ( (next < low) || (next >= high) )
                break;
            frame = (unsigned long *)next;
            next  = frame[0];
            addr  = frame[(offsetof(struct cpu_user_regs, eip) -
                           offsetof(struct cpu_user_regs, ebp))
                         / BYTES_PER_LONG];
        }
        else
        {
            /* Ordinary stack frame. */
            frame = (unsigned long *)next;
            next  = frame[0];
            addr  = frame[1];
        }

        printk("[<%p>]", _p(addr));
        print_symbol(" %s\n   ", addr);

        low = (unsigned long)&frame[2];
    }

    printk("\n");
}

#endif

void show_stack(struct cpu_user_regs *regs)
{
    unsigned long *stack = ESP_BEFORE_EXCEPTION(regs), addr;
    int i;

    if ( guest_mode(regs) )
        return show_guest_stack(regs);

    printk("Xen stack trace from "__OP"sp=%p:\n  ", stack);

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line); i++ )
    {
        if ( ((long)stack & (STACK_SIZE-BYTES_PER_LONG)) == 0 )
            break;
        if ( (i != 0) && ((i % stack_words_per_line) == 0) )
            printk("\n  ");
        addr = *stack++;
        printk(" %p", _p(addr));
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");

    show_trace(regs);
}

void show_xen_trace()
{
    struct cpu_user_regs regs;
#ifdef __x86_64
    __asm__("movq %%rsp,%0" : "=m" (regs.rsp));
    __asm__("movq %%rbp,%0" : "=m" (regs.rbp));
    __asm__("leaq 0(%%rip),%0" : "=a" (regs.rip));
#else
    __asm__("movl %%esp,%0" : "=m" (regs.esp));
    __asm__("movl %%ebp,%0" : "=m" (regs.ebp));
    __asm__("call 1f; 1: popl %0" : "=a" (regs.eip));
#endif
    show_trace(&regs);
}

void show_stack_overflow(unsigned long esp)
{
#ifdef MEMORY_GUARD
    unsigned long esp_top;
    unsigned long *stack, addr;

    esp_top = (esp | (STACK_SIZE - 1)) - DEBUG_STACK_SIZE;

    /* Trigger overflow trace if %esp is within 512 bytes of the guard page. */
    if ( ((unsigned long)(esp - esp_top) > 512) &&
         ((unsigned long)(esp_top - esp) > 512) )
        return;

    if ( esp < esp_top )
        esp = esp_top;

    printk("Xen stack overflow:\n   ");

    stack = (unsigned long *)esp;
    while ( ((long)stack & (STACK_SIZE-BYTES_PER_LONG)) != 0 )
    {
        addr = *stack++;
        if ( is_kernel_text(addr) || is_kernel_inittext(addr) )
        {
            printk("%p: [<%p>]", stack, _p(addr));
            print_symbol(" %s\n   ", addr);
        }
    }

    printk("\n");
#endif
}

void show_execution_state(struct cpu_user_regs *regs)
{
    show_registers(regs);
    show_stack(regs);
}

char *trapstr(int trapnr)
{
    static char *strings[] = { 
        "divide error", "debug", "nmi", "bkpt", "overflow", "bounds", 
        "invalid opcode", "device not available", "double fault", 
        "coprocessor segment", "invalid tss", "segment not found", 
        "stack error", "general protection fault", "page fault", 
        "spurious interrupt", "coprocessor error", "alignment check", 
        "machine check", "simd error"
    };

    if ( (trapnr < 0) || (trapnr >= ARRAY_SIZE(strings)) )
        return "???";

    return strings[trapnr];
}

/*
 * This is called for faults at very unexpected times (e.g., when interrupts
 * are disabled). In such situations we can't do much that is safe. We try to
 * print out some tracing and then we just spin.
 */
asmlinkage void fatal_trap(int trapnr, struct cpu_user_regs *regs)
{
    watchdog_disable();
    console_start_sync();

    show_execution_state(regs);

    if ( trapnr == TRAP_page_fault )
    {
        unsigned long cr2 = read_cr2();
        printk("Faulting linear address: %p\n", _p(cr2));
        show_page_walk(cr2);
    }

    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x] %s\n",
          trapnr, trapstr(trapnr), regs->error_code,
          (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
}

static int do_guest_trap(
    int trapnr, const struct cpu_user_regs *regs, int use_error_code)
{
    struct vcpu *v = current;
    struct trap_bounce *tb;
    const struct trap_info *ti;

    tb = &v->arch.trap_bounce;
    ti = &v->arch.guest_context.trap_ctxt[trapnr];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( use_error_code )
    {
        tb->flags |= TBF_EXCEPTION_ERRCODE;
        tb->error_code = regs->error_code;
    }

    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;

    if ( unlikely(null_trap_bounce(v, tb)) )
        gdprintk(XENLOG_WARNING, "Unhandled %s fault/trap [#%d] in "
                 "domain %d on VCPU %d [ec=%04x]\n",
                 trapstr(trapnr), trapnr, v->domain->domain_id, v->vcpu_id,
                 regs->error_code);

    return 0;
}

static inline int do_trap(
    int trapnr, struct cpu_user_regs *regs, int use_error_code)
{
    unsigned long fixup;

    DEBUGGER_trap_entry(trapnr, regs);

    if ( guest_mode(regs) )
        return do_guest_trap(trapnr, regs, use_error_code);

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        dprintk(XENLOG_ERR, "Trap %d: %p -> %p\n",
                trapnr, _p(regs->eip), _p(fixup));
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(trapnr, regs);

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x]\n",
          trapnr, trapstr(trapnr), regs->error_code);
    return 0;
}

#define DO_ERROR_NOCODE(trapnr, name)                   \
asmlinkage int do_##name(struct cpu_user_regs *regs)    \
{                                                       \
    return do_trap(trapnr, regs, 0);                    \
}

#define DO_ERROR(trapnr, name)                          \
asmlinkage int do_##name(struct cpu_user_regs *regs)    \
{                                                       \
    return do_trap(trapnr, regs, 1);                    \
}

DO_ERROR_NOCODE(TRAP_divide_error,    divide_error)
DO_ERROR_NOCODE(TRAP_overflow,        overflow)
DO_ERROR_NOCODE(TRAP_bounds,          bounds)
DO_ERROR_NOCODE(TRAP_copro_seg,       coprocessor_segment_overrun)
DO_ERROR(       TRAP_invalid_tss,     invalid_TSS)
DO_ERROR(       TRAP_no_segment,      segment_not_present)
DO_ERROR(       TRAP_stack_error,     stack_segment)
DO_ERROR_NOCODE(TRAP_copro_error,     coprocessor_error)
DO_ERROR(       TRAP_alignment_check, alignment_check)
DO_ERROR_NOCODE(TRAP_simd_error,      simd_coprocessor_error)

int rdmsr_hypervisor_regs(
    uint32_t idx, uint32_t *eax, uint32_t *edx)
{
    idx -= 0x40000000;
    if ( idx > 0 )
        return 0;

    *eax = *edx = 0;
    return 1;
}

int wrmsr_hypervisor_regs(
    uint32_t idx, uint32_t eax, uint32_t edx)
{
    struct domain *d = current->domain;

    idx -= 0x40000000;
    if ( idx > 0 )
        return 0;

    switch ( idx )
    {
    case 0:
    {
        void         *hypercall_page;
        unsigned long mfn;
        unsigned long gmfn = ((unsigned long)edx << 20) | (eax >> 12);
        unsigned int  idx  = eax & 0xfff;

        if ( idx > 0 )
        {
            gdprintk(XENLOG_WARNING,
                    "Dom%d: Out of range index %u to MSR %08x\n",
                    d->domain_id, idx, 0x40000000);
            return 0;
        }

        mfn = gmfn_to_mfn(d, gmfn);

        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
        {
            gdprintk(XENLOG_WARNING,
                    "Dom%d: Bad GMFN %lx (MFN %lx) to MSR %08x\n",
                    d->domain_id, gmfn, mfn, 0x40000000);
            return 0;
        }

        hypercall_page = map_domain_page(mfn);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(mfn_to_page(mfn));
        break;
    }

    default:
        BUG();
    }

    return 1;
}

int cpuid_hypervisor_leaves(
    uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    idx -= 0x40000000;
    if ( idx > 2 )
        return 0;

    switch ( idx )
    {
    case 0:
        *eax = 0x40000002; /* Largest leaf        */
        *ebx = 0x566e6558; /* Signature 1: "XenV" */
        *ecx = 0x65584d4d; /* Signature 2: "MMXe" */
        *edx = 0x4d4d566e; /* Signature 3: "nVMM" */
        break;

    case 1:
        *eax = (xen_major_version() << 16) | xen_minor_version();
        *ebx = 0;          /* Reserved */
        *ecx = 0;          /* Reserved */
        *edx = 0;          /* Reserved */
        break;

    case 2:
        *eax = 1;          /* Number of hypercall-transfer pages */
        *ebx = 0x40000000; /* MSR base address */
        *ecx = 0;          /* Features 1 */
        *edx = 0;          /* Features 2 */
        break;

    default:
        BUG();
    }

    return 1;
}

static int emulate_forced_invalid_op(struct cpu_user_regs *regs)
{
    char sig[5], instr[2];
    uint32_t a, b, c, d;
    unsigned long eip, rc;

    a = regs->eax;
    b = regs->ebx;
    c = regs->ecx;
    d = regs->edx;
    eip = regs->eip;

    /* Check for forced emulation signature: ud2 ; .ascii "xen". */
    if ( (rc = copy_from_user(sig, (char *)eip, sizeof(sig))) != 0 )
    {
        propagate_page_fault(eip + sizeof(sig) - rc, 0);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(sig, "\xf\xbxen", sizeof(sig)) )
        return 0;
    eip += sizeof(sig);

    /* We only emulate CPUID. */
    if ( ( rc = copy_from_user(instr, (char *)eip, sizeof(instr))) != 0 )
    {
        propagate_page_fault(eip + sizeof(instr) - rc, 0);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(instr, "\xf\xa2", sizeof(instr)) )
        return 0;
    eip += sizeof(instr);

    __asm__ ( 
        "cpuid"
        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
        : "0" (a), "1" (b), "2" (c), "3" (d) );

    if ( regs->eax == 1 )
    {
        /* Modify Feature Information. */
        clear_bit(X86_FEATURE_VME, &d);
        clear_bit(X86_FEATURE_DE,  &d);
        clear_bit(X86_FEATURE_PSE, &d);
        clear_bit(X86_FEATURE_PGE, &d);
        if ( !supervisor_mode_kernel )
            clear_bit(X86_FEATURE_SEP, &d);
        if ( !IS_PRIV(current->domain) )
            clear_bit(X86_FEATURE_MTRR, &d);
    }
    else if ( regs->eax == 0x80000001 )
    {
        /* Modify Feature Information. */
        clear_bit(X86_FEATURE_RDTSCP % 32, &d);
    }
    else
    {
        (void)cpuid_hypervisor_leaves(regs->eax, &a, &b, &c, &d);
    }

    regs->eax = a;
    regs->ebx = b;
    regs->ecx = c;
    regs->edx = d;
    regs->eip = eip;

    return EXCRET_fault_fixed;
}

asmlinkage int do_invalid_op(struct cpu_user_regs *regs)
{
    int rc;

    DEBUGGER_trap_entry(TRAP_invalid_op, regs);

    if ( unlikely(!guest_mode(regs)) )
    {
        struct bug_frame bug;
        if ( is_kernel(regs->eip) &&
             (__copy_from_user(&bug, (char *)regs->eip, sizeof(bug)) == 0) &&
             (memcmp(bug.ud2, "\xf\xb",    sizeof(bug.ud2)) == 0) &&
             (memcmp(bug.mov, BUG_MOV_STR, sizeof(bug.mov)) == 0) &&
             (bug.ret == 0xc2) )
        {
            char *filename = (char *)bug.filename;
            unsigned int line = bug.line & 0x7fff;
            int is_bug = !(bug.line & 0x8000);
            printk("Xen %s at %.50s:%d\n",
                   is_bug ? "BUG" : "State Dump", filename, line);
            if ( !is_bug )
            {
                show_execution_state(regs);
                regs->eip += sizeof(bug);
                return EXCRET_fault_fixed;
            }
        }
        DEBUGGER_trap_fatal(TRAP_invalid_op, regs);
        show_execution_state(regs);
        panic("FATAL TRAP: vector = %d (invalid opcode)\n", TRAP_invalid_op);
    }

    if ( (rc = emulate_forced_invalid_op(regs)) != 0 )
        return rc;

    return do_guest_trap(TRAP_invalid_op, regs, 0);
}

asmlinkage int do_int3(struct cpu_user_regs *regs)
{
    DEBUGGER_trap_entry(TRAP_int3, regs);

    if ( !guest_mode(regs) )
    {
        DEBUGGER_trap_fatal(TRAP_int3, regs);
        show_execution_state(regs);
        panic("FATAL TRAP: vector = 3 (Int3)\n");
    } 

    return do_guest_trap(TRAP_int3, regs, 0);
}

asmlinkage int do_machine_check(struct cpu_user_regs *regs)
{
    fatal_trap(TRAP_machine_check, regs);
    return 0;
}

void propagate_page_fault(unsigned long addr, u16 error_code)
{
    struct trap_info *ti;
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.trap_bounce;

    v->arch.guest_context.ctrlreg[2] = addr;
    arch_set_cr2(v, addr);

    /* Re-set error_code.user flag appropriately for the guest. */
    error_code &= ~PFEC_user_mode;
    if ( !guest_kernel_mode(v, guest_cpu_user_regs()) )
        error_code |= PFEC_user_mode;

    ti = &v->arch.guest_context.trap_ctxt[TRAP_page_fault];
    tb->flags = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;
    if ( unlikely(null_trap_bounce(v, tb)) )
    {
        printk("Unhandled page fault in domain %d on VCPU %d (ec=%04X)\n",
               v->domain->domain_id, v->vcpu_id, error_code);
        show_page_walk(addr);
    }
}

static int handle_gdt_ldt_mapping_fault(
    unsigned long offset, struct cpu_user_regs *regs)
{
    /* Which vcpu's area did we fault in, and is it in the ldt sub-area? */
    unsigned int is_ldt_area = (offset >> (GDT_LDT_VCPU_VA_SHIFT-1)) & 1;
    unsigned int vcpu_area   = (offset >> GDT_LDT_VCPU_VA_SHIFT);

    /* Should never fault in another vcpu's area. */
    BUG_ON(vcpu_area != current->vcpu_id);

    /* Byte offset within the gdt/ldt sub-area. */
    offset &= (1UL << (GDT_LDT_VCPU_VA_SHIFT-1)) - 1UL;

    if ( likely(is_ldt_area) )
    {
        /* LDT fault: Copy a mapping from the guest's LDT, if it is valid. */
        if ( unlikely(map_ldt_shadow_page(offset >> PAGE_SHIFT) == 0) )
        {
            /* In hypervisor mode? Leave it to the #PF handler to fix up. */
            if ( !guest_mode(regs) )
                return 0;
            /* In guest mode? Propagate #PF to guest, with adjusted %cr2. */
            propagate_page_fault(
                current->arch.guest_context.ldt_base + offset,
                regs->error_code);
        }
    }
    else
    {
        /* GDT fault: handle the fault as #GP(selector). */
        regs->error_code = (u16)offset & ~7;
        (void)do_general_protection(regs);
    }

    return EXCRET_fault_fixed;
}

#ifdef HYPERVISOR_VIRT_END
#define IN_HYPERVISOR_RANGE(va) \
    (((va) >= HYPERVISOR_VIRT_START) && ((va) < HYPERVISOR_VIRT_END))
#else
#define IN_HYPERVISOR_RANGE(va) \
    (((va) >= HYPERVISOR_VIRT_START))
#endif

static int __spurious_page_fault(
    unsigned long addr, struct cpu_user_regs *regs)
{
    unsigned long mfn, cr3 = read_cr3();
#if CONFIG_PAGING_LEVELS >= 4
    l4_pgentry_t l4e, *l4t;
#endif
#if CONFIG_PAGING_LEVELS >= 3
    l3_pgentry_t l3e, *l3t;
#endif
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;
    unsigned int required_flags, disallowed_flags;

    /* Reserved bit violations are never spurious faults. */
    if ( regs->error_code & PFEC_reserved_bit )
        return 0;

    required_flags  = _PAGE_PRESENT;
    if ( regs->error_code & PFEC_write_access )
        required_flags |= _PAGE_RW;
    if ( regs->error_code & PFEC_user_mode )
        required_flags |= _PAGE_USER;

    disallowed_flags = 0;
    if ( regs->error_code & PFEC_insn_fetch )
        disallowed_flags |= _PAGE_NX;

    mfn = cr3 >> PAGE_SHIFT;

#if CONFIG_PAGING_LEVELS >= 4
    l4t = map_domain_page(mfn);
    l4e = l4e_read_atomic(&l4t[l4_table_offset(addr)]);
    mfn = l4e_get_pfn(l4e);
    unmap_domain_page(l4t);
    if ( ((l4e_get_flags(l4e) & required_flags) != required_flags) ||
         (l4e_get_flags(l4e) & disallowed_flags) )
        return 0;
#endif

#if CONFIG_PAGING_LEVELS >= 3
    l3t  = map_domain_page(mfn);
#ifdef CONFIG_X86_PAE
    l3t += (cr3 & 0xFE0UL) >> 3;
#endif
    l3e = l3e_read_atomic(&l3t[l3_table_offset(addr)]);
    mfn = l3e_get_pfn(l3e);
    unmap_domain_page(l3t);
#ifdef CONFIG_X86_PAE
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return 0;
#else
    if ( ((l3e_get_flags(l3e) & required_flags) != required_flags) ||
         (l3e_get_flags(l3e) & disallowed_flags) )
        return 0;
#endif
#endif

    l2t = map_domain_page(mfn);
    l2e = l2e_read_atomic(&l2t[l2_table_offset(addr)]);
    mfn = l2e_get_pfn(l2e);
    unmap_domain_page(l2t);
    if ( ((l2e_get_flags(l2e) & required_flags) != required_flags) ||
         (l2e_get_flags(l2e) & disallowed_flags) )
        return 0;
    if ( l2e_get_flags(l2e) & _PAGE_PSE )
    {
        l1e = l1e_empty(); /* define before use in debug tracing */
        goto spurious;
    }

    l1t = map_domain_page(mfn);
    l1e = l1e_read_atomic(&l1t[l1_table_offset(addr)]);
    mfn = l1e_get_pfn(l1e);
    unmap_domain_page(l1t);
    if ( ((l1e_get_flags(l1e) & required_flags) != required_flags) ||
         (l1e_get_flags(l1e) & disallowed_flags) )
        return 0;

 spurious:
    dprintk(XENLOG_WARNING, "Spurious fault in domain %u:%u "
            "at addr %lx, e/c %04x\n",
            current->domain->domain_id, current->vcpu_id,
            addr, regs->error_code);
#if CONFIG_PAGING_LEVELS >= 4
    dprintk(XENLOG_WARNING, " l4e = %"PRIpte"\n", l4e_get_intpte(l4e));
#endif
#if CONFIG_PAGING_LEVELS >= 3
    dprintk(XENLOG_WARNING, " l3e = %"PRIpte"\n", l3e_get_intpte(l3e));
#endif
    dprintk(XENLOG_WARNING, " l2e = %"PRIpte"\n", l2e_get_intpte(l2e));
    dprintk(XENLOG_WARNING, " l1e = %"PRIpte"\n", l1e_get_intpte(l1e));
#ifndef NDEBUG
    show_registers(regs);
#endif
    return 1;
}

static int spurious_page_fault(
    unsigned long addr, struct cpu_user_regs *regs)
{
    unsigned long flags;
    int           is_spurious;

    /*
     * Disabling interrupts prevents TLB flushing, and hence prevents
     * page tables from becoming invalid under our feet during the walk.
     */
    local_irq_save(flags);
    is_spurious = __spurious_page_fault(addr, regs);
    local_irq_restore(flags);

    return is_spurious;
}

static int fixup_page_fault(unsigned long addr, struct cpu_user_regs *regs)
{
    struct vcpu   *v = current;
    struct domain *d = v->domain;

    if ( unlikely(IN_HYPERVISOR_RANGE(addr)) )
    {
        if ( paging_mode_external(d) && guest_mode(regs) )
            return paging_fault(addr, regs);
        if ( (addr >= GDT_LDT_VIRT_START) && (addr < GDT_LDT_VIRT_END) )
            return handle_gdt_ldt_mapping_fault(
                addr - GDT_LDT_VIRT_START, regs);
        return 0;
    }

    ASSERT(!in_irq());
    ASSERT(regs->eflags & X86_EFLAGS_IF);

    if ( VM_ASSIST(d, VMASST_TYPE_writable_pagetables) &&
         guest_kernel_mode(v, regs) &&
         /* Do not check if access-protection fault since the page may 
            legitimately be not present in shadow page tables */
         ((regs->error_code & PFEC_write_access) == PFEC_write_access) &&
         ptwr_do_page_fault(v, addr, regs) )
        return EXCRET_fault_fixed;

    if ( paging_mode_enabled(d) )
        return paging_fault(addr, regs);

    return 0;
}

/*
 * #PF error code:
 *  Bit 0: Protection violation (=1) ; Page not present (=0)
 *  Bit 1: Write access
 *  Bit 2: User mode (=1) ; Supervisor mode (=0)
 *  Bit 3: Reserved bit violation
 *  Bit 4: Instruction fetch
 */
asmlinkage int do_page_fault(struct cpu_user_regs *regs)
{
    unsigned long addr, fixup;
    int rc;

    addr = read_cr2();

    DEBUGGER_trap_entry(TRAP_page_fault, regs);

    perfc_incrc(page_faults);

    if ( unlikely((rc = fixup_page_fault(addr, regs)) != 0) )
        return rc;

    if ( unlikely(!guest_mode(regs)) )
    {
        if ( spurious_page_fault(addr, regs) )
            return EXCRET_not_a_fault;

        if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
        {
            perfc_incrc(copy_user_faults);
            regs->eip = fixup;
            return 0;
        }

        DEBUGGER_trap_fatal(TRAP_page_fault, regs);

        show_execution_state(regs);
        show_page_walk(addr);
        panic("FATAL PAGE FAULT\n"
              "[error_code=%04x]\n"
              "Faulting linear address: %p\n",
              regs->error_code, _p(addr));
    }

    propagate_page_fault(addr, regs->error_code);
    return 0;
}

/*
 * Early handler to deal with spurious page faults. For example, consider a 
 * routine that uses a mapping immediately after installing it (making it 
 * present). The CPU may speculatively execute the memory access before 
 * executing the PTE write. The instruction will then be marked to cause a 
 * page fault when it is retired, despite the fact that the PTE is present and 
 * correct at that point in time.
 */
asmlinkage int do_early_page_fault(struct cpu_user_regs *regs)
{
    static int stuck;
    static unsigned long prev_eip, prev_cr2;
    unsigned long cr2 = read_cr2();

    BUG_ON(smp_processor_id() != 0);

    if ( (regs->eip != prev_eip) || (cr2 != prev_cr2) )
    {
        prev_eip = regs->eip;
        prev_cr2 = cr2;
        stuck    = 0;
        return EXCRET_not_a_fault;
    }

    if ( stuck++ == 1000 )
        panic("Early fatal page fault at %04x:%p (cr2=%p, ec=%04x)\n", 
              regs->cs, _p(regs->eip), _p(cr2), regs->error_code);

    return EXCRET_not_a_fault;
}

long do_fpu_taskswitch(int set)
{
    struct vcpu *v = current;

    if ( set )
    {
        v->arch.guest_context.ctrlreg[0] |= X86_CR0_TS;
        stts();
    }
    else
    {
        v->arch.guest_context.ctrlreg[0] &= ~X86_CR0_TS;
        if ( test_bit(_VCPUF_fpu_dirtied, &v->vcpu_flags) )
            clts();
    }

    return 0;
}

static int read_descriptor(unsigned int sel,
                           const struct vcpu *v,
                           const struct cpu_user_regs * regs,
                           unsigned long *base,
                           unsigned long *limit,
                           unsigned int *ar,
                           unsigned int vm86attr)
{
    struct desc_struct desc;

    if ( !vm86_mode(regs) )
    {
        if ( sel < 4)
            desc.b = desc.a = 0;
        else if ( __get_user(desc,
                        (const struct desc_struct *)(!(sel & 4)
                                                     ? GDT_VIRT_START(v)
                                                     : LDT_VIRT_START(v))
                        + (sel >> 3)) )
            return 0;
        if ( !(vm86attr & _SEGMENT_CODE) )
            desc.b &= ~_SEGMENT_L;
    }
    else
    {
        desc.a = (sel << 20) | 0xffff;
        desc.b = vm86attr | (sel >> 12);
    }

    *ar = desc.b & 0x00f0ff00;
    if ( !(desc.b & _SEGMENT_L) )
    {
        *base = (desc.a >> 16) + ((desc.b & 0xff) << 16) + (desc.b & 0xff000000);
        *limit = (desc.a & 0xffff) | (desc.b & 0x000f0000);
        if ( desc.b & _SEGMENT_G )
            *limit = ((*limit + 1) << 12) - 1;
#ifndef NDEBUG
        if ( !vm86_mode(regs) && sel > 3 )
        {
            unsigned int a, l;
            unsigned char valid;

            __asm__("larl %2, %0\n\tsetz %1" : "=r" (a), "=rm" (valid) : "rm" (sel));
            BUG_ON(valid && (a & 0x00f0ff00) != *ar);
            __asm__("lsll %2, %0\n\tsetz %1" : "=r" (l), "=rm" (valid) : "rm" (sel));
            BUG_ON(valid && l != *limit);
        }
#endif
    }
    else
    {
        *base = 0UL;
        *limit = ~0UL;
    }

    return 1;
}

/* Has the guest requested sufficient permission for this I/O access? */
static inline int guest_io_okay(
    unsigned int port, unsigned int bytes,
    struct vcpu *v, struct cpu_user_regs *regs)
{
#if defined(__x86_64__)
    /* If in user mode, switch to kernel mode just to read I/O bitmap. */
    int user_mode = !(v->arch.flags & TF_kernel_mode);
#define TOGGLE_MODE() if ( user_mode ) toggle_guest_mode(v)
#elif defined(__i386__)
#define TOGGLE_MODE() ((void)0)
#endif

    if ( !vm86_mode(regs) &&
         (v->arch.iopl >= (guest_kernel_mode(v, regs) ? 1 : 3)) )
        return 1;

    if ( v->arch.iobmp_limit > (port + bytes) )
    {
        union { uint8_t bytes[2]; uint16_t mask; } x;

        /*
         * Grab permission bytes from guest space. Inaccessible bytes are
         * read as 0xff (no access allowed).
         */
        TOGGLE_MODE();
        switch ( __copy_from_guest_offset(&x.bytes[0], v->arch.iobmp,
                                          port>>3, 2) )
        {
        default: x.bytes[0] = ~0;
        case 1:  x.bytes[1] = ~0;
        case 0:  break;
        }
        TOGGLE_MODE();

        if ( (x.mask & (((1<<bytes)-1) << (port&7))) == 0 )
            return 1;
    }

    return 0;
}

/* Has the administrator granted sufficient permission for this I/O access? */
static inline int admin_io_okay(
    unsigned int port, unsigned int bytes,
    struct vcpu *v, struct cpu_user_regs *regs)
{
    return ioports_access_permitted(v->domain, port, port + bytes - 1);
}

#define guest_inb_okay(_p, _d, _r) admin_io_okay(_p, 1, _d, _r)
#define guest_inw_okay(_p, _d, _r) admin_io_okay(_p, 2, _d, _r)
#define guest_inl_okay(_p, _d, _r) admin_io_okay(_p, 4, _d, _r)
#define guest_outb_okay(_p, _d, _r) admin_io_okay(_p, 1, _d, _r)
#define guest_outw_okay(_p, _d, _r) admin_io_okay(_p, 2, _d, _r)
#define guest_outl_okay(_p, _d, _r) admin_io_okay(_p, 4, _d, _r)

/* I/O emulation support. Helper routines for, and type of, the stack stub.*/
void host_to_guest_gpr_switch(struct cpu_user_regs *)
    __attribute__((__regparm__(1)));
unsigned long guest_to_host_gpr_switch(unsigned long)
    __attribute__((__regparm__(1)));

/* Instruction fetch with error handling. */
#define insn_fetch(type, base, eip, limit)                                  \
({  unsigned long _rc, _ptr = (base) + (eip);                               \
    type _x;                                                                \
    if ( (limit) < sizeof(_x) - 1 || (eip) > (limit) - (sizeof(_x) - 1) )   \
        goto fail;                                                          \
    if ( (_rc = copy_from_user(&_x, (type *)_ptr, sizeof(_x))) != 0 )       \
    {                                                                       \
        propagate_page_fault(_ptr + sizeof(_x) - _rc, 0);                   \
        return EXCRET_fault_fixed;                                          \
    }                                                                       \
    (eip) += sizeof(_x); _x; })

#if defined(CONFIG_X86_32)
# define read_sreg(regs, sr) ((regs)->sr)
#elif defined(CONFIG_X86_64)
# define read_sreg(regs, sr) read_segment_register(sr)
#endif

static int emulate_privileged_op(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    unsigned long *reg, eip = regs->eip, res;
    u8 opcode, modrm_reg = 0, modrm_rm = 0, rep_prefix = 0, lock = 0, rex = 0;
    enum { lm_seg_none, lm_seg_fs, lm_seg_gs } lm_ovr = lm_seg_none;
    unsigned int port, i, data_sel, ar, data, rc;
    unsigned int op_bytes, op_default, ad_bytes, ad_default;
#define rd_ad(reg) (ad_bytes >= sizeof(regs->reg) \
                    ? regs->reg \
                    : ad_bytes == 4 \
                      ? (u32)regs->reg \
                      : (u16)regs->reg)
#define wr_ad(reg, val) (ad_bytes >= sizeof(regs->reg) \
                         ? regs->reg = (val) \
                         : ad_bytes == 4 \
                           ? (*(u32 *)&regs->reg = (val)) \
                           : (*(u16 *)&regs->reg = (val)))
    unsigned long code_base, code_limit;
    char io_emul_stub[16];
    void (*io_emul)(struct cpu_user_regs *) __attribute__((__regparm__(1)));
    u32 l, h;

    if ( !read_descriptor(regs->cs, v, regs,
                          &code_base, &code_limit, &ar,
                          _SEGMENT_CODE|_SEGMENT_S|_SEGMENT_DPL|_SEGMENT_P) )
        goto fail;
    op_default = op_bytes = (ar & (_SEGMENT_L|_SEGMENT_DB)) ? 4 : 2;
    ad_default = ad_bytes = (ar & _SEGMENT_L) ? 8 : op_default;
    if ( !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         !(ar & _SEGMENT_CODE) )
        goto fail;

    /* emulating only opcodes not allowing SS to be default */
    data_sel = read_sreg(regs, ds);

    /* Legacy prefixes. */
    for ( i = 0; i < 8; i++, rex == opcode || (rex = 0) )
    {
        switch ( opcode = insn_fetch(u8, code_base, eip, code_limit) )
        {
        case 0x66: /* operand-size override */
            op_bytes = op_default ^ 6; /* switch between 2/4 bytes */
            continue;
        case 0x67: /* address-size override */
            ad_bytes = ad_default != 4 ? 4 : 2; /* switch to 2/4 bytes */
            continue;
        case 0x2e: /* CS override */
            data_sel = regs->cs;
            continue;
        case 0x3e: /* DS override */
            data_sel = read_sreg(regs, ds);
            continue;
        case 0x26: /* ES override */
            data_sel = read_sreg(regs, es);
            continue;
        case 0x64: /* FS override */
            data_sel = read_sreg(regs, fs);
            lm_ovr = lm_seg_fs;
            continue;
        case 0x65: /* GS override */
            data_sel = read_sreg(regs, gs);
            lm_ovr = lm_seg_gs;
            continue;
        case 0x36: /* SS override */
            data_sel = regs->ss;
            continue;
        case 0xf0: /* LOCK */
            lock = 1;
            continue;
        case 0xf2: /* REPNE/REPNZ */
        case 0xf3: /* REP/REPE/REPZ */
            rep_prefix = 1;
            continue;
        default:
            if ( (ar & _SEGMENT_L) && (opcode & 0xf0) == 0x40 )
            {
                rex = opcode;
                continue;
            }
            break;
        }
        break;
    }

    /* REX prefix. */
    if ( rex & 8 ) /* REX.W */
        op_bytes = 4; /* emulating only opcodes not supporting 64-bit operands */
    modrm_reg = (rex & 4) << 1;  /* REX.R */
    /* REX.X does not need to be decoded. */
    modrm_rm  = (rex & 1) << 3;  /* REX.B */

    if ( opcode == 0x0f )
        goto twobyte_opcode;
    
    if ( lock )
        goto fail;

    /* Input/Output String instructions. */
    if ( (opcode >= 0x6c) && (opcode <= 0x6f) )
    {
        unsigned long data_base, data_limit;

        if ( rep_prefix && (rd_ad(ecx) == 0) )
            goto done;

        if ( !(opcode & 2) )
        {
            data_sel = read_sreg(regs, es);
            lm_ovr = lm_seg_none;
        }

        if ( !(ar & _SEGMENT_L) )
        {
            if ( !read_descriptor(data_sel, v, regs,
                                  &data_base, &data_limit, &ar,
                                  _SEGMENT_WR|_SEGMENT_S|_SEGMENT_DPL|_SEGMENT_P) )
                goto fail;
            if ( !(ar & _SEGMENT_S) ||
                 !(ar & _SEGMENT_P) ||
                 (opcode & 2 ?
                  (ar & _SEGMENT_CODE) && !(ar & _SEGMENT_WR) :
                  (ar & _SEGMENT_CODE) || !(ar & _SEGMENT_WR)) )
                goto fail;
        }
#ifdef CONFIG_X86_64
        else
        {
            if ( lm_ovr == lm_seg_none || data_sel < 4 )
            {
                switch ( lm_ovr )
                {
                case lm_seg_none:
                    data_base = 0UL;
                    break;
                case lm_seg_fs:
                    data_base = v->arch.guest_context.fs_base;
                    break;
                case lm_seg_gs:
                    if ( guest_kernel_mode(v, regs) )
                        data_base = v->arch.guest_context.gs_base_kernel;
                    else
                        data_base = v->arch.guest_context.gs_base_user;
                    break;
                }
            }
            else
                read_descriptor(data_sel, v, regs,
                                &data_base, &data_limit, &ar,
                                0);
            data_limit = ~0UL;
            ar = _SEGMENT_WR|_SEGMENT_S|_SEGMENT_DPL|_SEGMENT_P;
        }
#endif

    continue_io_string:
        switch ( opcode )
        {
        case 0x6c: /* INSB */
            op_bytes = 1;
        case 0x6d: /* INSW/INSL */
            if ( data_limit < op_bytes - 1 ||
                 rd_ad(edi) > data_limit - (op_bytes - 1) ||
                 !guest_io_okay((u16)regs->edx, op_bytes, v, regs) )
                goto fail;
            port = (u16)regs->edx;
            switch ( op_bytes )
            {
            case 1:
                /* emulate PIT counter 2 */
                data = (u8)(guest_inb_okay(port, v, regs) ? inb(port) : 
                       ((port == 0x42 || port == 0x43 || port == 0x61) ?
                       pv_pit_handler(port, 0, 0) : ~0)); 
                break;
            case 2:
                data = (u16)(guest_inw_okay(port, v, regs) ? inw(port) : ~0);
                break;
            case 4:
                data = (u32)(guest_inl_okay(port, v, regs) ? inl(port) : ~0);
                break;
            }
            if ( (rc = copy_to_user((void *)data_base + rd_ad(edi), &data, op_bytes)) != 0 )
            {
                propagate_page_fault(data_base + rd_ad(edi) + op_bytes - rc,
                                     PFEC_write_access);
                return EXCRET_fault_fixed;
            }
            wr_ad(edi, regs->edi + (int)((regs->eflags & EF_DF) ? -op_bytes : op_bytes));
            break;

        case 0x6e: /* OUTSB */
            op_bytes = 1;
        case 0x6f: /* OUTSW/OUTSL */
            if ( data_limit < op_bytes - 1 ||
                 rd_ad(esi) > data_limit - (op_bytes - 1) ||
                 !guest_io_okay((u16)regs->edx, op_bytes, v, regs) )
                goto fail;
            rc = copy_from_user(&data, (void *)data_base + rd_ad(esi), op_bytes);
            if ( rc != 0 )
            {
                propagate_page_fault(data_base + rd_ad(esi) + op_bytes - rc, 0);
                return EXCRET_fault_fixed;
            }
            port = (u16)regs->edx;
            switch ( op_bytes )
            {
            case 1:
                if ( guest_outb_okay(port, v, regs) )
                    outb((u8)data, port);
                else if ( port == 0x42 || port == 0x43 || port == 0x61 )
                    pv_pit_handler(port, data, 1);
                break;
            case 2:
                if ( guest_outw_okay(port, v, regs) )
                    outw((u16)data, port);
                break;
            case 4:
                if ( guest_outl_okay(port, v, regs) )
                    outl((u32)data, port);
                break;
            }
            wr_ad(esi, regs->esi + (int)((regs->eflags & EF_DF) ? -op_bytes : op_bytes));
            break;
        }

        if ( rep_prefix && (wr_ad(ecx, regs->ecx - 1) != 0) )
        {
            if ( !hypercall_preempt_check() )
                goto continue_io_string;
            eip = regs->eip;
        }

        goto done;
    }

    /*
     * Very likely to be an I/O instruction (IN/OUT).
     * Build an on-stack stub to execute the instruction with full guest
     * GPR context. This is needed for some systems which (ab)use IN/OUT
     * to communicate with BIOS code in system-management mode.
     */
    /* call host_to_guest_gpr_switch */
    io_emul_stub[0] = 0xe8;
    *(s32 *)&io_emul_stub[1] =
        (char *)host_to_guest_gpr_switch - &io_emul_stub[5];
    /* data16 or nop */
    io_emul_stub[5] = (op_bytes != 2) ? 0x90 : 0x66;
    /* <io-access opcode> */
    io_emul_stub[6] = opcode;
    /* imm8 or nop */
    io_emul_stub[7] = 0x90;
    /* jmp guest_to_host_gpr_switch */
    io_emul_stub[8] = 0xe9;
    *(s32 *)&io_emul_stub[9] =
        (char *)guest_to_host_gpr_switch - &io_emul_stub[13];

    /* Handy function-typed pointer to the stub. */
    io_emul = (void *)io_emul_stub;

    /* I/O Port and Interrupt Flag instructions. */
    switch ( opcode )
    {
    case 0xe4: /* IN imm8,%al */
        op_bytes = 1;
    case 0xe5: /* IN imm8,%eax */
        port = insn_fetch(u8, code_base, eip, code_limit);
        io_emul_stub[7] = port; /* imm8 */
    exec_in:
        if ( !guest_io_okay(port, op_bytes, v, regs) )
            goto fail;
        switch ( op_bytes )
        {
        case 1:
            if ( guest_inb_okay(port, v, regs) )
                io_emul(regs);
            else if ( port == 0x42 || port == 0x43 || port == 0x61 )
            {
                regs->eax &= ~0xffUL;
                regs->eax |= pv_pit_handler(port, 0, 0);
            } 
            else
                regs->eax |= (u8)~0;
            break;
        case 2:
            if ( guest_inw_okay(port, v, regs) )
                io_emul(regs);
            else
                regs->eax |= (u16)~0;
            break;
        case 4:
            if ( guest_inl_okay(port, v, regs) )
                io_emul(regs);
            else
                regs->eax = (u32)~0;
            break;
        }
        goto done;

    case 0xec: /* IN %dx,%al */
        op_bytes = 1;
    case 0xed: /* IN %dx,%eax */
        port = (u16)regs->edx;
        goto exec_in;

    case 0xe6: /* OUT %al,imm8 */
        op_bytes = 1;
    case 0xe7: /* OUT %eax,imm8 */
        port = insn_fetch(u8, code_base, eip, code_limit);
        io_emul_stub[7] = port; /* imm8 */
    exec_out:
        if ( !guest_io_okay(port, op_bytes, v, regs) )
            goto fail;
        switch ( op_bytes )
        {
        case 1:
            if ( guest_outb_okay(port, v, regs) )
                io_emul(regs);
            else if ( port == 0x42 || port == 0x43 || port == 0x61 )
                pv_pit_handler(port, regs->eax, 1);
            break;
        case 2:
            if ( guest_outw_okay(port, v, regs) )
                io_emul(regs);
            break;
        case 4:
            if ( guest_outl_okay(port, v, regs) )
                io_emul(regs);
            break;
        }
        goto done;

    case 0xee: /* OUT %al,%dx */
        op_bytes = 1;
    case 0xef: /* OUT %eax,%dx */
        port = (u16)regs->edx;
        goto exec_out;

    case 0xfa: /* CLI */
    case 0xfb: /* STI */
        if ( v->arch.iopl < (guest_kernel_mode(v, regs) ? 1 : 3) )
            goto fail;
        /*
         * This is just too dangerous to allow, in my opinion. Consider if the
         * caller then tries to reenable interrupts using POPF: we can't trap
         * that and we'll end up with hard-to-debug lockups. Fast & loose will
         * do for us. :-)
         */
        /*v->vcpu_info->evtchn_upcall_mask = (opcode == 0xfa);*/
        goto done;
    }

    /* No decode of this single-byte opcode. */
    goto fail;

 twobyte_opcode:
    /* Two-byte opcodes only emulated from guest kernel. */
    if ( !guest_kernel_mode(v, regs) )
        goto fail;

    /* Privileged (ring 0) instructions. */
    opcode = insn_fetch(u8, code_base, eip, code_limit);
    if ( lock && (opcode & ~3) != 0x20 )
        goto fail;
    switch ( opcode )
    {
    case 0x06: /* CLTS */
        (void)do_fpu_taskswitch(0);
        break;

    case 0x09: /* WBINVD */
        /* Ignore the instruction if unprivileged. */
        if ( !cache_flush_permitted(v->domain) )
            /* Non-physdev domain attempted WBINVD; ignore for now since
               newer linux uses this in some start-of-day timing loops */
            ;
        else
            wbinvd();
        break;

    case 0x20: /* MOV CR?,<reg> */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        switch ( modrm_reg )
        {
        case 0: /* Read CR0 */
            *reg = (read_cr0() & ~X86_CR0_TS) |
                v->arch.guest_context.ctrlreg[0];
            break;

        case 2: /* Read CR2 */
            *reg = v->arch.guest_context.ctrlreg[2];
            break;
            
        case 3: /* Read CR3 */
            if ( !IS_COMPAT(v->domain) )
                *reg = xen_pfn_to_cr3(mfn_to_gmfn(
                    v->domain, pagetable_get_pfn(v->arch.guest_table)));
#ifdef CONFIG_COMPAT
            else
                *reg = compat_pfn_to_cr3(mfn_to_gmfn(
                    v->domain, l4e_get_pfn(*(l4_pgentry_t *)__va(pagetable_get_paddr(v->arch.guest_table)))));
#endif
            break;

        case 4: /* Read CR4 */
            /*
             * Guests can read CR4 to see what features Xen has enabled. We
             * therefore lie about PGE & PSE as they are unavailable to guests.
             */
            *reg = read_cr4() & ~(X86_CR4_PGE|X86_CR4_PSE);
            break;

        default:
            goto fail;
        }
        break;

    case 0x21: /* MOV DR?,<reg> */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        if ( (res = do_get_debugreg(modrm_reg)) > (unsigned long)-256 )
            goto fail;
        *reg = res;
        break;

    case 0x22: /* MOV <reg>,CR? */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        switch ( modrm_reg )
        {
        case 0: /* Write CR0 */
            if ( (*reg ^ read_cr0()) & ~X86_CR0_TS )
            {
                gdprintk(XENLOG_WARNING,
                        "Attempt to change unmodifiable CR0 flags.\n");
                goto fail;
            }
            (void)do_fpu_taskswitch(!!(*reg & X86_CR0_TS));
            break;

        case 2: /* Write CR2 */
            v->arch.guest_context.ctrlreg[2] = *reg;
            arch_set_cr2(v, *reg);
            break;

        case 3: /* Write CR3 */
            LOCK_BIGLOCK(v->domain);
            if ( !IS_COMPAT(v->domain) )
                rc = new_guest_cr3(gmfn_to_mfn(v->domain, xen_cr3_to_pfn(*reg)));
#ifdef CONFIG_COMPAT
            else
                rc = new_guest_cr3(gmfn_to_mfn(v->domain, compat_cr3_to_pfn(*reg)));
#endif
            UNLOCK_BIGLOCK(v->domain);
            if ( rc == 0 ) /* not okay */
                goto fail;
            break;

        case 4:
            if ( *reg != (read_cr4() & ~(X86_CR4_PGE|X86_CR4_PSE)) )
            {
                gdprintk(XENLOG_WARNING, "Attempt to change CR4 flags.\n");
                goto fail;
            }
            break;

        default:
            goto fail;
        }
        break;

    case 0x23: /* MOV <reg>,DR? */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        if ( do_set_debugreg(modrm_reg, *reg) != 0 )
            goto fail;
        break;

    case 0x30: /* WRMSR */
        switch ( regs->ecx )
        {
#ifdef CONFIG_X86_64
        case MSR_FS_BASE:
            if ( IS_COMPAT(v->domain) )
                goto fail;
            if ( wrmsr_safe(MSR_FS_BASE, regs->eax, regs->edx) )
                goto fail;
            v->arch.guest_context.fs_base =
                ((u64)regs->edx << 32) | regs->eax;
            break;
        case MSR_GS_BASE:
            if ( IS_COMPAT(v->domain) )
                goto fail;
            if ( wrmsr_safe(MSR_GS_BASE, regs->eax, regs->edx) )
                goto fail;
            v->arch.guest_context.gs_base_kernel =
                ((u64)regs->edx << 32) | regs->eax;
            break;
        case MSR_SHADOW_GS_BASE:
            if ( IS_COMPAT(v->domain) )
                goto fail;
            if ( wrmsr_safe(MSR_SHADOW_GS_BASE, regs->eax, regs->edx) )
                goto fail;
            v->arch.guest_context.gs_base_user =
                ((u64)regs->edx << 32) | regs->eax;
            break;
#endif
        default:
            if ( wrmsr_hypervisor_regs(regs->ecx, regs->eax, regs->edx) )
                break;

            if ( (rdmsr_safe(regs->ecx, l, h) != 0) ||
                 (regs->eax != l) || (regs->edx != h) )
                gdprintk(XENLOG_WARNING, "Domain attempted WRMSR %p from "
                        "%08x:%08x to %08lx:%08lx.\n",
                        _p(regs->ecx), h, l, (long)regs->edx, (long)regs->eax);
            break;
        }
        break;

    case 0x32: /* RDMSR */
        switch ( regs->ecx )
        {
#ifdef CONFIG_X86_64
        case MSR_FS_BASE:
            if ( IS_COMPAT(v->domain) )
                goto fail;
            regs->eax = v->arch.guest_context.fs_base & 0xFFFFFFFFUL;
            regs->edx = v->arch.guest_context.fs_base >> 32;
            break;
        case MSR_GS_BASE:
            if ( IS_COMPAT(v->domain) )
                goto fail;
            regs->eax = v->arch.guest_context.gs_base_kernel & 0xFFFFFFFFUL;
            regs->edx = v->arch.guest_context.gs_base_kernel >> 32;
            break;
        case MSR_SHADOW_GS_BASE:
            if ( IS_COMPAT(v->domain) )
                goto fail;
            regs->eax = v->arch.guest_context.gs_base_user & 0xFFFFFFFFUL;
            regs->edx = v->arch.guest_context.gs_base_user >> 32;
            break;
#endif
        case MSR_EFER:
            if ( rdmsr_safe(regs->ecx, regs->eax, regs->edx) )
                goto fail;
            break;
        default:
            if ( rdmsr_hypervisor_regs(regs->ecx, &l, &h) )
            {
                regs->eax = l;
                regs->edx = h;
                break;
            }
            /* Everyone can read the MSR space. */
            /* gdprintk(XENLOG_WARNING,"Domain attempted RDMSR %p.\n",
                        _p(regs->ecx));*/
            if ( rdmsr_safe(regs->ecx, regs->eax, regs->edx) )
                goto fail;
            break;
        }
        break;

    default:
        goto fail;
    }

#undef wr_ad
#undef rd_ad

 done:
    regs->eip = eip;
    return EXCRET_fault_fixed;

 fail:
    return 0;
}

asmlinkage int do_general_protection(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    unsigned long fixup;

    DEBUGGER_trap_entry(TRAP_gp_fault, regs);

    if ( regs->error_code & 1 )
        goto hardware_gp;

    if ( !guest_mode(regs) )
        goto gp_in_kernel;

    /*
     * Cunning trick to allow arbitrary "INT n" handling.
     * 
     * We set DPL == 0 on all vectors in the IDT. This prevents any INT <n>
     * instruction from trapping to the appropriate vector, when that might not
     * be expected by Xen or the guest OS. For example, that entry might be for
     * a fault handler (unlike traps, faults don't increment EIP), or might
     * expect an error code on the stack (which a software trap never
     * provides), or might be a hardware interrupt handler that doesn't like
     * being called spuriously.
     * 
     * Instead, a GPF occurs with the faulting IDT vector in the error code.
     * Bit 1 is set to indicate that an IDT entry caused the fault. Bit 0 is 
     * clear to indicate that it's a software fault, not hardware.
     * 
     * NOTE: Vectors 3 and 4 are dealt with from their own handler. This is
     * okay because they can only be triggered by an explicit DPL-checked
     * instruction. The DPL specified by the guest OS for these vectors is NOT
     * CHECKED!!
     */
    if ( (regs->error_code & 3) == 2 )
    {
        /* This fault must be due to <INT n> instruction. */
        const struct trap_info *ti;
        unsigned char vector = regs->error_code >> 3;
        ti = &v->arch.guest_context.trap_ctxt[vector];
        if ( permit_softint(TI_GET_DPL(ti), v, regs) )
        {
            regs->eip += 2;
            return do_guest_trap(vector, regs, 0);
        }
    }

    /* Emulate some simple privileged and I/O instructions. */
    if ( (regs->error_code == 0) &&
         emulate_privileged_op(regs) )
        return 0;

#if defined(__i386__)
    if ( VM_ASSIST(v->domain, VMASST_TYPE_4gb_segments) && 
         (regs->error_code == 0) && 
         gpf_emulate_4gb(regs) )
        return 0;
#endif

    /* Pass on GPF as is. */
    return do_guest_trap(TRAP_gp_fault, regs, 1);

 gp_in_kernel:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        dprintk(XENLOG_INFO, "GPF (%04x): %p -> %p\n",
                regs->error_code, _p(regs->eip), _p(fixup));
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(TRAP_gp_fault, regs);

 hardware_gp:
    show_execution_state(regs);
    panic("GENERAL PROTECTION FAULT\n[error_code=%04x]\n", regs->error_code);
    return 0;
}

static void nmi_softirq(void)
{
    /* Only used to defer wakeup of dom0,vcpu0 to a safe (non-NMI) context. */
    vcpu_kick(dom0->vcpu[0]);
}

static void nmi_dom0_report(unsigned int reason_idx)
{
    struct domain *d;
    struct vcpu   *v;

    if ( ((d = dom0) == NULL) || ((v = d->vcpu[0]) == NULL) )
        return;

    set_bit(reason_idx, nmi_reason(d));

    if ( !test_and_set_bit(_VCPUF_nmi_pending, &v->vcpu_flags) )
        raise_softirq(NMI_SOFTIRQ); /* not safe to wake up a vcpu here */
}

asmlinkage void mem_parity_error(struct cpu_user_regs *regs)
{
    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        nmi_dom0_report(_XEN_NMIREASON_parity_error);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("\n\nNMI - MEMORY ERROR\n");
        fatal_trap(TRAP_nmi, regs);
    }

    outb((inb(0x61) & 0x0f) | 0x04, 0x61); /* clear-and-disable parity check */
    mdelay(1);
    outb((inb(0x61) & 0x0b) | 0x00, 0x61); /* enable parity check */
}

asmlinkage void io_check_error(struct cpu_user_regs *regs)
{
    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        nmi_dom0_report(_XEN_NMIREASON_io_error);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("\n\nNMI - I/O ERROR\n");
        fatal_trap(TRAP_nmi, regs);
    }

    outb((inb(0x61) & 0x0f) | 0x08, 0x61); /* clear-and-disable IOCK */
    mdelay(1);
    outb((inb(0x61) & 0x07) | 0x00, 0x61); /* enable IOCK */
}

static void unknown_nmi_error(unsigned char reason)
{
    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        nmi_dom0_report(_XEN_NMIREASON_unknown);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        printk("Uhhuh. NMI received for unknown reason %02x.\n", reason);
        printk("Dazed and confused, but trying to continue\n");
        printk("Do you have a strange power saving mode enabled?\n");
        kexec_crash();
    }
}

static int dummy_nmi_callback(struct cpu_user_regs *regs, int cpu)
{
    return 0;
}
 
static nmi_callback_t nmi_callback = dummy_nmi_callback;

asmlinkage void do_nmi(struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();
    unsigned char reason;

    ++nmi_count(cpu);

    if ( nmi_callback(regs, cpu) )
        return;

    if ( nmi_watchdog )
        nmi_watchdog_tick(regs);

    /* Only the BSP gets external NMIs from the system. */
    if ( cpu == 0 )
    {
        reason = inb(0x61);
        if ( reason & 0x80 )
            mem_parity_error(regs);
        else if ( reason & 0x40 )
            io_check_error(regs);
        else if ( !nmi_watchdog )
            unknown_nmi_error((unsigned char)(reason&0xff));
    }
}

void set_nmi_callback(nmi_callback_t callback)
{
    nmi_callback = callback;
}

void unset_nmi_callback(void)
{
    nmi_callback = dummy_nmi_callback;
}

asmlinkage int math_state_restore(struct cpu_user_regs *regs)
{
    BUG_ON(!guest_mode(regs));

    setup_fpu(current);

    if ( current->arch.guest_context.ctrlreg[0] & X86_CR0_TS )
    {
        do_guest_trap(TRAP_no_device, regs, 0);
        current->arch.guest_context.ctrlreg[0] &= ~X86_CR0_TS;
    }

    return EXCRET_fault_fixed;
}

asmlinkage int do_debug(struct cpu_user_regs *regs)
{
    unsigned long condition;
    struct vcpu *v = current;

    __asm__ __volatile__("mov %%db6,%0" : "=r" (condition));

    /* Mask out spurious debug traps due to lazy DR7 setting */
    if ( (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) &&
         (v->arch.guest_context.debugreg[7] == 0) )
    {
        __asm__("mov %0,%%db7" : : "r" (0UL));
        goto out;
    }

    DEBUGGER_trap_entry(TRAP_debug, regs);

    if ( !guest_mode(regs) )
    {
        /* Clear TF just for absolute sanity. */
        regs->eflags &= ~EF_TF;
        /*
         * We ignore watchpoints when they trigger within Xen. This may happen
         * when a buffer is passed to us which previously had a watchpoint set
         * on it. No need to bump EIP; the only faulting trap is an instruction
         * breakpoint, which can't happen to us.
         */
        goto out;
    } 

    /* Save debug status register where guest OS can peek at it */
    v->arch.guest_context.debugreg[6] = condition;

    return do_guest_trap(TRAP_debug, regs, 0);

 out:
    return EXCRET_not_a_fault;
}

asmlinkage int do_spurious_interrupt_bug(struct cpu_user_regs *regs)
{
    return EXCRET_not_a_fault;
}

void set_intr_gate(unsigned int n, void *addr)
{
#ifdef __i386__
    int i;
    /* Keep secondary tables in sync with IRQ updates. */
    for ( i = 1; i < NR_CPUS; i++ )
        if ( idt_tables[i] != NULL )
            _set_gate(&idt_tables[i][n], 14, 0, addr);
#endif
    _set_gate(&idt_table[n], 14, 0, addr);
}

void set_system_gate(unsigned int n, void *addr)
{
    _set_gate(idt_table+n,14,3,addr);
}

void set_task_gate(unsigned int n, unsigned int sel)
{
    idt_table[n].a = sel << 16;
    idt_table[n].b = 0x8500;
}

void set_tss_desc(unsigned int n, void *addr)
{
    _set_tssldt_desc(
        gdt_table + __TSS(n) - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)addr,
        offsetof(struct tss_struct, __cacheline_filler) - 1,
        9);
#ifdef CONFIG_COMPAT
    _set_tssldt_desc(
        compat_gdt_table + __TSS(n) - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)addr,
        offsetof(struct tss_struct, __cacheline_filler) - 1,
        11);
#endif
}

void __init trap_init(void)
{
    extern void percpu_traps_init(void);

    /*
     * Note that interrupt gates are always used, rather than trap gates. We 
     * must have interrupts disabled until DS/ES/FS/GS are saved because the 
     * first activation must have the "bad" value(s) for these registers and 
     * we may lose them if another activation is installed before they are 
     * saved. The page-fault handler also needs interrupts disabled until %cr2 
     * has been read and saved on the stack.
     */
    set_intr_gate(TRAP_divide_error,&divide_error);
    set_intr_gate(TRAP_debug,&debug);
    set_intr_gate(TRAP_nmi,&nmi);
    set_system_gate(TRAP_int3,&int3);         /* usable from all privileges */
    set_system_gate(TRAP_overflow,&overflow); /* usable from all privileges */
    set_intr_gate(TRAP_bounds,&bounds);
    set_intr_gate(TRAP_invalid_op,&invalid_op);
    set_intr_gate(TRAP_no_device,&device_not_available);
    set_intr_gate(TRAP_copro_seg,&coprocessor_segment_overrun);
    set_intr_gate(TRAP_invalid_tss,&invalid_TSS);
    set_intr_gate(TRAP_no_segment,&segment_not_present);
    set_intr_gate(TRAP_stack_error,&stack_segment);
    set_intr_gate(TRAP_gp_fault,&general_protection);
    set_intr_gate(TRAP_page_fault,&page_fault);
    set_intr_gate(TRAP_spurious_int,&spurious_interrupt_bug);
    set_intr_gate(TRAP_copro_error,&coprocessor_error);
    set_intr_gate(TRAP_alignment_check,&alignment_check);
    set_intr_gate(TRAP_machine_check,&machine_check);
    set_intr_gate(TRAP_simd_error,&simd_coprocessor_error);

    percpu_traps_init();

    cpu_init();

    open_softirq(NMI_SOFTIRQ, nmi_softirq);
}


long do_set_trap_table(XEN_GUEST_HANDLE(trap_info_t) traps)
{
    struct trap_info cur;
    struct trap_info *dst = current->arch.guest_context.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, 256 * sizeof(*dst));
        init_int80_direct_trap(current);
        return 0;
    }

    for ( ; ; )
    {
        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }

        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        fixup_guest_code_selector(current->domain, cur.cs);

        memcpy(&dst[cur.vector], &cur, sizeof(cur));

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(current);

        guest_handle_add_offset(traps, 1);
    }

    return rc;
}


long set_debugreg(struct vcpu *p, int reg, unsigned long value)
{
    int i;

    switch ( reg )
    {
    case 0: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db0" : : "r" (value) );
        break;
    case 1: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db1" : : "r" (value) );
        break;
    case 2: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db2" : : "r" (value) );
        break;
    case 3:
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db3" : : "r" (value) );
        break;
    case 6:
        /*
         * DR6: Bits 4-11,16-31 reserved (set to 1).
         *      Bit 12 reserved (set to 0).
         */
        value &= 0xffffefff; /* reserved bits => 0 */
        value |= 0xffff0ff0; /* reserved bits => 1 */
        if ( p == current ) 
            __asm__ ( "mov %0, %%db6" : : "r" (value) );
        break;
    case 7:
        /*
         * DR7: Bit 10 reserved (set to 1).
         *      Bits 11-12,14-15 reserved (set to 0).
         * Privileged bits:
         *      GD (bit 13): must be 0.
         *      R/Wn (bits 16-17,20-21,24-25,28-29): mustn't be 10.
         *      LENn (bits 18-19,22-23,26-27,30-31): mustn't be 10.
         */
        /* DR7 == 0 => debugging disabled for this domain. */
        if ( value != 0 )
        {
            value &= 0xffff27ff; /* reserved bits => 0 */
            value |= 0x00000400; /* reserved bits => 1 */
            if ( (value & (1<<13)) != 0 ) return -EPERM;
            for ( i = 0; i < 16; i += 2 )
                if ( ((value >> (i+16)) & 3) == 2 ) return -EPERM;
        }
        if ( p == current ) 
            __asm__ ( "mov %0, %%db7" : : "r" (value) );
        break;
    default:
        return -EINVAL;
    }

    p->arch.guest_context.debugreg[reg] = value;
    return 0;
}

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    if ( (reg < 0) || (reg > 7) ) return -EINVAL;
    return current->arch.guest_context.debugreg[reg];
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
