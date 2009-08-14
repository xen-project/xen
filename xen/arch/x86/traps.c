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
#include <xen/trace.h>
#include <xen/paging.h>
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
#include <asm/traps.h>
#include <asm/hvm/vpt.h>
#include <public/arch-x86/cpuid.h>

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

DEFINE_PER_CPU_READ_MOSTLY(u32, ler_msr);

/* Master table, used by CPU0. */
idt_entry_t idt_table[IDT_ENTRIES];

/* Pointer to the IDT of every CPU. */
idt_entry_t *idt_tables[NR_CPUS] __read_mostly;

#define DECLARE_TRAP_HANDLER(_name)                     \
asmlinkage void _name(void);                            \
asmlinkage void do_ ## _name(struct cpu_user_regs *regs)

DECLARE_TRAP_HANDLER(divide_error);
DECLARE_TRAP_HANDLER(debug);
DECLARE_TRAP_HANDLER(nmi);
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
DECLARE_TRAP_HANDLER(machine_check);
DECLARE_TRAP_HANDLER(alignment_check);
DECLARE_TRAP_HANDLER(spurious_interrupt_bug);

long do_set_debugreg(int reg, unsigned long value);
unsigned long do_get_debugreg(int reg);
void (*ioemul_handle_quirk)(
    u8 opcode, char *io_emul_stub, struct cpu_user_regs *regs);

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

static int opt_ler;
boolean_param("ler", opt_ler);

#ifdef CONFIG_X86_32
#define stack_words_per_line 8
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)&regs->esp)
#else
#define stack_words_per_line 4
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)regs->rsp)
#endif

static void show_guest_stack(struct vcpu *v, struct cpu_user_regs *regs)
{
    int i;
    unsigned long *stack, addr;
    unsigned long mask = STACK_SIZE;

    if ( is_hvm_vcpu(v) )
        return;

    if ( is_pv_32on64_vcpu(v) )
    {
        compat_show_guest_stack(v, regs, debug_stack_lines);
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

    if ( !access_ok(stack, sizeof(*stack)) )
    {
        printk("Guest-inaccessible memory.\n");
        return;
    }

    if ( v != current )
    {
        struct vcpu *vcpu;

        ASSERT(guest_kernel_mode(v, regs));
#ifndef __x86_64__
        addr = read_cr3();
        for_each_vcpu( v->domain, vcpu )
            if ( vcpu->arch.cr3 == addr )
                break;
#else
        vcpu = maddr_get_owner(read_cr3()) == v->domain ? v : NULL;
#endif
        if ( !vcpu )
        {
            stack = do_page_walk(v, (unsigned long)stack);
            if ( (unsigned long)stack < PAGE_SIZE )
            {
                printk("Inaccessible guest memory.\n");
                return;
            }
            mask = PAGE_SIZE;
        }
    }

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line); i++ )
    {
        if ( (((long)stack - 1) ^ ((long)(stack + 1) - 1)) & mask )
            break;
        if ( __get_user(addr, stack) )
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

#if !defined(CONFIG_FRAME_POINTER)

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
        return show_guest_stack(current, regs);

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

void show_stack_overflow(unsigned int cpu, unsigned long esp)
{
#ifdef MEMORY_GUARD
    unsigned long esp_top, esp_bottom;
    unsigned long *stack, addr;

    esp_bottom = (esp | (STACK_SIZE - 1)) + 1;
    esp_top    = esp_bottom - PRIMARY_STACK_SIZE;

    printk("Valid stack range: %p-%p, sp=%p, tss.esp0=%p\n",
           (void *)esp_top, (void *)esp_bottom, (void *)esp,
           (void *)per_cpu(init_tss, cpu).esp0);

    /* Trigger overflow trace if %esp is within 512 bytes of the guard page. */
    if ( ((unsigned long)(esp - esp_top) > 512) &&
         ((unsigned long)(esp_top - esp) > 512) )
    {
        printk("No stack overflow detected. Skipping stack trace.\n");
        return;
    }

    if ( esp < esp_top )
        esp = esp_top;

    printk("Xen stack overflow (dumping trace %p-%p):\n   ",
           (void *)esp, (void *)esp_bottom);

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

void vcpu_show_execution_state(struct vcpu *v)
{
    printk("*** Dumping Dom%d vcpu#%d state: ***\n",
           v->domain->domain_id, v->vcpu_id);

    if ( v == current )
    {
        show_execution_state(guest_cpu_user_regs());
        return;
    }

    vcpu_pause(v); /* acceptably dangerous */

    vcpu_show_registers(v);
    if ( guest_kernel_mode(v, &v->arch.guest_context.user_regs) )
        show_guest_stack(v, &v->arch.guest_context.user_regs);

    vcpu_unpause(v);
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
    static DEFINE_PER_CPU(char, depth);

    /*
     * In some cases, we can end up in a vicious cycle of fatal_trap()s
     * within fatal_trap()s. We give the problem a couple of iterations to
     * bottom out, and then we just panic.
     */
    if ( ++this_cpu(depth) < 3 )
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
    }

    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x] %s\n",
          trapnr, trapstr(trapnr), regs->error_code,
          (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
}

static void do_guest_trap(
    int trapnr, const struct cpu_user_regs *regs, int use_error_code)
{
    struct vcpu *v = current;
    struct trap_bounce *tb;
    const struct trap_info *ti;

    trace_pv_trap(trapnr, regs->eip, use_error_code, regs->error_code);

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
        gdprintk(XENLOG_WARNING, "Unhandled %s fault/trap [#%d] "
                 "on VCPU %d [ec=%04x]\n",
                 trapstr(trapnr), trapnr, v->vcpu_id, regs->error_code);
}

static void instruction_done(
    struct cpu_user_regs *regs, unsigned long eip, unsigned int bpmatch)
{
    regs->eip = eip;
    regs->eflags &= ~X86_EFLAGS_RF;
    if ( bpmatch || (regs->eflags & X86_EFLAGS_TF) )
    {
        current->arch.guest_context.debugreg[6] |= bpmatch | 0xffff0ff0;
        if ( regs->eflags & X86_EFLAGS_TF )
            current->arch.guest_context.debugreg[6] |= 0x4000;
        do_guest_trap(TRAP_debug, regs, 0);
    }
}

static unsigned int check_guest_io_breakpoint(struct vcpu *v,
    unsigned int port, unsigned int len)
{
    unsigned int width, i, match = 0;
    unsigned long start;

    if ( !(v->arch.guest_context.debugreg[5]) || 
         !(v->arch.guest_context.ctrlreg[4] & X86_CR4_DE) )
        return 0;

    for ( i = 0; i < 4; i++ )
    {
        if ( !(v->arch.guest_context.debugreg[5] &
               (3 << (i * DR_ENABLE_SIZE))) )
            continue;

        start = v->arch.guest_context.debugreg[i];
        width = 0;

        switch ( (v->arch.guest_context.debugreg[7] >>
                  (DR_CONTROL_SHIFT + i * DR_CONTROL_SIZE)) & 0xc )
        {
        case DR_LEN_1: width = 1; break;
        case DR_LEN_2: width = 2; break;
        case DR_LEN_4: width = 4; break;
        case DR_LEN_8: width = 8; break;
        }

        if ( (start < (port + len)) && ((start + width) > port) )
            match |= 1 << i;
    }

    return match;
}

/*
 * Called from asm to set up the MCE trapbounce info.
 * Returns 0 if no callback is set up, else 1.
 */
asmlinkage int set_guest_machinecheck_trapbounce(void)
{
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.trap_bounce;
 
    do_guest_trap(TRAP_machine_check, guest_cpu_user_regs(), 0);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for MCE delivery path */
    return !null_trap_bounce(v, tb);
}

/*
 * Called from asm to set up the NMI trapbounce info.
 * Returns 0 if no callback is set up, else 1.
 */
asmlinkage int set_guest_nmi_trapbounce(void)
{
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.trap_bounce;
    do_guest_trap(TRAP_nmi, guest_cpu_user_regs(), 0);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for NMI delivery path */
    return !null_trap_bounce(v, tb);
}

static inline void do_trap(
    int trapnr, struct cpu_user_regs *regs, int use_error_code)
{
    struct vcpu *curr = current;
    unsigned long fixup;

    DEBUGGER_trap_entry(trapnr, regs);

    if ( guest_mode(regs) )
    {
        do_guest_trap(trapnr, regs, use_error_code);
        return;
    }

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        dprintk(XENLOG_ERR, "Trap %d: %p -> %p\n",
                trapnr, _p(regs->eip), _p(fixup));
        regs->eip = fixup;
        return;
    }

    if ( ((trapnr == TRAP_copro_error) || (trapnr == TRAP_simd_error)) &&
         is_hvm_vcpu(curr) && curr->arch.hvm_vcpu.fpu_exception_callback )
    {
        curr->arch.hvm_vcpu.fpu_exception_callback(
            curr->arch.hvm_vcpu.fpu_exception_callback_arg, regs);
        return;
    }

    DEBUGGER_trap_fatal(trapnr, regs);

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x]\n",
          trapnr, trapstr(trapnr), regs->error_code);
}

#define DO_ERROR_NOCODE(trapnr, name)                   \
asmlinkage void do_##name(struct cpu_user_regs *regs)   \
{                                                       \
    do_trap(trapnr, regs, 0);                           \
}

#define DO_ERROR(trapnr, name)                          \
asmlinkage void do_##name(struct cpu_user_regs *regs)   \
{                                                       \
    do_trap(trapnr, regs, 1);                           \
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

int rdmsr_hypervisor_regs(uint32_t idx, uint64_t *val)
{
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    idx -= base;
    if ( idx > 0 )
        return 0;

    switch ( idx )
    {
    case 0:
    {
        *val = 0;
        break;
    }
    default:
        BUG();
    }

    return 1;
}

int wrmsr_hypervisor_regs(uint32_t idx, uint64_t val)
{
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    idx -= base;
    if ( idx > 0 )
        return 0;

    switch ( idx )
    {
    case 0:
    {
        void *hypercall_page;
        unsigned long mfn;
        unsigned long gmfn = val >> 12;
        unsigned int idx  = val & 0xfff;

        if ( idx > 0 )
        {
            gdprintk(XENLOG_WARNING,
                     "Out of range index %u to MSR %08x\n",
                     idx, 0x40000000);
            return 0;
        }

        mfn = gmfn_to_mfn(d, gmfn);

        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
        {
            gdprintk(XENLOG_WARNING,
                     "Bad GMFN %lx (MFN %lx) to MSR %08x\n",
                     gmfn, mfn, base + idx);
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
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural leaves. */
    uint32_t base = is_viridian_domain(d) ? 0x40000100 : 0x40000000;

    idx -= base;
    if ( idx > 2 ) 
        return 0;

    switch ( idx )
    {
    case 0:
        *eax = base + 2; /* Largest leaf */
        *ebx = XEN_CPUID_SIGNATURE_EBX;
        *ecx = XEN_CPUID_SIGNATURE_ECX;
        *edx = XEN_CPUID_SIGNATURE_EDX;
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
        if ( is_viridian_domain(d) )
            *ebx = 0x40000200;
        *ecx = 0;          /* Features 1 */
        *edx = 0;          /* Features 2 */
        if ( !is_hvm_vcpu(current) )
            *ecx |= XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD;
        break;

    default:
        BUG();
    }

    return 1;
}

static void pv_cpuid(struct cpu_user_regs *regs)
{
    uint32_t a, b, c, d;

    a = regs->eax;
    b = regs->ebx;
    c = regs->ecx;
    d = regs->edx;

    if ( current->domain->domain_id != 0 )
    {
        if ( !cpuid_hypervisor_leaves(a, &a, &b, &c, &d) )
            domain_cpuid(current->domain, a, c, &a, &b, &c, &d);
        goto out;
    }

    asm ( 
        "cpuid"
        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
        : "0" (a), "1" (b), "2" (c), "3" (d) );

    if ( (regs->eax & 0x7fffffff) == 1 )
    {
        /* Modify Feature Information. */
        __clear_bit(X86_FEATURE_VME, &d);
        if ( !cpu_has_apic )
            __clear_bit(X86_FEATURE_APIC, &d);
        if ( !opt_allow_hugepage )
            __clear_bit(X86_FEATURE_PSE, &d);
        __clear_bit(X86_FEATURE_PGE, &d);
        __clear_bit(X86_FEATURE_PSE36, &d);
    }
    switch ( (uint32_t)regs->eax )
    {
    case 1:
        /* Modify Feature Information. */
        if ( !cpu_has_sep )
            __clear_bit(X86_FEATURE_SEP, &d);
#ifdef __i386__
        if ( !supervisor_mode_kernel )
            __clear_bit(X86_FEATURE_SEP, &d);
#endif
        __clear_bit(X86_FEATURE_DS, &d);
        __clear_bit(X86_FEATURE_ACC, &d);
        __clear_bit(X86_FEATURE_PBE, &d);

        __clear_bit(X86_FEATURE_DTES64 % 32, &c);
        __clear_bit(X86_FEATURE_MWAIT % 32, &c);
        __clear_bit(X86_FEATURE_DSCPL % 32, &c);
        __clear_bit(X86_FEATURE_VMXE % 32, &c);
        __clear_bit(X86_FEATURE_SMXE % 32, &c);
        __clear_bit(X86_FEATURE_TM2 % 32, &c);
        if ( is_pv_32bit_vcpu(current) )
            __clear_bit(X86_FEATURE_CX16 % 32, &c);
        __clear_bit(X86_FEATURE_XTPR % 32, &c);
        __clear_bit(X86_FEATURE_PDCM % 32, &c);
        __clear_bit(X86_FEATURE_DCA % 32, &c);
        __clear_bit(X86_FEATURE_XSAVE % 32, &c);
        if ( !cpu_has_apic )
           __clear_bit(X86_FEATURE_X2APIC % 32, &c);
        __set_bit(X86_FEATURE_HYPERVISOR % 32, &c);
        break;
    case 0x80000001:
        /* Modify Feature Information. */
        if ( is_pv_32bit_vcpu(current) )
        {
            __clear_bit(X86_FEATURE_LM % 32, &d);
            __clear_bit(X86_FEATURE_LAHF_LM % 32, &c);
        }
#ifndef __i386__
        if ( is_pv_32on64_vcpu(current) &&
             boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
#endif
            __clear_bit(X86_FEATURE_SYSCALL % 32, &d);
        __clear_bit(X86_FEATURE_PAGE1GB % 32, &d);
        __clear_bit(X86_FEATURE_RDTSCP % 32, &d);

        __clear_bit(X86_FEATURE_SVME % 32, &c);
        if ( !cpu_has_apic )
           __clear_bit(X86_FEATURE_EXTAPICSPACE % 32, &c);
        __clear_bit(X86_FEATURE_OSVW % 32, &c);
        __clear_bit(X86_FEATURE_IBS % 32, &c);
        __clear_bit(X86_FEATURE_SKINIT % 32, &c);
        __clear_bit(X86_FEATURE_WDT % 32, &c);
        break;
    case 5: /* MONITOR/MWAIT */
    case 0xa: /* Architectural Performance Monitor Features */
    case 0x8000000a: /* SVM revision and features */
    case 0x8000001b: /* Instruction Based Sampling */
        a = b = c = d = 0;
        break;
    default:
        (void)cpuid_hypervisor_leaves(regs->eax, &a, &b, &c, &d);
        break;
    }

 out:
    regs->eax = a;
    regs->ebx = b;
    regs->ecx = c;
    regs->edx = d;
}

static int emulate_forced_invalid_op(struct cpu_user_regs *regs)
{
    char sig[5], instr[2];
    unsigned long eip, rc;

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

    pv_cpuid(regs);

    instruction_done(regs, eip, 0);

    trace_trap_one_addr(TRC_PV_FORCED_INVALID_OP, regs->eip);

    return EXCRET_fault_fixed;
}

asmlinkage void do_invalid_op(struct cpu_user_regs *regs)
{
    struct bug_frame bug;
    struct bug_frame_str bug_str;
    const char *filename, *predicate, *eip = (char *)regs->eip;
    unsigned long fixup;
    int id, lineno;

    DEBUGGER_trap_entry(TRAP_invalid_op, regs);

    if ( likely(guest_mode(regs)) )
    {
        if ( !emulate_forced_invalid_op(regs) )
            do_guest_trap(TRAP_invalid_op, regs, 0);
        return;
    }

    if ( !is_kernel(eip) ||
         __copy_from_user(&bug, eip, sizeof(bug)) ||
         memcmp(bug.ud2, "\xf\xb", sizeof(bug.ud2)) ||
         (bug.ret != 0xc2) )
        goto die;
    eip += sizeof(bug);

    id = bug.id & 3;

    if ( id == BUGFRAME_dump )
    {
        show_execution_state(regs);
        regs->eip = (unsigned long)eip;
        return;
    }

    /* WARN, BUG or ASSERT: decode the filename pointer and line number. */
    if ( !is_kernel(eip) ||
         __copy_from_user(&bug_str, eip, sizeof(bug_str)) ||
         (bug_str.mov != 0xbc) )
        goto die;
    filename = bug_str(bug_str, eip);
    eip += sizeof(bug_str);

    if ( !is_kernel(filename) )
        filename = "<unknown>";
    lineno   = bug.id >> 2;

    if ( id == BUGFRAME_warn )
    {
        printk("Xen WARN at %.50s:%d\n", filename, lineno);
        show_execution_state(regs);
        regs->eip = (unsigned long)eip;
        return;
    }

    if ( id == BUGFRAME_bug )
    {
        printk("Xen BUG at %.50s:%d\n", filename, lineno);
        DEBUGGER_trap_fatal(TRAP_invalid_op, regs);
        show_execution_state(regs);
        panic("Xen BUG at %.50s:%d\n", filename, lineno);
    }

    /* ASSERT: decode the predicate string pointer. */
    ASSERT(id == BUGFRAME_assert);
    if ( !is_kernel(eip) ||
         __copy_from_user(&bug_str, eip, sizeof(bug_str)) ||
         (bug_str.mov != 0xbc) )
        goto die;
    predicate = bug_str(bug_str, eip);
    eip += sizeof(bug_str);

    if ( !is_kernel(predicate) )
        predicate = "<unknown>";
    printk("Assertion '%s' failed at %.50s:%d\n",
           predicate, filename, lineno);
    DEBUGGER_trap_fatal(TRAP_invalid_op, regs);
    show_execution_state(regs);
    panic("Assertion '%s' failed at %.50s:%d\n",
          predicate, filename, lineno);

 die:
    if ( (fixup = search_exception_table(regs->eip)) != 0 )
    {
        regs->eip = fixup;
        return;
    }
    DEBUGGER_trap_fatal(TRAP_invalid_op, regs);
    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (invalid opcode)\n", TRAP_invalid_op);
}

asmlinkage void do_int3(struct cpu_user_regs *regs)
{
    DEBUGGER_trap_entry(TRAP_int3, regs);

    if ( !guest_mode(regs) )
    {
        debugger_trap_fatal(TRAP_int3, regs);
        return;
    } 

    do_guest_trap(TRAP_int3, regs, 0);
}

asmlinkage void do_machine_check(struct cpu_user_regs *regs)
{
    machine_check_vector(regs, regs->error_code);
}

static void reserved_bit_page_fault(
    unsigned long addr, struct cpu_user_regs *regs)
{
    printk("d%d:v%d: reserved bit in page table (ec=%04X)\n",
           current->domain->domain_id, current->vcpu_id, regs->error_code);
    show_page_walk(addr);
    show_execution_state(regs);
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

    trace_pv_page_fault(addr, error_code);

    ti = &v->arch.guest_context.trap_ctxt[TRAP_page_fault];
    tb->flags = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;
    if ( unlikely(null_trap_bounce(v, tb)) )
    {
        printk("d%d:v%d: unhandled page fault (ec=%04X)\n",
               v->domain->domain_id, v->vcpu_id, error_code);
        show_page_walk(addr);
    }

    if ( unlikely(error_code & PFEC_reserved_bit) )
        reserved_bit_page_fault(addr, guest_cpu_user_regs());
}

static int handle_gdt_ldt_mapping_fault(
    unsigned long offset, struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    /* Which vcpu's area did we fault in, and is it in the ldt sub-area? */
    unsigned int is_ldt_area = (offset >> (GDT_LDT_VCPU_VA_SHIFT-1)) & 1;
    unsigned int vcpu_area   = (offset >> GDT_LDT_VCPU_VA_SHIFT);

    /* Should never fault in another vcpu's area. */
    BUG_ON(vcpu_area != curr->vcpu_id);

    /* Byte offset within the gdt/ldt sub-area. */
    offset &= (1UL << (GDT_LDT_VCPU_VA_SHIFT-1)) - 1UL;

    if ( likely(is_ldt_area) )
    {
        /* LDT fault: Copy a mapping from the guest's LDT, if it is valid. */
        if ( likely(map_ldt_shadow_page(offset >> PAGE_SHIFT)) )
        {
            if ( guest_mode(regs) )
                trace_trap_two_addr(TRC_PV_GDT_LDT_MAPPING_FAULT,
                                    regs->eip, offset);
        }
        else
        {
            /* In hypervisor mode? Leave it to the #PF handler to fix up. */
            if ( !guest_mode(regs) )
                return 0;
            /* In guest mode? Propagate #PF to guest, with adjusted %cr2. */
            propagate_page_fault(
                curr->arch.guest_context.ldt_base + offset,
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
    unsigned long addr, unsigned int error_code)
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

    /*
     * We do not take spurious page faults in IRQ handlers as we do not
     * modify page tables in IRQ context. We therefore bail here because
     * map_domain_page() is not IRQ-safe.
     */
    if ( in_irq() )
        return 0;

    /* Reserved bit violations are never spurious faults. */
    if ( error_code & PFEC_reserved_bit )
        return 0;

    required_flags  = _PAGE_PRESENT;
    if ( error_code & PFEC_write_access )
        required_flags |= _PAGE_RW;
    if ( error_code & PFEC_user_mode )
        required_flags |= _PAGE_USER;

    disallowed_flags = 0;
    if ( error_code & PFEC_insn_fetch )
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
#if CONFIG_PAGING_LEVELS == 3
    l3t += (cr3 & 0xFE0UL) >> 3;
#endif
    l3e = l3e_read_atomic(&l3t[l3_table_offset(addr)]);
    mfn = l3e_get_pfn(l3e);
    unmap_domain_page(l3t);
#if CONFIG_PAGING_LEVELS == 3
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
            addr, error_code);
#if CONFIG_PAGING_LEVELS >= 4
    dprintk(XENLOG_WARNING, " l4e = %"PRIpte"\n", l4e_get_intpte(l4e));
#endif
#if CONFIG_PAGING_LEVELS >= 3
    dprintk(XENLOG_WARNING, " l3e = %"PRIpte"\n", l3e_get_intpte(l3e));
#endif
    dprintk(XENLOG_WARNING, " l2e = %"PRIpte"\n", l2e_get_intpte(l2e));
    dprintk(XENLOG_WARNING, " l1e = %"PRIpte"\n", l1e_get_intpte(l1e));
    return 1;
}

static int spurious_page_fault(
    unsigned long addr, unsigned int error_code)
{
    unsigned long flags;
    int           is_spurious;

    /*
     * Disabling interrupts prevents TLB flushing, and hence prevents
     * page tables from becoming invalid under our feet during the walk.
     */
    local_irq_save(flags);
    is_spurious = __spurious_page_fault(addr, error_code);
    local_irq_restore(flags);

    return is_spurious;
}

static int fixup_page_fault(unsigned long addr, struct cpu_user_regs *regs)
{
    struct vcpu   *v = current;
    struct domain *d = v->domain;

    /* No fixups in interrupt context or when interrupts are disabled. */
    if ( in_irq() || !(regs->eflags & X86_EFLAGS_IF) )
        return 0;

    /* Faults from external-mode guests are handled by shadow/hap */
    if ( paging_mode_external(d) && guest_mode(regs) )
    {
        int ret = paging_fault(addr, regs);
        if ( ret == EXCRET_fault_fixed )
            trace_trap_two_addr(TRC_PV_PAGING_FIXUP, regs->eip, addr);
        return ret;
    }

    if ( unlikely(IN_HYPERVISOR_RANGE(addr)) )
    {
        if ( !(regs->error_code & PFEC_reserved_bit) &&
             (addr >= GDT_LDT_VIRT_START) && (addr < GDT_LDT_VIRT_END) )
            return handle_gdt_ldt_mapping_fault(
                addr - GDT_LDT_VIRT_START, regs);
        return 0;
    }

    if ( VM_ASSIST(d, VMASST_TYPE_writable_pagetables) &&
         guest_kernel_mode(v, regs) &&
         /* Do not check if access-protection fault since the page may 
            legitimately be not present in shadow page tables */
         ((regs->error_code & (PFEC_write_access|PFEC_reserved_bit)) ==
          PFEC_write_access) &&
         ptwr_do_page_fault(v, addr, regs) )
        return EXCRET_fault_fixed;

    /* For non-external shadowed guests, we fix up both their own 
     * pagefaults and Xen's, since they share the pagetables. */
    if ( paging_mode_enabled(d) && !paging_mode_external(d) )
    {
        int ret = paging_fault(addr, regs);
        if ( ret == EXCRET_fault_fixed )
            trace_trap_two_addr(TRC_PV_PAGING_FIXUP, regs->eip, addr);
        return ret;
    }

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
asmlinkage void do_page_fault(struct cpu_user_regs *regs)
{
    unsigned long addr, fixup;
    unsigned int error_code;

    addr = read_cr2();

    /* fixup_page_fault() might change regs->error_code, so cache it here. */
    error_code = regs->error_code;

    DEBUGGER_trap_entry(TRAP_page_fault, regs);

    perfc_incr(page_faults);

    if ( unlikely(fixup_page_fault(addr, regs) != 0) )
        return;

    if ( unlikely(!guest_mode(regs)) )
    {
        if ( spurious_page_fault(addr, error_code) )
            return;

        if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
        {
            perfc_incr(copy_user_faults);
            if ( unlikely(regs->error_code & PFEC_reserved_bit) )
                reserved_bit_page_fault(addr, regs);
            regs->eip = fixup;
            return;
        }

        DEBUGGER_trap_fatal(TRAP_page_fault, regs);

        show_execution_state(regs);
        show_page_walk(addr);
        panic("FATAL PAGE FAULT\n"
              "[error_code=%04x]\n"
              "Faulting linear address: %p\n",
              error_code, _p(addr));
    }

    if ( unlikely(current->domain->arch.suppress_spurious_page_faults
                  && spurious_page_fault(addr, error_code)) )
        return;

    propagate_page_fault(addr, regs->error_code);
}

/*
 * Early #PF handler to print CR2, error code, and stack.
 * 
 * We also deal with spurious faults here, even though they should never happen
 * during early boot (an issue was seen once, but was most likely a hardware 
 * problem).
 */
asmlinkage void do_early_page_fault(struct cpu_user_regs *regs)
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
        return;
    }

    if ( stuck++ == 1000 )
    {
        unsigned long *stk = (unsigned long *)regs;
        printk("Early fatal page fault at %04x:%p (cr2=%p, ec=%04x)\n", 
               regs->cs, _p(regs->eip), _p(cr2), regs->error_code);
        printk("Stack dump: ");
        while ( ((long)stk & ((PAGE_SIZE - 1) & ~(BYTES_PER_LONG - 1))) != 0 )
            printk("%p ", _p(*stk++));
        for ( ; ; ) ;
    }
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
        if ( v->fpu_dirtied )
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
        *base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                 (desc.b & 0xff000000));
        *limit = (desc.a & 0xffff) | (desc.b & 0x000f0000);
        if ( desc.b & _SEGMENT_G )
            *limit = ((*limit + 1) << 12) - 1;
#ifndef NDEBUG
        if ( !vm86_mode(regs) && (sel > 3) )
        {
            unsigned int a, l;
            unsigned char valid;

            asm volatile (
                "larl %2,%0 ; setz %1"
                : "=r" (a), "=qm" (valid) : "rm" (sel));
            BUG_ON(valid && ((a & 0x00f0ff00) != *ar));
            asm volatile (
                "lsll %2,%0 ; setz %1"
                : "=r" (l), "=qm" (valid) : "rm" (sel));
            BUG_ON(valid && (l != *limit));
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

#ifdef __x86_64__
static int read_gate_descriptor(unsigned int gate_sel,
                                const struct vcpu *v,
                                unsigned int *sel,
                                unsigned long *off,
                                unsigned int *ar)
{
    struct desc_struct desc;
    const struct desc_struct *pdesc;


    pdesc = (const struct desc_struct *)
        (!(gate_sel & 4) ? GDT_VIRT_START(v) : LDT_VIRT_START(v))
        + (gate_sel >> 3);
    if ( (gate_sel < 4) ||
         ((gate_sel >= FIRST_RESERVED_GDT_BYTE) && !(gate_sel & 4)) ||
         __get_user(desc, pdesc) )
        return 0;

    *sel = (desc.a >> 16) & 0x0000fffc;
    *off = (desc.a & 0x0000ffff) | (desc.b & 0xffff0000);
    *ar = desc.b & 0x0000ffff;

    /*
     * check_descriptor() clears the DPL field and stores the
     * guest requested DPL in the selector's RPL field.
     */
    if ( *ar & _SEGMENT_DPL )
        return 0;
    *ar |= (desc.a >> (16 - 13)) & _SEGMENT_DPL;

    if ( !is_pv_32bit_vcpu(v) )
    {
        if ( (*ar & 0x1f00) != 0x0c00 ||
             (gate_sel >= FIRST_RESERVED_GDT_BYTE - 8 && !(gate_sel & 4)) ||
             __get_user(desc, pdesc + 1) ||
             (desc.b & 0x1f00) )
            return 0;

        *off |= (unsigned long)desc.a << 32;
        return 1;
    }

    switch ( *ar & 0x1f00 )
    {
    case 0x0400:
        *off &= 0xffff;
        break;
    case 0x0c00:
        break;
    default:
        return 0;
    }

    return 1;
}
#endif

/* Has the guest requested sufficient permission for this I/O access? */
static int guest_io_okay(
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
        switch ( __copy_from_guest_offset(x.bytes, v->arch.iobmp,
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
static int admin_io_okay(
    unsigned int port, unsigned int bytes,
    struct vcpu *v, struct cpu_user_regs *regs)
{
    /*
     * Port 0xcf8 (CONFIG_ADDRESS) is only visible for DWORD accesses.
     * We never permit direct access to that register.
     */
    if ( (port == 0xcf8) && (bytes == 4) )
        return 0;

    return ioports_access_permitted(v->domain, port, port + bytes - 1);
}

static uint32_t guest_io_read(
    unsigned int port, unsigned int bytes,
    struct vcpu *v, struct cpu_user_regs *regs)
{
    extern uint32_t pci_conf_read(
        uint32_t cf8, uint8_t offset, uint8_t bytes);

    uint32_t data = 0;
    unsigned int shift = 0;

    if ( admin_io_okay(port, bytes, v, regs) )
    {
        switch ( bytes )
        {
        case 1: return inb(port);
        case 2: return inw(port);
        case 4: return inl(port);
        }
    }

    while ( bytes != 0 )
    {
        unsigned int size = 1;
        uint32_t sub_data = 0xff;

        if ( (port == 0x42) || (port == 0x43) || (port == 0x61) )
        {
            sub_data = pv_pit_handler(port, 0, 0);
        }
        else if ( (port == 0xcf8) && (bytes == 4) )
        {
            size = 4;
            sub_data = v->domain->arch.pci_cf8;
        }
        else if ( ((port & 0xfffc) == 0xcfc) && IS_PRIV(v->domain) )
        {
            size = min(bytes, 4 - (port & 3));
            if ( size == 3 )
                size = 2;
            sub_data = pci_conf_read(v->domain->arch.pci_cf8, port & 3, size);
        }

        if ( size == 4 )
            return sub_data;

        data |= (sub_data & ((1u << (size * 8)) - 1)) << shift;
        shift += size * 8;
        port += size;
        bytes -= size;
    }

    return data;
}

extern void (*pv_rtc_handler)(unsigned int port, uint8_t value);

static void guest_io_write(
    unsigned int port, unsigned int bytes, uint32_t data,
    struct vcpu *v, struct cpu_user_regs *regs)
{
    extern void pci_conf_write(
        uint32_t cf8, uint8_t offset, uint8_t bytes, uint32_t data);

    if ( admin_io_okay(port, bytes, v, regs) )
    {
        switch ( bytes ) {
        case 1:
            if ( ((port == 0x70) || (port == 0x71)) && pv_rtc_handler )
                pv_rtc_handler(port, (uint8_t)data);
            outb((uint8_t)data, port);
            if ( pv_post_outb_hook )
                pv_post_outb_hook(port, (uint8_t)data);
            break;
        case 2:
            outw((uint16_t)data, port);
            break;
        case 4:
            outl(data, port);
            break;
        }
        return;
    }

    while ( bytes != 0 )
    {
        unsigned int size = 1;

        if ( (port == 0x42) || (port == 0x43) || (port == 0x61) )
        {
            pv_pit_handler(port, (uint8_t)data, 1);
        }
        else if ( (port == 0xcf8) && (bytes == 4) )
        {
            size = 4;
            v->domain->arch.pci_cf8 = data;
        }
        else if ( ((port & 0xfffc) == 0xcfc) && IS_PRIV(v->domain) )
        {
            size = min(bytes, 4 - (port & 3));
            if ( size == 3 )
                size = 2;
            pci_conf_write(v->domain->arch.pci_cf8, port & 3, size, data);
        }

        if ( size == 4 )
            return;

        port += size;
        bytes -= size;
        data >>= size * 8;
    }
}

/* I/O emulation support. Helper routines for, and type of, the stack stub.*/
void host_to_guest_gpr_switch(struct cpu_user_regs *)
    __attribute__((__regparm__(1)));
unsigned long guest_to_host_gpr_switch(unsigned long)
    __attribute__((__regparm__(1)));

void (*pv_post_outb_hook)(unsigned int port, u8 value);

/* Instruction fetch with error handling. */
#define insn_fetch(type, base, eip, limit)                                  \
({  unsigned long _rc, _ptr = (base) + (eip);                               \
    type _x;                                                                \
    if ( ad_default < 8 )                                                   \
        _ptr = (unsigned int)_ptr;                                          \
    if ( (limit) < sizeof(_x) - 1 || (eip) > (limit) - (sizeof(_x) - 1) )   \
        goto fail;                                                          \
    if ( (_rc = copy_from_user(&_x, (type *)_ptr, sizeof(_x))) != 0 )       \
    {                                                                       \
        propagate_page_fault(_ptr + sizeof(_x) - _rc, 0);                   \
        goto skip;                                                          \
    }                                                                       \
    (eip) += sizeof(_x); _x; })

#if defined(CONFIG_X86_32)
# define read_sreg(regs, sr) ((regs)->sr)
#elif defined(CONFIG_X86_64)
# define read_sreg(regs, sr) read_segment_register(sr)
#endif

static int is_cpufreq_controller(struct domain *d)
{
    return ((cpufreq_controller == FREQCTL_dom0_kernel) &&
            (d->domain_id == 0));
}

static int emulate_privileged_op(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    unsigned long *reg, eip = regs->eip;
    u8 opcode, modrm_reg = 0, modrm_rm = 0, rep_prefix = 0, lock = 0, rex = 0;
    enum { lm_seg_none, lm_seg_fs, lm_seg_gs } lm_ovr = lm_seg_none;
    int rc;
    unsigned int port, i, data_sel, ar, data, bpmatch = 0;
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
    char io_emul_stub[32];
    void (*io_emul)(struct cpu_user_regs *) __attribute__((__regparm__(1)));
    uint32_t l, h;
    uint64_t val;

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
        op_bytes = 4; /* emulate only opcodes not supporting 64-bit operands */
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
                                  _SEGMENT_WR|_SEGMENT_S|_SEGMENT_DPL|
                                  _SEGMENT_P) )
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

        port = (u16)regs->edx;

    continue_io_string:
        switch ( opcode )
        {
        case 0x6c: /* INSB */
            op_bytes = 1;
        case 0x6d: /* INSW/INSL */
            if ( (data_limit < (op_bytes - 1)) ||
                 (rd_ad(edi) > (data_limit - (op_bytes - 1))) ||
                 !guest_io_okay(port, op_bytes, v, regs) )
                goto fail;
            data = guest_io_read(port, op_bytes, v, regs);
            if ( (rc = copy_to_user((void *)data_base + rd_ad(edi),
                                    &data, op_bytes)) != 0 )
            {
                propagate_page_fault(data_base + rd_ad(edi) + op_bytes - rc,
                                     PFEC_write_access);
                return EXCRET_fault_fixed;
            }
            wr_ad(edi, regs->edi + (int)((regs->eflags & X86_EFLAGS_DF)
                                         ? -op_bytes : op_bytes));
            break;

        case 0x6e: /* OUTSB */
            op_bytes = 1;
        case 0x6f: /* OUTSW/OUTSL */
            if ( (data_limit < (op_bytes - 1)) ||
                 (rd_ad(esi) > (data_limit - (op_bytes - 1))) ||
                  !guest_io_okay(port, op_bytes, v, regs) )
                goto fail;
            if ( (rc = copy_from_user(&data, (void *)data_base + rd_ad(esi),
                                      op_bytes)) != 0 )
            {
                propagate_page_fault(data_base + rd_ad(esi)
                                     + op_bytes - rc, 0);
                return EXCRET_fault_fixed;
            }
            guest_io_write(port, op_bytes, data, v, regs);
            wr_ad(esi, regs->esi + (int)((regs->eflags & X86_EFLAGS_DF)
                                         ? -op_bytes : op_bytes));
            break;
        }

        bpmatch = check_guest_io_breakpoint(v, port, op_bytes);

        if ( rep_prefix && (wr_ad(ecx, regs->ecx - 1) != 0) )
        {
            if ( !bpmatch && !hypercall_preempt_check() )
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
#ifdef __x86_64__
    /* movq $host_to_guest_gpr_switch,%rcx */
    io_emul_stub[0] = 0x48;
    io_emul_stub[1] = 0xb9;
    *(void **)&io_emul_stub[2] = (void *)host_to_guest_gpr_switch;
    /* callq *%rcx */
    io_emul_stub[10] = 0xff;
    io_emul_stub[11] = 0xd1;
#else
    /* call host_to_guest_gpr_switch */
    io_emul_stub[0] = 0xe8;
    *(s32 *)&io_emul_stub[1] =
        (char *)host_to_guest_gpr_switch - &io_emul_stub[5];
    /* 7 x nop */
    memset(&io_emul_stub[5], 0x90, 7);
#endif
    /* data16 or nop */
    io_emul_stub[12] = (op_bytes != 2) ? 0x90 : 0x66;
    /* <io-access opcode> */
    io_emul_stub[13] = opcode;
    /* imm8 or nop */
    io_emul_stub[14] = 0x90;
    /* ret (jumps to guest_to_host_gpr_switch) */
    io_emul_stub[15] = 0xc3;

    /* Handy function-typed pointer to the stub. */
    io_emul = (void *)io_emul_stub;

    if ( ioemul_handle_quirk )
        ioemul_handle_quirk(opcode, &io_emul_stub[12], regs);

    /* I/O Port and Interrupt Flag instructions. */
    switch ( opcode )
    {
    case 0xe4: /* IN imm8,%al */
        op_bytes = 1;
    case 0xe5: /* IN imm8,%eax */
        port = insn_fetch(u8, code_base, eip, code_limit);
        io_emul_stub[14] = port; /* imm8 */
    exec_in:
        if ( !guest_io_okay(port, op_bytes, v, regs) )
            goto fail;
        if ( admin_io_okay(port, op_bytes, v, regs) )
        {
            io_emul(regs);            
        }
        else
        {
            if ( op_bytes == 4 )
                regs->eax = 0;
            else
                regs->eax &= ~((1u << (op_bytes * 8)) - 1);
            regs->eax |= guest_io_read(port, op_bytes, v, regs);
        }
        bpmatch = check_guest_io_breakpoint(v, port, op_bytes);
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
        io_emul_stub[14] = port; /* imm8 */
    exec_out:
        if ( !guest_io_okay(port, op_bytes, v, regs) )
            goto fail;
        if ( admin_io_okay(port, op_bytes, v, regs) )
        {
            if ( (op_bytes == 1) &&
                 ((port == 0x71) || (port == 0x70)) &&
                 pv_rtc_handler )
                pv_rtc_handler(port, regs->eax);
            io_emul(regs);            
            if ( (op_bytes == 1) && pv_post_outb_hook )
                pv_post_outb_hook(port, regs->eax);
        }
        else
        {
            guest_io_write(port, op_bytes, regs->eax, v, regs);
        }
        bpmatch = check_guest_io_breakpoint(v, port, op_bytes);
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
        if ( opcode < 0xc0 )
            goto fail;
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
            if ( !is_pv_32on64_vcpu(v) )
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
             * therefore lie about PGE as it is unavailable to guests.
             * Also disallow PSE if hugepages are not enabled.
             */
            *reg = read_cr4() & ~X86_CR4_PGE;
            if ( !opt_allow_hugepage )
                *reg &= ~X86_CR4_PSE;
            break;

        default:
            goto fail;
        }
        break;

    case 0x21: /* MOV DR?,<reg> */ {
        unsigned long res;
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        if ( opcode < 0xc0 )
            goto fail;
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        if ( (res = do_get_debugreg(modrm_reg)) > (unsigned long)-256 )
            goto fail;
        *reg = res;
        break;
    }

    case 0x22: /* MOV <reg>,CR? */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        if ( opcode < 0xc0 )
            goto fail;
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
            domain_lock(v->domain);
            if ( !is_pv_32on64_vcpu(v) )
                rc = new_guest_cr3(gmfn_to_mfn(v->domain, xen_cr3_to_pfn(*reg)));
#ifdef CONFIG_COMPAT
            else
                rc = new_guest_cr3(gmfn_to_mfn(v->domain, compat_cr3_to_pfn(*reg)));
#endif
            domain_unlock(v->domain);
            if ( rc == 0 ) /* not okay */
                goto fail;
            break;

        case 4: /* Write CR4 */
            v->arch.guest_context.ctrlreg[4] = pv_guest_cr4_fixup(*reg);
            write_cr4(pv_guest_cr4_to_real_cr4(
                v->arch.guest_context.ctrlreg[4]));
            break;

        default:
            goto fail;
        }
        break;

    case 0x23: /* MOV <reg>,DR? */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        if ( opcode < 0xc0 )
            goto fail;
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        if ( do_set_debugreg(modrm_reg, *reg) != 0 )
            goto fail;
        break;

    case 0x30: /* WRMSR */ {
        u32 eax = regs->eax;
        u32 edx = regs->edx;
        u64 val = ((u64)edx << 32) | eax;
        switch ( (u32)regs->ecx )
        {
#ifdef CONFIG_X86_64
        case MSR_FS_BASE:
            if ( is_pv_32on64_vcpu(v) )
                goto fail;
            if ( wrmsr_safe(MSR_FS_BASE, eax, edx) )
                goto fail;
            v->arch.guest_context.fs_base = val;
            break;
        case MSR_GS_BASE:
            if ( is_pv_32on64_vcpu(v) )
                goto fail;
            if ( wrmsr_safe(MSR_GS_BASE, eax, edx) )
                goto fail;
            v->arch.guest_context.gs_base_kernel = val;
            break;
        case MSR_SHADOW_GS_BASE:
            if ( is_pv_32on64_vcpu(v) )
                goto fail;
            if ( wrmsr_safe(MSR_SHADOW_GS_BASE, eax, edx) )
                goto fail;
            v->arch.guest_context.gs_base_user = val;
            break;
#endif
        case MSR_K7_FID_VID_STATUS:
        case MSR_K7_FID_VID_CTL:
        case MSR_K8_PSTATE_LIMIT:
        case MSR_K8_PSTATE_CTRL:
        case MSR_K8_PSTATE_STATUS:
        case MSR_K8_PSTATE0:
        case MSR_K8_PSTATE1:
        case MSR_K8_PSTATE2:
        case MSR_K8_PSTATE3:
        case MSR_K8_PSTATE4:
        case MSR_K8_PSTATE5:
        case MSR_K8_PSTATE6:
        case MSR_K8_PSTATE7:
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
                goto fail;
            if ( !is_cpufreq_controller(v->domain) )
                break;
            if ( wrmsr_safe(regs->ecx, eax, edx) != 0 )
                goto fail;
            break;
        case MSR_AMD64_NB_CFG:
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
                 boot_cpu_data.x86 < 0x10 || boot_cpu_data.x86 > 0x11 )
                goto fail;
            if ( !IS_PRIV(v->domain) )
                break;
            if ( (rdmsr_safe(MSR_AMD64_NB_CFG, l, h) != 0) ||
                 (eax != l) ||
                 ((edx ^ h) & ~(1 << (AMD64_NB_CFG_CF8_EXT_ENABLE_BIT - 32))) )
                goto invalid;
            if ( wrmsr_safe(MSR_AMD64_NB_CFG, eax, edx) != 0 )
                goto fail;
            break;
        case MSR_FAM10H_MMIO_CONF_BASE:
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
                 boot_cpu_data.x86 < 0x10 || boot_cpu_data.x86 > 0x11 )
                goto fail;
            if ( !IS_PRIV(v->domain) )
                break;
            if ( (rdmsr_safe(MSR_FAM10H_MMIO_CONF_BASE, l, h) != 0) ||
                 (((((u64)h << 32) | l) ^ val) &
                  ~( FAM10H_MMIO_CONF_ENABLE |
                    (FAM10H_MMIO_CONF_BUSRANGE_MASK <<
                     FAM10H_MMIO_CONF_BUSRANGE_SHIFT) |
                    ((u64)FAM10H_MMIO_CONF_BASE_MASK <<
                     FAM10H_MMIO_CONF_BASE_SHIFT))) )
                goto invalid;
            if ( wrmsr_safe(MSR_FAM10H_MMIO_CONF_BASE, eax, edx) != 0 )
                goto fail;
            break;
        case MSR_IA32_MPERF:
        case MSR_IA32_APERF:
        case MSR_IA32_PERF_CTL:
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
                goto fail;
            if ( !is_cpufreq_controller(v->domain) )
                break;
            if ( wrmsr_safe(regs->ecx, eax, edx) != 0 )
                goto fail;
            break;
        case MSR_IA32_THERM_CONTROL:
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
                goto fail;
            if ( (v->domain->domain_id != 0) || !v->domain->is_pinned )
                break;
            if ( wrmsr_safe(regs->ecx, eax, edx) != 0 )
                goto fail;
            break;
        default:
            if ( wrmsr_hypervisor_regs(regs->ecx, val) )
                break;

            rc = mce_wrmsr(regs->ecx, val);
            if ( rc < 0 )
                goto fail;
            if ( rc )
                break;

            if ( (rdmsr_safe(regs->ecx, l, h) != 0) ||
                 (eax != l) || (edx != h) )
        invalid:
                gdprintk(XENLOG_WARNING, "Domain attempted WRMSR %p from "
                        "%08x:%08x to %08x:%08x.\n",
                        _p(regs->ecx), h, l, edx, eax);
            break;
        }
        break;
    }

    case 0x31: /* RDTSC */
        rdtsc(regs->eax, regs->edx);
        break;

    case 0x32: /* RDMSR */
        switch ( (u32)regs->ecx )
        {
#ifdef CONFIG_X86_64
        case MSR_FS_BASE:
            if ( is_pv_32on64_vcpu(v) )
                goto fail;
            regs->eax = v->arch.guest_context.fs_base & 0xFFFFFFFFUL;
            regs->edx = v->arch.guest_context.fs_base >> 32;
            break;
        case MSR_GS_BASE:
            if ( is_pv_32on64_vcpu(v) )
                goto fail;
            regs->eax = v->arch.guest_context.gs_base_kernel & 0xFFFFFFFFUL;
            regs->edx = v->arch.guest_context.gs_base_kernel >> 32;
            break;
        case MSR_SHADOW_GS_BASE:
            if ( is_pv_32on64_vcpu(v) )
                goto fail;
            regs->eax = v->arch.guest_context.gs_base_user & 0xFFFFFFFFUL;
            regs->edx = v->arch.guest_context.gs_base_user >> 32;
            break;
#endif
        case MSR_K7_FID_VID_CTL:
        case MSR_K7_FID_VID_STATUS:
        case MSR_K8_PSTATE_LIMIT:
        case MSR_K8_PSTATE_CTRL:
        case MSR_K8_PSTATE_STATUS:
        case MSR_K8_PSTATE0:
        case MSR_K8_PSTATE1:
        case MSR_K8_PSTATE2:
        case MSR_K8_PSTATE3:
        case MSR_K8_PSTATE4:
        case MSR_K8_PSTATE5:
        case MSR_K8_PSTATE6:
        case MSR_K8_PSTATE7:
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
                goto fail;
            if ( !is_cpufreq_controller(v->domain) )
            {
                regs->eax = regs->edx = 0;
                break;
            }
            if ( rdmsr_safe(regs->ecx, regs->eax, regs->edx) != 0 )
                goto fail;
            break;
        case MSR_IA32_MISC_ENABLE:
            if ( rdmsr_safe(regs->ecx, regs->eax, regs->edx) )
                goto fail;
            regs->eax &= ~(MSR_IA32_MISC_ENABLE_PERF_AVAIL |
                           MSR_IA32_MISC_ENABLE_MONITOR_ENABLE);
            regs->eax |= MSR_IA32_MISC_ENABLE_BTS_UNAVAIL |
                         MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL |
                         MSR_IA32_MISC_ENABLE_XTPR_DISABLE;
            break;
        case MSR_EFER:
        case MSR_AMD_PATCHLEVEL:
        default:
            if ( rdmsr_hypervisor_regs(regs->ecx, &val) )
            {
 rdmsr_writeback:
                regs->eax = (uint32_t)val;
                regs->edx = (uint32_t)(val >> 32);
                break;
            }

            rc = mce_rdmsr(regs->ecx, &val);
            if ( rc < 0 )
                goto fail;
            if ( rc )
                goto rdmsr_writeback;

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
    instruction_done(regs, eip, bpmatch);
 skip:
    return EXCRET_fault_fixed;

 fail:
    return 0;
}

static inline int check_stack_limit(unsigned int ar, unsigned int limit,
                                    unsigned int esp, unsigned int decr)
{
    return (((esp - decr) < (esp - 1)) &&
            (!(ar & _SEGMENT_EC) ? (esp - 1) <= limit : (esp - decr) > limit));
}

static void emulate_gate_op(struct cpu_user_regs *regs)
{
#ifdef __x86_64__
    struct vcpu *v = current;
    unsigned int sel, ar, dpl, nparm, opnd_sel;
    unsigned int op_default, op_bytes, ad_default, ad_bytes;
    unsigned long off, eip, opnd_off, base, limit;
    int jump;

    /* Check whether this fault is due to the use of a call gate. */
    if ( !read_gate_descriptor(regs->error_code, v, &sel, &off, &ar) ||
         (((ar >> 13) & 3) < (regs->cs & 3)) ||
         ((ar & _SEGMENT_TYPE) != 0xc00) )
    {
        do_guest_trap(TRAP_gp_fault, regs, 1);
        return;
    }
    if ( !(ar & _SEGMENT_P) )
    {
        do_guest_trap(TRAP_no_segment, regs, 1);
        return;
    }
    dpl = (ar >> 13) & 3;
    nparm = ar & 0x1f;

    /*
     * Decode instruction (and perhaps operand) to determine RPL,
     * whether this is a jump or a call, and the call return offset.
     */
    if ( !read_descriptor(regs->cs, v, regs, &base, &limit, &ar, 0) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         !(ar & _SEGMENT_CODE) )
    {
        do_guest_trap(TRAP_gp_fault, regs, 1);
        return;
    }

    op_bytes = op_default = ar & _SEGMENT_DB ? 4 : 2;
    ad_default = ad_bytes = op_default;
    opnd_sel = opnd_off = 0;
    jump = -1;
    for ( eip = regs->eip; eip - regs->_eip < 10; )
    {
        switch ( insn_fetch(u8, base, eip, limit) )
        {
        case 0x66: /* operand-size override */
            op_bytes = op_default ^ 6; /* switch between 2/4 bytes */
            continue;
        case 0x67: /* address-size override */
            ad_bytes = ad_default != 4 ? 4 : 2; /* switch to 2/4 bytes */
            continue;
        case 0x2e: /* CS override */
            opnd_sel = regs->cs;
            ASSERT(opnd_sel);
            continue;
        case 0x3e: /* DS override */
            opnd_sel = read_sreg(regs, ds);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x26: /* ES override */
            opnd_sel = read_sreg(regs, es);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x64: /* FS override */
            opnd_sel = read_sreg(regs, fs);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x65: /* GS override */
            opnd_sel = read_sreg(regs, gs);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x36: /* SS override */
            opnd_sel = regs->ss;
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0xea:
            ++jump;
            /* FALLTHROUGH */
        case 0x9a:
            ++jump;
            opnd_sel = regs->cs;
            opnd_off = eip;
            ad_bytes = ad_default;
            eip += op_bytes + 2;
            break;
        case 0xff:
            {
                unsigned int modrm;

                switch ( (modrm = insn_fetch(u8, base, eip, limit)) & 0xf8 )
                {
                case 0x28: case 0x68: case 0xa8:
                    ++jump;
                    /* FALLTHROUGH */
                case 0x18: case 0x58: case 0x98:
                    ++jump;
                    if ( ad_bytes != 2 )
                    {
                        if ( (modrm & 7) == 4 )
                        {
                            unsigned int sib;
                            sib = insn_fetch(u8, base, eip, limit);

                            modrm = (modrm & ~7) | (sib & 7);
                            if ( (sib >>= 3) != 4 )
                                opnd_off = *(unsigned long *)
                                    decode_register(sib & 7, regs, 0);
                            opnd_off <<= sib >> 3;
                        }
                        if ( (modrm & 7) != 5 || (modrm & 0xc0) )
                            opnd_off += *(unsigned long *)
                                decode_register(modrm & 7, regs, 0);
                        else
                            modrm |= 0x87;
                        if ( !opnd_sel )
                        {
                            switch ( modrm & 7 )
                            {
                            default:
                                opnd_sel = read_sreg(regs, ds);
                                break;
                            case 4: case 5:
                                opnd_sel = regs->ss;
                                break;
                            }
                        }
                    }
                    else
                    {
                        switch ( modrm & 7 )
                        {
                        case 0: case 1: case 7:
                            opnd_off = regs->ebx;
                            break;
                        case 6:
                            if ( !(modrm & 0xc0) )
                                modrm |= 0x80;
                            else
                        case 2: case 3:
                            {
                                opnd_off = regs->ebp;
                                if ( !opnd_sel )
                                    opnd_sel = regs->ss;
                            }
                            break;
                        }
                        if ( !opnd_sel )
                            opnd_sel = read_sreg(regs, ds);
                        switch ( modrm & 7 )
                        {
                        case 0: case 2: case 4:
                            opnd_off += regs->esi;
                            break;
                        case 1: case 3: case 5:
                            opnd_off += regs->edi;
                            break;
                        }
                    }
                    switch ( modrm & 0xc0 )
                    {
                    case 0x40:
                        opnd_off += insn_fetch(s8, base, eip, limit);
                        break;
                    case 0x80:
                        opnd_off += insn_fetch(s32, base, eip, limit);
                        break;
                    }
                    if ( ad_bytes == 4 )
                        opnd_off = (unsigned int)opnd_off;
                    else if ( ad_bytes == 2 )
                        opnd_off = (unsigned short)opnd_off;
                    break;
                }
            }
            break;
        }
        break;
    }

    if ( jump < 0 )
    {
 fail:
        do_guest_trap(TRAP_gp_fault, regs, 1);
 skip:
        return;
    }

    if ( (opnd_sel != regs->cs &&
          !read_descriptor(opnd_sel, v, regs, &base, &limit, &ar, 0)) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         ((ar & _SEGMENT_CODE) && !(ar & _SEGMENT_WR)) )
    {
        do_guest_trap(TRAP_gp_fault, regs, 1);
        return;
    }

    opnd_off += op_bytes;
#define ad_default ad_bytes
    opnd_sel = insn_fetch(u16, base, opnd_off, limit);
#undef ad_default
    ASSERT((opnd_sel & ~3) == regs->error_code);
    if ( dpl < (opnd_sel & 3) )
    {
        do_guest_trap(TRAP_gp_fault, regs, 1);
        return;
    }

    if ( !read_descriptor(sel, v, regs, &base, &limit, &ar, 0) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_CODE) ||
         (!jump || (ar & _SEGMENT_EC) ?
          ((ar >> 13) & 3) > (regs->cs & 3) :
          ((ar >> 13) & 3) != (regs->cs & 3)) )
    {
        regs->error_code = sel;
        do_guest_trap(TRAP_gp_fault, regs, 1);
        return;
    }
    if ( !(ar & _SEGMENT_P) )
    {
        regs->error_code = sel;
        do_guest_trap(TRAP_no_segment, regs, 1);
        return;
    }
    if ( off > limit )
    {
        regs->error_code = 0;
        do_guest_trap(TRAP_gp_fault, regs, 1);
        return;
    }

    if ( !jump )
    {
        unsigned int ss, esp, *stkp;
        int rc;
#define push(item) do \
        { \
            --stkp; \
            esp -= 4; \
            rc = __put_user(item, stkp); \
            if ( rc ) \
            { \
                propagate_page_fault((unsigned long)(stkp + 1) - rc, \
                                     PFEC_write_access); \
                return; \
            } \
        } while ( 0 )

        if ( ((ar >> 13) & 3) < (regs->cs & 3) )
        {
            sel |= (ar >> 13) & 3;
            /* Inner stack known only for kernel ring. */
            if ( (sel & 3) != GUEST_KERNEL_RPL(v->domain) )
            {
                do_guest_trap(TRAP_gp_fault, regs, 1);
                return;
            }
            esp = v->arch.guest_context.kernel_sp;
            ss = v->arch.guest_context.kernel_ss;
            if ( (ss & 3) != (sel & 3) ||
                 !read_descriptor(ss, v, regs, &base, &limit, &ar, 0) ||
                 ((ar >> 13) & 3) != (sel & 3) ||
                 !(ar & _SEGMENT_S) ||
                 (ar & _SEGMENT_CODE) ||
                 !(ar & _SEGMENT_WR) )
            {
                regs->error_code = ss & ~3;
                do_guest_trap(TRAP_invalid_tss, regs, 1);
                return;
            }
            if ( !(ar & _SEGMENT_P) ||
                 !check_stack_limit(ar, limit, esp, (4 + nparm) * 4) )
            {
                regs->error_code = ss & ~3;
                do_guest_trap(TRAP_stack_error, regs, 1);
                return;
            }
            stkp = (unsigned int *)(unsigned long)((unsigned int)base + esp);
            if ( !compat_access_ok(stkp - 4 - nparm, (4 + nparm) * 4) )
            {
                do_guest_trap(TRAP_gp_fault, regs, 1);
                return;
            }
            push(regs->ss);
            push(regs->esp);
            if ( nparm )
            {
                const unsigned int *ustkp;

                if ( !read_descriptor(regs->ss, v, regs, &base, &limit, &ar, 0) ||
                     ((ar >> 13) & 3) != (regs->cs & 3) ||
                     !(ar & _SEGMENT_S) ||
                     (ar & _SEGMENT_CODE) ||
                     !(ar & _SEGMENT_WR) ||
                     !check_stack_limit(ar, limit, esp + nparm * 4, nparm * 4) )
                    return do_guest_trap(TRAP_gp_fault, regs, 1);
                ustkp = (unsigned int *)(unsigned long)((unsigned int)base + regs->_esp + nparm * 4);
                if ( !compat_access_ok(ustkp - nparm, nparm * 4) )
                {
                    do_guest_trap(TRAP_gp_fault, regs, 1);
                    return;
                }
                do
                {
                    unsigned int parm;

                    --ustkp;
                    rc = __get_user(parm, ustkp);
                    if ( rc )
                    {
                        propagate_page_fault((unsigned long)(ustkp + 1) - rc, 0);
                        return;
                    }
                    push(parm);
                } while ( --nparm );
            }
        }
        else
        {
            sel |= (regs->cs & 3);
            esp = regs->esp;
            ss = regs->ss;
            if ( !read_descriptor(ss, v, regs, &base, &limit, &ar, 0) ||
                 ((ar >> 13) & 3) != (sel & 3) )
            {
                do_guest_trap(TRAP_gp_fault, regs, 1);
                return;
            }
            if ( !check_stack_limit(ar, limit, esp, 2 * 4) )
            {
                regs->error_code = 0;
                do_guest_trap(TRAP_stack_error, regs, 1);
                return;
            }
            stkp = (unsigned int *)(unsigned long)((unsigned int)base + esp);
            if ( !compat_access_ok(stkp - 2, 2 * 4) )
            {
                do_guest_trap(TRAP_gp_fault, regs, 1);
                return;
            }
        }
        push(regs->cs);
        push(eip);
#undef push
        regs->esp = esp;
        regs->ss = ss;
    }
    else
        sel |= (regs->cs & 3);

    regs->cs = sel;
    instruction_done(regs, off, 0);
#endif
}

asmlinkage void do_general_protection(struct cpu_user_regs *regs)
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
            do_guest_trap(vector, regs, 0);
            return;
        }
    }
    else if ( is_pv_32on64_vcpu(v) && regs->error_code )
    {
        emulate_gate_op(regs);
        return;
    }

    /* Emulate some simple privileged and I/O instructions. */
    if ( (regs->error_code == 0) &&
         emulate_privileged_op(regs) )
    {
        trace_trap_one_addr(TRC_PV_EMULATE_PRIVOP, regs->eip);
        return;
    }

#if defined(__i386__)
    if ( VM_ASSIST(v->domain, VMASST_TYPE_4gb_segments) && 
         (regs->error_code == 0) && 
         gpf_emulate_4gb(regs) )
    {
        TRACE_1D(TRC_PV_EMULATE_4GB, regs->eip);
        return;
    }
#endif

    /* Pass on GPF as is. */
    do_guest_trap(TRAP_gp_fault, regs, 1);
    return;

 gp_in_kernel:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        dprintk(XENLOG_INFO, "GPF (%04x): %p -> %p\n",
                regs->error_code, _p(regs->eip), _p(fixup));
        regs->eip = fixup;
        return;
    }

    DEBUGGER_trap_fatal(TRAP_gp_fault, regs);

 hardware_gp:
    show_execution_state(regs);
    panic("GENERAL PROTECTION FAULT\n[error_code=%04x]\n", regs->error_code);
}

static DEFINE_PER_CPU(struct softirq_trap, softirq_trap);

static void nmi_mce_softirq(void)
{
    int cpu = smp_processor_id();
    struct softirq_trap *st = &per_cpu(softirq_trap, cpu);
    cpumask_t affinity;

    BUG_ON(st == NULL);
    BUG_ON(st->vcpu == NULL);

    /* Set the tmp value unconditionally, so that
     * the check in the iret hypercall works. */
    st->vcpu->cpu_affinity_tmp = st->vcpu->cpu_affinity;

    if ((cpu != st->processor)
       || (st->processor != st->vcpu->processor))
    {
        /* We are on a different physical cpu.
         * Make sure to wakeup the vcpu on the
         * specified processor.
         */
        cpus_clear(affinity);
        cpu_set(st->processor, affinity);
        vcpu_set_affinity(st->vcpu, &affinity);

        /* Affinity is restored in the iret hypercall. */
    }

    /* Only used to defer wakeup of domain/vcpu to
     * a safe (non-NMI/MCE) context.
     */
    vcpu_kick(st->vcpu);
}

static void nmi_dom0_report(unsigned int reason_idx)
{
    struct domain *d = dom0;

    if ( (d == NULL) || (d->vcpu == NULL) || (d->vcpu[0] == NULL) )
        return;

    set_bit(reason_idx, nmi_reason(d));

    send_guest_trap(d, 0, TRAP_nmi);
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

asmlinkage void do_device_not_available(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;

    BUG_ON(!guest_mode(regs));

    setup_fpu(curr);

    if ( curr->arch.guest_context.ctrlreg[0] & X86_CR0_TS )
    {
        do_guest_trap(TRAP_no_device, regs, 0);
        curr->arch.guest_context.ctrlreg[0] &= ~X86_CR0_TS;
    }
    else
        TRACE_0D(TRC_PV_MATH_STATE_RESTORE);

    return;
}

asmlinkage void do_debug(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    DEBUGGER_trap_entry(TRAP_debug, regs);

    if ( !guest_mode(regs) )
    {
        if ( regs->eflags & X86_EFLAGS_TF )
        {
#ifdef __x86_64__
            void sysenter_entry(void);
            void sysenter_eflags_saved(void);
            /* In SYSENTER entry path we can't zap TF until EFLAGS is saved. */
            if ( (regs->rip >= (unsigned long)sysenter_entry) &&
                 (regs->rip <= (unsigned long)sysenter_eflags_saved) )
            {
                if ( regs->rip == (unsigned long)sysenter_eflags_saved )
                    regs->eflags &= ~X86_EFLAGS_TF;
                goto out;
            }
#endif
            if ( !debugger_trap_fatal(TRAP_debug, regs) )
            {
                WARN_ON(1);
                regs->eflags &= ~X86_EFLAGS_TF;
            }
        }
        else
        {
            /*
             * We ignore watchpoints when they trigger within Xen. This may
             * happen when a buffer is passed to us which previously had a
             * watchpoint set on it. No need to bump EIP; the only faulting
             * trap is an instruction breakpoint, which can't happen to us.
             */
            WARN_ON(!search_exception_table(regs->eip));
        }
        goto out;
    }

    /* Save debug status register where guest OS can peek at it */
    v->arch.guest_context.debugreg[6] = read_debugreg(6);

    ler_enable();
    do_guest_trap(TRAP_debug, regs, 0);
    return;

 out:
    ler_enable();
    return;
}

asmlinkage void do_spurious_interrupt_bug(struct cpu_user_regs *regs)
{
}

static void __set_intr_gate(unsigned int n, uint32_t dpl, void *addr)
{
    int i;
    /* Keep secondary tables in sync with IRQ updates. */
    for ( i = 1; i < NR_CPUS; i++ )
        if ( idt_tables[i] != NULL )
            _set_gate(&idt_tables[i][n], 14, dpl, addr);
    _set_gate(&idt_table[n], 14, dpl, addr);
}

static void set_swint_gate(unsigned int n, void *addr)
{
    __set_intr_gate(n, 3, addr);
}

void set_intr_gate(unsigned int n, void *addr)
{
    __set_intr_gate(n, 0, addr);
}

void load_TR(void)
{
    struct tss_struct *tss = &this_cpu(init_tss);
    struct desc_ptr old_gdt, tss_gdt = {
        .base = (long)(this_cpu(gdt_table) - FIRST_RESERVED_GDT_ENTRY),
        .limit = LAST_RESERVED_GDT_BYTE
    };

    _set_tssldt_desc(
        this_cpu(gdt_table) + TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)tss,
        offsetof(struct tss_struct, __cacheline_filler) - 1,
        9);
#ifdef CONFIG_COMPAT
    _set_tssldt_desc(
        this_cpu(compat_gdt_table) + TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)tss,
        offsetof(struct tss_struct, __cacheline_filler) - 1,
        11);
#endif

    /* Switch to non-compat GDT (which has B bit clear) to execute LTR. */
    asm volatile (
        "sgdt %0; lgdt %2; ltr %w1; lgdt %0"
        : "=m" (old_gdt) : "rm" (TSS_ENTRY << 3), "m" (tss_gdt) : "memory" );
}

void __devinit percpu_traps_init(void)
{
    subarch_percpu_traps_init();

    if ( !opt_ler )
        return;

    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        switch ( boot_cpu_data.x86 )
        {
        case 6:
            this_cpu(ler_msr) = MSR_IA32_LASTINTFROMIP;
            break;
        case 15:
            this_cpu(ler_msr) = MSR_P4_LER_FROM_LIP;
            break;
        }
        break;
    case X86_VENDOR_AMD:
        switch ( boot_cpu_data.x86 )
        {
        case 6:
        case 15:
        case 16:
            this_cpu(ler_msr) = MSR_IA32_LASTINTFROMIP;
            break;
        }
        break;
    }

    ler_enable();
}

void __init trap_init(void)
{
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
    set_swint_gate(TRAP_int3,&int3);         /* usable from all privileges */
    set_swint_gate(TRAP_overflow,&overflow); /* usable from all privileges */
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

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    percpu_traps_init();

    cpu_init();

    open_softirq(NMI_MCE_SOFTIRQ, nmi_mce_softirq);
}

long register_guest_nmi_callback(unsigned long address)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct trap_info *t = &v->arch.guest_context.trap_ctxt[TRAP_nmi];

    t->vector  = TRAP_nmi;
    t->flags   = 0;
    t->cs      = (is_pv_32on64_domain(d) ?
                  FLAT_COMPAT_KERNEL_CS : FLAT_KERNEL_CS);
    t->address = address;
    TI_SET_IF(t, 1);

    /*
     * If no handler was registered we can 'lose the NMI edge'. Re-assert it
     * now.
     */
    if ( (v->vcpu_id == 0) && (arch_get_nmi_reason(d) != 0) )
        v->nmi_pending = 1;

    return 0;
}

long unregister_guest_nmi_callback(void)
{
    struct vcpu *v = current;
    struct trap_info *t = &v->arch.guest_context.trap_ctxt[TRAP_nmi];

    memset(t, 0, sizeof(*t));

    return 0;
}

int guest_has_trap_callback(struct domain *d, uint16_t vcpuid, unsigned int trap_nr)
{
    struct vcpu *v;
    struct trap_info *t;

    BUG_ON(d == NULL);
    BUG_ON(vcpuid >= d->max_vcpus);

    /* Sanity check - XXX should be more fine grained. */
    BUG_ON(trap_nr > TRAP_syscall);

    v = d->vcpu[vcpuid];
    t = &v->arch.guest_context.trap_ctxt[trap_nr];

    return (t->address != 0);
}


int send_guest_trap(struct domain *d, uint16_t vcpuid, unsigned int trap_nr)
{
    struct vcpu *v;
    struct softirq_trap *st;

    BUG_ON(d == NULL);
    BUG_ON(vcpuid >= d->max_vcpus);
    v = d->vcpu[vcpuid];

    switch (trap_nr) {
    case TRAP_nmi:
        if ( !test_and_set_bool(v->nmi_pending) ) {
               st = &per_cpu(softirq_trap, smp_processor_id());
               st->domain = dom0;
               st->vcpu = dom0->vcpu[0];
               st->processor = st->vcpu->processor;

               /* not safe to wake up a vcpu here */
               raise_softirq(NMI_MCE_SOFTIRQ);
               return 0;
        }
        break;

    case TRAP_machine_check:

        /* We are called by the machine check (exception or polling) handlers
         * on the physical CPU that reported a machine check error. */

        if ( !test_and_set_bool(v->mce_pending) ) {
                st = &per_cpu(softirq_trap, smp_processor_id());
                st->domain = d;
                st->vcpu = v;
                st->processor = v->processor;

                /* not safe to wake up a vcpu here */
                raise_softirq(NMI_MCE_SOFTIRQ);
                return 0;
        }
        break;
    }

    /* delivery failed */
    return -EIO;
}


long do_set_trap_table(XEN_GUEST_HANDLE(const_trap_info_t) traps)
{
    struct trap_info cur;
    struct vcpu *curr = current;
    struct trap_info *dst = curr->arch.guest_context.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, 256 * sizeof(*dst));
        init_int80_direct_trap(curr);
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

        fixup_guest_code_selector(curr->domain, cur.cs);

        memcpy(&dst[cur.vector], &cur, sizeof(cur));

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(curr);

        guest_handle_add_offset(traps, 1);
    }

    return rc;
}

long set_debugreg(struct vcpu *v, int reg, unsigned long value)
{
    int i;
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( v == curr ) 
            write_debugreg(0, value);
        break;
    case 1: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( v == curr ) 
            write_debugreg(1, value);
        break;
    case 2: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( v == curr ) 
            write_debugreg(2, value);
        break;
    case 3:
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( v == curr ) 
            write_debugreg(3, value);
        break;
    case 6:
        /*
         * DR6: Bits 4-11,16-31 reserved (set to 1).
         *      Bit 12 reserved (set to 0).
         */
        value &= 0xffffefff; /* reserved bits => 0 */
        value |= 0xffff0ff0; /* reserved bits => 1 */
        if ( v == curr ) 
            write_debugreg(6, value);
        break;
    case 7:
        /*
         * DR7: Bit 10 reserved (set to 1).
         *      Bits 11-12,14-15 reserved (set to 0).
         */
        value &= ~DR_CONTROL_RESERVED_ZERO; /* reserved bits => 0 */
        value |=  DR_CONTROL_RESERVED_ONE;  /* reserved bits => 1 */
        /*
         * Privileged bits:
         *      GD (bit 13): must be 0.
         */
        if ( value & DR_GENERAL_DETECT )
            return -EPERM;
        /* DR7.{G,L}E = 0 => debugging disabled for this domain. */
        if ( value & DR7_ACTIVE_MASK )
        {
            unsigned int io_enable = 0;

            for ( i = DR_CONTROL_SHIFT; i < 32; i += DR_CONTROL_SIZE )
            {
                if ( ((value >> i) & 3) == DR_IO )
                {
                    if ( !(v->arch.guest_context.ctrlreg[4] & X86_CR4_DE) )
                        return -EPERM;
                    io_enable |= value & (3 << ((i - 16) >> 1));
                }
#ifdef __i386__
                if ( ((boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) ||
                      !boot_cpu_has(X86_FEATURE_LM)) &&
                     (((value >> i) & 0xc) == DR_LEN_8) )
                    return -EPERM;
#endif
            }

            /* Guest DR5 is a handy stash for I/O intercept information. */
            v->arch.guest_context.debugreg[5] = io_enable;
            value &= ~io_enable;

            /*
             * If DR7 was previously clear then we need to load all other
             * debug registers at this point as they were not restored during
             * context switch.
             */
            if ( (v == curr) &&
                 !(v->arch.guest_context.debugreg[7] & DR7_ACTIVE_MASK) )
            {
                write_debugreg(0, v->arch.guest_context.debugreg[0]);
                write_debugreg(1, v->arch.guest_context.debugreg[1]);
                write_debugreg(2, v->arch.guest_context.debugreg[2]);
                write_debugreg(3, v->arch.guest_context.debugreg[3]);
                write_debugreg(6, v->arch.guest_context.debugreg[6]);
            }
        }
        if ( v == curr )
            write_debugreg(7, value);
        break;
    default:
        return -EINVAL;
    }

    v->arch.guest_context.debugreg[reg] = value;
    return 0;
}

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0 ... 3:
    case 6:
        return curr->arch.guest_context.debugreg[reg];
    case 7:
        return (curr->arch.guest_context.debugreg[7] |
                curr->arch.guest_context.debugreg[5]);
    case 4 ... 5:
        return ((curr->arch.guest_context.ctrlreg[4] & X86_CR4_DE) ?
                curr->arch.guest_context.debugreg[reg + 2] : 0);
    }

    return -EINVAL;
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
