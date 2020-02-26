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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/err.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/console.h>
#include <xen/shutdown.h>
#include <xen/guest_access.h>
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
#include <xen/version.h>
#include <xen/kexec.h>
#include <xen/trace.h>
#include <xen/paging.h>
#include <xen/virtual_region.h>
#include <xen/watchdog.h>
#include <xen/livepatch.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <xen/bitops.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/smp.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/debugger.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/shared.h>
#include <asm/x86_emulate.h>
#include <asm/traps.h>
#include <asm/hvm/vpt.h>
#include <asm/hypercall.h>
#include <asm/mce.h>
#include <asm/apic.h>
#include <asm/mc146818rtc.h>
#include <asm/hpet.h>
#include <asm/vpmu.h>
#include <public/arch-x86/cpuid.h>
#include <asm/cpuid.h>
#include <xsm/xsm.h>
#include <asm/pv/traps.h>
#include <asm/pv/mm.h>

/*
 * opt_nmi: one of 'ignore', 'dom0', or 'fatal'.
 *  fatal:  Xen prints diagnostic message and then hangs.
 *  dom0:   The NMI is virtualised to DOM0.
 *  ignore: The NMI error is cleared and ignored.
 */
#ifdef NDEBUG
static char __read_mostly opt_nmi[10] = "dom0";
#else
static char __read_mostly opt_nmi[10] = "fatal";
#endif
string_param("nmi", opt_nmi);

DEFINE_PER_CPU(uint64_t, efer);
static DEFINE_PER_CPU(unsigned long, last_extable_addr);

DEFINE_PER_CPU_READ_MOSTLY(seg_desc_t *, gdt);
DEFINE_PER_CPU_READ_MOSTLY(l1_pgentry_t, gdt_l1e);
DEFINE_PER_CPU_READ_MOSTLY(seg_desc_t *, compat_gdt);
DEFINE_PER_CPU_READ_MOSTLY(l1_pgentry_t, compat_gdt_l1e);

/* Master table, used by CPU0. */
idt_entry_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
    idt_table[IDT_ENTRIES];

/* Pointer to the IDT of every CPU. */
idt_entry_t *idt_tables[NR_CPUS] __read_mostly;

/*
 * The TSS is smaller than a page, but we give it a full page to avoid
 * adjacent per-cpu data leaking via Meltdown when XPTI is in use.
 */
DEFINE_PER_CPU_PAGE_ALIGNED(struct tss_page, tss_page);

bool (*ioemul_handle_quirk)(
    u8 opcode, char *io_emul_stub, struct cpu_user_regs *regs);

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

static bool opt_ler;
boolean_param("ler", opt_ler);

/* LastExceptionFromIP on this hardware.  Zero if LER is not in use. */
unsigned int __read_mostly ler_msr;

const unsigned int nmi_cpu;

#define stack_words_per_line 4
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)regs->rsp)

static void do_trap(struct cpu_user_regs *regs);
static void do_reserved_trap(struct cpu_user_regs *regs);

void (* const exception_table[TRAP_nr])(struct cpu_user_regs *regs) = {
    [TRAP_divide_error]                 = do_trap,
    [TRAP_debug]                        = do_debug,
    [TRAP_nmi]                          = (void *)do_nmi,
    [TRAP_int3]                         = do_int3,
    [TRAP_overflow]                     = do_trap,
    [TRAP_bounds]                       = do_trap,
    [TRAP_invalid_op]                   = do_invalid_op,
    [TRAP_no_device]                    = do_device_not_available,
    [TRAP_double_fault]                 = do_reserved_trap,
    [TRAP_copro_seg]                    = do_reserved_trap,
    [TRAP_invalid_tss]                  = do_trap,
    [TRAP_no_segment]                   = do_trap,
    [TRAP_stack_error]                  = do_trap,
    [TRAP_gp_fault]                     = do_general_protection,
    [TRAP_page_fault]                   = do_page_fault,
    [TRAP_spurious_int]                 = do_reserved_trap,
    [TRAP_copro_error]                  = do_trap,
    [TRAP_alignment_check]              = do_trap,
    [TRAP_machine_check]                = (void *)do_machine_check,
    [TRAP_simd_error]                   = do_trap,
    [TRAP_virtualisation ...
     (ARRAY_SIZE(exception_table) - 1)] = do_reserved_trap,
};

void show_code(const struct cpu_user_regs *regs)
{
    unsigned char insns_before[8] = {}, insns_after[16] = {};
    unsigned int i, tmp, missing_before, missing_after;

    if ( guest_mode(regs) )
        return;

    stac();

    /*
     * Copy forward from regs->rip.  In the case of a fault, %ecx contains the
     * number of bytes remaining to copy.
     */
    asm volatile ("1: rep movsb; 2:"
                  _ASM_EXTABLE(1b, 2b)
                  : "=&c" (missing_after),
                    "=&D" (tmp), "=&S" (tmp)
                  : "0" (ARRAY_SIZE(insns_after)),
                    "1" (insns_after),
                    "2" (regs->rip));

    /*
     * Copy backwards from regs->rip - 1.  In the case of a fault, %ecx
     * contains the number of bytes remaining to copy.
     */
    asm volatile ("std;"
                  "1: rep movsb;"
                  "2: cld;"
                  _ASM_EXTABLE(1b, 2b)
                  : "=&c" (missing_before),
                    "=&D" (tmp), "=&S" (tmp)
                  : "0" (ARRAY_SIZE(insns_before)),
                    "1" (insns_before + ARRAY_SIZE(insns_before) - 1),
                    "2" (regs->rip - 1));
    clac();

    printk("Xen code around <%p> (%ps)%s:\n",
           _p(regs->rip), _p(regs->rip),
           (missing_before || missing_after) ? " [fault on access]" : "");

    /* Print bytes from insns_before[]. */
    for ( i = 0; i < ARRAY_SIZE(insns_before); ++i )
    {
        if ( i < missing_before )
            printk(" --");
        else
            printk(" %02x", insns_before[i]);
    }

    /* Print the byte under %rip. */
    if ( missing_after != ARRAY_SIZE(insns_after) )
        printk(" <%02x>", insns_after[0]);
    else
        printk(" <-->");

    /* Print bytes from insns_after[]. */
    for ( i = 1; i < ARRAY_SIZE(insns_after); ++i )
    {
        if ( i < (ARRAY_SIZE(insns_after) - missing_after) )
            printk(" %02x", insns_after[i]);
        else
            printk(" --");
    }

    printk("\n");
}

static void compat_show_guest_stack(struct vcpu *v,
                                    const struct cpu_user_regs *regs,
                                    int debug_stack_lines)
{
    unsigned int i, *stack, addr, mask = STACK_SIZE;

    stack = (unsigned int *)(unsigned long)regs->esp;
    printk("Guest stack trace from esp=%08lx:\n ", (unsigned long)stack);

    if ( !__compat_access_ok(v->domain, stack, sizeof(*stack)) )
    {
        printk("Guest-inaccessible memory.\n");
        return;
    }

    if ( v != current )
    {
        struct vcpu *vcpu;
        unsigned long mfn;

        ASSERT(guest_kernel_mode(v, regs));
        mfn = read_cr3() >> PAGE_SHIFT;
        for_each_vcpu( v->domain, vcpu )
            if ( pagetable_get_pfn(vcpu->arch.guest_table) == mfn )
                break;
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

    for ( i = 0; i < debug_stack_lines * 8; i++ )
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
        if ( (i != 0) && ((i % 8) == 0) )
            printk("\n ");
        printk(" %08x", addr);
        stack++;
    }
    if ( mask == PAGE_SIZE )
    {
        BUILD_BUG_ON(PAGE_SIZE == STACK_SIZE);
        unmap_domain_page(stack);
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

static void show_guest_stack(struct vcpu *v, const struct cpu_user_regs *regs)
{
    int i;
    unsigned long *stack, addr;
    unsigned long mask = STACK_SIZE;

    /* Avoid HVM as we don't know what the stack looks like. */
    if ( is_hvm_vcpu(v) )
        return;

    if ( is_pv_32bit_vcpu(v) )
    {
        compat_show_guest_stack(v, regs, debug_stack_lines);
        return;
    }

    stack = (unsigned long *)regs->rsp;
    printk("Guest stack trace from "__OP"sp=%p:\n  ", stack);

    if ( !access_ok(stack, sizeof(*stack)) )
    {
        printk("Guest-inaccessible memory.\n");
        return;
    }

    if ( v != current )
    {
        struct vcpu *vcpu;

        ASSERT(guest_kernel_mode(v, regs));
        vcpu = maddr_get_owner(read_cr3()) == v->domain ? v : NULL;
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
    if ( mask == PAGE_SIZE )
    {
        BUILD_BUG_ON(PAGE_SIZE == STACK_SIZE);
        unmap_domain_page(stack);
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

/*
 * Notes for get_stack_trace_bottom() and get_stack_dump_bottom()
 *
 * Stack pages 0 - 3:
 *   These are all 1-page IST stacks.  Each of these stacks have an exception
 *   frame and saved register state at the top.  The interesting bound for a
 *   trace is the word adjacent to this, while the bound for a dump is the
 *   very top, including the exception frame.
 *
 * Stack pages 4 and 5:
 *   None of these are particularly interesting.  With MEMORY_GUARD, page 5 is
 *   explicitly not present, so attempting to dump or trace it is
 *   counterproductive.  Without MEMORY_GUARD, it is possible for a call chain
 *   to use the entire primary stack and wander into page 5.  In this case,
 *   consider these pages an extension of the primary stack to aid debugging
 *   hopefully rare situations where the primary stack has effective been
 *   overflown.
 *
 * Stack pages 6 and 7:
 *   These form the primary stack, and have a cpu_info at the top.  For a
 *   trace, the interesting bound is adjacent to the cpu_info, while for a
 *   dump, the entire cpu_info is interesting.
 *
 * For the cases where the stack should not be inspected, pretend that the
 * passed stack pointer is already out of reasonable bounds.
 */
unsigned long get_stack_trace_bottom(unsigned long sp)
{
    switch ( get_stack_page(sp) )
    {
    case 0 ... 3:
        return ROUNDUP(sp, PAGE_SIZE) -
            offsetof(struct cpu_user_regs, es) - sizeof(unsigned long);

#ifndef MEMORY_GUARD
    case 4 ... 5:
#endif
    case 6 ... 7:
        return ROUNDUP(sp, STACK_SIZE) -
            sizeof(struct cpu_info) - sizeof(unsigned long);

    default:
        return sp - sizeof(unsigned long);
    }
}

unsigned long get_stack_dump_bottom(unsigned long sp)
{
    switch ( get_stack_page(sp) )
    {
    case 0 ... 3:
        return ROUNDUP(sp, PAGE_SIZE) - sizeof(unsigned long);

#ifndef MEMORY_GUARD
    case 4 ... 5:
#endif
    case 6 ... 7:
        return ROUNDUP(sp, STACK_SIZE) - sizeof(unsigned long);

    default:
        return sp - sizeof(unsigned long);
    }
}

#if !defined(CONFIG_FRAME_POINTER)

/*
 * Stack trace from pointers found in stack, unaided by frame pointers.  For
 * caller convenience, this has the same prototype as its alternative, and
 * simply ignores the base pointer parameter.
 */
static void _show_trace(unsigned long sp, unsigned long __maybe_unused bp)
{
    unsigned long *stack = (unsigned long *)sp, addr;
    unsigned long *bottom = (unsigned long *)get_stack_trace_bottom(sp);

    while ( stack <= bottom )
    {
        addr = *stack++;
        if ( is_active_kernel_text(addr) )
            printk("   [<%p>] S %pS\n", _p(addr), _p(addr));
    }
}

#else

/* Stack trace from frames in the stack, using frame pointers */
static void _show_trace(unsigned long sp, unsigned long bp)
{
    unsigned long *frame, next, addr;

    /* Bounds for range of valid frame pointer. */
    unsigned long low = sp, high = get_stack_trace_bottom(sp);

    /* The initial frame pointer. */
    next = bp;

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
            addr  = frame[(offsetof(struct cpu_user_regs, rip) -
                           offsetof(struct cpu_user_regs, rbp))
                         / BYTES_PER_LONG];
        }
        else
        {
            /* Ordinary stack frame. */
            frame = (unsigned long *)next;
            next  = frame[0];
            addr  = frame[1];
        }

        printk("   [<%p>] F %pS\n", _p(addr), _p(addr));

        low = (unsigned long)&frame[2];
    }
}

#endif

static void show_trace(const struct cpu_user_regs *regs)
{
    unsigned long *sp = ESP_BEFORE_EXCEPTION(regs), tos = 0;
    bool fault = false;

    printk("Xen call trace:\n");

    /* Guarded read of the stack top. */
    asm ( "1: mov %[data], %[tos]; 2:\n"
          ".pushsection .fixup,\"ax\"\n"
          "3: movb $1, %[fault]; jmp 2b\n"
          ".popsection\n"
          _ASM_EXTABLE(1b, 3b)
          : [tos] "+r" (tos), [fault] "+qm" (fault) : [data] "m" (*sp) );

    /*
     * If RIP looks sensible, or the top of the stack doesn't, print RIP at
     * the top of the stack trace.
     */
    if ( is_active_kernel_text(regs->rip) ||
         !is_active_kernel_text(tos) )
        printk("   [<%p>] R %pS\n", _p(regs->rip), _p(regs->rip));

    if ( fault )
    {
        printk("   [Fault on access]\n");
        return;
    }

    /*
     * If RIP looks bad or the top of the stack looks good, log the top of
     * stack as well.  Perhaps we followed a wild function pointer, or we're
     * in a function without frame pointer, or in a function prologue before
     * the frame pointer gets set up?  Let's assume the top of the stack is a
     * return address; print it and skip past so _show_trace() doesn't print
     * it again.
     */
    if ( !is_active_kernel_text(regs->rip) ||
         is_active_kernel_text(tos) )
    {
        printk("   [<%p>] S %pS\n", _p(tos), _p(tos));
        sp++;
    }

    _show_trace((unsigned long)sp, regs->rbp);

    printk("\n");
}

void show_stack(const struct cpu_user_regs *regs)
{
    unsigned long *stack = ESP_BEFORE_EXCEPTION(regs), *stack_bottom, addr;
    int i;

    if ( guest_mode(regs) )
        return show_guest_stack(current, regs);

    printk("Xen stack trace from "__OP"sp=%p:\n  ", stack);

    stack_bottom = _p(get_stack_dump_bottom(regs->rsp));

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line) &&
              (stack <= stack_bottom); i++ )
    {
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

void show_stack_overflow(unsigned int cpu, const struct cpu_user_regs *regs)
{
    unsigned long esp = regs->rsp;
    unsigned long curr_stack_base = esp & ~(STACK_SIZE - 1);
#ifdef MEMORY_GUARD
    unsigned long esp_top, esp_bottom;
#endif

    if ( _p(curr_stack_base) != stack_base[cpu] )
        printk("Current stack base %p differs from expected %p\n",
               _p(curr_stack_base), stack_base[cpu]);

#ifdef MEMORY_GUARD
    esp_bottom = (esp | (STACK_SIZE - 1)) + 1;
    esp_top    = esp_bottom - PRIMARY_STACK_SIZE;

    printk("Valid stack range: %p-%p, sp=%p, tss.rsp0=%p\n",
           (void *)esp_top, (void *)esp_bottom, (void *)esp,
           (void *)per_cpu(tss_page, cpu).tss.rsp0);

    /*
     * Trigger overflow trace if %esp is anywhere within the guard page, or
     * with fewer than 512 bytes remaining on the primary stack.
     */
    if ( (esp > (esp_top + 512)) ||
         (esp < (esp_top - PAGE_SIZE)) )
    {
        printk("No stack overflow detected. Skipping stack trace.\n");
        return;
    }

    if ( esp < esp_top )
        esp = esp_top;

    printk("Xen stack overflow (dumping trace %p-%p):\n",
           (void *)esp, (void *)esp_bottom);

    _show_trace(esp, regs->rbp);

    printk("\n");
#endif
}

void show_execution_state(const struct cpu_user_regs *regs)
{
    /* Prevent interleaving of output. */
    unsigned long flags = console_lock_recursive_irqsave();

    show_registers(regs);
    show_code(regs);
    show_stack(regs);

    console_unlock_recursive_irqrestore(flags);
}

void vcpu_show_execution_state(struct vcpu *v)
{
    unsigned long flags;

    printk("*** Dumping Dom%d vcpu#%d state: ***\n",
           v->domain->domain_id, v->vcpu_id);

    if ( v == current )
    {
        show_execution_state(guest_cpu_user_regs());
        return;
    }

    vcpu_pause(v); /* acceptably dangerous */

    /* Prevent interleaving of output. */
    flags = console_lock_recursive_irqsave();

    vcpu_show_registers(v);
    if ( guest_kernel_mode(v, &v->arch.user_regs) )
        show_guest_stack(v, &v->arch.user_regs);

    console_unlock_recursive_irqrestore(flags);

    vcpu_unpause(v);
}

static cpumask_t show_state_mask;
static bool opt_show_all;
boolean_param("async-show-all", opt_show_all);

static int nmi_show_execution_state(const struct cpu_user_regs *regs, int cpu)
{
    if ( !cpumask_test_cpu(cpu, &show_state_mask) )
        return 0;

    if ( opt_show_all )
        show_execution_state(regs);
    else
        printk(XENLOG_ERR "CPU%d @ %04x:%08lx (%pS)\n", cpu, regs->cs,
               regs->rip, guest_mode(regs) ? NULL : _p(regs->rip));
    cpumask_clear_cpu(cpu, &show_state_mask);

    return 1;
}

const char *trapstr(unsigned int trapnr)
{
    static const char * const strings[] = {
        "divide error", "debug", "nmi", "bkpt", "overflow", "bounds",
        "invalid opcode", "device not available", "double fault",
        "coprocessor segment", "invalid tss", "segment not found",
        "stack error", "general protection fault", "page fault",
        "spurious interrupt", "coprocessor error", "alignment check",
        "machine check", "simd error", "virtualisation exception"
    };

    return trapnr < ARRAY_SIZE(strings) ? strings[trapnr] : "???";
}

/*
 * This is called for faults at very unexpected times (e.g., when interrupts
 * are disabled). In such situations we can't do much that is safe. We try to
 * print out some tracing and then we just spin.
 */
void fatal_trap(const struct cpu_user_regs *regs, bool show_remote)
{
    static DEFINE_PER_CPU(char, depth);
    unsigned int trapnr = regs->entry_vector;

    /* Set AC to reduce chance of further SMAP faults */
    stac();

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
            show_page_walk(read_cr2());

        if ( show_remote )
        {
            unsigned int msecs, pending;

            cpumask_andnot(&show_state_mask, &cpu_online_map,
                           cpumask_of(smp_processor_id()));
            set_nmi_callback(nmi_show_execution_state);
            /* Ensure new callback is set before sending out the NMI. */
            smp_wmb();
            smp_send_nmi_allbutself();

            /* Wait at most 10ms for some other CPU to respond. */
            msecs = 10;
            pending = cpumask_weight(&show_state_mask);
            while ( pending && msecs-- )
            {
                unsigned int left;

                mdelay(1);
                left = cpumask_weight(&show_state_mask);
                if ( left < pending )
                {
                    pending = left;
                    msecs = 10;
                }
            }
        }
    }

    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x] %s\n",
          trapnr, trapstr(trapnr), regs->error_code,
          (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
}

static void do_reserved_trap(struct cpu_user_regs *regs)
{
    unsigned int trapnr = regs->entry_vector;

    if ( debugger_trap_fatal(trapnr, regs) )
        return;

    show_execution_state(regs);
    panic("FATAL RESERVED TRAP %#x: %s\n", trapnr, trapstr(trapnr));
}

static void do_trap(struct cpu_user_regs *regs)
{
    unsigned int trapnr = regs->entry_vector;
    unsigned long fixup;

    if ( regs->error_code & X86_XEC_EXT )
        goto hardware_trap;

    if ( debugger_trap_entry(trapnr, regs) )
        return;

    ASSERT(trapnr < 32);

    if ( guest_mode(regs) )
    {
        pv_inject_hw_exception(trapnr,
                               (TRAP_HAVE_EC & (1u << trapnr))
                               ? regs->error_code : X86_EVENT_NO_EC);
        return;
    }

    if ( likely((fixup = search_exception_table(regs)) != 0) )
    {
        dprintk(XENLOG_ERR, "Trap %u: %p [%ps] -> %p\n",
                trapnr, _p(regs->rip), _p(regs->rip), _p(fixup));
        this_cpu(last_extable_addr) = regs->rip;
        regs->rip = fixup;
        return;
    }

 hardware_trap:
    if ( debugger_trap_fatal(trapnr, regs) )
        return;

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x]\n",
          trapnr, trapstr(trapnr), regs->error_code);
}

int guest_rdmsr_xen(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    const struct domain *d = v->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    switch ( idx - base )
    {
    case 0: /* Write hypercall page MSR.  Read as zero. */
        *val = 0;
        return X86EMUL_OKAY;
    }

    return X86EMUL_EXCEPTION;
}

int guest_wrmsr_xen(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct domain *d = v->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    switch ( idx - base )
    {
    case 0: /* Write hypercall page */
    {
        void *hypercall_page;
        unsigned long gmfn = val >> PAGE_SHIFT;
        unsigned int page_index = val & (PAGE_SIZE - 1);
        struct page_info *page;
        p2m_type_t t;

        if ( page_index > 0 )
        {
            gdprintk(XENLOG_WARNING,
                     "wrmsr hypercall page index %#x unsupported\n",
                     page_index);
            return X86EMUL_EXCEPTION;
        }

        page = get_page_from_gfn(d, gmfn, &t, P2M_ALLOC);

        if ( !page || !get_page_type(page, PGT_writable_page) )
        {
            if ( page )
                put_page(page);

            if ( p2m_is_paging(t) )
            {
                p2m_mem_paging_populate(d, gmfn);
                return X86EMUL_RETRY;
            }

            gdprintk(XENLOG_WARNING,
                     "Bad GMFN %lx (MFN %#"PRI_mfn") to MSR %08x\n",
                     gmfn, mfn_x(page ? page_to_mfn(page) : INVALID_MFN), base);
            return X86EMUL_EXCEPTION;
        }

        hypercall_page = __map_domain_page(page);
        init_hypercall_page(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(page);
        return X86EMUL_OKAY;
    }

    default:
        return X86EMUL_EXCEPTION;
    }
}

void cpuid_hypervisor_leaves(const struct vcpu *v, uint32_t leaf,
                             uint32_t subleaf, struct cpuid_leaf *res)
{
    const struct domain *d = v->domain;
    const struct cpuid_policy *p = d->arch.cpuid;
    uint32_t base = is_viridian_domain(d) ? 0x40000100 : 0x40000000;
    uint32_t idx  = leaf - base;
    unsigned int limit = is_viridian_domain(d) ? p->hv2_limit : p->hv_limit;

    if ( limit == 0 )
        /* Default number of leaves */
        limit = XEN_CPUID_MAX_NUM_LEAVES;
    else
        /* Clamp toolstack value between 2 and MAX_NUM_LEAVES. */
        limit = min(max(limit, 2u), XEN_CPUID_MAX_NUM_LEAVES + 0u);

    if ( idx > limit )
        return;

    switch ( idx )
    {
    case 0:
        res->a = base + limit; /* Largest leaf */
        res->b = XEN_CPUID_SIGNATURE_EBX;
        res->c = XEN_CPUID_SIGNATURE_ECX;
        res->d = XEN_CPUID_SIGNATURE_EDX;
        break;

    case 1:
        res->a = (xen_major_version() << 16) | xen_minor_version();
        break;

    case 2:
        res->a = 1;            /* Number of hypercall-transfer pages */
                               /* MSR base address */
        res->b = is_viridian_domain(d) ? 0x40000200 : 0x40000000;
        if ( is_pv_domain(d) ) /* Features */
            res->c |= XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD;
        break;

    case 3: /* Time leaf. */
        switch ( subleaf )
        {
        case 0: /* features */
            res->a = ((d->arch.vtsc << 0) |
                      (!!host_tsc_is_safe() << 1) |
                      (!!boot_cpu_has(X86_FEATURE_RDTSCP) << 2));
            res->b = d->arch.tsc_mode;
            res->c = d->arch.tsc_khz;
            res->d = d->arch.incarnation;
            break;

        case 1: /* scale and offset */
        {
            uint64_t offset;

            if ( !d->arch.vtsc )
                offset = d->arch.vtsc_offset;
            else
                /* offset already applied to value returned by virtual rdtscp */
                offset = 0;
            res->a = offset;
            res->b = offset >> 32;
            res->c = d->arch.vtsc_to_ns.mul_frac;
            res->d = (s8)d->arch.vtsc_to_ns.shift;
            break;
        }

        case 2: /* physical cpu_khz */
            res->a = cpu_khz;
            break;
        }
        break;

    case 4: /* HVM hypervisor leaf. */
        if ( !is_hvm_domain(d) || subleaf != 0 )
            break;

        if ( cpu_has_vmx_apic_reg_virt )
            res->a |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;

        /*
         * We want to claim that x2APIC is virtualized if APIC MSR accesses
         * are not intercepted. When all three of these are true both rdmsr
         * and wrmsr in the guest will run without VMEXITs (see
         * vmx_vlapic_msr_changed()).
         */
        if ( cpu_has_vmx_virtualize_x2apic_mode &&
             cpu_has_vmx_apic_reg_virt &&
             cpu_has_vmx_virtual_intr_delivery )
            res->a |= XEN_HVM_CPUID_X2APIC_VIRT;

        /*
         * Indicate that memory mapped from other domains (either grants or
         * foreign pages) has valid IOMMU entries.
         */
        res->a |= XEN_HVM_CPUID_IOMMU_MAPPINGS;

        /* Indicate presence of vcpu id and set it in ebx */
        res->a |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
        res->b = v->vcpu_id;

        /* Indicate presence of domain id and set it in ecx */
        res->a |= XEN_HVM_CPUID_DOMID_PRESENT;
        res->c = d->domain_id;

        break;

    case 5: /* PV-specific parameters */
        if ( is_hvm_domain(d) || subleaf != 0 )
            break;

        res->b = flsl(get_upper_mfn_bound()) + PAGE_SHIFT;
        break;

    default:
        ASSERT_UNREACHABLE();
    }
}

void do_invalid_op(struct cpu_user_regs *regs)
{
    const struct bug_frame *bug = NULL;
    u8 bug_insn[2];
    const char *prefix = "", *filename, *predicate, *eip = (char *)regs->rip;
    unsigned long fixup;
    int id = -1, lineno;
    const struct virtual_region *region;

    if ( debugger_trap_entry(TRAP_invalid_op, regs) )
        return;

    if ( likely(guest_mode(regs)) )
    {
        if ( pv_emulate_invalid_op(regs) )
            pv_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        return;
    }

    if ( !is_active_kernel_text(regs->rip) ||
         __copy_from_user(bug_insn, eip, sizeof(bug_insn)) ||
         memcmp(bug_insn, "\xf\xb", sizeof(bug_insn)) )
        goto die;

    region = find_text_region(regs->rip);
    if ( region )
    {
        for ( id = 0; id < BUGFRAME_NR; id++ )
        {
            const struct bug_frame *b;
            unsigned int i;

            for ( i = 0, b = region->frame[id].bugs;
                  i < region->frame[id].n_bugs; b++, i++ )
            {
                if ( bug_loc(b) == eip )
                {
                    bug = b;
                    goto found;
                }
            }
        }
    }

 found:
    if ( !bug )
        goto die;
    eip += sizeof(bug_insn);
    if ( id == BUGFRAME_run_fn )
    {
        void (*fn)(struct cpu_user_regs *) = bug_ptr(bug);

        fn(regs);
        regs->rip = (unsigned long)eip;
        return;
    }

    /* WARN, BUG or ASSERT: decode the filename pointer and line number. */
    filename = bug_ptr(bug);
    if ( !is_kernel(filename) && !is_patch(filename) )
        goto die;
    fixup = strlen(filename);
    if ( fixup > 50 )
    {
        filename += fixup - 47;
        prefix = "...";
    }
    lineno = bug_line(bug);

    switch ( id )
    {
    case BUGFRAME_warn:
        printk("Xen WARN at %s%s:%d\n", prefix, filename, lineno);
        show_execution_state(regs);
        regs->rip = (unsigned long)eip;
        return;

    case BUGFRAME_bug:
        printk("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

        if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
            return;

        show_execution_state(regs);
        panic("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

    case BUGFRAME_assert:
        /* ASSERT: decode the predicate string pointer. */
        predicate = bug_msg(bug);
        if ( !is_kernel(predicate) && !is_patch(predicate) )
            predicate = "<unknown>";

        printk("Assertion '%s' failed at %s%s:%d\n",
               predicate, prefix, filename, lineno);

        if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
            return;

        show_execution_state(regs);
        panic("Assertion '%s' failed at %s%s:%d\n",
              predicate, prefix, filename, lineno);
    }

 die:
    if ( (fixup = search_exception_table(regs)) != 0 )
    {
        this_cpu(last_extable_addr) = regs->rip;
        regs->rip = fixup;
        return;
    }

    if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
        return;

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (invalid opcode)\n", TRAP_invalid_op);
}

void do_int3(struct cpu_user_regs *regs)
{
    if ( debugger_trap_entry(TRAP_int3, regs) )
        return;

    if ( !guest_mode(regs) )
    {
        unsigned long fixup;

        if ( (fixup = search_exception_table(regs)) != 0 )
        {
            this_cpu(last_extable_addr) = regs->rip;
            dprintk(XENLOG_DEBUG, "Trap %u: %p [%ps] -> %p\n",
                    TRAP_int3, _p(regs->rip), _p(regs->rip), _p(fixup));
            regs->rip = fixup;
            return;
        }

        if ( !debugger_trap_fatal(TRAP_int3, regs) )
            printk(XENLOG_DEBUG "Hit embedded breakpoint at %p [%ps]\n",
                   _p(regs->rip), _p(regs->rip));

        return;
    }

    pv_inject_hw_exception(TRAP_int3, X86_EVENT_NO_EC);
}

static void reserved_bit_page_fault(unsigned long addr,
                                    struct cpu_user_regs *regs)
{
    printk("%pv: reserved bit in page table (ec=%04X)\n",
           current, regs->error_code);
    show_page_walk(addr);
    show_execution_state(regs);
}

#ifdef CONFIG_PV
static int handle_ldt_mapping_fault(unsigned int offset,
                                    struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;

    /*
     * Not in PV context?  Something is very broken.  Leave it to the #PF
     * handler, which will probably result in a panic().
     */
    if ( !is_pv_vcpu(curr) )
        return 0;

    /* Try to copy a mapping from the guest's LDT, if it is valid. */
    if ( likely(pv_map_ldt_shadow_page(offset)) )
    {
        if ( guest_mode(regs) )
            trace_trap_two_addr(TRC_PV_GDT_LDT_MAPPING_FAULT,
                                regs->rip, offset);
    }
    else
    {
        /* In hypervisor mode? Leave it to the #PF handler to fix up. */
        if ( !guest_mode(regs) )
            return 0;

        /* Access would have become non-canonical? Pass #GP[sel] back. */
        if ( unlikely(!is_canonical_address(curr->arch.pv.ldt_base + offset)) )
        {
            uint16_t ec = (offset & ~(X86_XEC_EXT | X86_XEC_IDT)) | X86_XEC_TI;

            pv_inject_hw_exception(TRAP_gp_fault, ec);
        }
        else
            /* else pass the #PF back, with adjusted %cr2. */
            pv_inject_page_fault(regs->error_code,
                                 curr->arch.pv.ldt_base + offset);
    }

    return EXCRET_fault_fixed;
}

static int handle_gdt_ldt_mapping_fault(unsigned long offset,
                                        struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    /* Which vcpu's area did we fault in, and is it in the ldt sub-area? */
    unsigned int is_ldt_area = (offset >> (GDT_LDT_VCPU_VA_SHIFT-1)) & 1;
    unsigned int vcpu_area   = (offset >> GDT_LDT_VCPU_VA_SHIFT);

    /*
     * If the fault is in another vcpu's area, it cannot be due to
     * a GDT/LDT descriptor load. Thus we can reasonably exit immediately, and
     * indeed we have to since pv_map_ldt_shadow_page() works correctly only on
     * accesses to a vcpu's own area.
     */
    if ( vcpu_area != curr->vcpu_id )
        return 0;

    /* Byte offset within the gdt/ldt sub-area. */
    offset &= (1UL << (GDT_LDT_VCPU_VA_SHIFT-1)) - 1UL;

    if ( likely(is_ldt_area) )
        return handle_ldt_mapping_fault(offset, regs);

    /* GDT fault: handle the fault as #GP[sel]. */
    regs->error_code = offset & ~(X86_XEC_EXT | X86_XEC_IDT | X86_XEC_TI);
    do_general_protection(regs);

    return EXCRET_fault_fixed;
}
#endif

#define IN_HYPERVISOR_RANGE(va) \
    (((va) >= HYPERVISOR_VIRT_START) && ((va) < HYPERVISOR_VIRT_END))

enum pf_type {
    real_fault,
    smep_fault,
    smap_fault,
    spurious_fault
};

static enum pf_type __page_fault_type(unsigned long addr,
                                      const struct cpu_user_regs *regs)
{
    unsigned long mfn, cr3 = read_cr3();
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;
    unsigned int required_flags, disallowed_flags, page_user;
    unsigned int error_code = regs->error_code;

    /*
     * We do not take spurious page faults in IRQ handlers as we do not
     * modify page tables in IRQ context. We therefore bail here because
     * map_domain_page() is not IRQ-safe.
     */
    if ( in_irq() )
        return real_fault;

    /* Reserved bit violations are never spurious faults. */
    if ( error_code & PFEC_reserved_bit )
        return real_fault;

    required_flags  = _PAGE_PRESENT;
    if ( error_code & PFEC_write_access )
        required_flags |= _PAGE_RW;
    if ( error_code & PFEC_user_mode )
        required_flags |= _PAGE_USER;

    disallowed_flags = 0;
    if ( error_code & PFEC_insn_fetch )
        disallowed_flags |= _PAGE_NX_BIT;

    page_user = _PAGE_USER;

    mfn = cr3 >> PAGE_SHIFT;

    l4t = map_domain_page(_mfn(mfn));
    l4e = l4e_read_atomic(&l4t[l4_table_offset(addr)]);
    mfn = l4e_get_pfn(l4e);
    unmap_domain_page(l4t);
    if ( ((l4e_get_flags(l4e) & required_flags) != required_flags) ||
         (l4e_get_flags(l4e) & disallowed_flags) )
        return real_fault;
    page_user &= l4e_get_flags(l4e);

    l3t  = map_domain_page(_mfn(mfn));
    l3e = l3e_read_atomic(&l3t[l3_table_offset(addr)]);
    mfn = l3e_get_pfn(l3e);
    unmap_domain_page(l3t);
    if ( ((l3e_get_flags(l3e) & required_flags) != required_flags) ||
         (l3e_get_flags(l3e) & disallowed_flags) )
        return real_fault;
    page_user &= l3e_get_flags(l3e);
    if ( l3e_get_flags(l3e) & _PAGE_PSE )
        goto leaf;

    l2t = map_domain_page(_mfn(mfn));
    l2e = l2e_read_atomic(&l2t[l2_table_offset(addr)]);
    mfn = l2e_get_pfn(l2e);
    unmap_domain_page(l2t);
    if ( ((l2e_get_flags(l2e) & required_flags) != required_flags) ||
         (l2e_get_flags(l2e) & disallowed_flags) )
        return real_fault;
    page_user &= l2e_get_flags(l2e);
    if ( l2e_get_flags(l2e) & _PAGE_PSE )
        goto leaf;

    l1t = map_domain_page(_mfn(mfn));
    l1e = l1e_read_atomic(&l1t[l1_table_offset(addr)]);
    mfn = l1e_get_pfn(l1e);
    unmap_domain_page(l1t);
    if ( ((l1e_get_flags(l1e) & required_flags) != required_flags) ||
         (l1e_get_flags(l1e) & disallowed_flags) )
        return real_fault;
    page_user &= l1e_get_flags(l1e);

leaf:
    if ( page_user )
    {
        unsigned long cr4 = read_cr4();
        /*
         * Supervisor Mode Execution Prevention (SMEP):
         * Disallow supervisor execution from user-accessible mappings
         */
        if ( (cr4 & X86_CR4_SMEP) &&
             ((error_code & (PFEC_insn_fetch|PFEC_user_mode)) == PFEC_insn_fetch) )
            return smep_fault;

        /*
         * Supervisor Mode Access Prevention (SMAP):
         * Disallow supervisor access user-accessible mappings
         * A fault is considered as an SMAP violation if the following
         * conditions are true:
         *   - X86_CR4_SMAP is set in CR4
         *   - A user page is being accessed
         *   - CPL=3 or X86_EFLAGS_AC is clear
         *   - Page fault in kernel mode
         */
        if ( (cr4 & X86_CR4_SMAP) && !(error_code & PFEC_user_mode) &&
             (((regs->cs & 3) == 3) || !(regs->eflags & X86_EFLAGS_AC)) )
            return smap_fault;
    }

    return spurious_fault;
}

static enum pf_type spurious_page_fault(unsigned long addr,
                                        const struct cpu_user_regs *regs)
{
    unsigned long flags;
    enum pf_type pf_type;

    /*
     * Disabling interrupts prevents TLB flushing, and hence prevents
     * page tables from becoming invalid under our feet during the walk.
     */
    local_irq_save(flags);
    pf_type = __page_fault_type(addr, regs);
    local_irq_restore(flags);

    return pf_type;
}

static int fixup_page_fault(unsigned long addr, struct cpu_user_regs *regs)
{
    struct vcpu   *v = current;
    struct domain *d = v->domain;

    /* No fixups in interrupt context or when interrupts are disabled. */
    if ( in_irq() || !(regs->eflags & X86_EFLAGS_IF) )
        return 0;

    if ( !(regs->error_code & PFEC_page_present) &&
          (pagefault_by_memadd(addr, regs)) )
        return handle_memadd_fault(addr, regs);

    if ( unlikely(IN_HYPERVISOR_RANGE(addr)) )
    {
#ifdef CONFIG_PV
        if ( !(regs->error_code & (PFEC_user_mode | PFEC_reserved_bit)) &&
             (addr >= GDT_LDT_VIRT_START) && (addr < GDT_LDT_VIRT_END) )
            return handle_gdt_ldt_mapping_fault(
                addr - GDT_LDT_VIRT_START, regs);
#endif
        return 0;
    }

    if ( guest_kernel_mode(v, regs) &&
         !(regs->error_code & (PFEC_reserved_bit | PFEC_insn_fetch)) &&
         (regs->error_code & PFEC_write_access) )
    {
        bool ptwr, mmio_ro;

        ptwr = VM_ASSIST(d, writable_pagetables) &&
               /* Do not check if access-protection fault since the page may
                  legitimately be not present in shadow page tables */
               (paging_mode_enabled(d) ||
                (regs->error_code & PFEC_page_present));

        mmio_ro = is_hardware_domain(d) &&
                  (regs->error_code & PFEC_page_present);

        if ( (ptwr || mmio_ro) && pv_ro_page_fault(addr, regs) )
            return EXCRET_fault_fixed;
    }

    /*
     * For non-external shadowed guests, we fix up both their own pagefaults
     * and Xen's, since they share the pagetables.  This includes hypervisor
     * faults, e.g. from copy_to_user().
     */
    if ( paging_mode_enabled(d) && !paging_mode_external(d) )
    {
        int ret = paging_fault(addr, regs);

        if ( ret == EXCRET_fault_fixed )
            trace_trap_two_addr(TRC_PV_PAGING_FIXUP, regs->rip, addr);
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
void do_page_fault(struct cpu_user_regs *regs)
{
    unsigned long addr, fixup;
    unsigned int error_code;

    addr = read_cr2();

    /* fixup_page_fault() might change regs->error_code, so cache it here. */
    error_code = regs->error_code;

    if ( debugger_trap_entry(TRAP_page_fault, regs) )
        return;

    perfc_incr(page_faults);

    if ( unlikely(fixup_page_fault(addr, regs) != 0) )
        return;

    if ( unlikely(!guest_mode(regs)) )
    {
        enum pf_type pf_type = spurious_page_fault(addr, regs);

        if ( (pf_type == smep_fault) || (pf_type == smap_fault) )
        {
            console_start_sync();
            printk("Xen SM%cP violation\n",
                   (pf_type == smep_fault) ? 'E' : 'A');
            fatal_trap(regs, 0);
        }

        if ( pf_type != real_fault )
            return;

        if ( likely((fixup = search_exception_table(regs)) != 0) )
        {
            perfc_incr(copy_user_faults);
            if ( unlikely(regs->error_code & PFEC_reserved_bit) )
                reserved_bit_page_fault(addr, regs);
            this_cpu(last_extable_addr) = regs->rip;
            regs->rip = fixup;
            return;
        }

        if ( debugger_trap_fatal(TRAP_page_fault, regs) )
            return;

        show_execution_state(regs);
        show_page_walk(addr);
        panic("FATAL PAGE FAULT\n"
              "[error_code=%04x]\n"
              "Faulting linear address: %p\n",
              error_code, _p(addr));
    }

    if ( unlikely(regs->error_code & PFEC_reserved_bit) )
        reserved_bit_page_fault(addr, regs);

    pv_inject_page_fault(regs->error_code, addr);
}

/*
 * Early #PF handler to print CR2, error code, and stack.
 *
 * We also deal with spurious faults here, even though they should never happen
 * during early boot (an issue was seen once, but was most likely a hardware
 * problem).
 */
void __init do_early_page_fault(struct cpu_user_regs *regs)
{
    static unsigned int __initdata stuck;
    static unsigned long __initdata prev_eip, prev_cr2;
    unsigned long cr2 = read_cr2();

    BUG_ON(smp_processor_id() != 0);

    if ( (regs->rip != prev_eip) || (cr2 != prev_cr2) )
    {
        prev_eip = regs->rip;
        prev_cr2 = cr2;
        stuck    = 0;
        return;
    }

    if ( stuck++ == 1000 )
    {
        console_start_sync();
        printk("Early fatal page fault at %04x:%p (cr2=%p, ec=%04x)\n",
               regs->cs, _p(regs->rip), _p(cr2), regs->error_code);
        fatal_trap(regs, 0);
    }
}

void do_general_protection(struct cpu_user_regs *regs)
{
#ifdef CONFIG_PV
    struct vcpu *v = current;
#endif
    unsigned long fixup;

    if ( debugger_trap_entry(TRAP_gp_fault, regs) )
        return;

    if ( regs->error_code & X86_XEC_EXT )
        goto hardware_gp;

    if ( !guest_mode(regs) )
        goto gp_in_kernel;

#ifdef CONFIG_PV
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
     * clear (which got already checked above) to indicate that it's a software
     * fault, not a hardware one.
     *
     * NOTE: Vectors 3 and 4 are dealt with from their own handler. This is
     * okay because they can only be triggered by an explicit DPL-checked
     * instruction. The DPL specified by the guest OS for these vectors is NOT
     * CHECKED!!
     */
    if ( regs->error_code & X86_XEC_IDT )
    {
        /* This fault must be due to <INT n> instruction. */
        uint8_t vector = regs->error_code >> 3;
        const struct trap_info *ti = &v->arch.pv.trap_ctxt[vector];

        if ( permit_softint(TI_GET_DPL(ti), v, regs) )
        {
            regs->rip += 2;
            pv_inject_sw_interrupt(vector);
            return;
        }
    }
    else if ( is_pv_32bit_vcpu(v) && regs->error_code )
    {
        pv_emulate_gate_op(regs);
        return;
    }

    /* Emulate some simple privileged and I/O instructions. */
    if ( (regs->error_code == 0) &&
         pv_emulate_privileged_op(regs) )
    {
        trace_trap_one_addr(TRC_PV_EMULATE_PRIVOP, regs->rip);
        return;
    }

    /* Pass on GPF as is. */
    pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
    return;
#endif

 gp_in_kernel:

    if ( likely((fixup = search_exception_table(regs)) != 0) )
    {
        dprintk(XENLOG_INFO, "GPF (%04x): %p [%ps] -> %p\n",
                regs->error_code, _p(regs->rip), _p(regs->rip), _p(fixup));
        this_cpu(last_extable_addr) = regs->rip;
        regs->rip = fixup;
        return;
    }

 hardware_gp:
    if ( debugger_trap_fatal(TRAP_gp_fault, regs) )
        return;

    show_execution_state(regs);
    panic("GENERAL PROTECTION FAULT\n[error_code=%04x]\n", regs->error_code);
}

static void pci_serr_softirq(void)
{
    printk("\n\nNMI - PCI system error (SERR)\n");
    outb(inb(0x61) & 0x0b, 0x61); /* re-enable the PCI SERR error line. */
}

static void nmi_hwdom_report(unsigned int reason_idx)
{
    struct domain *d = hardware_domain;

    if ( !d || !d->vcpu || !d->vcpu[0] || !is_pv_domain(d) /* PVH fixme */ )
        return;

    set_bit(reason_idx, nmi_reason(d));

    pv_raise_nmi(d->vcpu[0]);
}

static void pci_serr_error(const struct cpu_user_regs *regs)
{
    outb((inb(0x61) & 0x0f) | 0x04, 0x61); /* clear-and-disable the PCI SERR error line. */

    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        nmi_hwdom_report(_XEN_NMIREASON_pci_serr);
        /* fallthrough */
    case 'i': /* 'ignore' */
        /* Would like to print a diagnostic here but can't call printk()
           from NMI context -- raise a softirq instead. */
        raise_softirq(PCI_SERR_SOFTIRQ);
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("\n\nNMI - PCI system error (SERR)\n");
        fatal_trap(regs, 0);
    }
}

static void io_check_error(const struct cpu_user_regs *regs)
{
    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        nmi_hwdom_report(_XEN_NMIREASON_io_error);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("\n\nNMI - I/O ERROR\n");
        fatal_trap(regs, 0);
    }

    outb((inb(0x61) & 0x0f) | 0x08, 0x61); /* clear-and-disable IOCK */
    mdelay(1);
    outb((inb(0x61) & 0x07) | 0x00, 0x61); /* enable IOCK */
}

static void unknown_nmi_error(const struct cpu_user_regs *regs,
                              unsigned char reason)
{
    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        nmi_hwdom_report(_XEN_NMIREASON_unknown);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("Uhhuh. NMI received for unknown reason %02x.\n", reason);
        printk("Do you have a strange power saving mode enabled?\n");
        fatal_trap(regs, 0);
    }
}

static int dummy_nmi_callback(const struct cpu_user_regs *regs, int cpu)
{
    return 0;
}

static nmi_callback_t *nmi_callback = dummy_nmi_callback;

DEFINE_PER_CPU(unsigned int, nmi_count);

void do_nmi(const struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();
    unsigned char reason = 0;
    bool handle_unknown = false;

    this_cpu(nmi_count)++;
    nmi_enter();

    if ( nmi_callback(regs, cpu) )
    {
        nmi_exit();
        return;
    }

    /*
     * Accessing port 0x61 may trap to SMM which has been actually
     * observed on some production SKX servers. This SMI sometimes
     * takes enough time for the next NMI tick to happen. By reading
     * this port before we re-arm the NMI watchdog, we reduce the chance
     * of having an NMI watchdog expire while in the SMI handler.
     */
    if ( cpu == nmi_cpu )
        reason = inb(0x61);

    if ( (nmi_watchdog == NMI_NONE) ||
         (!nmi_watchdog_tick(regs) && watchdog_force) )
        handle_unknown = true;

    /* Only the BSP gets external NMIs from the system. */
    if ( cpu == nmi_cpu )
    {
        if ( reason & 0x80 )
            pci_serr_error(regs);
        if ( reason & 0x40 )
            io_check_error(regs);
        if ( !(reason & 0xc0) && handle_unknown )
            unknown_nmi_error(regs, reason);
    }

    nmi_exit();
}

nmi_callback_t *set_nmi_callback(nmi_callback_t *callback)
{
    nmi_callback_t *old_nmi_callback = nmi_callback;

    nmi_callback = callback;

    return old_nmi_callback;
}

void unset_nmi_callback(void)
{
    nmi_callback = dummy_nmi_callback;
}

void do_device_not_available(struct cpu_user_regs *regs)
{
#ifdef CONFIG_PV
    struct vcpu *curr = current;
#endif

    if ( !guest_mode(regs) )
    {
        unsigned long fixup = search_exception_table(regs);

        gprintk(XENLOG_ERR, "#NM: %p [%ps] -> %p\n",
                _p(regs->rip), _p(regs->rip), _p(fixup));
        /*
         * We shouldn't be able to reach here, but for release builds have
         * the recovery logic in place nevertheless.
         */
        ASSERT_UNREACHABLE();
        BUG_ON(!fixup);
        regs->rip = fixup;
        return;
    }

#ifdef CONFIG_PV
    vcpu_restore_fpu_lazy(curr);

    if ( curr->arch.pv.ctrlreg[0] & X86_CR0_TS )
    {
        pv_inject_hw_exception(TRAP_no_device, X86_EVENT_NO_EC);
        curr->arch.pv.ctrlreg[0] &= ~X86_CR0_TS;
    }
    else
        TRACE_0D(TRC_PV_MATH_STATE_RESTORE);
#else
    ASSERT_UNREACHABLE();
#endif
}

void do_debug(struct cpu_user_regs *regs)
{
    unsigned long dr6;
    struct vcpu *v = current;

    /* Stash dr6 as early as possible. */
    dr6 = read_debugreg(6);

    if ( debugger_trap_entry(TRAP_debug, regs) )
        return;

    /*
     * At the time of writing (March 2018), on the subject of %dr6:
     *
     * The Intel manual says:
     *   Certain debug exceptions may clear bits 0-3. The remaining contents
     *   of the DR6 register are never cleared by the processor. To avoid
     *   confusion in identifying debug exceptions, debug handlers should
     *   clear the register (except bit 16, which they should set) before
     *   returning to the interrupted task.
     *
     * The AMD manual says:
     *   Bits 15:13 of the DR6 register are not cleared by the processor and
     *   must be cleared by software after the contents have been read.
     *
     * Some bits are reserved set, some are reserved clear, and some bits
     * which were previously reserved set are reused and cleared by hardware.
     * For future compatibility, reset to the default value, which will allow
     * us to spot any bit being changed by hardware to its non-default value.
     */
    write_debugreg(6, X86_DR6_DEFAULT);

    /* #DB automatically disabled LBR.  Reinstate it if debugging Xen. */
    if ( cpu_has_xen_lbr )
        wrmsrl(MSR_IA32_DEBUGCTLMSR, IA32_DEBUGCTLMSR_LBR);

    if ( !guest_mode(regs) )
    {
        /*
         * !!! WARNING !!!
         *
         * %dr6 is mostly guest controlled at this point.  Any decsions base
         * on its value must be crosschecked with non-guest controlled state.
         */

        if ( regs->eflags & X86_EFLAGS_TF )
        {
#ifdef CONFIG_PV
            /* In SYSENTER entry path we can't zap TF until EFLAGS is saved. */
            if ( (regs->rip >= (unsigned long)sysenter_entry) &&
                 (regs->rip <= (unsigned long)sysenter_eflags_saved) )
            {
                if ( regs->rip == (unsigned long)sysenter_eflags_saved )
                    regs->eflags &= ~X86_EFLAGS_TF;
                return;
            }
#endif
            if ( !debugger_trap_fatal(TRAP_debug, regs) )
            {
                WARN();
                regs->eflags &= ~X86_EFLAGS_TF;
            }
        }

        /*
         * Check for fault conditions.  General Detect, and instruction
         * breakpoints are faults rather than traps, at which point attempting
         * to ignore and continue will result in a livelock.
         *
         * However, on entering the #DB handler, hardware clears %dr7.gd for
         * us (as confirmed by the earlier %dr6 accesses succeeding), meaning
         * that a real General Detect exception is restartable.
         *
         * PV guests are not permitted to point %dr{0..3} at Xen linear
         * addresses, and Instruction Breakpoints (being faults) don't get
         * delayed by a MovSS shadow, so we should never encounter one in
         * hypervisor context.
         *
         * If however we do, safety measures need to be enacted.  Use a big
         * hammer and clear all debug settings.
         */
        if ( dr6 & (DR_TRAP3 | DR_TRAP2 | DR_TRAP1 | DR_TRAP0) )
        {
            unsigned int bp, dr7 = read_debugreg(7);

            for ( bp = 0; bp < 4; ++bp )
            {
                if ( (dr6 & (1u << bp)) && /* Breakpoint triggered? */
                     (dr7 & (3u << (bp * DR_ENABLE_SIZE))) && /* Enabled? */
                     ((dr7 & (3u << ((bp * DR_CONTROL_SIZE) + /* Insn? */
                                     DR_CONTROL_SHIFT))) == DR_RW_EXECUTE) )
                {
                    ASSERT_UNREACHABLE();

                    printk(XENLOG_ERR
                           "Hit instruction breakpoint in Xen context\n");
                    write_debugreg(7, 0);
                    break;
                }
            }
        }

        /*
         * Whatever caused this #DB should be restartable by this point.  Note
         * it and continue.  Guests can trigger this in certain corner cases,
         * so ensure the message is ratelimited.
         */
        gprintk(XENLOG_WARNING,
                "Hit #DB in Xen context: %04x:%p [%ps], stk %04x:%p, dr6 %lx\n",
                regs->cs, _p(regs->rip), _p(regs->rip),
                regs->ss, _p(regs->rsp), dr6);

        return;
    }

    /* Save debug status register where guest OS can peek at it */
    v->arch.dr6 |= (dr6 & ~X86_DR6_DEFAULT);
    v->arch.dr6 &= (dr6 | ~X86_DR6_DEFAULT);

    pv_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);
}

static void __init noinline __set_intr_gate(unsigned int n,
                                            uint32_t dpl, void *addr)
{
    _set_gate(&idt_table[n], SYS_DESC_irq_gate, dpl, addr);
}

static void __init set_swint_gate(unsigned int n, void *addr)
{
    __set_intr_gate(n, 3, addr);
}

static void __init set_intr_gate(unsigned int n, void *addr)
{
    __set_intr_gate(n, 0, addr);
}

static unsigned int calc_ler_msr(void)
{
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        switch ( boot_cpu_data.x86 )
        {
        case 6:
            return MSR_IA32_LASTINTFROMIP;

        case 15:
            return MSR_P4_LER_FROM_LIP;
        }
        break;

    case X86_VENDOR_AMD:
        switch ( boot_cpu_data.x86 )
        {
        case 6:
        case 0xf ... 0x17:
            return MSR_IA32_LASTINTFROMIP;
        }
        break;

    case X86_VENDOR_HYGON:
        return MSR_IA32_LASTINTFROMIP;
    }

    return 0;
}

void percpu_traps_init(void)
{
    subarch_percpu_traps_init();

    if ( !opt_ler )
        return;

    if ( !ler_msr && (ler_msr = calc_ler_msr()) )
        setup_force_cpu_cap(X86_FEATURE_XEN_LBR);

    if ( cpu_has_xen_lbr )
        wrmsrl(MSR_IA32_DEBUGCTLMSR, IA32_DEBUGCTLMSR_LBR);
}

void __init init_idt_traps(void)
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
    set_intr_gate(TRAP_double_fault,&double_fault);
    set_intr_gate(TRAP_invalid_tss,&invalid_TSS);
    set_intr_gate(TRAP_no_segment,&segment_not_present);
    set_intr_gate(TRAP_stack_error,&stack_segment);
    set_intr_gate(TRAP_gp_fault,&general_protection);
    set_intr_gate(TRAP_page_fault,&early_page_fault);
    set_intr_gate(TRAP_copro_error,&coprocessor_error);
    set_intr_gate(TRAP_alignment_check,&alignment_check);
    set_intr_gate(TRAP_machine_check,&machine_check);
    set_intr_gate(TRAP_simd_error,&simd_coprocessor_error);

    /* Specify dedicated interrupt stacks for NMI, #DF, and #MC. */
    enable_each_ist(idt_table);

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    this_cpu(gdt) = boot_gdt;
    this_cpu(compat_gdt) = boot_compat_gdt;
}

extern void (*const autogen_entrypoints[X86_NR_VECTORS])(void);
void __init trap_init(void)
{
    unsigned int vector;

    /* Replace early pagefault with real pagefault handler. */
    set_intr_gate(TRAP_page_fault, &page_fault);

    pv_trap_init();

    for ( vector = 0; vector < X86_NR_VECTORS; ++vector )
    {
        if ( autogen_entrypoints[vector] )
        {
            /* Found autogen entry: check we won't clobber an existing trap. */
            ASSERT(idt_table[vector].b == 0);
            set_intr_gate(vector, autogen_entrypoints[vector]);
        }
        else
        {
            /* No entry point: confirm we have an existing trap in place. */
            ASSERT(idt_table[vector].b != 0);
        }
    }

    /* Cache {,compat_}gdt_l1e now that physically relocation is done. */
    this_cpu(gdt_l1e) =
        l1e_from_pfn(virt_to_mfn(boot_gdt), __PAGE_HYPERVISOR_RW);
    this_cpu(compat_gdt_l1e) =
        l1e_from_pfn(virt_to_mfn(boot_compat_gdt), __PAGE_HYPERVISOR_RW);

    percpu_traps_init();

    cpu_init();

    open_softirq(PCI_SERR_SOFTIRQ, pci_serr_softirq);
}

void activate_debugregs(const struct vcpu *curr)
{
    ASSERT(curr == current);

    write_debugreg(0, curr->arch.dr[0]);
    write_debugreg(1, curr->arch.dr[1]);
    write_debugreg(2, curr->arch.dr[2]);
    write_debugreg(3, curr->arch.dr[3]);
    write_debugreg(6, curr->arch.dr6);

    /*
     * Avoid writing the subsequently getting replaced value when getting
     * called from set_debugreg() below. Eventual future callers will need
     * to take this into account.
     */
    if ( curr->arch.dr7 & DR7_ACTIVE_MASK )
        write_debugreg(7, curr->arch.dr7);

    if ( boot_cpu_has(X86_FEATURE_DBEXT) )
    {
        wrmsrl(MSR_AMD64_DR0_ADDRESS_MASK, curr->arch.msrs->dr_mask[0]);
        wrmsrl(MSR_AMD64_DR1_ADDRESS_MASK, curr->arch.msrs->dr_mask[1]);
        wrmsrl(MSR_AMD64_DR2_ADDRESS_MASK, curr->arch.msrs->dr_mask[2]);
        wrmsrl(MSR_AMD64_DR3_ADDRESS_MASK, curr->arch.msrs->dr_mask[3]);
    }
}

void asm_domain_crash_synchronous(unsigned long addr)
{
    /*
     * We need clear AC bit here because in entry.S AC is set
     * by ASM_STAC to temporarily allow accesses to user pages
     * which is prevented by SMAP by default.
     *
     * For some code paths, where this function is called, clac()
     * is not needed, but adding clac() here instead of each place
     * asm_domain_crash_synchronous() is called can reduce the code
     * redundancy, and it is harmless as well.
     */
    clac();

    if ( addr == 0 )
        addr = this_cpu(last_extable_addr);

    printk("domain_crash_sync called from entry.S: fault at %p %pS\n",
           _p(addr), _p(addr));

    __domain_crash(current->domain);

    for ( ; ; )
        do_softirq();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
