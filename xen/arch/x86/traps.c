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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
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
#include <xen/nmi.h>
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

DEFINE_PER_CPU(u64, efer);
static DEFINE_PER_CPU(unsigned long, last_extable_addr);

DEFINE_PER_CPU_READ_MOSTLY(u32, ler_msr);

DEFINE_PER_CPU_READ_MOSTLY(struct desc_struct *, gdt_table);
DEFINE_PER_CPU_READ_MOSTLY(struct desc_struct *, compat_gdt_table);

/* Master table, used by CPU0. */
idt_entry_t idt_table[IDT_ENTRIES];

/* Pointer to the IDT of every CPU. */
idt_entry_t *idt_tables[NR_CPUS] __read_mostly;

void (*ioemul_handle_quirk)(
    u8 opcode, char *io_emul_stub, struct cpu_user_regs *regs);

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

static bool_t opt_ler;
boolean_param("ler", opt_ler);

#define stack_words_per_line 4
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)regs->rsp)

static void show_code(const struct cpu_user_regs *regs)
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

    stack = (unsigned long *)regs->esp;
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
 * Stack pages 0, 1 and 2:
 *   These are all 1-page IST stacks.  Each of these stacks have an exception
 *   frame and saved register state at the top.  The interesting bound for a
 *   trace is the word adjacent to this, while the bound for a dump is the
 *   very top, including the exception frame.
 *
 * Stack pages 3, 4 and 5:
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
    case 0 ... 2:
        return ROUNDUP(sp, PAGE_SIZE) -
            offsetof(struct cpu_user_regs, es) - sizeof(unsigned long);

#ifndef MEMORY_GUARD
    case 3 ... 5:
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
    case 0 ... 2:
        return ROUNDUP(sp, PAGE_SIZE) - sizeof(unsigned long);

#ifndef MEMORY_GUARD
    case 3 ... 5:
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
            printk("   [<%p>] %pS\n", _p(addr), _p(addr));
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

        printk("   [<%p>] %pS\n", _p(addr), _p(addr));

        low = (unsigned long)&frame[2];
    }
}

#endif

static void show_trace(const struct cpu_user_regs *regs)
{
    unsigned long *sp = ESP_BEFORE_EXCEPTION(regs);

    printk("Xen call trace:\n");

    /*
     * If RIP looks sensible, or the top of the stack doesn't, print RIP at
     * the top of the stack trace.
     */
    if ( is_active_kernel_text(regs->rip) ||
         !is_active_kernel_text(*sp) )
        printk("   [<%p>] %pS\n", _p(regs->rip), _p(regs->rip));
    /*
     * Else RIP looks bad but the top of the stack looks good.  Perhaps we
     * followed a wild function pointer? Lets assume the top of the stack is a
     * return address; print it and skip past so _show_trace() doesn't print
     * it again.
     */
    else
    {
        printk("   [<%p>] %pS\n", _p(*sp), _p(*sp));
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

    printk("Valid stack range: %p-%p, sp=%p, tss.esp0=%p\n",
           (void *)esp_top, (void *)esp_bottom, (void *)esp,
           (void *)per_cpu(init_tss, cpu).esp0);

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
static bool_t opt_show_all;
boolean_param("async-show-all", opt_show_all);

static int nmi_show_execution_state(const struct cpu_user_regs *regs, int cpu)
{
    if ( !cpumask_test_cpu(cpu, &show_state_mask) )
        return 0;

    if ( opt_show_all )
        show_execution_state(regs);
    else
        printk(XENLOG_ERR "CPU%d @ %04x:%08lx (%pS)\n", cpu, regs->cs, regs->rip,
               guest_mode(regs) ? _p(regs->rip) : NULL);
    cpumask_clear_cpu(cpu, &show_state_mask);

    return 1;
}

static const char *trapstr(unsigned int trapnr)
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
void fatal_trap(const struct cpu_user_regs *regs, bool_t show_remote)
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
        {
            unsigned long cr2 = read_cr2();
            printk("Faulting linear address: %p\n", _p(cr2));
            show_page_walk(cr2);
        }

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
          "[error_code=%04x] %s",
          trapnr, trapstr(trapnr), regs->error_code,
          (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
}

static void pv_inject_event(
    unsigned int trapnr, const struct cpu_user_regs *regs, unsigned int type)
{
    struct vcpu *v = current;
    struct trap_bounce *tb;
    const struct trap_info *ti;
    bool use_error_code;

    if ( type == X86_EVENTTYPE_HW_EXCEPTION )
    {
        ASSERT(trapnr < 32);
        use_error_code = TRAP_HAVE_EC & (1u << trapnr);
    }
    else
    {
        ASSERT(type == X86_EVENTTYPE_SW_INTERRUPT);
        use_error_code = false;
    }

    trace_pv_trap(trapnr, regs->eip, use_error_code, regs->error_code);

    tb = &v->arch.pv_vcpu.trap_bounce;
    ti = &v->arch.pv_vcpu.trap_ctxt[trapnr];

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
        gprintk(XENLOG_WARNING,
                "Unhandled %s fault/trap [#%d, ec=%04x]\n",
                trapstr(trapnr), trapnr, regs->error_code);
}

static void do_guest_trap(
    unsigned int trapnr, const struct cpu_user_regs *regs)
{
    pv_inject_event(trapnr, regs, X86_EVENTTYPE_HW_EXCEPTION);
}

static void instruction_done(
    struct cpu_user_regs *regs, unsigned long eip, unsigned int bpmatch)
{
    regs->eip = eip;
    regs->eflags &= ~X86_EFLAGS_RF;
    if ( bpmatch || (regs->eflags & X86_EFLAGS_TF) )
    {
        current->arch.debugreg[6] |= bpmatch | DR_STATUS_RESERVED_ONE;
        if ( regs->eflags & X86_EFLAGS_TF )
            current->arch.debugreg[6] |= DR_STEP;
        do_guest_trap(TRAP_debug, regs);
    }
}

static unsigned int check_guest_io_breakpoint(struct vcpu *v,
    unsigned int port, unsigned int len)
{
    unsigned int width, i, match = 0;
    unsigned long start;

    if ( !(v->arch.debugreg[5]) ||
         !(v->arch.pv_vcpu.ctrlreg[4] & X86_CR4_DE) )
        return 0;

    for ( i = 0; i < 4; i++ )
    {
        if ( !(v->arch.debugreg[5] &
               (3 << (i * DR_ENABLE_SIZE))) )
            continue;

        start = v->arch.debugreg[i];
        width = 0;

        switch ( (v->arch.debugreg[7] >>
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
int set_guest_machinecheck_trapbounce(void)
{
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.pv_vcpu.trap_bounce;
 
    do_guest_trap(TRAP_machine_check, guest_cpu_user_regs());
    tb->flags &= ~TBF_EXCEPTION; /* not needed for MCE delivery path */
    return !null_trap_bounce(v, tb);
}

/*
 * Called from asm to set up the NMI trapbounce info.
 * Returns 0 if no callback is set up, else 1.
 */
int set_guest_nmi_trapbounce(void)
{
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.pv_vcpu.trap_bounce;
    do_guest_trap(TRAP_nmi, guest_cpu_user_regs());
    tb->flags &= ~TBF_EXCEPTION; /* not needed for NMI delivery path */
    return !null_trap_bounce(v, tb);
}

void do_reserved_trap(struct cpu_user_regs *regs)
{
    unsigned int trapnr = regs->entry_vector;

    if ( debugger_trap_fatal(trapnr, regs) )
        return;

    show_execution_state(regs);
    panic("FATAL RESERVED TRAP %#x: %s", trapnr, trapstr(trapnr));
}

void do_trap(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    unsigned int trapnr = regs->entry_vector;
    unsigned long fixup;

    if ( regs->error_code & X86_XEC_EXT )
        goto hardware_trap;

    if ( debugger_trap_entry(trapnr, regs) )
        return;

    if ( guest_mode(regs) )
    {
        do_guest_trap(trapnr, regs);
        return;
    }

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        dprintk(XENLOG_ERR, "Trap %d: %p -> %p\n",
                trapnr, _p(regs->eip), _p(fixup));
        this_cpu(last_extable_addr) = regs->eip;
        regs->eip = fixup;
        return;
    }

    if ( ((trapnr == TRAP_copro_error) || (trapnr == TRAP_simd_error)) &&
         system_state >= SYS_STATE_active && has_hvm_container_vcpu(curr) &&
         curr->arch.hvm_vcpu.fpu_exception_callback )
    {
        curr->arch.hvm_vcpu.fpu_exception_callback(
            curr->arch.hvm_vcpu.fpu_exception_callback_arg, regs);
        return;
    }

 hardware_trap:
    if ( debugger_trap_fatal(trapnr, regs) )
        return;

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x]",
          trapnr, trapstr(trapnr), regs->error_code);
}

/* Returns 0 if not handled, and non-0 for success. */
int rdmsr_hypervisor_regs(uint32_t idx, uint64_t *val)
{
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    switch ( idx - base )
    {
    case 0: /* Write hypercall page MSR.  Read as zero. */
    {
        *val = 0;
        return 1;
    }
    }

    return 0;
}

/* Returns 1 if handled, 0 if not and -Exx for error. */
int wrmsr_hypervisor_regs(uint32_t idx, uint64_t val)
{
    struct domain *d = current->domain;
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
            return 0;
        }

        page = get_page_from_gfn(d, gmfn, &t, P2M_ALLOC);

        if ( !page || !get_page_type(page, PGT_writable_page) )
        {
            if ( page )
                put_page(page);

            if ( p2m_is_paging(t) )
            {
                p2m_mem_paging_populate(d, gmfn);
                return -ERESTART;
            }

            gdprintk(XENLOG_WARNING,
                     "Bad GMFN %lx (MFN %lx) to MSR %08x\n",
                     gmfn, page ? page_to_mfn(page) : -1UL, base);
            return 0;
        }

        hypercall_page = __map_domain_page(page);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(page);
        return 1;
    }
    }

    return 0;
}

int cpuid_hypervisor_leaves( uint32_t idx, uint32_t sub_idx,
               uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    struct domain *currd = current->domain;
    /* Optionally shift out of the way of Viridian architectural leaves. */
    uint32_t base = is_viridian_domain(currd) ? 0x40000100 : 0x40000000;
    uint32_t limit, dummy;

    idx -= base;
    if ( idx > XEN_CPUID_MAX_NUM_LEAVES )
        return 0; /* Avoid unnecessary pass through domain_cpuid() */

    domain_cpuid(currd, base, 0, &limit, &dummy, &dummy, &dummy);
    if ( limit == 0 )
        /* Default number of leaves */
        limit = XEN_CPUID_MAX_NUM_LEAVES;
    else
    {
        /* User-specified number of leaves */
        limit &= 0xff;
        if ( limit < 2 )
            limit = 2;
        else if ( limit > XEN_CPUID_MAX_NUM_LEAVES )
            limit = XEN_CPUID_MAX_NUM_LEAVES;
    }

    if ( idx > limit ) 
        return 0;

    switch ( idx )
    {
    case 0:
        *eax = base + limit; /* Largest leaf */
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
        if ( is_viridian_domain(currd) )
            *ebx = 0x40000200;
        *ecx = 0;          /* Features 1 */
        *edx = 0;          /* Features 2 */
        if ( is_pv_domain(currd) )
            *ecx |= XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD;
        break;

    case 3:
        *eax = *ebx = *ecx = *edx = 0;
        cpuid_time_leaf( sub_idx, eax, ebx, ecx, edx );
        break;

    case 4:
        if ( !has_hvm_container_domain(currd) )
        {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        hvm_hypervisor_cpuid_leaf(sub_idx, eax, ebx, ecx, edx);
        break;

    default:
        BUG();
    }

    return 1;
}

void pv_cpuid(struct cpu_user_regs *regs)
{
    uint32_t leaf, subleaf, a, b, c, d;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;

    leaf = a = regs->eax;
    b = regs->ebx;
    subleaf = c = regs->ecx;
    d = regs->edx;

    if ( cpuid_hypervisor_leaves(leaf, subleaf, &a, &b, &c, &d) )
        goto out;

    if ( leaf & 0x7fffffff )
    {
        /*
         * Requests outside the supported leaf ranges return zero on AMD
         * and the highest basic leaf output on Intel. Uniformly follow
         * the AMD model as the more sane one.
         */
        unsigned int limit = (leaf >> 16) != 0x8000 ? 0 : 0x80000000, dummy;

        if ( !is_control_domain(currd) && !is_hardware_domain(currd) )
            domain_cpuid(currd, limit, 0, &limit, &dummy, &dummy, &dummy);
        else
            limit = cpuid_eax(limit);
        if ( leaf > limit )
        {
            regs->eax = 0;
            regs->ebx = 0;
            regs->ecx = 0;
            regs->edx = 0;
            return;
        }
    }

    if ( !is_control_domain(currd) && !is_hardware_domain(currd) )
        domain_cpuid(currd, leaf, subleaf, &a, &b, &c, &d);
    else
        cpuid_count(leaf, subleaf, &a, &b, &c, &d);

    switch ( leaf )
    {
        uint32_t tmp, _ecx, _ebx;

    case 0x00000001:
        c &= pv_featureset[FEATURESET_1c];
        d &= pv_featureset[FEATURESET_1d];

        if ( is_pv_32bit_domain(currd) )
            c &= ~cpufeat_mask(X86_FEATURE_CX16);

        if ( !is_pvh_domain(currd) )
        {
            /*
             * Delete the PVH condition when HVMLite formally replaces PVH,
             * and HVM guests no longer enter a PV codepath.
             */

            /*
             * !!! OSXSAVE handling for PV guests is non-architectural !!!
             *
             * Architecturally, the correct code here is simply:
             *
             *   if ( curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_OSXSAVE )
             *       c |= cpufeat_mask(X86_FEATURE_OSXSAVE);
             *
             * However because of bugs in Xen (before c/s bd19080b, Nov 2010,
             * the XSAVE cpuid flag leaked into guests despite the feature not
             * being available for use), buggy workarounds where introduced to
             * Linux (c/s 947ccf9c, also Nov 2010) which relied on the fact
             * that Xen also incorrectly leaked OSXSAVE into the guest.
             *
             * Furthermore, providing architectural OSXSAVE behaviour to a
             * many Linux PV guests triggered a further kernel bug when the
             * fpu code observes that XSAVEOPT is available, assumes that
             * xsave state had been set up for the task, and follows a wild
             * pointer.
             *
             * Older Linux PVOPS kernels however do require architectural
             * behaviour.  They observe Xen's leaked OSXSAVE and assume they
             * can already use XSETBV, dying with a #UD because the shadowed
             * CR4.OSXSAVE is clear.  This behaviour has been adjusted in all
             * observed cases via stable backports of the above changeset.
             *
             * Therefore, the leaking of Xen's OSXSAVE setting has become a
             * defacto part of the PV ABI and can't reasonably be corrected.
             * It can however be restricted to only the enlightened CPUID
             * view, as seen by the guest kernel.
             *
             * The following situations and logic now applies:
             *
             * - Hardware without CPUID faulting support and native CPUID:
             *    There is nothing Xen can do here.  The hosts XSAVE flag will
             *    leak through and Xen's OSXSAVE choice will leak through.
             *
             *    In the case that the guest kernel has not set up OSXSAVE, only
             *    SSE will be set in xcr0, and guest userspace can't do too much
             *    damage itself.
             *
             * - Enlightened CPUID or CPUID faulting available:
             *    Xen can fully control what is seen here.  Guest kernels need
             *    to see the leaked OSXSAVE via the enlightened path, but
             *    guest userspace and the native is given architectural
             *    behaviour.
             *
             *    Emulated vs Faulted CPUID is distinguised based on whether a
             *    #UD or #GP is currently being serviced.
             */
            /* OSXSAVE cleared by pv_featureset.  Fast-forward CR4 back in. */
            if ( (curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_OSXSAVE) ||
                 (regs->entry_vector == TRAP_invalid_op &&
                  guest_kernel_mode(curr, regs) &&
                  (read_cr4() & X86_CR4_OSXSAVE)) )
                c |= cpufeat_mask(X86_FEATURE_OSXSAVE);

            /*
             * At the time of writing, a PV domain is the only viable option
             * for Dom0.  Several interactions between dom0 and Xen for real
             * hardware setup have unfortunately been implemented based on
             * state which incorrectly leaked into dom0.
             *
             * These leaks are retained for backwards compatibility, but
             * restricted to the hardware domains kernel only.
             */
            if ( is_hardware_domain(currd) && guest_kernel_mode(curr, regs) )
            {
                /*
                 * MTRR used to unconditionally leak into PV guests.  They
                 * cannot MTRR infrastructure at all, and shouldn't be able to
                 * see the feature.
                 *
                 * Modern PVOPS Linux self-clobbers the MTRR feature, to avoid
                 * trying to use the associated MSRs.  Xenolinux-based PV dom0's
                 * however use the MTRR feature as an indication of the presence
                 * of the XENPF_{add,del,read}_memtype hypercalls.
                 */
                if ( cpu_has_mtrr )
                    d |= cpufeat_mask(X86_FEATURE_MTRR);

                /*
                 * MONITOR never leaked into PV guests, as PV guests cannot
                 * use the MONITOR/MWAIT instructions.  As such, they require
                 * the feature to not being present in emulated CPUID.
                 *
                 * Modern PVOPS Linux try to be cunning and use native CPUID
                 * to see if the hardware actually supports MONITOR, and by
                 * extension, deep C states.
                 *
                 * If the feature is seen, deep-C state information is
                 * obtained from the DSDT and handed back to Xen via the
                 * XENPF_set_processor_pminfo hypercall.
                 *
                 * This mechanism is incompatible with an HVM-based hardware
                 * domain, and also with CPUID Faulting.
                 *
                 * Luckily, Xen can be just as 'cunning', and distinguish an
                 * emulated CPUID from a faulted CPUID by whether a #UD or #GP
                 * fault is currently being serviced.  Yuck...
                 */
                if ( cpu_has_monitor && regs->entry_vector == TRAP_gp_fault )
                    c |= cpufeat_mask(X86_FEATURE_MONITOR);

                /*
                 * While MONITOR never leaked into PV guests, EIST always used
                 * to.
                 *
                 * Modern PVOPS will only parse P state information from the
                 * DSDT and return it to Xen if EIST is seen in the emulated
                 * CPUID information.
                 */
                if ( cpu_has_eist )
                    c |= cpufeat_mask(X86_FEATURE_EIST);
            }
        }

        c |= cpufeat_mask(X86_FEATURE_HYPERVISOR);
        break;

    case 0x00000007:
        if ( subleaf == 0 )
        {
            /* Fold host's FDP_EXCP_ONLY and NO_FPU_SEL into guest's view. */
            b &= (pv_featureset[FEATURESET_7b0] &
                  ~special_features[FEATURESET_7b0]);
            b |= (host_featureset[FEATURESET_7b0] &
                  special_features[FEATURESET_7b0]);

            c &= pv_featureset[FEATURESET_7c0];

            if ( !is_pvh_domain(currd) )
            {
                /*
                 * Delete the PVH condition when HVMLite formally replaces PVH,
                 * and HVM guests no longer enter a PV codepath.
                 */

                /* OSPKE cleared by pv_featureset.  Fast-forward CR4 back in. */
                if ( curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_PKE )
                    c |= cpufeat_mask(X86_FEATURE_OSPKE);
            }
        }
        else
            b = c = 0;
        a = d = 0;
        break;

    case XSTATE_CPUID:

        if ( !is_control_domain(currd) && !is_hardware_domain(currd) )
            domain_cpuid(currd, 1, 0, &tmp, &tmp, &_ecx, &tmp);
        else
            _ecx = cpuid_ecx(1);
        _ecx &= pv_featureset[FEATURESET_1c];

        if ( !(_ecx & cpufeat_mask(X86_FEATURE_XSAVE)) || subleaf >= 63 )
            goto unsupported;
        switch ( subleaf )
        {
        case 0:
        {
            uint64_t xfeature_mask = XSTATE_FP_SSE;
            uint32_t xstate_size = XSTATE_AREA_MIN_SIZE;

            if ( _ecx & cpufeat_mask(X86_FEATURE_AVX) )
            {
                xfeature_mask |= XSTATE_YMM;
                xstate_size = (xstate_offsets[_XSTATE_YMM] +
                               xstate_sizes[_XSTATE_YMM]);
            }

            if ( !is_control_domain(currd) && !is_hardware_domain(currd) )
                domain_cpuid(currd, 7, 0, &tmp, &_ebx, &tmp, &tmp);
            else
                cpuid_count(7, 0, &tmp, &_ebx, &tmp, &tmp);
            _ebx &= pv_featureset[FEATURESET_7b0];

            if ( _ebx & cpufeat_mask(X86_FEATURE_AVX512F) )
            {
                xfeature_mask |= XSTATE_OPMASK | XSTATE_ZMM | XSTATE_HI_ZMM;
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_OPMASK] +
                                  xstate_sizes[_XSTATE_OPMASK]);
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_ZMM] +
                                  xstate_sizes[_XSTATE_ZMM]);
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_HI_ZMM] +
                                  xstate_sizes[_XSTATE_HI_ZMM]);
            }

            a = (uint32_t)xfeature_mask;
            d = (uint32_t)(xfeature_mask >> 32);
            c = xstate_size;

            /*
             * Always read CPUID.0xD[ECX=0].EBX from hardware, rather than
             * domain policy.  It varies with enabled xstate, and the correct
             * xcr0 is in context.
             */
            cpuid_count(leaf, subleaf, &tmp, &b, &tmp, &tmp);
            break;
        }

        case 1:
            a &= pv_featureset[FEATURESET_Da1];
            b = c = d = 0;
            break;
        }
        break;

    case 0x80000001:
        c &= pv_featureset[FEATURESET_e1c];
        d &= pv_featureset[FEATURESET_e1d];

        /* If not emulating AMD, clear the duplicated features in e1d. */
        if ( currd->arch.x86_vendor != X86_VENDOR_AMD )
            d &= ~CPUID_COMMON_1D_FEATURES;

        /*
         * MTRR used to unconditionally leak into PV guests.  They cannot MTRR
         * infrastructure at all, and shouldn't be able to see the feature.
         *
         * Modern PVOPS Linux self-clobbers the MTRR feature, to avoid trying
         * to use the associated MSRs.  Xenolinux-based PV dom0's however use
         * the MTRR feature as an indication of the presence of the
         * XENPF_{add,del,read}_memtype hypercalls.
         */
        if ( is_hardware_domain(currd) && guest_kernel_mode(curr, regs) &&
             cpu_has_mtrr )
            d |= cpufeat_mask(X86_FEATURE_MTRR);

        if ( is_pv_32bit_domain(currd) )
        {
            d &= ~cpufeat_mask(X86_FEATURE_LM);
            c &= ~cpufeat_mask(X86_FEATURE_LAHF_LM);

            if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
                d &= ~cpufeat_mask(X86_FEATURE_SYSCALL);
        }
        break;

    case 0x80000007:
        d &= (pv_featureset[FEATURESET_e7d] |
              (host_featureset[FEATURESET_e7d] & cpufeat_mask(X86_FEATURE_ITSC)));
        break;

    case 0x80000008:
        a = paddr_bits | (vaddr_bits << 8);
        b &= pv_featureset[FEATURESET_e8b];
        break;

    case 0x0000000a: /* Architectural Performance Monitor Features (Intel) */
        break;

    case 0x00000005: /* MONITOR/MWAIT */
    case 0x0000000b: /* Extended Topology Enumeration */
    case 0x8000000a: /* SVM revision and features */
    case 0x8000001b: /* Instruction Based Sampling */
    case 0x8000001c: /* Light Weight Profiling */
    case 0x8000001e: /* Extended topology reporting */
    unsupported:
        a = b = c = d = 0;
        break;
    }

 out:
    /* VPMU may decide to modify some of the leaves */
    vpmu_do_cpuid(leaf, &a, &b, &c, &d);

    regs->eax = a;
    regs->ebx = b;
    regs->ecx = c;
    regs->edx = d;
}

static int emulate_invalid_rdtscp(struct cpu_user_regs *regs)
{
    char opcode[3];
    unsigned long eip, rc;
    struct vcpu *v = current;

    eip = regs->eip;
    if ( (rc = copy_from_user(opcode, (char *)eip, sizeof(opcode))) != 0 )
    {
        propagate_page_fault(eip + sizeof(opcode) - rc, 0);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(opcode, "\xf\x1\xf9", sizeof(opcode)) )
        return 0;
    eip += sizeof(opcode);
    pv_soft_rdtsc(v, regs, 1);
    instruction_done(regs, eip, 0);
    return EXCRET_fault_fixed;
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

    /* If cpuid faulting is enabled and CPL>0 inject a #GP in place of #UD. */
    if ( current->arch.cpuid_faulting && !guest_kernel_mode(current, regs) )
    {
        regs->eip = eip;
        do_guest_trap(TRAP_gp_fault, regs);
        return EXCRET_fault_fixed;
    }

    eip += sizeof(instr);

    pv_cpuid(regs);

    instruction_done(regs, eip, 0);

    trace_trap_one_addr(TRC_PV_FORCED_INVALID_OP, regs->eip);

    return EXCRET_fault_fixed;
}

void do_invalid_op(struct cpu_user_regs *regs)
{
    const struct bug_frame *bug = NULL;
    u8 bug_insn[2];
    const char *prefix = "", *filename, *predicate, *eip = (char *)regs->eip;
    unsigned long fixup;
    int id = -1, lineno;
    const struct virtual_region *region;

    if ( debugger_trap_entry(TRAP_invalid_op, regs) )
        return;

    if ( likely(guest_mode(regs)) )
    {
        if ( !emulate_invalid_rdtscp(regs) &&
             !emulate_forced_invalid_op(regs) )
            do_guest_trap(TRAP_invalid_op, regs);
        return;
    }

    if ( !is_active_kernel_text(regs->eip) ||
         __copy_from_user(bug_insn, eip, sizeof(bug_insn)) ||
         memcmp(bug_insn, "\xf\xb", sizeof(bug_insn)) )
        goto die;

    region = find_text_region(regs->eip);
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
        regs->eip = (unsigned long)eip;
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
        regs->eip = (unsigned long)eip;
        return;

    case BUGFRAME_bug:
        printk("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

        if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
            return;

        show_execution_state(regs);
        panic("Xen BUG at %s%s:%d", prefix, filename, lineno);

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
        panic("Assertion '%s' failed at %s%s:%d",
              predicate, prefix, filename, lineno);
    }

 die:
    if ( (fixup = search_exception_table(regs->eip)) != 0 )
    {
        this_cpu(last_extable_addr) = regs->eip;
        regs->eip = fixup;
        return;
    }

    if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
        return;

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (invalid opcode)", TRAP_invalid_op);
}

void do_int3(struct cpu_user_regs *regs)
{
    if ( debugger_trap_entry(TRAP_int3, regs) )
        return;

    if ( !guest_mode(regs) )
    {
        debugger_trap_fatal(TRAP_int3, regs);
        return;
    } 

    do_guest_trap(TRAP_int3, regs);
}

static void reserved_bit_page_fault(
    unsigned long addr, struct cpu_user_regs *regs)
{
    printk("%pv: reserved bit in page table (ec=%04X)\n",
           current, regs->error_code);
    show_page_walk(addr);
    show_execution_state(regs);
}

struct trap_bounce *propagate_page_fault(unsigned long addr, u16 error_code)
{
    struct trap_info *ti;
    struct vcpu *v = current;
    struct trap_bounce *tb = &v->arch.pv_vcpu.trap_bounce;

    if ( unlikely(!is_canonical_address(addr)) )
    {
        ti = &v->arch.pv_vcpu.trap_ctxt[TRAP_gp_fault];
        tb->flags      = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
        tb->error_code = 0;
        tb->cs         = ti->cs;
        tb->eip        = ti->address;
        if ( TI_GET_IF(ti) )
            tb->flags |= TBF_INTERRUPT;
        return tb;
    }

    v->arch.pv_vcpu.ctrlreg[2] = addr;
    arch_set_cr2(v, addr);

    /* Re-set error_code.user flag appropriately for the guest. */
    error_code &= ~PFEC_user_mode;
    if ( !guest_kernel_mode(v, guest_cpu_user_regs()) )
        error_code |= PFEC_user_mode;

    trace_pv_page_fault(addr, error_code);

    ti = &v->arch.pv_vcpu.trap_ctxt[TRAP_page_fault];
    tb->flags = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;
    if ( unlikely(null_trap_bounce(v, tb)) )
    {
        printk("%pv: unhandled page fault (ec=%04X)\n", v, error_code);
        show_page_walk(addr);
    }

    if ( unlikely(error_code & PFEC_reserved_bit) )
        reserved_bit_page_fault(addr, guest_cpu_user_regs());

    return NULL;
}

static int handle_gdt_ldt_mapping_fault(
    unsigned long offset, struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    /* Which vcpu's area did we fault in, and is it in the ldt sub-area? */
    unsigned int is_ldt_area = (offset >> (GDT_LDT_VCPU_VA_SHIFT-1)) & 1;
    unsigned int vcpu_area   = (offset >> GDT_LDT_VCPU_VA_SHIFT);

    /*
     * If the fault is in another vcpu's area, it cannot be due to
     * a GDT/LDT descriptor load. Thus we can reasonably exit immediately, and
     * indeed we have to since map_ldt_shadow_page() works correctly only on
     * accesses to a vcpu's own area.
     */
    if ( vcpu_area != curr->vcpu_id )
        return 0;

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
            struct trap_bounce *tb;

            /* In hypervisor mode? Leave it to the #PF handler to fix up. */
            if ( !guest_mode(regs) )
                return 0;
            /* In guest mode? Propagate fault to guest, with adjusted %cr2. */
            tb = propagate_page_fault(curr->arch.pv_vcpu.ldt_base + offset,
                                      regs->error_code);
            if ( tb )
                tb->error_code = (offset & ~(X86_XEC_EXT | X86_XEC_IDT)) |
                                 X86_XEC_TI;
        }
    }
    else
    {
        /* GDT fault: handle the fault as #GP(selector). */
        regs->error_code = offset & ~(X86_XEC_EXT | X86_XEC_IDT | X86_XEC_TI);
        (void)do_general_protection(regs);
    }

    return EXCRET_fault_fixed;
}

#define IN_HYPERVISOR_RANGE(va) \
    (((va) >= HYPERVISOR_VIRT_START) && ((va) < HYPERVISOR_VIRT_END))

enum pf_type {
    real_fault,
    smep_fault,
    smap_fault,
    spurious_fault
};

static enum pf_type __page_fault_type(
    unsigned long addr, const struct cpu_user_regs *regs)
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

static enum pf_type spurious_page_fault(
    unsigned long addr, const struct cpu_user_regs *regs)
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

    /* Faults from external-mode guests are handled by shadow/hap */
    if ( paging_mode_external(d) && guest_mode(regs) )
    {
        int ret = paging_fault(addr, regs);
        if ( ret == EXCRET_fault_fixed )
            trace_trap_two_addr(TRC_PV_PAGING_FIXUP, regs->eip, addr);
        return ret;
    }

    if ( !(regs->error_code & PFEC_page_present) &&
          (pagefault_by_memadd(addr, regs)) )
        return handle_memadd_fault(addr, regs);

    if ( unlikely(IN_HYPERVISOR_RANGE(addr)) )
    {
        if ( !(regs->error_code & (PFEC_user_mode | PFEC_reserved_bit)) &&
             (addr >= GDT_LDT_VIRT_START) && (addr < GDT_LDT_VIRT_END) )
            return handle_gdt_ldt_mapping_fault(
                addr - GDT_LDT_VIRT_START, regs);
        return 0;
    }

    if ( guest_kernel_mode(v, regs) &&
         !(regs->error_code & (PFEC_reserved_bit | PFEC_insn_fetch)) &&
         (regs->error_code & PFEC_write_access) )
    {
        if ( VM_ASSIST(d, writable_pagetables) &&
             /* Do not check if access-protection fault since the page may
                legitimately be not present in shadow page tables */
             (paging_mode_enabled(d) ||
              (regs->error_code & PFEC_page_present)) &&
             ptwr_do_page_fault(v, addr, regs) )
            return EXCRET_fault_fixed;

        if ( is_hardware_domain(d) && (regs->error_code & PFEC_page_present) &&
             mmio_ro_do_page_fault(v, addr, regs) )
            return EXCRET_fault_fixed;
    }

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
void do_page_fault(struct cpu_user_regs *regs)
{
    unsigned long addr, fixup;
    unsigned int error_code;
    enum pf_type pf_type;

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
        pf_type = spurious_page_fault(addr, regs);
        if ( (pf_type == smep_fault) || (pf_type == smap_fault) )
        {
            console_start_sync();
            printk("Xen SM%cP violation\n", (pf_type == smep_fault) ? 'E' : 'A');
            fatal_trap(regs, 0);
        }

        if ( pf_type != real_fault )
            return;

        if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
        {
            perfc_incr(copy_user_faults);
            if ( unlikely(regs->error_code & PFEC_reserved_bit) )
                reserved_bit_page_fault(addr, regs);
            this_cpu(last_extable_addr) = regs->eip;
            regs->eip = fixup;
            return;
        }

        if ( debugger_trap_fatal(TRAP_page_fault, regs) )
            return;

        show_execution_state(regs);
        show_page_walk(addr);
        panic("FATAL PAGE FAULT\n"
              "[error_code=%04x]\n"
              "Faulting linear address: %p",
              error_code, _p(addr));
    }

    if ( unlikely(current->domain->arch.suppress_spurious_page_faults) )
    {
        pf_type = spurious_page_fault(addr, regs);
        if ( (pf_type == smep_fault) || (pf_type == smap_fault))
        {
            printk(XENLOG_G_ERR "%pv fatal SM%cP violation\n",
                   current, (pf_type == smep_fault) ? 'E' : 'A');

            domain_crash(current->domain);
        }
        if ( pf_type != real_fault )
            return;
    }

    propagate_page_fault(addr, regs->error_code);
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

    if ( (regs->eip != prev_eip) || (cr2 != prev_cr2) )
    {
        prev_eip = regs->eip;
        prev_cr2 = cr2;
        stuck    = 0;
        return;
    }

    if ( stuck++ == 1000 )
    {
        console_start_sync();
        printk("Early fatal page fault at %04x:%p (cr2=%p, ec=%04x)\n",
               regs->cs, _p(regs->eip), _p(cr2), regs->error_code);
        fatal_trap(regs, 0);
    }
}

long do_fpu_taskswitch(int set)
{
    struct vcpu *v = current;

    if ( set )
    {
        v->arch.pv_vcpu.ctrlreg[0] |= X86_CR0_TS;
        stts();
    }
    else
    {
        v->arch.pv_vcpu.ctrlreg[0] &= ~X86_CR0_TS;
        if ( v->fpu_dirtied )
            clts();
    }

    return 0;
}

static int read_descriptor(unsigned int sel,
                           const struct vcpu *v,
                           unsigned long *base,
                           unsigned long *limit,
                           unsigned int *ar,
                           bool_t insn_fetch)
{
    struct desc_struct desc;

    if ( sel < 4)
        desc.b = desc.a = 0;
    else if ( __get_user(desc,
                         (const struct desc_struct *)(!(sel & 4)
                                                      ? GDT_VIRT_START(v)
                                                      : LDT_VIRT_START(v))
                         + (sel >> 3)) )
        return 0;
    if ( !insn_fetch )
        desc.b &= ~_SEGMENT_L;

    *ar = desc.b & 0x00f0ff00;
    if ( !(desc.b & _SEGMENT_L) )
    {
        *base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                 (desc.b & 0xff000000));
        *limit = (desc.a & 0xffff) | (desc.b & 0x000f0000);
        if ( desc.b & _SEGMENT_G )
            *limit = ((*limit + 1) << 12) - 1;
#ifndef NDEBUG
        if ( sel > 3 )
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

/* Perform IOPL check between the vcpu's shadowed IOPL, and the assumed cpl. */
static bool_t iopl_ok(const struct vcpu *v, const struct cpu_user_regs *regs)
{
    unsigned int cpl = guest_kernel_mode(v, regs) ?
        (VM_ASSIST(v->domain, architectural_iopl) ? 0 : 1) : 3;

    ASSERT((v->arch.pv_vcpu.iopl & ~X86_EFLAGS_IOPL) == 0);

    return IOPL(cpl) <= v->arch.pv_vcpu.iopl;
}

/* Has the guest requested sufficient permission for this I/O access? */
static int guest_io_okay(
    unsigned int port, unsigned int bytes,
    struct vcpu *v, struct cpu_user_regs *regs)
{
    /* If in user mode, switch to kernel mode just to read I/O bitmap. */
    int user_mode = !(v->arch.flags & TF_kernel_mode);
#define TOGGLE_MODE() if ( user_mode ) toggle_guest_pt(v)

    if ( iopl_ok(v, regs) )
        return 1;

    if ( v->arch.pv_vcpu.iobmp_limit > (port + bytes) )
    {
        union { uint8_t bytes[2]; uint16_t mask; } x;

        /*
         * Grab permission bytes from guest space. Inaccessible bytes are
         * read as 0xff (no access allowed).
         */
        TOGGLE_MODE();
        switch ( __copy_from_guest_offset(x.bytes, v->arch.pv_vcpu.iobmp,
                                          port>>3, 2) )
        {
        default: x.bytes[0] = ~0;
            /* fallthrough */
        case 1:  x.bytes[1] = ~0;
            /* fallthrough */
        case 0:  break;
        }
        TOGGLE_MODE();

        if ( (x.mask & (((1<<bytes)-1) << (port&7))) == 0 )
            return 1;
    }

    return 0;
}

/* Has the administrator granted sufficient permission for this I/O access? */
static bool_t admin_io_okay(unsigned int port, unsigned int bytes,
                            const struct domain *d)
{
    /*
     * Port 0xcf8 (CONFIG_ADDRESS) is only visible for DWORD accesses.
     * We never permit direct access to that register.
     */
    if ( (port == 0xcf8) && (bytes == 4) )
        return 0;

    /* We also never permit direct access to the RTC/CMOS registers. */
    if ( ((port & ~1) == RTC_PORT(0)) )
        return 0;

    return ioports_access_permitted(d, port, port + bytes - 1);
}

static bool_t pci_cfg_ok(struct domain *currd, unsigned int start,
                         unsigned int size, uint32_t *write)
{
    uint32_t machine_bdf;

    if ( !is_hardware_domain(currd) )
        return 0;

    if ( !CF8_ENABLED(currd->arch.pci_cf8) )
        return 1;

    machine_bdf = CF8_BDF(currd->arch.pci_cf8);
    if ( write )
    {
        const unsigned long *ro_map = pci_get_ro_map(0);

        if ( ro_map && test_bit(machine_bdf, ro_map) )
            return 0;
    }
    start |= CF8_ADDR_LO(currd->arch.pci_cf8);
    /* AMD extended configuration space access? */
    if ( CF8_ADDR_HI(currd->arch.pci_cf8) &&
         boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
         boot_cpu_data.x86 >= 0x10 && boot_cpu_data.x86 <= 0x17 )
    {
        uint64_t msr_val;

        if ( rdmsr_safe(MSR_AMD64_NB_CFG, msr_val) )
            return 0;
        if ( msr_val & (1ULL << AMD64_NB_CFG_CF8_EXT_ENABLE_BIT) )
            start |= CF8_ADDR_HI(currd->arch.pci_cf8);
    }

    return !write ?
           xsm_pci_config_permission(XSM_HOOK, currd, machine_bdf,
                                     start, start + size - 1, 0) == 0 :
           pci_conf_write_intercept(0, machine_bdf, start, size, write) >= 0;
}

uint32_t guest_io_read(unsigned int port, unsigned int bytes,
                       struct domain *currd)
{
    uint32_t data = 0;
    unsigned int shift = 0;

    if ( admin_io_okay(port, bytes, currd) )
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
        uint32_t sub_data = ~0;

        if ( (port == 0x42) || (port == 0x43) || (port == 0x61) )
        {
            sub_data = pv_pit_handler(port, 0, 0);
        }
        else if ( (port == RTC_PORT(0)) )
        {
            sub_data = currd->arch.cmos_idx;
        }
        else if ( (port == RTC_PORT(1)) &&
                  ioports_access_permitted(currd, RTC_PORT(0), RTC_PORT(1)) )
        {
            unsigned long flags;

            spin_lock_irqsave(&rtc_lock, flags);
            outb(currd->arch.cmos_idx & 0x7f, RTC_PORT(0));
            sub_data = inb(RTC_PORT(1));
            spin_unlock_irqrestore(&rtc_lock, flags);
        }
        else if ( (port == 0xcf8) && (bytes == 4) )
        {
            size = 4;
            sub_data = currd->arch.pci_cf8;
        }
        else if ( (port & 0xfffc) == 0xcfc )
        {
            size = min(bytes, 4 - (port & 3));
            if ( size == 3 )
                size = 2;
            if ( pci_cfg_ok(currd, port & 3, size, NULL) )
                sub_data = pci_conf_read(currd->arch.pci_cf8, port & 3, size);
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

void guest_io_write(unsigned int port, unsigned int bytes, uint32_t data,
                    struct domain *currd)
{
    if ( admin_io_okay(port, bytes, currd) )
    {
        switch ( bytes ) {
        case 1:
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
        else if ( (port == RTC_PORT(0)) )
        {
            currd->arch.cmos_idx = data;
        }
        else if ( (port == RTC_PORT(1)) &&
                  ioports_access_permitted(currd, RTC_PORT(0), RTC_PORT(1)) )
        {
            unsigned long flags;

            if ( pv_rtc_handler )
                pv_rtc_handler(currd->arch.cmos_idx & 0x7f, data);
            spin_lock_irqsave(&rtc_lock, flags);
            outb(currd->arch.cmos_idx & 0x7f, RTC_PORT(0));
            outb(data, RTC_PORT(1));
            spin_unlock_irqrestore(&rtc_lock, flags);
        }
        else if ( (port == 0xcf8) && (bytes == 4) )
        {
            size = 4;
            currd->arch.pci_cf8 = data;
        }
        else if ( (port & 0xfffc) == 0xcfc )
        {
            size = min(bytes, 4 - (port & 3));
            if ( size == 3 )
                size = 2;
            if ( pci_cfg_ok(currd, port & 3, size, &data) )
                pci_conf_write(currd->arch.pci_cf8, port & 3, size, data);
        }

        if ( size == 4 )
            return;

        port += size;
        bytes -= size;
        data >>= size * 8;
    }
}

/* I/O emulation support. Helper routines for, and type of, the stack stub.*/
void host_to_guest_gpr_switch(struct cpu_user_regs *);
unsigned long guest_to_host_gpr_switch(unsigned long);

void (*pv_post_outb_hook)(unsigned int port, u8 value);

static int priv_op_read_cr(unsigned int reg, unsigned long *val,
                           struct x86_emulate_ctxt *ctxt)
{
    const struct vcpu *curr = current;

    switch ( reg )
    {
    case 0: /* Read CR0 */
        *val = (read_cr0() & ~X86_CR0_TS) | curr->arch.pv_vcpu.ctrlreg[0];
        return X86EMUL_OKAY;

    case 2: /* Read CR2 */
    case 4: /* Read CR4 */
        *val = curr->arch.pv_vcpu.ctrlreg[reg];
        return X86EMUL_OKAY;

    case 3: /* Read CR3 */
    {
        const struct domain *currd = curr->domain;
        unsigned long mfn;

        if ( !is_pv_32bit_domain(currd) )
        {
            mfn = pagetable_get_pfn(curr->arch.guest_table);
            *val = xen_pfn_to_cr3(mfn_to_gmfn(currd, mfn));
        }
        else
        {
            l4_pgentry_t *pl4e =
                map_domain_page(_mfn(pagetable_get_pfn(curr->arch.guest_table)));

            mfn = l4e_get_pfn(*pl4e);
            unmap_domain_page(pl4e);
            *val = compat_pfn_to_cr3(mfn_to_gmfn(currd, mfn));
        }
        /* PTs should not be shared */
        BUG_ON(page_get_owner(mfn_to_page(mfn)) == dom_cow);
        return X86EMUL_OKAY;
    }
    }

    return X86EMUL_UNHANDLEABLE;
}

static int priv_op_write_cr(unsigned int reg, unsigned long val,
                            struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0: /* Write CR0 */
        if ( (val ^ read_cr0()) & ~X86_CR0_TS )
        {
            gdprintk(XENLOG_WARNING,
                    "Attempt to change unmodifiable CR0 flags\n");
            break;
        }
        do_fpu_taskswitch(!!(val & X86_CR0_TS));
        return X86EMUL_OKAY;

    case 2: /* Write CR2 */
        curr->arch.pv_vcpu.ctrlreg[2] = val;
        arch_set_cr2(curr, val);
        return X86EMUL_OKAY;

    case 3: /* Write CR3 */
    {
        struct domain *currd = curr->domain;
        unsigned long gfn;
        struct page_info *page;
        int rc;

        gfn = !is_pv_32bit_domain(currd)
              ? xen_cr3_to_pfn(val) : compat_cr3_to_pfn(val);
        page = get_page_from_gfn(currd, gfn, NULL, P2M_ALLOC);
        if ( !page )
            break;
        rc = new_guest_cr3(page_to_mfn(page));
        put_page(page);

        switch ( rc )
        {
        case 0:
            return X86EMUL_OKAY;
        case -ERESTART: /* retry after preemption */
            return X86EMUL_RETRY;
        }
        break;
    }

    case 4: /* Write CR4 */
        curr->arch.pv_vcpu.ctrlreg[4] = pv_guest_cr4_fixup(curr, val);
        write_cr4(pv_guest_cr4_to_real_cr4(curr));
        ctxt_switch_levelling(curr);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static int priv_op_read_dr(unsigned int reg, unsigned long *val,
                           struct x86_emulate_ctxt *ctxt)
{
    unsigned long res = do_get_debugreg(reg);

    if ( IS_ERR_VALUE(res) )
        return X86EMUL_UNHANDLEABLE;

    *val = res;

    return X86EMUL_OKAY;
}

static int priv_op_write_dr(unsigned int reg, unsigned long val,
                            struct x86_emulate_ctxt *ctxt)
{
    return do_set_debugreg(reg, val) == 0
           ? X86EMUL_OKAY : X86EMUL_UNHANDLEABLE;
}

static inline uint64_t guest_misc_enable(uint64_t val)
{
    val &= ~(MSR_IA32_MISC_ENABLE_PERF_AVAIL |
             MSR_IA32_MISC_ENABLE_MONITOR_ENABLE);
    val |= MSR_IA32_MISC_ENABLE_BTS_UNAVAIL |
           MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL |
           MSR_IA32_MISC_ENABLE_XTPR_DISABLE;
    return val;
}

static inline bool is_cpufreq_controller(const struct domain *d)
{
    return ((cpufreq_controller == FREQCTL_dom0_kernel) &&
            is_hardware_domain(d));
}

static int priv_op_read_msr(unsigned int reg, uint64_t *val,
                            struct x86_emulate_ctxt *ctxt)
{
    const struct vcpu *curr = current;
    const struct domain *currd = curr->domain;
    bool vpmu_msr = false;

    switch ( reg )
    {
        int rc;

    case MSR_FS_BASE:
        if ( is_pv_32bit_domain(currd) )
            break;
        *val = cpu_has_fsgsbase ? __rdfsbase() : curr->arch.pv_vcpu.fs_base;
        return X86EMUL_OKAY;

    case MSR_GS_BASE:
        if ( is_pv_32bit_domain(currd) )
            break;
        *val = cpu_has_fsgsbase ? __rdgsbase()
                                : curr->arch.pv_vcpu.gs_base_kernel;
        return X86EMUL_OKAY;

    case MSR_SHADOW_GS_BASE:
        if ( is_pv_32bit_domain(currd) )
            break;
        *val = curr->arch.pv_vcpu.gs_base_user;
        return X86EMUL_OKAY;

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
            break;
        if ( unlikely(is_cpufreq_controller(currd)) )
            goto normal;
        *val = 0;
        return X86EMUL_OKAY;

    case MSR_IA32_UCODE_REV:
        BUILD_BUG_ON(MSR_IA32_UCODE_REV != MSR_AMD_PATCHLEVEL);
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        {
            if ( wrmsr_safe(MSR_IA32_UCODE_REV, 0) )
                break;
            sync_core();
        }
        goto normal;

    case MSR_IA32_MISC_ENABLE:
        if ( rdmsr_safe(reg, *val) )
            break;
        *val = guest_misc_enable(*val);
        return X86EMUL_OKAY;

    case MSR_AMD64_DR0_ADDRESS_MASK:
        if ( !boot_cpu_has(X86_FEATURE_DBEXT) )
            break;
        *val = curr->arch.pv_vcpu.dr_mask[0];
        return X86EMUL_OKAY;

    case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
        if ( !boot_cpu_has(X86_FEATURE_DBEXT) )
            break;
        *val = curr->arch.pv_vcpu.dr_mask[reg - MSR_AMD64_DR1_ADDRESS_MASK + 1];
        return X86EMUL_OKAY;

    case MSR_IA32_PERF_CAPABILITIES:
        /* No extra capabilities are supported. */
        *val = 0;
        return X86EMUL_OKAY;

    case MSR_INTEL_PLATFORM_INFO:
        if ( !boot_cpu_has(X86_FEATURE_MSR_PLATFORM_INFO) )
            break;
        *val = 0;
        if ( this_cpu(cpuid_faulting_enabled) )
            *val |= MSR_PLATFORM_INFO_CPUID_FAULTING;
        return X86EMUL_OKAY;

    case MSR_INTEL_MISC_FEATURES_ENABLES:
        if ( !boot_cpu_has(X86_FEATURE_MSR_MISC_FEATURES) )
            break;
        *val = 0;
        if ( curr->arch.cpuid_faulting )
            *val |= MSR_MISC_FEATURES_CPUID_FAULTING;
        return X86EMUL_OKAY;

    case MSR_P6_PERFCTR(0)...MSR_P6_PERFCTR(7):
    case MSR_P6_EVNTSEL(0)...MSR_P6_EVNTSEL(3):
    case MSR_CORE_PERF_FIXED_CTR0...MSR_CORE_PERF_FIXED_CTR2:
    case MSR_CORE_PERF_FIXED_CTR_CTRL...MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        {
            vpmu_msr = true;
            /* fall through */
    case MSR_AMD_FAM15H_EVNTSEL0...MSR_AMD_FAM15H_PERFCTR5:
    case MSR_K7_EVNTSEL0...MSR_K7_PERFCTR3:
            if ( vpmu_msr || (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) )
            {
                /* Don't leak PMU MSRs to unprivileged domains. */
                if ( (vpmu_mode & XENPMU_MODE_ALL) &&
                     !is_hardware_domain(currd) )
                    *val = 0;
                else if ( vpmu_do_rdmsr(reg, val) )
                    break;
                return X86EMUL_OKAY;
            }
        }
        /* fall through */
    default:
        if ( rdmsr_hypervisor_regs(reg, val) )
            return X86EMUL_OKAY;

        rc = vmce_rdmsr(reg, val);
        if ( rc < 0 )
            break;
        if ( rc )
            return X86EMUL_OKAY;
        /* fall through */
    case MSR_EFER:
    normal:
        /* Everyone can read the MSR space. */
        /* gdprintk(XENLOG_WARNING, "Domain attempted RDMSR %08x\n", reg); */
        if ( rdmsr_safe(reg, *val) )
            break;
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

#include "x86_64/mmconfig.h"

static int priv_op_write_msr(unsigned int reg, uint64_t val,
                             struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;
    const struct domain *currd = curr->domain;
    bool vpmu_msr = false;

    switch ( reg )
    {
        uint64_t temp;
        int rc;

    case MSR_FS_BASE:
        if ( is_pv_32bit_domain(currd) || !is_canonical_address(val) )
            break;
        wrfsbase(val);
        curr->arch.pv_vcpu.fs_base = val;
        return X86EMUL_OKAY;

    case MSR_GS_BASE:
        if ( is_pv_32bit_domain(currd) || !is_canonical_address(val) )
            break;
        wrgsbase(val);
        curr->arch.pv_vcpu.gs_base_kernel = val;
        return X86EMUL_OKAY;

    case MSR_SHADOW_GS_BASE:
        if ( is_pv_32bit_domain(currd) || !is_canonical_address(val) ||
             wrmsr_safe(MSR_SHADOW_GS_BASE, val) )
            break;
        curr->arch.pv_vcpu.gs_base_user = val;
        return X86EMUL_OKAY;

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
    case MSR_K8_HWCR:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
            break;
        if ( likely(!is_cpufreq_controller(currd)) ||
             wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_AMD64_NB_CFG:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
             boot_cpu_data.x86 < 0x10 || boot_cpu_data.x86 > 0x17 )
            break;
        if ( !is_hardware_domain(currd) || !is_pinned_vcpu(curr) )
            return X86EMUL_OKAY;
        if ( (rdmsr_safe(MSR_AMD64_NB_CFG, temp) != 0) ||
             ((val ^ temp) & ~(1ULL << AMD64_NB_CFG_CF8_EXT_ENABLE_BIT)) )
            goto invalid;
        if ( wrmsr_safe(MSR_AMD64_NB_CFG, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_FAM10H_MMIO_CONF_BASE:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
             boot_cpu_data.x86 < 0x10 || boot_cpu_data.x86 > 0x17 )
            break;
        if ( !is_hardware_domain(currd) || !is_pinned_vcpu(curr) )
            return X86EMUL_OKAY;
        if ( rdmsr_safe(MSR_FAM10H_MMIO_CONF_BASE, temp) != 0 )
            break;
        if ( (pci_probe & PCI_PROBE_MASK) == PCI_PROBE_MMCONF ?
             temp != val :
             ((temp ^ val) &
              ~(FAM10H_MMIO_CONF_ENABLE |
                (FAM10H_MMIO_CONF_BUSRANGE_MASK <<
                 FAM10H_MMIO_CONF_BUSRANGE_SHIFT) |
                ((u64)FAM10H_MMIO_CONF_BASE_MASK <<
                 FAM10H_MMIO_CONF_BASE_SHIFT))) )
            goto invalid;
        if ( wrmsr_safe(MSR_FAM10H_MMIO_CONF_BASE, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_IA32_UCODE_REV:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
            break;
        if ( !is_hardware_domain(currd) || !is_pinned_vcpu(curr) )
            return X86EMUL_OKAY;
        if ( rdmsr_safe(reg, temp) )
            break;
        if ( val )
            goto invalid;
        return X86EMUL_OKAY;

    case MSR_IA32_MISC_ENABLE:
        if ( rdmsr_safe(reg, temp) )
            break;
        if ( val != guest_misc_enable(temp) )
            goto invalid;
        return X86EMUL_OKAY;

    case MSR_IA32_MPERF:
    case MSR_IA32_APERF:
        if ( (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) &&
             (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) )
            break;
        if ( likely(!is_cpufreq_controller(currd)) ||
             wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_IA32_PERF_CTL:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
            break;
        if ( likely(!is_cpufreq_controller(currd)) ||
             wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_IA32_THERM_CONTROL:
    case MSR_IA32_ENERGY_PERF_BIAS:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
            break;
        if ( !is_hardware_domain(currd) || !is_pinned_vcpu(curr) ||
             wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_AMD64_DR0_ADDRESS_MASK:
        if ( !boot_cpu_has(X86_FEATURE_DBEXT) || (val >> 32) )
            break;
        curr->arch.pv_vcpu.dr_mask[0] = val;
        if ( curr->arch.debugreg[7] & DR7_ACTIVE_MASK )
            wrmsrl(MSR_AMD64_DR0_ADDRESS_MASK, val);
        return X86EMUL_OKAY;

    case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
        if ( !boot_cpu_has(X86_FEATURE_DBEXT) || (val >> 32) )
            break;
        curr->arch.pv_vcpu.dr_mask[reg - MSR_AMD64_DR1_ADDRESS_MASK + 1] = val;
        if ( curr->arch.debugreg[7] & DR7_ACTIVE_MASK )
            wrmsrl(reg, val);
        return X86EMUL_OKAY;

    case MSR_INTEL_PLATFORM_INFO:
        /* The MSR is read-only. */
        break;

    case MSR_INTEL_MISC_FEATURES_ENABLES:
        if ( !boot_cpu_has(X86_FEATURE_MSR_MISC_FEATURES) ||
             (val & ~MSR_MISC_FEATURES_CPUID_FAULTING) )
            break;
        if ( (val & MSR_MISC_FEATURES_CPUID_FAULTING) &&
             !this_cpu(cpuid_faulting_enabled) )
            break;
        curr->arch.cpuid_faulting = !!(val & MSR_MISC_FEATURES_CPUID_FAULTING);
        return X86EMUL_OKAY;

    case MSR_P6_PERFCTR(0)...MSR_P6_PERFCTR(7):
    case MSR_P6_EVNTSEL(0)...MSR_P6_EVNTSEL(3):
    case MSR_CORE_PERF_FIXED_CTR0...MSR_CORE_PERF_FIXED_CTR2:
    case MSR_CORE_PERF_FIXED_CTR_CTRL...MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        {
            vpmu_msr = true;
    case MSR_AMD_FAM15H_EVNTSEL0...MSR_AMD_FAM15H_PERFCTR5:
    case MSR_K7_EVNTSEL0...MSR_K7_PERFCTR3:
            if ( vpmu_msr || (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) )
            {
                if ( (vpmu_mode & XENPMU_MODE_ALL) &&
                     !is_hardware_domain(currd) )
                    return X86EMUL_OKAY;

                if ( vpmu_do_wrmsr(reg, val, 0) )
                    break;
                return X86EMUL_OKAY;
            }
        }
        /* fall through */
    default:
        if ( wrmsr_hypervisor_regs(reg, val) == 1 )
            return X86EMUL_OKAY;

        rc = vmce_wrmsr(reg, val);
        if ( rc < 0 )
            break;
        if ( rc )
            return X86EMUL_OKAY;

        if ( (rdmsr_safe(reg, temp) != 0) || (val != temp) )
    invalid:
            gdprintk(XENLOG_WARNING,
                     "Domain attempted WRMSR %08x from 0x%016"PRIx64" to 0x%016"PRIx64"\n",
                     reg, temp, val);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

int pv_emul_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx,
                  unsigned int *edx, struct x86_emulate_ctxt *ctxt)
{
    struct cpu_user_regs regs = *ctxt->regs;

    regs._eax = *eax;
    regs._ecx = *ecx;

    pv_cpuid(&regs);

    *eax = regs._eax;
    *ebx = regs._ebx;
    *ecx = regs._ecx;
    *edx = regs._edx;

    return X86EMUL_OKAY;
}

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

static int emulate_privileged_op(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct domain *currd = v->domain;
    unsigned long *reg, eip = regs->eip;
    u8 opcode, modrm_reg = 0, modrm_rm = 0, rep_prefix = 0, lock = 0, rex = 0;
    enum { lm_seg_none, lm_seg_fs, lm_seg_gs } lm_ovr = lm_seg_none;
    int rc;
    unsigned int port, i, data_sel, ar, data, bpmatch = 0;
    unsigned int op_bytes, op_default, ad_bytes, ad_default, opsize_prefix= 0;
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
    char *io_emul_stub = NULL;
    void (*io_emul)(struct cpu_user_regs *);
    uint64_t val;

    if ( !read_descriptor(regs->cs, v, &code_base, &code_limit, &ar, 1) )
        goto fail;
    op_default = op_bytes = (ar & (_SEGMENT_L|_SEGMENT_DB)) ? 4 : 2;
    ad_default = ad_bytes = (ar & _SEGMENT_L) ? 8 : op_default;
    if ( !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         !(ar & _SEGMENT_CODE) )
        goto fail;

    /* emulating only opcodes not allowing SS to be default */
    data_sel = read_sreg(ds);

    /* Legacy prefixes. */
    for ( i = 0; i < 8; i++, rex == opcode || (rex = 0) )
    {
        switch ( opcode = insn_fetch(u8, code_base, eip, code_limit) )
        {
        case 0x66: /* operand-size override */
            opsize_prefix = 1;
            op_bytes = op_default ^ 6; /* switch between 2/4 bytes */
            continue;
        case 0x67: /* address-size override */
            ad_bytes = ad_default != 4 ? 4 : 2; /* switch to 2/4 bytes */
            continue;
        case 0x2e: /* CS override */
            data_sel = regs->cs;
            continue;
        case 0x3e: /* DS override */
            data_sel = read_sreg(ds);
            continue;
        case 0x26: /* ES override */
            data_sel = read_sreg(es);
            continue;
        case 0x64: /* FS override */
            data_sel = read_sreg(fs);
            lm_ovr = lm_seg_fs;
            continue;
        case 0x65: /* GS override */
            data_sel = read_sreg(gs);
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
            data_sel = read_sreg(es);
            lm_ovr = lm_seg_none;
        }

        if ( !(ar & _SEGMENT_L) )
        {
            if ( !read_descriptor(data_sel, v, &data_base, &data_limit,
                                  &ar, 0) )
                goto fail;
            if ( !(ar & _SEGMENT_S) ||
                 !(ar & _SEGMENT_P) ||
                 (opcode & 2 ?
                  (ar & _SEGMENT_CODE) && !(ar & _SEGMENT_WR) :
                  (ar & _SEGMENT_CODE) || !(ar & _SEGMENT_WR)) )
                goto fail;
        }
        else
        {
            switch ( lm_ovr )
            {
            default:
                data_base = 0UL;
                break;
            case lm_seg_fs:
                data_base = rdfsbase();
                break;
            case lm_seg_gs:
                data_base = rdgsbase();
                break;
            }
            data_limit = ~0UL;
            ar = _SEGMENT_WR|_SEGMENT_S|_SEGMENT_DPL|_SEGMENT_P;
        }

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
            data = guest_io_read(port, op_bytes, currd);
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
            guest_io_write(port, op_bytes, data, currd);
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
     * Build an stub to execute the instruction with full guest GPR
     * context. This is needed for some systems which (ab)use IN/OUT
     * to communicate with BIOS code in system-management mode.
     */
    io_emul_stub = map_domain_page(_mfn(this_cpu(stubs.mfn))) +
                   (this_cpu(stubs.addr) & ~PAGE_MASK) +
                   STUB_BUF_SIZE / 2;
    /* movq $host_to_guest_gpr_switch,%rcx */
    io_emul_stub[0] = 0x48;
    io_emul_stub[1] = 0xb9;
    *(void **)&io_emul_stub[2] = (void *)host_to_guest_gpr_switch;
    /* callq *%rcx */
    io_emul_stub[10] = 0xff;
    io_emul_stub[11] = 0xd1;
    /* data16 or nop */
    io_emul_stub[12] = (op_bytes != 2) ? 0x90 : 0x66;
    /* <io-access opcode> */
    io_emul_stub[13] = opcode;
    /* imm8 or nop */
    io_emul_stub[14] = 0x90;
    /* ret (jumps to guest_to_host_gpr_switch) */
    io_emul_stub[15] = 0xc3;
    BUILD_BUG_ON(STUB_BUF_SIZE / 2 < 16);

    /* Handy function-typed pointer to the stub. */
    io_emul = (void *)(this_cpu(stubs.addr) + STUB_BUF_SIZE / 2);

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
        if ( admin_io_okay(port, op_bytes, currd) )
        {
            io_emul(regs);            
        }
        else
        {
            if ( op_bytes == 4 )
                regs->eax = 0;
            else
                regs->eax &= ~((1 << (op_bytes * 8)) - 1);
            regs->eax |= guest_io_read(port, op_bytes, currd);
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
        if ( admin_io_okay(port, op_bytes, currd) )
        {
            io_emul(regs);            
            if ( (op_bytes == 1) && pv_post_outb_hook )
                pv_post_outb_hook(port, regs->eax);
        }
        else
        {
            guest_io_write(port, op_bytes, regs->eax, currd);
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
        if ( !iopl_ok(v, regs) )
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
    /*
     * All 2 and 3 byte opcodes, except RDTSC (0x31), RDTSCP (0x1,0xF9),
     * and CPUID (0xa2), are executable only from guest kernel mode 
     * (virtual ring 0).
     */
    opcode = insn_fetch(u8, code_base, eip, code_limit);
    if ( !guest_kernel_mode(v, regs) && 
        (opcode != 0x1) && (opcode != 0x31) && (opcode != 0xa2) )
        goto fail;

    if ( lock && (opcode & ~3) != 0x20 )
        goto fail;
    switch ( opcode )
    {
    case 0x1: /* RDTSCP and XSETBV */
        switch ( insn_fetch(u8, code_base, eip, code_limit) )
        {
        case 0xf9: /* RDTSCP */
            if ( (v->arch.pv_vcpu.ctrlreg[4] & X86_CR4_TSD) &&
                 !guest_kernel_mode(v, regs) )
                goto fail;
            pv_soft_rdtsc(v, regs, 1);
            break;
        case 0xd1: /* XSETBV */
        {
            u64 new_xfeature = (u32)regs->eax | ((u64)regs->edx << 32);

            if ( lock || rep_prefix || opsize_prefix
                 || !(v->arch.pv_vcpu.ctrlreg[4] & X86_CR4_OSXSAVE) )
            {
                do_guest_trap(TRAP_invalid_op, regs);
                goto skip;
            }

            if ( !guest_kernel_mode(v, regs) )
                goto fail;

            if ( handle_xsetbv(regs->ecx, new_xfeature) )
                goto fail;

            break;
        }
        default:
            goto fail;
        }
        break;

    case 0x06: /* CLTS */
        (void)do_fpu_taskswitch(0);
        break;

    case 0x09: /* WBINVD */
        /* Ignore the instruction if unprivileged. */
        if ( !cache_flush_permitted(currd) )
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
        if ( priv_op_read_cr(modrm_reg, decode_register(modrm_rm, regs, 0),
                             NULL) != X86EMUL_OKAY )
            goto fail;
        break;

    case 0x21: /* MOV DR?,<reg> */ {
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        if ( opcode < 0xc0 )
            goto fail;
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        if ( priv_op_read_dr(modrm_reg, decode_register(modrm_rm, regs, 0),
                             NULL) != X86EMUL_OKAY )
            goto fail;
        break;
    }

    case 0x22: /* MOV <reg>,CR? */
        opcode = insn_fetch(u8, code_base, eip, code_limit);
        if ( opcode < 0xc0 )
            goto fail;
        modrm_reg += ((opcode >> 3) & 7) + (lock << 3);
        modrm_rm  |= (opcode >> 0) & 7;
        reg = decode_register(modrm_rm, regs, 0);
        switch ( priv_op_write_cr(modrm_reg, *reg, NULL) )
        {
        case X86EMUL_OKAY:
            break;
        case X86EMUL_RETRY: /* retry after preemption */
            goto skip;
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
        if ( priv_op_write_dr(modrm_reg, *reg, NULL) != X86EMUL_OKAY )
            goto fail;
        break;

    case 0x30: /* WRMSR */
        if ( priv_op_write_msr(regs->_ecx, (regs->rdx << 32) | regs->_eax,
                               NULL) != X86EMUL_OKAY )
            goto fail;
        break;

    case 0x31: /* RDTSC */
        if ( (v->arch.pv_vcpu.ctrlreg[4] & X86_CR4_TSD) &&
             !guest_kernel_mode(v, regs) )
            goto fail;
        if ( currd->arch.vtsc )
            pv_soft_rdtsc(v, regs, 0);
        else
        {
            val = rdtsc();
            goto rdmsr_writeback;
        }
        break;

    case 0x32: /* RDMSR */
        if ( priv_op_read_msr(regs->_ecx, &val, NULL) != X86EMUL_OKAY )
            goto fail;
 rdmsr_writeback:
        regs->eax = (uint32_t)val;
        regs->edx = (uint32_t)(val >> 32);
        break;

    case 0xa2: /* CPUID */
        /* If cpuid faulting is enabled and CPL>0 leave the #GP untouched. */
        if ( v->arch.cpuid_faulting && !guest_kernel_mode(v, regs) )
            goto fail;

        pv_cpuid(regs);
        break;

    default:
        goto fail;
    }

#undef wr_ad
#undef rd_ad

 done:
    instruction_done(regs, eip, bpmatch);
 skip:
    if ( io_emul_stub )
        unmap_domain_page(io_emul_stub);
    return EXCRET_fault_fixed;

 fail:
    if ( io_emul_stub )
        unmap_domain_page(io_emul_stub);
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
        do_guest_trap(TRAP_gp_fault, regs);
        return;
    }
    if ( !(ar & _SEGMENT_P) )
    {
        do_guest_trap(TRAP_no_segment, regs);
        return;
    }
    dpl = (ar >> 13) & 3;
    nparm = ar & 0x1f;

    /*
     * Decode instruction (and perhaps operand) to determine RPL,
     * whether this is a jump or a call, and the call return offset.
     */
    if ( !read_descriptor(regs->cs, v, &base, &limit, &ar, 0) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         !(ar & _SEGMENT_CODE) )
    {
        do_guest_trap(TRAP_gp_fault, regs);
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
            opnd_sel = read_sreg(ds);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x26: /* ES override */
            opnd_sel = read_sreg(es);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x64: /* FS override */
            opnd_sel = read_sreg(fs);
            if ( !opnd_sel )
                opnd_sel = dpl;
            continue;
        case 0x65: /* GS override */
            opnd_sel = read_sreg(gs);
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
                            if ( ((sib >>= 3) & 7) != 4 )
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
                                opnd_sel = read_sreg(ds);
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
                            opnd_sel = read_sreg(ds);
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
                        if ( ad_bytes > 2 )
                            opnd_off += insn_fetch(s32, base, eip, limit);
                        else
                            opnd_off += insn_fetch(s16, base, eip, limit);
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
        do_guest_trap(TRAP_gp_fault, regs);
 skip:
        return;
    }

    if ( (opnd_sel != regs->cs &&
          !read_descriptor(opnd_sel, v, &base, &limit, &ar, 0)) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         ((ar & _SEGMENT_CODE) && !(ar & _SEGMENT_WR)) )
    {
        do_guest_trap(TRAP_gp_fault, regs);
        return;
    }

    opnd_off += op_bytes;
#define ad_default ad_bytes
    opnd_sel = insn_fetch(u16, base, opnd_off, limit);
#undef ad_default
    if ( (opnd_sel & ~3) != regs->error_code || dpl < (opnd_sel & 3) )
    {
        do_guest_trap(TRAP_gp_fault, regs);
        return;
    }

    if ( !read_descriptor(sel, v, &base, &limit, &ar, 0) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_CODE) ||
         (!jump || (ar & _SEGMENT_EC) ?
          ((ar >> 13) & 3) > (regs->cs & 3) :
          ((ar >> 13) & 3) != (regs->cs & 3)) )
    {
        regs->error_code = sel;
        do_guest_trap(TRAP_gp_fault, regs);
        return;
    }
    if ( !(ar & _SEGMENT_P) )
    {
        regs->error_code = sel;
        do_guest_trap(TRAP_no_segment, regs);
        return;
    }
    if ( off > limit )
    {
        regs->error_code = 0;
        do_guest_trap(TRAP_gp_fault, regs);
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
                do_guest_trap(TRAP_gp_fault, regs);
                return;
            }
            esp = v->arch.pv_vcpu.kernel_sp;
            ss = v->arch.pv_vcpu.kernel_ss;
            if ( (ss & 3) != (sel & 3) ||
                 !read_descriptor(ss, v, &base, &limit, &ar, 0) ||
                 ((ar >> 13) & 3) != (sel & 3) ||
                 !(ar & _SEGMENT_S) ||
                 (ar & _SEGMENT_CODE) ||
                 !(ar & _SEGMENT_WR) )
            {
                regs->error_code = ss & ~3;
                do_guest_trap(TRAP_invalid_tss, regs);
                return;
            }
            if ( !(ar & _SEGMENT_P) ||
                 !check_stack_limit(ar, limit, esp, (4 + nparm) * 4) )
            {
                regs->error_code = ss & ~3;
                do_guest_trap(TRAP_stack_error, regs);
                return;
            }
            stkp = (unsigned int *)(unsigned long)((unsigned int)base + esp);
            if ( !compat_access_ok(stkp - 4 - nparm, 16 + nparm * 4) )
            {
                do_guest_trap(TRAP_gp_fault, regs);
                return;
            }
            push(regs->ss);
            push(regs->esp);
            if ( nparm )
            {
                const unsigned int *ustkp;

                if ( !read_descriptor(regs->ss, v, &base, &limit, &ar, 0) ||
                     ((ar >> 13) & 3) != (regs->cs & 3) ||
                     !(ar & _SEGMENT_S) ||
                     (ar & _SEGMENT_CODE) ||
                     !(ar & _SEGMENT_WR) ||
                     !check_stack_limit(ar, limit, esp + nparm * 4, nparm * 4) )
                    return do_guest_trap(TRAP_gp_fault, regs);
                ustkp = (unsigned int *)(unsigned long)((unsigned int)base + regs->_esp + nparm * 4);
                if ( !compat_access_ok(ustkp - nparm, 0 + nparm * 4) )
                {
                    do_guest_trap(TRAP_gp_fault, regs);
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
            if ( !read_descriptor(ss, v, &base, &limit, &ar, 0) ||
                 ((ar >> 13) & 3) != (sel & 3) )
            {
                do_guest_trap(TRAP_gp_fault, regs);
                return;
            }
            if ( !check_stack_limit(ar, limit, esp, 2 * 4) )
            {
                regs->error_code = 0;
                do_guest_trap(TRAP_stack_error, regs);
                return;
            }
            stkp = (unsigned int *)(unsigned long)((unsigned int)base + esp);
            if ( !compat_access_ok(stkp - 2, 2 * 4) )
            {
                do_guest_trap(TRAP_gp_fault, regs);
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
}

void do_general_protection(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    unsigned long fixup;

    if ( debugger_trap_entry(TRAP_gp_fault, regs) )
        return;

    if ( regs->error_code & X86_XEC_EXT )
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
        const struct trap_info *ti;
        unsigned char vector = regs->error_code >> 3;
        ti = &v->arch.pv_vcpu.trap_ctxt[vector];
        if ( permit_softint(TI_GET_DPL(ti), v, regs) )
        {
            regs->eip += 2;
            pv_inject_event(vector, regs, X86_EVENTTYPE_SW_INTERRUPT);
            return;
        }
    }
    else if ( is_pv_32bit_vcpu(v) && regs->error_code )
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

    /* Pass on GPF as is. */
    do_guest_trap(TRAP_gp_fault, regs);
    return;

 gp_in_kernel:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        dprintk(XENLOG_INFO, "GPF (%04x): %p -> %p\n",
                regs->error_code, _p(regs->eip), _p(fixup));
        this_cpu(last_extable_addr) = regs->eip;
        regs->eip = fixup;
        return;
    }

 hardware_gp:
    if ( debugger_trap_fatal(TRAP_gp_fault, regs) )
        return;

    show_execution_state(regs);
    panic("GENERAL PROTECTION FAULT\n[error_code=%04x]", regs->error_code);
}

static DEFINE_PER_CPU(struct softirq_trap, softirq_trap);

static void nmi_mce_softirq(void)
{
    int cpu = smp_processor_id();
    struct softirq_trap *st = &per_cpu(softirq_trap, cpu);

    BUG_ON(st->vcpu == NULL);

    /* Set the tmp value unconditionally, so that
     * the check in the iret hypercall works. */
    cpumask_copy(st->vcpu->cpu_hard_affinity_tmp,
                 st->vcpu->cpu_hard_affinity);

    if ((cpu != st->processor)
       || (st->processor != st->vcpu->processor))
    {
        /* We are on a different physical cpu.
         * Make sure to wakeup the vcpu on the
         * specified processor.
         */
        vcpu_set_hard_affinity(st->vcpu, cpumask_of(st->processor));

        /* Affinity is restored in the iret hypercall. */
    }

    /* Only used to defer wakeup of domain/vcpu to
     * a safe (non-NMI/MCE) context.
     */
    vcpu_kick(st->vcpu);
    st->vcpu = NULL;
}

static void pci_serr_softirq(void)
{
    printk("\n\nNMI - PCI system error (SERR)\n");
    outb(inb(0x61) & 0x0b, 0x61); /* re-enable the PCI SERR error line. */
}

void async_exception_cleanup(struct vcpu *curr)
{
    int trap;

    if ( !curr->async_exception_mask )
        return;

    /* Restore affinity.  */
    if ( !cpumask_empty(curr->cpu_hard_affinity_tmp) &&
         !cpumask_equal(curr->cpu_hard_affinity_tmp, curr->cpu_hard_affinity) )
    {
        vcpu_set_hard_affinity(curr, curr->cpu_hard_affinity_tmp);
        cpumask_clear(curr->cpu_hard_affinity_tmp);
    }

    if ( !(curr->async_exception_mask & (curr->async_exception_mask - 1)) )
        trap = __scanbit(curr->async_exception_mask, VCPU_TRAP_NONE);
    else
        for ( trap = VCPU_TRAP_NONE + 1; trap <= VCPU_TRAP_LAST; ++trap )
            if ( (curr->async_exception_mask ^
                  curr->async_exception_state(trap).old_mask) == (1 << trap) )
                break;
    if ( unlikely(trap > VCPU_TRAP_LAST) )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    /* Restore previous asynchronous exception mask. */
    curr->async_exception_mask = curr->async_exception_state(trap).old_mask;
}

static void nmi_hwdom_report(unsigned int reason_idx)
{
    struct domain *d = hardware_domain;

    if ( !d || !d->vcpu || !d->vcpu[0] || !is_pv_domain(d) /* PVH fixme */ )
        return;

    set_bit(reason_idx, nmi_reason(d));

    send_guest_trap(d, 0, TRAP_nmi);
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

static void unknown_nmi_error(const struct cpu_user_regs *regs, unsigned char reason)
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

void do_nmi(const struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();
    unsigned char reason;
    bool_t handle_unknown = 0;

    ++nmi_count(cpu);

    if ( nmi_callback(regs, cpu) )
        return;

    if ( (nmi_watchdog == NMI_NONE) ||
         (!nmi_watchdog_tick(regs) && watchdog_force) )
        handle_unknown = 1;

    /* Only the BSP gets external NMIs from the system. */
    if ( cpu == 0 )
    {
        reason = inb(0x61);
        if ( reason & 0x80 )
            pci_serr_error(regs);
        if ( reason & 0x40 )
            io_check_error(regs);
        if ( !(reason & 0xc0) && handle_unknown )
            unknown_nmi_error(regs, reason);
    }
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
    struct vcpu *curr = current;

    BUG_ON(!guest_mode(regs));

    vcpu_restore_fpu_lazy(curr);

    if ( curr->arch.pv_vcpu.ctrlreg[0] & X86_CR0_TS )
    {
        do_guest_trap(TRAP_no_device, regs);
        curr->arch.pv_vcpu.ctrlreg[0] &= ~X86_CR0_TS;
    }
    else
        TRACE_0D(TRC_PV_MATH_STATE_RESTORE);

    return;
}

u64 read_efer(void)
{
    return this_cpu(efer);
}

void write_efer(u64 val)
{
    this_cpu(efer) = val;
    wrmsrl(MSR_EFER, val);
}

static void ler_enable(void)
{
    u64 debugctl;

    if ( !this_cpu(ler_msr) )
        return;

    rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl | IA32_DEBUGCTLMSR_LBR);
}

void do_debug(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    if ( debugger_trap_entry(TRAP_debug, regs) )
        return;

    if ( !guest_mode(regs) )
    {
        if ( regs->eflags & X86_EFLAGS_TF )
        {
            /* In SYSENTER entry path we can't zap TF until EFLAGS is saved. */
            if ( (regs->rip >= (unsigned long)sysenter_entry) &&
                 (regs->rip <= (unsigned long)sysenter_eflags_saved) )
            {
                if ( regs->rip == (unsigned long)sysenter_eflags_saved )
                    regs->eflags &= ~X86_EFLAGS_TF;
                goto out;
            }
            if ( !debugger_trap_fatal(TRAP_debug, regs) )
            {
                WARN();
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
    v->arch.debugreg[6] = read_debugreg(6);

    ler_enable();
    do_guest_trap(TRAP_debug, regs);
    return;

 out:
    ler_enable();
    return;
}

static void __init noinline __set_intr_gate(unsigned int n, uint32_t dpl, void *addr)
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
        SYS_DESC_tss_avail);
    _set_tssldt_desc(
        this_cpu(compat_gdt_table) + TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)tss,
        offsetof(struct tss_struct, __cacheline_filler) - 1,
        SYS_DESC_tss_busy);

    /* Switch to non-compat GDT (which has B bit clear) to execute LTR. */
    asm volatile (
        "sgdt %0; lgdt %2; ltr %w1; lgdt %0"
        : "=m" (old_gdt) : "rm" (TSS_ENTRY << 3), "m" (tss_gdt) : "memory" );
}

void percpu_traps_init(void)
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
        case 0xf ... 0x17:
            this_cpu(ler_msr) = MSR_IA32_LASTINTFROMIP;
            break;
        }
        break;
    }

    ler_enable();
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
    set_ist(&idt_table[TRAP_double_fault],  IST_DF);
    set_ist(&idt_table[TRAP_nmi],           IST_NMI);
    set_ist(&idt_table[TRAP_machine_check], IST_MCE);

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    this_cpu(gdt_table) = boot_cpu_gdt_table;
    this_cpu(compat_gdt_table) = boot_cpu_compat_gdt_table;
}

extern void (*const autogen_entrypoints[NR_VECTORS])(void);
void __init trap_init(void)
{
    unsigned int vector;

    /* Replace early pagefault with real pagefault handler. */
    set_intr_gate(TRAP_page_fault, &page_fault);

    /* The 32-on-64 hypercall vector is only accessible from ring 1. */
    _set_gate(idt_table + HYPERCALL_VECTOR,
              SYS_DESC_trap_gate, 1, &compat_hypercall);

    /* Fast trap for int80 (faster than taking the #GP-fixup path). */
    _set_gate(idt_table + 0x80, SYS_DESC_trap_gate, 3, &int80_direct_trap);

    for ( vector = 0; vector < NR_VECTORS; ++vector )
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

    percpu_traps_init();

    cpu_init();

    open_softirq(NMI_MCE_SOFTIRQ, nmi_mce_softirq);
    open_softirq(PCI_SERR_SOFTIRQ, pci_serr_softirq);
}

long register_guest_nmi_callback(unsigned long address)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct trap_info *t = &v->arch.pv_vcpu.trap_ctxt[TRAP_nmi];

    if ( !is_canonical_address(address) )
        return -EINVAL;

    t->vector  = TRAP_nmi;
    t->flags   = 0;
    t->cs      = (is_pv_32bit_domain(d) ?
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
    struct trap_info *t = &v->arch.pv_vcpu.trap_ctxt[TRAP_nmi];

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
    BUG_ON(trap_nr >= NR_VECTORS);

    v = d->vcpu[vcpuid];
    t = &v->arch.pv_vcpu.trap_ctxt[trap_nr];

    return (t->address != 0);
}


int send_guest_trap(struct domain *d, uint16_t vcpuid, unsigned int trap_nr)
{
    struct vcpu *v;
    struct softirq_trap *st = &per_cpu(softirq_trap, smp_processor_id());

    BUG_ON(d == NULL);
    BUG_ON(vcpuid >= d->max_vcpus);
    v = d->vcpu[vcpuid];

    switch (trap_nr) {
    case TRAP_nmi:
        if ( cmpxchgptr(&st->vcpu, NULL, v) )
            return -EBUSY;
        if ( !test_and_set_bool(v->nmi_pending) ) {
               st->domain = d;
               st->processor = v->processor;

               /* not safe to wake up a vcpu here */
               raise_softirq(NMI_MCE_SOFTIRQ);
               return 0;
        }
        st->vcpu = NULL;
        break;

    case TRAP_machine_check:
        if ( cmpxchgptr(&st->vcpu, NULL, v) )
            return -EBUSY;

        /* We are called by the machine check (exception or polling) handlers
         * on the physical CPU that reported a machine check error. */

        if ( !test_and_set_bool(v->mce_pending) ) {
                st->domain = d;
                st->processor = v->processor;

                /* not safe to wake up a vcpu here */
                raise_softirq(NMI_MCE_SOFTIRQ);
                return 0;
        }
        st->vcpu = NULL;
        break;
    }

    /* delivery failed */
    return -EIO;
}


long do_set_trap_table(XEN_GUEST_HANDLE_PARAM(const_trap_info_t) traps)
{
    struct trap_info cur;
    struct vcpu *curr = current;
    struct trap_info *dst = curr->arch.pv_vcpu.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, NR_VECTORS * sizeof(*dst));
        init_int80_direct_trap(curr);
        return 0;
    }

    for ( ; ; )
    {
        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        if ( !is_canonical_address(cur.address) )
            return -EINVAL;

        fixup_guest_code_selector(curr->domain, cur.cs);

        memcpy(&dst[cur.vector], &cur, sizeof(cur));

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(curr);

        guest_handle_add_offset(traps, 1);

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }
    }

    return rc;
}

void activate_debugregs(const struct vcpu *curr)
{
    ASSERT(curr == current);

    write_debugreg(0, curr->arch.debugreg[0]);
    write_debugreg(1, curr->arch.debugreg[1]);
    write_debugreg(2, curr->arch.debugreg[2]);
    write_debugreg(3, curr->arch.debugreg[3]);
    write_debugreg(6, curr->arch.debugreg[6]);

    /*
     * Avoid writing the subsequently getting replaced value when getting
     * called from set_debugreg() below. Eventual future callers will need
     * to take this into account.
     */
    if ( curr->arch.debugreg[7] & DR7_ACTIVE_MASK )
        write_debugreg(7, curr->arch.debugreg[7]);

    if ( boot_cpu_has(X86_FEATURE_DBEXT) )
    {
        wrmsrl(MSR_AMD64_DR0_ADDRESS_MASK, curr->arch.pv_vcpu.dr_mask[0]);
        wrmsrl(MSR_AMD64_DR1_ADDRESS_MASK, curr->arch.pv_vcpu.dr_mask[1]);
        wrmsrl(MSR_AMD64_DR2_ADDRESS_MASK, curr->arch.pv_vcpu.dr_mask[2]);
        wrmsrl(MSR_AMD64_DR3_ADDRESS_MASK, curr->arch.pv_vcpu.dr_mask[3]);
    }
}

long set_debugreg(struct vcpu *v, unsigned int reg, unsigned long value)
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
        value &= ~DR_STATUS_RESERVED_ZERO; /* reserved bits => 0 */
        value |=  DR_STATUS_RESERVED_ONE;  /* reserved bits => 1 */
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
                    if ( !(v->arch.pv_vcpu.ctrlreg[4] & X86_CR4_DE) )
                        return -EPERM;
                    io_enable |= value & (3 << ((i - 16) >> 1));
                }
            }

            /* Guest DR5 is a handy stash for I/O intercept information. */
            v->arch.debugreg[5] = io_enable;
            value &= ~io_enable;

            /*
             * If DR7 was previously clear then we need to load all other
             * debug registers at this point as they were not restored during
             * context switch.
             */
            if ( (v == curr) &&
                 !(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
            {
                activate_debugregs(v);
                break;
            }
        }
        if ( v == curr )
            write_debugreg(7, value);
        break;
    default:
        return -EINVAL;
    }

    v->arch.debugreg[reg] = value;
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
        return curr->arch.debugreg[reg];
    case 7:
        return (curr->arch.debugreg[7] |
                curr->arch.debugreg[5]);
    case 4 ... 5:
        return ((curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_DE) ?
                curr->arch.debugreg[reg + 2] : 0);
    }

    return -EINVAL;
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

    __domain_crash_synchronous();
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
