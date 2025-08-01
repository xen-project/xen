/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/traps.c
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 */

/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/bitops.h>
#include <xen/bug.h>
#include <xen/console.h>
#include <xen/delay.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/paging.h>
#include <xen/param.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <xen/watchdog.h>

#include <asm/apic.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/flushtlb.h>
#include <asm/gdbsx.h>
#include <asm/i387.h>
#include <asm/io.h>
#include <asm/irq-vectors.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/pv/mm.h>
#include <asm/pv/trace.h>
#include <asm/pv/traps.h>
#include <asm/regs.h>
#include <asm/shared.h>
#include <asm/shstk.h>
#include <asm/smp.h>
#include <asm/system.h>
#include <asm/traps.h>
#include <asm/uaccess.h>
#include <asm/xenoprof.h>

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
#ifdef CONFIG_PV32
DEFINE_PER_CPU_READ_MOSTLY(seg_desc_t *, compat_gdt);
DEFINE_PER_CPU_READ_MOSTLY(l1_pgentry_t, compat_gdt_l1e);
#endif

/*
 * The TSS is smaller than a page, but we give it a full page to avoid
 * adjacent per-cpu data leaking via Meltdown when XPTI is in use.
 */
DEFINE_PER_CPU_PAGE_ALIGNED(struct tss_page, tss_page);

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

const unsigned int nmi_cpu;

#define stack_words_per_line 4
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)(regs)->rsp)

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
    asm_inline volatile (
        "1: rep movsb; 2:"
        _ASM_EXTABLE(1b, 2b)
        : "=&c" (missing_after),
          "=&D" (tmp), "=&S" (tmp)
        : "0" (ARRAY_SIZE(insns_after)),
          "1" (insns_after),
          "2" (regs->rip) );

    /*
     * Copy backwards from regs->rip - 1.  In the case of a fault, %ecx
     * contains the number of bytes remaining to copy.
     */
    asm_inline volatile (
        "std;"
        "1: rep movsb;"
        "2: cld;"
        _ASM_EXTABLE(1b, 2b)
        : "=&c" (missing_before),
          "=&D" (tmp), "=&S" (tmp)
        : "0" (ARRAY_SIZE(insns_before)),
          "1" (insns_before + ARRAY_SIZE(insns_before) - 1),
          "2" (regs->rip - 1) );
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
                                    const struct cpu_user_regs *regs)
{
    unsigned int i, *stack, addr, mask = STACK_SIZE;
    void *stack_page = NULL;

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

        mfn = read_cr3() >> PAGE_SHIFT;
        for_each_vcpu( v->domain, vcpu )
            if ( pagetable_get_pfn(vcpu->arch.guest_table) == mfn )
                break;
        if ( !vcpu )
        {
            stack_page = stack = do_page_walk(v, (unsigned long)stack);
            if ( (unsigned long)stack < PAGE_SIZE )
            {
                printk("Inaccessible guest memory.\n");
                return;
            }
            mask = PAGE_SIZE;
        }
        else if ( !guest_kernel_mode(v, regs) )
            mask = PAGE_SIZE;
    }

    for ( i = 0; i < debug_stack_lines * 8; i++ )
    {
        if ( (((long)stack - 1) ^ ((long)(stack + 1) - 1)) & mask )
            break;
        if ( stack_page )
            addr = *stack;
        else if ( __get_guest(addr, stack) )
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

    UNMAP_DOMAIN_PAGE(stack_page);

    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

static void show_guest_stack(struct vcpu *v, const struct cpu_user_regs *regs)
{
    int i;
    unsigned long *stack, addr;
    unsigned long mask = STACK_SIZE;
    void *stack_page = NULL;

    /* Avoid HVM as we don't know what the stack looks like. */
    if ( is_hvm_vcpu(v) )
        return;

    if ( is_pv_32bit_vcpu(v) )
    {
        compat_show_guest_stack(v, regs);
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
        if ( !guest_kernel_mode(v, regs) )
        {
            printk("User mode stack\n");
            return;
        }

        if ( maddr_get_owner(read_cr3()) != v->domain )
        {
            stack_page = stack = do_page_walk(v, (unsigned long)stack);
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
        if ( stack_page )
            addr = *stack;
        else if ( __get_guest(addr, stack) )
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

    UNMAP_DOMAIN_PAGE(stack_page);

    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

static void show_hvm_stack(struct vcpu *v, const struct cpu_user_regs *regs)
{
#ifdef CONFIG_HVM
    unsigned long sp = regs->rsp, addr;
    unsigned int i, bytes, words_per_line, pfec = PFEC_page_present;
    struct segment_register ss, cs;

    hvm_get_segment_register(v, x86_seg_ss, &ss);
    hvm_get_segment_register(v, x86_seg_cs, &cs);

    if ( hvm_long_mode_active(v) && cs.l )
        i = 16, bytes = 8;
    else
    {
        sp = ss.db ? (uint32_t)sp : (uint16_t)sp;
        i = ss.db ? 8 : 4;
        bytes = cs.db ? 4 : 2;
    }

    if ( bytes == 8 || (ss.db && !ss.base) )
        printk("Guest stack trace from sp=%0*lx:", i, sp);
    else
        printk("Guest stack trace from ss:sp=%04x:%0*lx:", ss.sel, i, sp);

    if ( !hvm_vcpu_virtual_to_linear(v, x86_seg_ss, &ss, sp, bytes,
                                     hvm_access_read, &cs, &addr) )
    {
        printk(" Guest-inaccessible memory\n");
        return;
    }

    if ( ss.dpl == 3 )
        pfec |= PFEC_user_mode;

    words_per_line = stack_words_per_line * (sizeof(void *) / bytes);
    for ( i = 0; i < debug_stack_lines * words_per_line; )
    {
        unsigned long val = 0;

        if ( (addr ^ (addr + bytes - 1)) & PAGE_SIZE )
            break;

        if ( !(i++ % words_per_line) )
            printk("\n  ");

        if ( hvm_copy_from_vcpu_linear(&val, addr, bytes, v,
                                       pfec) != HVMTRANS_okay )
        {
            printk(" Fault while accessing guest memory.");
            break;
        }

        printk(" %0*lx", 2 * bytes, val);

        addr += bytes;
        if ( !(addr & (PAGE_SIZE - 1)) )
            break;
    }

    if ( !i )
        printk(" Stack empty.");
    printk("\n");
#endif
}

/*
 * Notes for get_{stack,shstk}*_bottom() helpers
 *
 * Stack pages 1 - 4:
 *   These are all 1-page IST stacks.  Each of these stacks have an exception
 *   frame and saved register state at the top.  The interesting bound for a
 *   trace is the word adjacent to this, while the bound for a dump is the
 *   very top, including the exception frame.
 *
 * Stack pages 0 and 5:
 *   Shadow stacks.  These are mapped read-only, and used by CET-SS capable
 *   processors.  They will never contain regular stack data.
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
    case 1 ... 4:
        return ROUNDUP(sp, PAGE_SIZE) -
            offsetof(struct cpu_user_regs, es) - sizeof(unsigned long);

    case 6 ... 7:
        return ROUNDUP(sp, STACK_SIZE) -
            sizeof(struct cpu_info) - sizeof(unsigned long);

    default:
        return sp - sizeof(unsigned long);
    }
}

static unsigned long get_shstk_bottom(unsigned long sp)
{
    /* SAF-11-safe */
    switch ( get_stack_page(sp) )
    {
#ifdef CONFIG_XEN_SHSTK
    case 0:  return ROUNDUP(sp, IST_SHSTK_SIZE) - sizeof(unsigned long);
    case 5:  return ROUNDUP(sp, PAGE_SIZE)      - sizeof(unsigned long);
#endif
    default: return sp - sizeof(unsigned long);
    }
}

unsigned long get_stack_dump_bottom(unsigned long sp)
{
    switch ( get_stack_page(sp) )
    {
    case 1 ... 4:
        return ROUNDUP(sp, PAGE_SIZE) - sizeof(unsigned long);

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
    asm_inline (
        "1: mov %[data], %[tos]; 2:\n"
        ".pushsection .fixup,\"ax\"\n"
        "3: movb $1, %[fault]; jmp 2b\n"
        ".popsection\n"
        _ASM_EXTABLE(1b, 3b)
        : [tos] "+r" (tos), [fault] "+qm" (fault)
        : [data] "m" (*sp) );

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

static void show_stack(const struct cpu_user_regs *regs)
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
    unsigned long esp_top, esp_bottom;

    if ( _p(curr_stack_base) != stack_base[cpu] )
        printk("Current stack base %p differs from expected %p\n",
               _p(curr_stack_base), stack_base[cpu]);

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
}

void cf_check show_execution_state(const struct cpu_user_regs *regs)
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
    unsigned long flags = 0;

    if ( test_bit(_VPF_down, &v->pause_flags) )
    {
        printk("*** %pv is offline ***\n", v);
        return;
    }

    printk("*** Dumping Dom%d vcpu#%d state: ***\n",
           v->domain->domain_id, v->vcpu_id);

    if ( v == current )
    {
        show_execution_state(guest_cpu_user_regs());
        return;
    }

    vcpu_pause(v); /* acceptably dangerous */

    /*
     * For VMX special care is needed: Reading some of the register state will
     * require VMCS accesses. Engaging foreign VMCSes involves acquiring of a
     * lock, which check_lock() would object to when done from an IRQs-disabled
     * region. Despite this being a layering violation, engage the VMCS right
     * here. This then also avoids doing so several times in close succession.
     */
    if ( using_vmx() && is_hvm_vcpu(v) )
    {
        ASSERT(!in_irq());
        vmx_vmcs_enter(v);
    }

    /* Prevent interleaving of output. */
    flags = console_lock_recursive_irqsave();

    vcpu_show_registers(v);

    if ( is_hvm_vcpu(v) )
    {
        /*
         * Stop interleaving prevention: The necessary P2M lookups involve
         * locking, which has to occur with IRQs enabled.
         */
        console_unlock_recursive_irqrestore(flags);

        show_hvm_stack(v, &v->arch.user_regs);
    }
    else
    {
        if ( guest_kernel_mode(v, &v->arch.user_regs) )
            show_guest_stack(v, &v->arch.user_regs);

        console_unlock_recursive_irqrestore(flags);
    }

    if ( using_vmx() && is_hvm_vcpu(v) )
        vmx_vmcs_exit(v);

    vcpu_unpause(v);
}

static cpumask_t show_state_mask;
static bool opt_show_all;
boolean_param("async-show-all", opt_show_all);

static int cf_check nmi_show_execution_state(
    const struct cpu_user_regs *regs, int cpu)
{
    if ( !cpumask_test_cpu(cpu, &show_state_mask) )
        return 0;

    if ( opt_show_all )
        show_execution_state(regs);
    else if ( guest_mode(regs) )
        printk(XENLOG_ERR "CPU%d\t%pv\t%04x:%p in guest\n",
               cpu, current, regs->cs, _p(regs->rip));
    else
        printk(XENLOG_ERR "CPU%d\t%pv\t%04x:%p in Xen: %pS\n",
               cpu, current, regs->cs, _p(regs->rip), _p(regs->rip));

    cpumask_clear_cpu(cpu, &show_state_mask);

    return 1;
}

void show_execution_state_nmi(const cpumask_t *mask, bool show_all)
{
    unsigned int msecs, pending;

    /*
     * Overwrite the global variable, caller is expected to panic after having
     * dumped the execution state.
     */
    if ( show_all )
        opt_show_all = true;

    watchdog_disable();
    console_start_sync();

    cpumask_copy(&show_state_mask, mask);
    set_nmi_callback(nmi_show_execution_state);
    send_IPI_mask(mask, APIC_DM_NMI);

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
    if ( pending )
        printk("Non-responding CPUs: {%*pbl}\n", CPUMASK_PR(&show_state_mask));
}

const char *vector_name(unsigned int vec)
{
    static const char names[][4] = {
#define P(x) [X86_EXC_ ## x] = "#" #x
#define N(x) [X86_EXC_ ## x] = #x
        P(DE),  P(DB),  N(NMI), P(BP),  P(OF),  P(BR),  P(UD),  P(NM),
        P(DF),  N(CSO), P(TS),  P(NP),  P(SS),  P(GP),  P(PF),  N(SPV),
        P(MF),  P(AC),  P(MC),  P(XM),  P(VE),  P(CP),
                                        P(HV),  P(VC),  P(SX),
#undef N
#undef P
    };

    return (vec < ARRAY_SIZE(names) && names[vec][0]) ? names[vec] : "???";
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

        if ( trapnr == X86_EXC_PF )
            show_page_walk(read_cr2());

        if ( show_remote )
        {
            cpumask_t *scratch = this_cpu(scratch_cpumask);

            cpumask_andnot(scratch, &cpu_online_map,
                           cpumask_of(smp_processor_id()));
            show_execution_state_nmi(scratch, false);
        }
    }

    panic("FATAL TRAP: vec %u, %s[%04x]%s\n",
          trapnr, vector_name(trapnr), regs->error_code,
          (regs->eflags & X86_EFLAGS_IF) ? "" : " IN INTERRUPT CONTEXT");
}

void asmlinkage noreturn do_unhandled_trap(struct cpu_user_regs *regs)
{
    fatal_trap(regs, false);
}

static void fixup_exception_return(struct cpu_user_regs *regs,
                                   unsigned long fixup, unsigned long stub_ra)
{
    if ( IS_ENABLED(CONFIG_XEN_SHSTK) )
    {
        unsigned long ssp, *ptr, *base;

        if ( (ssp = rdssp()) == SSP_NO_SHSTK )
            goto shstk_done;

        ptr = _p(ssp);
        base = _p(get_shstk_bottom(ssp));

        for ( ; ptr < base; ++ptr )
        {
            /*
             * Search for %rip.  The shstk currently looks like this:
             *
             *   tok  [Supervisor token, == &tok | BUSY, only with FRED inactive]
             *   ...  [Pointed to by SSP for most exceptions, empty in IST cases]
             *   %cs  [== regs->cs]
             *   %rip [== regs->rip]
             *   SSP  [Likely points to 3 slots higher, above %cs]
             *   ...  [call tree to this function, likely 2/3 slots]
             *
             * and we want to overwrite %rip with fixup.  There are two
             * complications:
             *   1) We cant depend on SSP values, because they won't differ by
             *      3 slots if the exception is taken on an IST stack.
             *   2) There are synthetic (unrealistic but not impossible)
             *      scenarios where %rip can end up in the call tree to this
             *      function, so we can't check against regs->rip alone.
             *
             * Check for both regs->rip and regs->cs matching.
             */
            if ( ptr[0] == regs->rip && ptr[1] == regs->cs )
            {
                unsigned long primary_shstk =
                    (ssp & ~(STACK_SIZE - 1)) +
                    (PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE - 8;

                wrss(fixup, ptr);

                if ( !stub_ra )
                    goto shstk_done;

                /*
                 * Stub recovery ought to happen only when the outer context
                 * was on the main shadow stack.  We need to also "pop" the
                 * stub's return address from the interrupted context's shadow
                 * stack.  That is,
                 * - if we're still on the main stack, we need to move the
                 *   entire stack (up to and including the exception frame)
                 *   up by one slot, incrementing the original SSP in the
                 *   exception frame,
                 * - if we're on an IST stack, we need to increment the
                 *   original SSP.
                 */
                BUG_ON((ptr[-1] ^ primary_shstk) >> PAGE_SHIFT);

                if ( (ssp ^ primary_shstk) >> PAGE_SHIFT )
                {
                    /*
                     * We're on an IST stack.  First make sure the two return
                     * addresses actually match.  Then increment the interrupted
                     * context's SSP.
                     */
                    BUG_ON(stub_ra != *(unsigned long*)ptr[-1]);
                    wrss(ptr[-1] + 8, &ptr[-1]);
                    goto shstk_done;
                }

                /* Make sure the two return addresses actually match. */
                BUG_ON(stub_ra != ptr[2]);

                /* Move exception frame, updating SSP there. */
                wrss(ptr[1], &ptr[2]); /* %cs */
                wrss(ptr[0], &ptr[1]); /* %rip */
                wrss(ptr[-1] + 8, &ptr[0]); /* SSP */

                /* Move all newer entries. */
                while ( --ptr != _p(ssp) )
                    wrss(ptr[-1], &ptr[0]);

                /* Finally account for our own stack having shifted up. */
                asm volatile ( "incsspd %0" :: "r" (2) );

                goto shstk_done;
            }
        }

        /*
         * We failed to locate and fix up the shadow IRET frame.  This could
         * be due to shadow stack corruption, or bad logic above.  We cannot
         * continue executing the interrupted context.
         */
        BUG();

    }
 shstk_done:

    /* Fixup the regular stack. */
    regs->rip = fixup;
}

static bool extable_fixup(struct cpu_user_regs *regs, bool print)
{
    unsigned long stub_ra = 0;
    unsigned long fixup = search_exception_table(regs, &stub_ra);

    if ( unlikely(fixup == 0) )
        return false;

    /*
     * Don't use dprintk() because the __FILE__ reference is unhelpful.
     * Can currently be triggered by guests.  Make sure we ratelimit.
     */
    if ( IS_ENABLED(CONFIG_DEBUG) && print )
        printk(XENLOG_GUEST XENLOG_WARNING "Fixup %s[%04x]: %p [%ps] -> %p\n",
               vector_name(regs->entry_vector), regs->error_code,
               _p(regs->rip), _p(regs->rip), _p(fixup));

    fixup_exception_return(regs, fixup, stub_ra);
    this_cpu(last_extable_addr) = regs->rip;

    return true;
}

void asmlinkage do_trap(struct cpu_user_regs *regs)
{
    unsigned int trapnr = regs->entry_vector;

    if ( regs->error_code & X86_XEC_EXT )
        goto hardware_trap;

    ASSERT(trapnr < 32);

    if ( guest_mode(regs) )
    {
        pv_inject_hw_exception(trapnr,
                               (X86_EXC_HAVE_EC & (1u << trapnr))
                               ? regs->error_code : X86_EVENT_NO_EC);
        return;
    }

    if ( likely(extable_fixup(regs, true)) )
        return;

 hardware_trap:
    fatal_trap(regs, false);
}

void asmlinkage do_invalid_op(struct cpu_user_regs *regs)
{
    u8 bug_insn[2];
    const void *eip = (const void *)regs->rip;
    int id;

    if ( likely(guest_mode(regs)) )
    {
        if ( pv_emulate_invalid_op(regs) )
            pv_inject_hw_exception(X86_EXC_UD, X86_EVENT_NO_EC);
        return;
    }

    if ( !is_active_kernel_text(regs->rip) ||
         copy_from_unsafe(bug_insn, eip, sizeof(bug_insn)) ||
         memcmp(bug_insn, "\xf\xb", sizeof(bug_insn)) )
        goto die;

    id = do_bug_frame(regs, regs->rip);
    if ( id < 0 )
        goto die;

    eip += sizeof(bug_insn);

    switch ( id )
    {
    case BUGFRAME_run_fn:
    case BUGFRAME_warn:
        fixup_exception_return(regs, (unsigned long)eip, 0);
        fallthrough;
    case BUGFRAME_bug:
    case BUGFRAME_assert:
        return;
    }

 die:
    if ( likely(extable_fixup(regs, true)) )
        return;

    show_execution_state(regs);
    panic("FATAL TRAP: vector = %d (invalid opcode)\n", X86_EXC_UD);
}

void asmlinkage do_int3(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;

    if ( !guest_mode(regs) )
    {
        if ( likely(extable_fixup(regs, true)) )
            return;

        printk(XENLOG_DEBUG "Hit embedded breakpoint at %p [%ps]\n",
               _p(regs->rip), _p(regs->rip));

        return;
    }

    if ( guest_kernel_mode(curr, regs) && curr->domain->debugger_attached )
    {
        curr->arch.gdbsx_vcpu_event = X86_EXC_BP;
        domain_pause_for_debugger();
        return;
    }

    pv_inject_hw_exception(X86_EXC_BP, X86_EVENT_NO_EC);
}

/* SAF-1-safe */
void do_general_protection(struct cpu_user_regs *regs)
{
#ifdef CONFIG_PV
    struct vcpu *v = current;
#endif

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
    pv_inject_hw_exception(X86_EXC_GP, regs->error_code);
    return;
#endif

 gp_in_kernel:
    if ( likely(extable_fixup(regs, true)) )
        return;

 hardware_gp:
    show_execution_state(regs);
    panic("GENERAL PROTECTION FAULT\n[error_code=%04x]\n", regs->error_code);
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

            pv_inject_hw_exception(X86_EXC_GP, ec);
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
    l4e = l4e_read(&l4t[l4_table_offset(addr)]);
    mfn = l4e_get_pfn(l4e);
    unmap_domain_page(l4t);
    if ( ((l4e_get_flags(l4e) & required_flags) != required_flags) ||
         (l4e_get_flags(l4e) & disallowed_flags) )
        return real_fault;
    page_user &= l4e_get_flags(l4e);

    l3t  = map_domain_page(_mfn(mfn));
    l3e = l3e_read(&l3t[l3_table_offset(addr)]);
    mfn = l3e_get_pfn(l3e);
    unmap_domain_page(l3t);
    if ( ((l3e_get_flags(l3e) & required_flags) != required_flags) ||
         (l3e_get_flags(l3e) & disallowed_flags) )
        return real_fault;
    page_user &= l3e_get_flags(l3e);
    if ( l3e_get_flags(l3e) & _PAGE_PSE )
        goto leaf;

    l2t = map_domain_page(_mfn(mfn));
    l2e = l2e_read(&l2t[l2_table_offset(addr)]);
    mfn = l2e_get_pfn(l2e);
    unmap_domain_page(l2t);
    if ( ((l2e_get_flags(l2e) & required_flags) != required_flags) ||
         (l2e_get_flags(l2e) & disallowed_flags) )
        return real_fault;
    page_user &= l2e_get_flags(l2e);
    if ( l2e_get_flags(l2e) & _PAGE_PSE )
        goto leaf;

    l1t = map_domain_page(_mfn(mfn));
    l1e = l1e_read(&l1t[l1_table_offset(addr)]);
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

        if ( IS_ENABLED(CONFIG_PV) && ret == EXCRET_fault_fixed )
            trace_trap_two_addr(TRC_PV_PAGING_FIXUP, regs->rip, addr);
        return ret;
    }

    return 0;
}

void asmlinkage do_page_fault(struct cpu_user_regs *regs)
{
    unsigned long addr;
    unsigned int error_code;

    addr = read_cr2();

    /*
     * Don't re-enable interrupts if we were running an IRQ-off region when
     * we hit the page fault, or we'll break that code.
     */
    ASSERT(!local_irq_is_enabled());
    if ( regs->flags & X86_EFLAGS_IF )
        local_irq_enable();

    /* fixup_page_fault() might change regs->error_code, so cache it here. */
    error_code = regs->error_code;

    perfc_incr(page_faults);

    /* Any shadow stack access fault is a bug in Xen. */
    if ( error_code & PFEC_shstk )
        goto fatal;

    if ( unlikely(fixup_page_fault(addr, regs) != 0) )
        return;

    /*
     * Xen doesn't have reserved bits set in its pagetables, nor do we permit
     * PV guests to write any.  Such entries would generally be vulnerable to
     * the L1TF sidechannel.
     *
     * The shadow pagetable logic may use reserved bits as part of
     * SHOPT_FAST_FAULT_PATH.  Pagefaults arising from these will be resolved
     * via the fixup_page_fault() path.
     *
     * Anything remaining is an error, constituting corruption of the
     * pagetables and probably an L1TF vulnerable gadget.
     */
    if ( error_code & PFEC_reserved_bit )
        goto fatal;

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

        if ( likely(extable_fixup(regs, false)) )
        {
            perfc_incr(copy_user_faults);
            return;
        }

    fatal:
        show_execution_state(regs);
        show_page_walk(addr);
        panic("FATAL PAGE FAULT\n"
              "[error_code=%04x]\n"
              "Faulting linear address: %p\n",
              error_code, _p(addr));
    }

    pv_inject_page_fault(regs->error_code, addr);
}

/*
 * Early #PF handler to print CR2, error code, and stack.
 *
 * We also deal with spurious faults here, even though they should never happen
 * during early boot (an issue was seen once, but was most likely a hardware
 * problem).
 */
void asmlinkage __init do_early_page_fault(struct cpu_user_regs *regs)
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

static bool pci_serr_cont;

static bool pci_serr_nmicont(void)
{
    if ( !pci_serr_cont )
        return false;

    pci_serr_cont = false;
    printk("\n\nNMI - PCI system error (SERR)\n");
    outb(inb(0x61) & 0x0b, 0x61); /* re-enable the PCI SERR error line. */

    return true;
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
        /* Issue error message in NMI continuation. */
        pci_serr_cont = true;
        trigger_nmi_continuation();
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
        break;
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
        break;
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("Uhhuh. NMI received for unknown reason %02x.\n", reason);
        printk("Do you have a strange power saving mode enabled?\n");
        fatal_trap(regs, 0);
    }
}

static nmi_callback_t *__read_mostly nmi_callback;

DEFINE_PER_CPU(unsigned int, nmi_count);

void do_nmi(const struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();
    nmi_callback_t *callback;
    unsigned char reason = 0;
    bool handle_unknown = false;

    this_cpu(nmi_count)++;
    nmi_enter();

    /*
     * Think carefully before putting any logic before this point.
     * nmi_callback() might be the crash quiesce...
     */

    callback = ACCESS_ONCE(nmi_callback);
    if ( unlikely(callback) && callback(regs, cpu) )
        goto out;

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

 out:
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
    nmi_callback = NULL;
}

bool nmi_check_continuation(void)
{
    bool ret = false;

    if ( pci_serr_nmicont() )
        ret = true;

    if ( nmi_oprofile_send_virq() )
        ret = true;

    return ret;
}

void trigger_nmi_continuation(void)
{
    /*
     * Issue a self-IPI. Handling is done in spurious_interrupt().
     * NMI could have happened in IPI sequence, so wait for ICR being idle
     * again before leaving NMI handler.
     * This relies on self-IPI using a simple shorthand, thus avoiding any
     * use of locking or percpu cpumasks.
     */
    send_IPI_self(SPURIOUS_APIC_VECTOR);
    apic_wait_icr_idle();
}

void asmlinkage do_device_not_available(struct cpu_user_regs *regs)
{
#ifdef CONFIG_PV
    struct vcpu *curr = current;
#endif

    if ( !guest_mode(regs) )
    {
        /*
         * We shouldn't be able to reach here, but for release builds have
         * the recovery logic in place nevertheless.
         */
        if ( extable_fixup(regs, true) )
        {
            ASSERT_UNREACHABLE();
            return;
        }

        fatal_trap(regs, false);
    }

#ifdef CONFIG_PV
    vcpu_restore_fpu_lazy(curr);

    if ( curr->arch.pv.ctrlreg[0] & X86_CR0_TS )
    {
        pv_inject_hw_exception(X86_EXC_NM, X86_EVENT_NO_EC);
        curr->arch.pv.ctrlreg[0] &= ~X86_CR0_TS;
    }
    else
        TRACE_TIME(TRC_PV_MATH_STATE_RESTORE);
#else
    ASSERT_UNREACHABLE();
#endif
}

void nocall sysenter_eflags_saved(void);

void asmlinkage do_debug(struct cpu_user_regs *regs)
{
    unsigned long dr6;
    struct vcpu *v = current;

    /* Stash dr6 as early as possible. */
    dr6 = read_debugreg(6);

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
            WARN();
            regs->eflags &= ~X86_EFLAGS_TF;
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

    /*
     * Update the guest's dr6 so the debugger can peek at it.
     *
     * TODO: This should be passed out-of-band, so guest state is not modified
     * by debugging actions completed behind it's back.
     */
    v->arch.dr6 = x86_merge_dr6(v->domain->arch.cpu_policy,
                                v->arch.dr6, dr6 ^ X86_DR6_DEFAULT);

    if ( guest_kernel_mode(v, regs) && v->domain->debugger_attached )
    {
        domain_pause_for_debugger();
        return;
    }

    pv_inject_DB(dr6 ^ X86_DR6_DEFAULT);
}

void asmlinkage do_entry_CP(struct cpu_user_regs *regs)
{
    static const char errors[][10] = {
        [1] = "near ret",
        [2] = "far/iret",
        [3] = "endbranch",
        [4] = "rstorssp",
        [5] = "setssbsy",
    };
    const char *err = "??";
    unsigned int ec = regs->error_code;

    /* Decode ec if possible */
    if ( ec < ARRAY_SIZE(errors) && errors[ec][0] )
        err = errors[ec];

    /*
     * For now, only supervisors shadow stacks should be active.  A #CP from
     * guest context is probably a Xen bug, but kill the guest in an attempt
     * to recover.
     */
    if ( guest_mode(regs) )
    {
        gprintk(XENLOG_ERR, "Hit #CP[%04x] in guest context %04x:%p\n",
                ec, regs->cs, _p(regs->rip));
        ASSERT_UNREACHABLE();
        domain_crash(current->domain);
        return;
    }

    show_execution_state(regs);
    panic("CONTROL-FLOW PROTECTION FAULT: #CP[%04x] %s\n", ec, err);
}

void asm_domain_crash_synchronous(unsigned long addr)
{
    /*
     * We need to clear the AC bit here because the exception fixup logic
     * may leave user accesses enabled.
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

#ifdef CONFIG_DEBUG
void asmlinkage check_ist_exit(const struct cpu_user_regs *regs, bool ist_exit)
{
    const unsigned int ist_mask =
        (1U << X86_EXC_NMI) | (1U << X86_EXC_DB) |
        (1U << X86_EXC_DF)  | (1U << X86_EXC_MC);
    uint8_t ev = regs->entry_vector;
    bool is_ist = (ev < X86_EXC_NUM) && ((1U << ev) & ist_mask);

    ASSERT(is_ist == ist_exit);
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
