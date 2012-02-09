/*
 * xen/arch/arm/traps.c
 *
 * ARM Trap handlers
 *
 * Copyright (c) 2011 Citrix Systems.
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
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/string.h>
#include <xen/version.h>
#include <xen/smp.h>
#include <xen/symbols.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/errno.h>
#include <xen/hypercall.h>
#include <xen/softirq.h>
#include <public/xen.h>
#include <asm/regs.h>
#include <asm/cpregs.h>

#include "io.h"
#include "vtimer.h"
#include "gic.h"

/* The base of the stack must always be double-word aligned, which means
 * that both the kernel half of struct cpu_user_regs (which is pushed in
 * entry.S) and struct cpu_info (which lives at the bottom of a Xen
 * stack) must be doubleword-aligned in size.  */
static inline void check_stack_alignment_constraints(void) {
    BUILD_BUG_ON((sizeof (struct cpu_user_regs)) & 0x7);
    BUILD_BUG_ON((offsetof(struct cpu_user_regs, r8_fiq)) & 0x7);
    BUILD_BUG_ON((sizeof (struct cpu_info)) & 0x7);
}

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

#define stack_words_per_line 8

asmlinkage void __div0(void)
{
    printk("Division by zero in hypervisor.\n");
    BUG();
}

/* XXX could/should be common code */
static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];
    char debug = 'n';

#ifndef NDEBUG
    debug = 'y';
#endif

    printk("----[ Xen-%d.%d%s  x86_64  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           debug, print_tainted(taint_str));
}

static const char *decode_fsc(uint32_t fsc, int *level)
{
    const char *msg = NULL;

    switch ( fsc & 0x3f )
    {
    case FSC_FLT_TRANS ... FSC_FLT_TRANS + 3:
        msg = "Translation fault";
        *level = fsc & FSC_LL_MASK;
        break;
    case FSC_FLT_ACCESS ... FSC_FLT_ACCESS + 3:
        msg = "Access fault";
        *level = fsc & FSC_LL_MASK;
        break;
    case FSC_FLT_PERM ... FSC_FLT_PERM + 3:
        msg = "Permission fault";
        *level = fsc & FSC_LL_MASK;
        break;

    case FSC_SEA:
        msg = "Synchronous External Abort";
        break;
    case FSC_SPE:
        msg = "Memory Access Synchronous Parity Error";
        break;
    case FSC_APE:
        msg = "Memory Access Asynchronous Parity Error";
        break;
    case FSC_SEATT ... FSC_SEATT + 3:
        msg = "Sync. Ext. Abort Translation Table";
        *level = fsc & FSC_LL_MASK;
        break;
    case FSC_SPETT ... FSC_SPETT + 3:
        msg = "Sync. Parity. Error Translation Table";
        *level = fsc & FSC_LL_MASK;
        break;
    case FSC_AF:
        msg = "Alignment Fault";
        break;
    case FSC_DE:
        msg = "Debug Event";
        break;

    case FSC_LKD:
        msg = "Implementation Fault: Lockdown Abort";
        break;
    case FSC_CPR:
        msg = "Implementation Fault: Coprocossor Abort";
        break;

    default:
        msg = "Unknown Failure";
        break;
    }
    return msg;
}

static const char *fsc_level_str(int level)
{
    switch ( level )
    {
    case -1: return "";
    case 1:  return " at level 1";
    case 2:  return " at level 2";
    case 3:  return " at level 3";
    default: return " (level invalid)";
    }
}

void panic_PAR(uint64_t par, const char *when)
{
    if ( par & PAR_F )
    {
        const char *msg;
        int level = -1;
        int stage = par & PAR_STAGE2 ? 2 : 1;
        int second_in_first = !!(par & PAR_STAGE21);

        msg = decode_fsc( (par&PAR_FSC_MASK) >> PAR_FSC_SHIFT, &level);

        printk("PAR: %010"PRIx64": %s stage %d%s%s\n",
               par, msg,
               stage,
               second_in_first ? " during second stage lookup" : "",
               fsc_level_str(level));
    }
    else
    {
        printk("PAR: %010"PRIx64": paddr:%010"PRIx64
               " attr %"PRIx64" sh %"PRIx64" %s\n",
               par, par & PADDR_MASK, par >> PAR_MAIR_SHIFT,
               (par & PAR_SH_MASK) >> PAR_SH_SHIFT,
               (par & PAR_NS) ? "Non-Secure" : "Secure");
    }
    panic("Error during %s-to-physical address translation\n", when);
}

void show_registers(struct cpu_user_regs *regs)
{
    static const char *mode_strings[] = {
       [PSR_MODE_USR] = "USR",
       [PSR_MODE_FIQ] = "FIQ",
       [PSR_MODE_IRQ] = "IRQ",
       [PSR_MODE_SVC] = "SVC",
       [PSR_MODE_MON] = "MON",
       [PSR_MODE_ABT] = "ABT",
       [PSR_MODE_HYP] = "HYP",
       [PSR_MODE_UND] = "UND",
       [PSR_MODE_SYS] = "SYS"
    };

    print_xen_info();
    printk("CPU:    %d\n", smp_processor_id());
    printk("PC:     %08"PRIx32, regs->pc);
    if ( !guest_mode(regs) )
            print_symbol(" %s", regs->pc);
    printk("\n");
    printk("CPSR:   %08"PRIx32" MODE:%s\n", regs->cpsr,
           mode_strings[regs->cpsr & PSR_MODE_MASK]);
    printk("     R0: %08"PRIx32" R1: %08"PRIx32" R2: %08"PRIx32" R3: %08"PRIx32"\n",
           regs->r0, regs->r1, regs->r2, regs->r3);
    printk("     R4: %08"PRIx32" R5: %08"PRIx32" R6: %08"PRIx32" R7: %08"PRIx32"\n",
           regs->r4, regs->r5, regs->r6, regs->r7);
    printk("     R8: %08"PRIx32" R9: %08"PRIx32" R10:%08"PRIx32" R11:%08"PRIx32" R12:%08"PRIx32"\n",
           regs->r8, regs->r9, regs->r10, regs->r11, regs->r12);

    if ( guest_mode(regs) )
    {
        printk("USR: SP: %08"PRIx32" LR: %08"PRIx32" CPSR:%08"PRIx32"\n",
               regs->sp_usr, regs->lr_usr, regs->cpsr);
        printk("SVC: SP: %08"PRIx32" LR: %08"PRIx32" SPSR:%08"PRIx32"\n",
               regs->sp_svc, regs->lr_svc, regs->spsr_svc);
        printk("ABT: SP: %08"PRIx32" LR: %08"PRIx32" SPSR:%08"PRIx32"\n",
               regs->sp_abt, regs->lr_abt, regs->spsr_abt);
        printk("UND: SP: %08"PRIx32" LR: %08"PRIx32" SPSR:%08"PRIx32"\n",
               regs->sp_und, regs->lr_und, regs->spsr_und);
        printk("IRQ: SP: %08"PRIx32" LR: %08"PRIx32" SPSR:%08"PRIx32"\n",
               regs->sp_irq, regs->lr_irq, regs->spsr_irq);
        printk("FIQ: SP: %08"PRIx32" LR: %08"PRIx32" SPSR:%08"PRIx32"\n",
               regs->sp_fiq, regs->lr_fiq, regs->spsr_fiq);
        printk("FIQ: R8: %08"PRIx32" R9: %08"PRIx32" R10:%08"PRIx32" R11:%08"PRIx32" R12:%08"PRIx32"\n",
               regs->r8_fiq, regs->r9_fiq, regs->r10_fiq, regs->r11_fiq, regs->r11_fiq);
        printk("\n");
        printk("TTBR0 %08"PRIx32" TTBR1 %08"PRIx32" TTBCR %08"PRIx32"\n",
               READ_CP32(TTBR0), READ_CP32(TTBR1), READ_CP32(TTBCR));
        printk("SCTLR %08"PRIx32"\n", READ_CP32(SCTLR));
        printk("VTTBR %010"PRIx64"\n", READ_CP64(VTTBR));
        printk("\n");
    }
    else
    {
        printk("     SP: %08"PRIx32" LR: %08"PRIx32"\n", regs->sp, regs->lr);
        printk("\n");
    }

    printk("HTTBR %"PRIx64"\n", READ_CP64(HTTBR));
    printk("HDFAR %"PRIx32"\n", READ_CP32(HDFAR));
    printk("HIFAR %"PRIx32"\n", READ_CP32(HIFAR));
    printk("HPFAR %"PRIx32"\n", READ_CP32(HPFAR));
    printk("HCR %08"PRIx32"\n", READ_CP32(HCR));
    printk("HSR   %"PRIx32"\n", READ_CP32(HSR));
    printk("\n");

    printk("DFSR %"PRIx32" DFAR %"PRIx32"\n", READ_CP32(DFSR), READ_CP32(DFAR));
    printk("IFSR %"PRIx32" IFAR %"PRIx32"\n", READ_CP32(IFSR), READ_CP32(IFAR));
    printk("\n");
}

static void show_guest_stack(struct cpu_user_regs *regs)
{
    printk("GUEST STACK GOES HERE\n");
}

#define STACK_BEFORE_EXCEPTION(regs) ((uint32_t*)(regs)->sp)

static void show_trace(struct cpu_user_regs *regs)
{
    uint32_t *frame, next, addr, low, high;

    printk("Xen call trace:\n   ");

    printk("[<%p>]", _p(regs->pc));
    print_symbol(" %s\n   ", regs->pc);

    /* Bounds for range of valid frame pointer. */
    low  = (uint32_t)(STACK_BEFORE_EXCEPTION(regs)/* - 2*/);
    high = (low & ~(STACK_SIZE - 1)) +
        (STACK_SIZE - sizeof(struct cpu_info));

    /* Frame:
     * (largest address)
     * | cpu_info
     * | [...]                                   |
     * | return addr      <-----------------,    |
     * | fp --------------------------------+----'
     * | [...]                              |
     * | return addr      <------------,    |
     * | fp ---------------------------+----'
     * | [...]                         |
     * | return addr      <- regs->fp  |
     * | fp ---------------------------'
     * |
     * v (smallest address, sp)
     */

    /* The initial frame pointer. */
    next = regs->fp;

    for ( ; ; )
    {
        if ( (next < low) || (next >= high) )
            break;
        {
            /* Ordinary stack frame. */
            frame = (uint32_t *)next;
            next  = frame[-1];
            addr  = frame[0];
        }

        printk("[<%p>]", _p(addr));
        print_symbol(" %s\n   ", addr);

        low = (uint32_t)&frame[1];
    }

    printk("\n");
}

void show_stack(struct cpu_user_regs *regs)
{
    uint32_t *stack = STACK_BEFORE_EXCEPTION(regs), addr;
    int i;

    if ( guest_mode(regs) )
        return show_guest_stack(regs);

    printk("Xen stack trace from sp=%p:\n  ", stack);

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

void show_execution_state(struct cpu_user_regs *regs)
{
    show_registers(regs);
    show_stack(regs);
}

static void do_unexpected_trap(const char *msg, struct cpu_user_regs *regs)
{
    printk("Unexpected Trap: %s\n", msg);
    show_execution_state(regs);
    while(1);
}

asmlinkage void do_trap_undefined_instruction(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Undefined Instruction", regs);
}

asmlinkage void do_trap_supervisor_call(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Supervisor Call", regs);
}

asmlinkage void do_trap_prefetch_abort(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Prefetch Abort", regs);
}

asmlinkage void do_trap_data_abort(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Data Abort", regs);
}

unsigned long do_arch_0(unsigned int cmd, unsigned long long value)
{
        printk("do_arch_0 cmd=%x arg=%llx\n", cmd, value);
        return 0;
}

typedef unsigned long arm_hypercall_t(
    unsigned int, unsigned int, unsigned int, unsigned int, unsigned int,
    unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);

#define HYPERCALL(x)                                        \
    [ __HYPERVISOR_ ## x ] = (arm_hypercall_t *) do_ ## x

static arm_hypercall_t *arm_hypercall_table[] = {
    HYPERCALL(arch_0),
    HYPERCALL(sched_op),
    HYPERCALL(console_io),
};

static void do_debug_trap(struct cpu_user_regs *regs, unsigned int code)
{
    uint32_t reg, *r;

    switch ( code ) {
    case 0xe0 ... 0xef:
        reg = code - 0xe0;
        r = &regs->r0 + reg;
        printk("R%d = %#010"PRIx32" at %#010"PRIx32"\n", reg, *r, regs->pc);
        break;
    case 0xfd:
        printk("Reached %08"PRIx32"\n", regs->pc);
        break;
    case 0xfe:
        printk("%c", (char)(regs->r0 & 0xff));
        break;
    case 0xff:
        printk("DEBUG\n");
        show_execution_state(regs);
        break;
    default:
        panic("Unhandled debug trap %#x\n", code);
        break;
    }
}

static void do_trap_hypercall(struct cpu_user_regs *regs, unsigned long iss)
{
    local_irq_enable();

    regs->r0 = arm_hypercall_table[iss](regs->r0,
                             regs->r1,
                             regs->r2,
                             regs->r3,
                             regs->r4,
                             regs->r5,
                             regs->r6,
                             regs->r7,
                             regs->r8,
                             regs->r9);
}

static void do_cp15_32(struct cpu_user_regs *regs,
                       union hsr hsr)
{
    struct hsr_cp32 cp32 = hsr.cp32;
    uint32_t *r = &regs->r0 + cp32.reg;

    if ( !cp32.ccvalid ) {
        dprintk(XENLOG_ERR, "cp_15(32): need to handle invalid condition codes\n");
        domain_crash_synchronous();
    }
    if ( cp32.cc != 0xe ) {
        dprintk(XENLOG_ERR, "cp_15(32): need to handle condition codes %x\n",
                cp32.cc);
        domain_crash_synchronous();
    }

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    case HSR_CPREG32(CLIDR):
        if ( !cp32.read )
        {
            dprintk(XENLOG_ERR,
                    "attempt to write to read-only register CLIDR\n");
            domain_crash_synchronous();
        }
        *r = READ_CP32(CLIDR);
        break;
    case HSR_CPREG32(CCSIDR):
        if ( !cp32.read )
        {
            dprintk(XENLOG_ERR,
                    "attempt to write to read-only register CSSIDR\n");
            domain_crash_synchronous();
        }
        *r = READ_CP32(CCSIDR);
        break;
    case HSR_CPREG32(DCCISW):
        if ( cp32.read )
        {
            dprintk(XENLOG_ERR,
                    "attempt to read from write-only register DCCISW\n");
            domain_crash_synchronous();
        }
        WRITE_CP32(*r, DCCISW);
        break;
    case HSR_CPREG32(CNTP_CTL):
    case HSR_CPREG32(CNTP_TVAL):
        BUG_ON(!vtimer_emulate(regs, hsr));
        break;
    default:
        printk("%s p15, %d, r%d, cr%d, cr%d, %d @ %#08x\n",
               cp32.read ? "mrc" : "mcr",
               cp32.op1, cp32.reg, cp32.crn, cp32.crm, cp32.op2, regs->pc);
        panic("unhandled 32-bit CP15 access %#x\n", hsr.bits & HSR_CP32_REGS_MASK);
    }
    regs->pc += cp32.len ? 4 : 2;

}

static void do_cp15_64(struct cpu_user_regs *regs,
                       union hsr hsr)
{
    struct hsr_cp64 cp64 = hsr.cp64;

    if ( !cp64.ccvalid ) {
        dprintk(XENLOG_ERR, "cp_15(64): need to handle invalid condition codes\n");
        domain_crash_synchronous();
    }
    if ( cp64.cc != 0xe ) {
        dprintk(XENLOG_ERR, "cp_15(64): need to handle condition codes %x\n",
                cp64.cc);
        domain_crash_synchronous();
    }

    switch ( hsr.bits & HSR_CP64_REGS_MASK )
    {
    case HSR_CPREG64(CNTPCT):
        BUG_ON(!vtimer_emulate(regs, hsr));
        break;
    default:
        printk("%s p15, %d, r%d, r%d, cr%d @ %#08x\n",
               cp64.read ? "mrrc" : "mcrr",
               cp64.op1, cp64.reg1, cp64.reg2, cp64.crm, regs->pc);
        panic("unhandled 64-bit CP15 access %#x\n", hsr.bits & HSR_CP64_REGS_MASK);
    }
    regs->pc += cp64.len ? 4 : 2;

}

static void do_trap_data_abort_guest(struct cpu_user_regs *regs,
                                     struct hsr_dabt dabt)
{
    const char *msg;
    int level = -1;
    mmio_info_t info;

    if (dabt.s1ptw)
        goto bad_data_abort;

    info.dabt = dabt;
    info.gva = READ_CP32(HDFAR);
    info.gpa = gva_to_ipa(info.gva);

    if (handle_mmio(&info))
    {
        regs->pc += dabt.len ? 4 : 2;
        return;
    }

bad_data_abort:

    msg = decode_fsc( dabt.dfsc, &level);

    printk("Guest data abort: %s%s%s\n"
           "    gva=%"PRIx32" gpa=%"PRIpaddr"\n",
           msg, dabt.s1ptw ? " S2 during S1" : "",
           fsc_level_str(level),
           info.gva, info.gpa);
    if (dabt.valid)
        printk("    size=%d sign=%d write=%d reg=%d\n",
               dabt.size, dabt.sign, dabt.write, dabt.reg);
    else
        printk("    instruction syndrome invalid\n");
    printk("    eat=%d cm=%d s1ptw=%d dfsc=%d\n",
           dabt.eat, dabt.cache, dabt.s1ptw, dabt.dfsc);

    show_execution_state(regs);
    panic("Unhandled guest data abort\n");
}

asmlinkage void do_trap_hypervisor(struct cpu_user_regs *regs)
{
    union hsr hsr = { .bits = READ_CP32(HSR) };

    switch (hsr.ec) {
    case HSR_EC_CP15_32:
        do_cp15_32(regs, hsr);
        break;
    case HSR_EC_CP15_64:
        do_cp15_64(regs, hsr);
        break;
    case HSR_EC_HVC:
        if ( (hsr.iss & 0xff00) == 0xff00 )
            return do_debug_trap(regs, hsr.iss & 0x00ff);
        do_trap_hypercall(regs, hsr.iss);
        break;
    case HSR_EC_DATA_ABORT_GUEST:
        do_trap_data_abort_guest(regs, hsr.dabt);
        break;
    default:
        printk("Hypervisor Trap. HSR=0x%x EC=0x%x IL=%x Syndrome=%"PRIx32"\n",
               hsr.bits, hsr.ec, hsr.len, hsr.iss);
        do_unexpected_trap("Hypervisor", regs);
    }
}

asmlinkage void do_trap_irq(struct cpu_user_regs *regs)
{
    gic_interrupt(regs, 0);
}

asmlinkage void do_trap_fiq(struct cpu_user_regs *regs)
{
    gic_interrupt(regs, 1);
}

asmlinkage void leave_hypervisor_tail(void)
{
    while (1)
    {
        local_irq_disable();
        if (!softirq_pending(smp_processor_id()))
            return;
        local_irq_enable();
        do_softirq();
    }
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
