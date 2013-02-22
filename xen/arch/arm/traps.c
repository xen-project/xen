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
#include <xen/domain_page.h>
#include <public/xen.h>
#include <asm/regs.h>
#include <asm/cpregs.h>

#include "io.h"
#include "vtimer.h"
#include <asm/gic.h>

/* The base of the stack must always be double-word aligned, which means
 * that both the kernel half of struct cpu_user_regs (which is pushed in
 * entry.S) and struct cpu_info (which lives at the bottom of a Xen
 * stack) must be doubleword-aligned in size.  */
static inline void check_stack_alignment_constraints(void) {
    BUILD_BUG_ON((sizeof (struct cpu_user_regs)) & 0x7);
    BUILD_BUG_ON((offsetof(struct cpu_user_regs, sp_usr)) & 0x7);
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

    printk("----[ Xen-%d.%d%s  arm32  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           debug_build() ? 'y' : 'n', print_tainted(taint_str));
}

register_t *select_user_reg(struct cpu_user_regs *regs, int reg)
{
    BUG_ON( !guest_mode(regs) );

    /*
     * We rely heavily on the layout of cpu_user_regs to avoid having
     * to handle all of the registers individually. Use BUILD_BUG_ON to
     * ensure that things which expect are contiguous actually are.
     */
#define REGOFFS(R) offsetof(struct cpu_user_regs, R)

    switch ( reg ) {
    case 0 ... 7: /* Unbanked registers */
        BUILD_BUG_ON(REGOFFS(r0) + 7*sizeof(register_t) != REGOFFS(r7));
        return &regs->r0 + reg;
    case 8 ... 12: /* Register banked in FIQ mode */
        BUILD_BUG_ON(REGOFFS(r8_fiq) + 4*sizeof(register_t) != REGOFFS(r12_fiq));
        if ( fiq_mode(regs) )
            return &regs->r8_fiq + reg - 8;
        else
            return &regs->r8 + reg - 8;
    case 13 ... 14: /* Banked SP + LR registers */
        BUILD_BUG_ON(REGOFFS(sp_fiq) + 1*sizeof(register_t) != REGOFFS(lr_fiq));
        BUILD_BUG_ON(REGOFFS(sp_irq) + 1*sizeof(register_t) != REGOFFS(lr_irq));
        BUILD_BUG_ON(REGOFFS(sp_svc) + 1*sizeof(register_t) != REGOFFS(lr_svc));
        BUILD_BUG_ON(REGOFFS(sp_abt) + 1*sizeof(register_t) != REGOFFS(lr_abt));
        BUILD_BUG_ON(REGOFFS(sp_und) + 1*sizeof(register_t) != REGOFFS(lr_und));
        switch ( regs->cpsr & PSR_MODE_MASK )
        {
        case PSR_MODE_USR:
        case PSR_MODE_SYS: /* Sys regs are the usr regs */
            if ( reg == 13 )
                return &regs->sp_usr;
            else /* lr_usr == lr in a user frame */
                return &regs->lr;
        case PSR_MODE_FIQ:
            return &regs->sp_fiq + reg - 13;
        case PSR_MODE_IRQ:
            return &regs->sp_irq + reg - 13;
        case PSR_MODE_SVC:
            return &regs->sp_svc + reg - 13;
        case PSR_MODE_ABT:
            return &regs->sp_abt + reg - 13;
        case PSR_MODE_UND:
            return &regs->sp_und + reg - 13;
        case PSR_MODE_MON:
        case PSR_MODE_HYP:
        default:
            BUG();
        }
    case 15: /* PC */
        return &regs->pc;
    default:
        BUG();
    }
#undef REGOFFS
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

void panic_PAR(uint64_t par)
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

    panic("Error during Hypervisor-to-physical address translation\n");
}

struct reg_ctxt {
    uint32_t sctlr, tcr;
    uint64_t ttbr0, ttbr1;
#ifdef CONFIG_ARM_32
    uint32_t dfar, ifar;
#else
    uint64_t far;
#endif
};

static void show_registers_32(struct cpu_user_regs *regs,
                              struct reg_ctxt *ctxt,
                              int guest_mode,
                              const struct vcpu *v)
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

#ifdef CONFIG_ARM_64
    printk("PC:     %08"PRIx32"\n", regs->pc32);
#else
    printk("PC:     %08"PRIx32, regs->pc);
    if ( !guest_mode )
        print_symbol(" %s", regs->pc);
    printk("\n");
#endif
    printk("CPSR:   %08"PRIx32" MODE:%s%s\n", regs->cpsr,
           guest_mode ? "32-bit Guest " : "Hypervisor",
           guest_mode ? mode_strings[regs->cpsr & PSR_MODE_MASK] : "");
    printk("     R0: %08"PRIx32" R1: %08"PRIx32" R2: %08"PRIx32" R3: %08"PRIx32"\n",
           regs->r0, regs->r1, regs->r2, regs->r3);
    printk("     R4: %08"PRIx32" R5: %08"PRIx32" R6: %08"PRIx32" R7: %08"PRIx32"\n",
           regs->r4, regs->r5, regs->r6, regs->r7);
    printk("     R8: %08"PRIx32" R9: %08"PRIx32" R10:%08"PRIx32" R11:%08"PRIx32" R12:%08"PRIx32"\n",
           regs->r8, regs->r9, regs->r10,
#ifdef CONFIG_ARM_64
           regs->r11,
#else
           regs->fp,
#endif
           regs->r12);

    if ( guest_mode )
    {
        printk("USR: SP: %08"PRIx32" LR: %08"PRIregister"\n",
               regs->sp_usr, regs->lr);
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
    }
#ifndef CONFIG_ARM_64
    else
    {
        printk("HYP: SP: %08"PRIx32" LR: %08"PRIregister"\n", regs->sp, regs->lr);
    }
#endif
    printk("\n");

    if ( guest_mode )
    {
        printk("TTBR0 %010"PRIx64" TTBR1 %010"PRIx64" TCR %08"PRIx32"\n",
               ctxt->ttbr0, ctxt->ttbr1, ctxt->tcr);
        printk("SCTLR %08"PRIx32"\n", ctxt->sctlr);
        printk("IFAR %08"PRIx32" DFAR %08"PRIx32"\n",
#ifdef CONFIG_ARM_64
               (uint32_t)(ctxt->far >> 32),
               (uint32_t)(ctxt->far & 0xffffffff)
#else
               ctxt->ifar, ctxt->dfar
#endif
            );
        printk("\n");
    }
}

#ifdef CONFIG_ARM_64
static void show_registers_64(struct cpu_user_regs *regs,
                              struct reg_ctxt *ctxt,
                              int guest_mode,
                              const struct vcpu *v)
{
    printk("PC:     %016"PRIx64, regs->pc);
    if ( !guest_mode )
        print_symbol(" %s", regs->pc);
    printk("\n");
    printk("SP:     %08"PRIx64"\n", regs->sp);
    printk("CPSR:   %08"PRIx32" MODE:%s\n", regs->cpsr,
           guest_mode ? "64-bit Guest" : "Hypervisor");
    printk("     X0: %016"PRIx64"  X1: %016"PRIx64"  X2: %016"PRIx64"\n",
           regs->x0, regs->x1, regs->x2);
    printk("     X3: %016"PRIx64"  X4: %016"PRIx64"  X5: %016"PRIx64"\n",
           regs->x3, regs->x4, regs->x5);
    printk("     X6: %016"PRIx64"  X7: %016"PRIx64"  X8: %016"PRIx64"\n",
           regs->x6, regs->x7, regs->x8);
    printk("     X9: %016"PRIx64" X10: %016"PRIx64" X11: %016"PRIx64"\n",
           regs->x9, regs->x10, regs->x11);
    printk("    X12: %016"PRIx64" X13: %016"PRIx64" X14: %016"PRIx64"\n",
           regs->x12, regs->x13, regs->x14);
    printk("    X15: %016"PRIx64" X16: %016"PRIx64" X17: %016"PRIx64"\n",
           regs->x15, regs->x16, regs->x17);
    printk("    X18: %016"PRIx64" X19: %016"PRIx64" X20: %016"PRIx64"\n",
           regs->x18, regs->x19, regs->x20);
    printk("    X21: %016"PRIx64" X22: %016"PRIx64" X23: %016"PRIx64"\n",
           regs->x21, regs->x22, regs->x23);
    printk("    X24: %016"PRIx64" X25: %016"PRIx64" X26: %016"PRIx64"\n",
           regs->x24, regs->x25, regs->x26);
    printk("    X27: %016"PRIx64" X28: %016"PRIx64" X29: %016"PRIx64"\n",
           regs->x27, regs->x28, regs->lr);
    printk("\n");

    if ( guest_mode )
    {
        printk("SCTLR_EL1: %08"PRIx32"\n", ctxt->sctlr);
        printk("  TCR_EL1: %08"PRIx32"\n", ctxt->tcr);
        printk("TTBR0_EL1: %010"PRIx64"\n", ctxt->ttbr0);
        printk("TTBR1_EL1: %010"PRIx64"\n", ctxt->ttbr1);
        printk("  FAR_EL1: %010"PRIx64"\n", ctxt->far);
        printk("\n");
    }
}
#endif

static void _show_registers(struct cpu_user_regs *regs,
                            struct reg_ctxt *ctxt,
                            int guest_mode,
                            const struct vcpu *v)
{
    print_xen_info();

    printk("CPU:    %d\n", smp_processor_id());

    if ( guest_mode )
    {
        if ( is_pv32_domain(v->domain) )
            show_registers_32(regs, ctxt, guest_mode, v);
#ifdef CONFIG_ARM_64
        else if ( is_pv64_domain(v->domain) )
            show_registers_64(regs, ctxt, guest_mode, v);
#endif
    }
    else
    {
#ifdef CONFIG_ARM_64
        show_registers_64(regs, ctxt, guest_mode, v);
#else
        show_registers_32(regs, ctxt, guest_mode, v);
#endif
    }

#ifdef CONFIG_ARM_32
    printk("HTTBR %"PRIx64"\n", READ_CP64(HTTBR));
    printk("HDFAR %"PRIx32"\n", READ_CP32(HDFAR));
    printk("HIFAR %"PRIx32"\n", READ_CP32(HIFAR));
    printk("HPFAR %"PRIx32"\n", READ_CP32(HPFAR));
    printk("HCR %08"PRIx32"\n", READ_CP32(HCR));
    printk("HSR   %"PRIx32"\n", READ_CP32(HSR));
    printk("VTTBR %010"PRIx64"\n", READ_CP64(VTTBR));
    printk("\n");

    printk("DFSR %"PRIx32" DFAR %"PRIx32"\n", READ_CP32(DFSR), READ_CP32(DFAR));
    printk("IFSR %"PRIx32" IFAR %"PRIx32"\n", READ_CP32(IFSR), READ_CP32(IFAR));
    printk("\n");
#else
    printk("TTBR0_EL2: %"PRIx64"\n", READ_SYSREG64(TTBR0_EL2));
    printk("  FAR_EL2: %"PRIx64"\n", READ_SYSREG64(FAR_EL2));
    printk("HPFAR_EL2: %"PRIx64"\n", READ_SYSREG64(HPFAR_EL2));
    printk("  HCR_EL2: %"PRIx64"\n", READ_SYSREG64(HCR_EL2));
    printk("  ESR_EL2: %"PRIx64"\n", READ_SYSREG64(ESR_EL2));
    printk("VTTBR_EL2: %"PRIx64"\n", READ_SYSREG64(VTTBR_EL2));
    printk("\n");
#endif
}

void show_registers(struct cpu_user_regs *regs)
{
    struct reg_ctxt ctxt;
    ctxt.sctlr = READ_SYSREG(SCTLR_EL1);
    ctxt.tcr = READ_SYSREG(TCR_EL1);
    ctxt.ttbr0 = READ_SYSREG64(TTBR0_EL1);
    ctxt.ttbr1 = READ_SYSREG64(TTBR1_EL1);
#ifdef CONFIG_ARM_32
    ctxt.dfar = READ_CP32(DFAR);
    ctxt.ifar = READ_CP32(IFAR);
#else
    ctxt.far = READ_SYSREG(FAR_EL1);
#endif
    _show_registers(regs, &ctxt, guest_mode(regs), current);
}

void vcpu_show_registers(const struct vcpu *v)
{
    struct reg_ctxt ctxt;
    ctxt.sctlr = v->arch.sctlr;
    ctxt.tcr = v->arch.ttbcr;
    ctxt.ttbr0 = v->arch.ttbr0;
    ctxt.ttbr1 = v->arch.ttbr1;
#ifdef CONFIG_ARM_32
    ctxt.dfar = v->arch.dfar;
    ctxt.ifar = v->arch.ifar;
#else
    ctxt.far = v->arch.far;
#endif
    _show_registers(&v->arch.cpu_info->guest_cpu_user_regs, &ctxt, 1, v);
}

static void show_guest_stack(struct cpu_user_regs *regs)
{
    printk("GUEST STACK GOES HERE\n");
}

#define STACK_BEFORE_EXCEPTION(regs) ((register_t*)(regs)->sp)

static void show_trace(struct cpu_user_regs *regs)
{
    register_t *frame, next, addr, low, high;

    printk("Xen call trace:\n   ");

    printk("[<%p>]", _p(regs->pc));
    print_symbol(" %s\n   ", regs->pc);

    /* Bounds for range of valid frame pointer. */
    low  = (register_t)(STACK_BEFORE_EXCEPTION(regs)/* - 2*/);
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
            frame = (register_t *)next;
            next  = frame[-1];
            addr  = frame[0];
        }

        printk("[<%p>]", _p(addr));
        print_symbol(" %s\n   ", addr);

        low = (register_t)&frame[1];
    }

    printk("\n");
}

void show_stack(struct cpu_user_regs *regs)
{
    register_t *stack = STACK_BEFORE_EXCEPTION(regs), addr;
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
    if ( !usr_mode(&v->arch.cpu_info->guest_cpu_user_regs) )
        show_guest_stack(&v->arch.cpu_info->guest_cpu_user_regs);

    vcpu_unpause(v);
}

void do_unexpected_trap(const char *msg, struct cpu_user_regs *regs)
{
    printk("Unexpected Trap: %s\n", msg);
    show_execution_state(regs);
    while(1);
}

unsigned long do_arch_0(unsigned int cmd, unsigned long long value)
{
        printk("do_arch_0 cmd=%x arg=%llx\n", cmd, value);
        return 0;
}

typedef unsigned long (*arm_hypercall_fn_t)(
    unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);

typedef struct {
    arm_hypercall_fn_t fn;
    int nr_args;
} arm_hypercall_t;

#define HYPERCALL(_name, _nr_args)                                   \
    [ __HYPERVISOR_ ## _name ] =  {                                  \
        .fn = (arm_hypercall_fn_t) &do_ ## _name,                    \
        .nr_args = _nr_args,                                         \
    }

static arm_hypercall_t arm_hypercall_table[] = {
    HYPERCALL(memory_op, 2),
    HYPERCALL(domctl, 1),
    HYPERCALL(arch_0, 2),
    HYPERCALL(sched_op, 2),
    HYPERCALL(console_io, 3),
    HYPERCALL(xen_version, 2),
    HYPERCALL(event_channel_op, 2),
    HYPERCALL(physdev_op, 2),
    HYPERCALL(sysctl, 2),
    HYPERCALL(hvm_op, 2),
    HYPERCALL(grant_table_op, 3),
};

static void do_debug_trap(struct cpu_user_regs *regs, unsigned int code)
{
    register_t *r;
    uint32_t reg;
    uint32_t domid = current->domain->domain_id;
    switch ( code ) {
    case 0xe0 ... 0xef:
        reg = code - 0xe0;
        r = select_user_reg(regs, reg);
        printk("DOM%d: R%d = 0x%"PRIregister" at 0x%"PRIvaddr"\n",
               domid, reg, *r, regs->pc);
        break;
    case 0xfd:
        printk("DOM%d: Reached %"PRIvaddr"\n", domid, regs->pc);
        break;
    case 0xfe:
        r = select_user_reg(regs, 0);
        printk("%c", (char)(*r & 0xff));
        break;
    case 0xff:
        printk("DOM%d: DEBUG\n", domid);
        show_execution_state(regs);
        break;
    default:
        panic("DOM%d: Unhandled debug trap %#x\n", domid, code);
        break;
    }
}

static void do_trap_hypercall(struct cpu_user_regs *regs, unsigned long iss)
{
    arm_hypercall_fn_t call = NULL;
#ifndef NDEBUG
    uint32_t orig_pc = regs->pc;
#endif

    if ( iss != XEN_HYPERCALL_TAG )
        domain_crash_synchronous();

    if ( regs->r12 >= ARRAY_SIZE(arm_hypercall_table) )
    {
        regs->r0 = -ENOSYS;
        return;
    }

    call = arm_hypercall_table[regs->r12].fn;
    if ( call == NULL )
    {
        regs->r0 = -ENOSYS;
        return;
    }

    regs->r0 = call(regs->r0, regs->r1, regs->r2, regs->r3, regs->r4);

#ifndef NDEBUG
    /*
     * Clobber argument registers only if pc is unchanged, otherwise
     * this is a hypercall continuation.
     */
    if ( orig_pc == regs->pc )
    {
        switch ( arm_hypercall_table[regs->r12].nr_args ) {
        case 5: regs->r4 = 0xDEADBEEF;
        case 4: regs->r3 = 0xDEADBEEF;
        case 3: regs->r2 = 0xDEADBEEF;
        case 2: regs->r1 = 0xDEADBEEF;
        case 1: /* Don't clobber r0 -- it's the return value */
            break;
        default: BUG();
        }
        regs->r12 = 0xDEADBEEF;
    }
#endif
}

static void do_cp15_32(struct cpu_user_regs *regs,
                       union hsr hsr)
{
    struct hsr_cp32 cp32 = hsr.cp32;
    uint32_t *r = (uint32_t*)select_user_reg(regs, cp32.reg);

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
        printk("%s p15, %d, r%d, cr%d, cr%d, %d @ 0x%"PRIregister"\n",
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
        printk("%s p15, %d, r%d, r%d, cr%d @ 0x%"PRIregister"\n",
               cp64.read ? "mrrc" : "mcrr",
               cp64.op1, cp64.reg1, cp64.reg2, cp64.crm, regs->pc);
        panic("unhandled 64-bit CP15 access %#x\n", hsr.bits & HSR_CP64_REGS_MASK);
    }
    regs->pc += cp64.len ? 4 : 2;

}

void dump_guest_s1_walk(struct domain *d, vaddr_t addr)
{
    uint32_t ttbcr = READ_CP32(TTBCR);
    uint64_t ttbr0 = READ_CP64(TTBR0);
    paddr_t paddr;
    uint32_t offset;
    uint32_t *first = NULL, *second = NULL;

    printk("dom%d VA 0x%08"PRIvaddr"\n", d->domain_id, addr);
    printk("    TTBCR: 0x%08"PRIx32"\n", ttbcr);
    printk("    TTBR0: 0x%010"PRIx64" = 0x%"PRIpaddr"\n",
           ttbr0, p2m_lookup(d, ttbr0 & PAGE_MASK));

    if ( ttbcr & TTBCR_EAE )
    {
        printk("Cannot handle LPAE guest PT walk\n");
        return;
    }
    if ( (ttbcr & TTBCR_N_MASK) != 0 )
    {
        printk("Cannot handle TTBR1 guest walks\n");
        return;
    }

    paddr = p2m_lookup(d, ttbr0 & PAGE_MASK);
    if ( paddr == INVALID_PADDR )
    {
        printk("Failed TTBR0 maddr lookup\n");
        goto done;
    }
    first = map_domain_page(paddr>>PAGE_SHIFT);

    offset = addr >> (12+10);
    printk("1ST[0x%"PRIx32"] (0x%"PRIpaddr") = 0x%08"PRIx32"\n",
           offset, paddr, first[offset]);
    if ( !(first[offset] & 0x1) ||
         !(first[offset] & 0x2) )
        goto done;

    paddr = p2m_lookup(d, first[offset] & PAGE_MASK);

    if ( paddr == INVALID_PADDR )
    {
        printk("Failed L1 entry maddr lookup\n");
        goto done;
    }
    second = map_domain_page(paddr>>PAGE_SHIFT);
    offset = (addr >> 12) & 0x3FF;
    printk("2ND[0x%"PRIx32"] (0x%"PRIpaddr") = 0x%08"PRIx32"\n",
           offset, paddr, second[offset]);

done:
    if (second) unmap_domain_page(second);
    if (first) unmap_domain_page(first);
}

static void do_trap_data_abort_guest(struct cpu_user_regs *regs,
                                     struct hsr_dabt dabt)
{
    const char *msg;
    int rc, level = -1;
    mmio_info_t info;

    info.dabt = dabt;
#ifdef CONFIG_ARM_32
    info.gva = READ_CP32(HDFAR);
#else
    info.gva = READ_SYSREG64(FAR_EL2);
#endif

    if (dabt.s1ptw)
        goto bad_data_abort;

    rc = gva_to_ipa(info.gva, &info.gpa);
    if ( rc == -EFAULT )
        goto bad_data_abort;

    if (handle_mmio(&info))
    {
        regs->pc += dabt.len ? 4 : 2;
        return;
    }

bad_data_abort:

    msg = decode_fsc( dabt.dfsc, &level);

    /* XXX inject a suitable fault into the guest */
    printk("Guest data abort: %s%s%s\n"
           "    gva=%"PRIvaddr"\n",
           msg, dabt.s1ptw ? " S2 during S1" : "",
           fsc_level_str(level),
           info.gva);
    if ( !dabt.s1ptw )
        printk("    gpa=%"PRIpaddr"\n", info.gpa);
    if ( dabt.valid )
        printk("    size=%d sign=%d write=%d reg=%d\n",
               dabt.size, dabt.sign, dabt.write, dabt.reg);
    else
        printk("    instruction syndrome invalid\n");
    printk("    eat=%d cm=%d s1ptw=%d dfsc=%d\n",
           dabt.eat, dabt.cache, dabt.s1ptw, dabt.dfsc);
    if ( !dabt.s1ptw )
        dump_p2m_lookup(current->domain, info.gpa);
    else
        dump_guest_s1_walk(current->domain, info.gva);
    show_execution_state(regs);
    domain_crash_synchronous();
}

asmlinkage void do_trap_hypervisor(struct cpu_user_regs *regs)
{
    union hsr hsr = { .bits = READ_SYSREG32(ESR_EL2) };

    switch (hsr.ec) {
    case HSR_EC_CP15_32:
        if ( ! is_pv32_domain(current->domain) )
            goto bad_trap;
        do_cp15_32(regs, hsr);
        break;
    case HSR_EC_CP15_64:
        if ( ! is_pv32_domain(current->domain) )
            goto bad_trap;
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
 bad_trap:
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
        if (!softirq_pending(smp_processor_id())) {
            gic_inject();
            return;
        }
        local_irq_enable();
        do_softirq();
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
