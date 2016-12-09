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
#include <xen/livepatch.h>
#include <xen/mm.h>
#include <xen/errno.h>
#include <xen/hypercall.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/perfc.h>
#include <xen/virtual_region.h>
#include <public/sched.h>
#include <public/xen.h>
#include <asm/debugger.h>
#include <asm/event.h>
#include <asm/regs.h>
#include <asm/cpregs.h>
#include <asm/psci.h>
#include <asm/mmio.h>
#include <asm/cpufeature.h>
#include <asm/flushtlb.h>
#include <asm/monitor.h>

#include "decode.h"
#include "vtimer.h"
#include <asm/gic.h>
#include <asm/vgic.h>
#include <asm/cpuerrata.h>

/* The base of the stack must always be double-word aligned, which means
 * that both the kernel half of struct cpu_user_regs (which is pushed in
 * entry.S) and struct cpu_info (which lives at the bottom of a Xen
 * stack) must be doubleword-aligned in size.  */
static inline void check_stack_alignment_constraints(void) {
#ifdef CONFIG_ARM_64
    BUILD_BUG_ON((sizeof (struct cpu_user_regs)) & 0xf);
    BUILD_BUG_ON((offsetof(struct cpu_user_regs, spsr_el1)) & 0xf);
    BUILD_BUG_ON((offsetof(struct cpu_user_regs, lr)) & 0xf);
    BUILD_BUG_ON((sizeof (struct cpu_info)) & 0xf);
#else
    BUILD_BUG_ON((sizeof (struct cpu_user_regs)) & 0x7);
    BUILD_BUG_ON((offsetof(struct cpu_user_regs, sp_usr)) & 0x7);
    BUILD_BUG_ON((sizeof (struct cpu_info)) & 0x7);
#endif
}

/*
 * GUEST_BUG_ON is intended for checking that the guest state has not been
 * corrupted in hardware and/or that the hardware behaves as we
 * believe it should (i.e. that certain traps can only occur when the
 * guest is in a particular mode).
 *
 * The intention is to limit the damage such h/w bugs (or spec
 * misunderstandings) can do by turning them into Denial of Service
 * attacks instead of e.g. information leaks or privilege escalations.
 *
 * GUEST_BUG_ON *MUST* *NOT* be used to check for guest controllable state!
 *
 * Compared with regular BUG_ON it dumps the guest vcpu state instead
 * of Xen's state.
 */
#define guest_bug_on_failed(p)                          \
do {                                                    \
    show_execution_state(guest_cpu_user_regs());        \
    panic("Guest Bug: %pv: '%s', line %d, file %s\n",   \
          current, p, __LINE__, __FILE__);              \
} while (0)
#define GUEST_BUG_ON(p) \
    do { if ( unlikely(p) ) guest_bug_on_failed(#p); } while (0)

#ifdef CONFIG_ARM_32
static int debug_stack_lines = 20;
#define stack_words_per_line 8
#else
static int debug_stack_lines = 40;
#define stack_words_per_line 4
#endif

integer_param("debug_stack_lines", debug_stack_lines);

static enum {
	TRAP,
	NATIVE,
} vwfi;

static void __init parse_vwfi(const char *s)
{
	if ( !strcmp(s, "native") )
		vwfi = NATIVE;
	else
		vwfi = TRAP;
}
custom_param("vwfi", parse_vwfi);

void init_traps(void)
{
    /* Setup Hyp vector base */
    WRITE_SYSREG((vaddr_t)hyp_traps_vector, VBAR_EL2);

    /* Trap Debug and Performance Monitor accesses */
    WRITE_SYSREG(HDCR_TDRA|HDCR_TDOSA|HDCR_TDA|HDCR_TPM|HDCR_TPMCR,
                 MDCR_EL2);

    /* Trap CP15 c15 used for implementation defined registers */
    WRITE_SYSREG(HSTR_T(15), HSTR_EL2);

    /* Trap all coprocessor registers (0-13) except cp10 and
     * cp11 for VFP.
     *
     * /!\ All coprocessors except cp10 and cp11 cannot be used in Xen.
     *
     * On ARM64 the TCPx bits which we set here (0..9,12,13) are all
     * RES1, i.e. they would trap whether we did this write or not.
     */
    WRITE_SYSREG((HCPTR_CP_MASK & ~(HCPTR_CP(10) | HCPTR_CP(11))) | HCPTR_TTA,
                 CPTR_EL2);

    /* Setup hypervisor traps */
    WRITE_SYSREG(HCR_PTW|HCR_BSU_INNER|HCR_AMO|HCR_IMO|HCR_FMO|HCR_VM|
                 (vwfi != NATIVE ? (HCR_TWI|HCR_TWE) : 0) |
                 HCR_TSC|HCR_TAC|HCR_SWIO|HCR_TIDCP|HCR_FB,HCR_EL2);
    isb();
}

asmlinkage void __div0(void)
{
    printk("Division by zero in hypervisor.\n");
    BUG();
}

/* XXX could/should be common code */
static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];

    printk("----[ Xen-%d.%d%s  %s  debug=%c " gcov_string "  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
#ifdef CONFIG_ARM_32
           "arm32",
#else
           "arm64",
#endif
           debug_build() ? 'y' : 'n', print_tainted(taint_str));
}

#ifdef CONFIG_ARM_32
static inline bool_t is_zero_register(int reg)
{
    /* There is no zero register for ARM32 */
    return 0;
}
#else
static inline bool_t is_zero_register(int reg)
{
    /*
     * For store/load and sysreg instruction, the encoding 31 always
     * corresponds to {w,x}zr which is the zero register.
     */
    return (reg == 31);
}
#endif

/*
 * Returns a pointer to the given register value in regs, taking the
 * processor mode (CPSR) into account.
 *
 * Note that this function should not be used directly but via
 * {get,set}_user_reg.
 */
static register_t *select_user_reg(struct cpu_user_regs *regs, int reg)
{
    BUG_ON( !guest_mode(regs) );

#ifdef CONFIG_ARM_32
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
#else
    /*
     * On 64-bit the syndrome register contains the register index as
     * viewed in AArch64 state even if the trap was from AArch32 mode.
     */
    BUG_ON(is_zero_register(reg)); /* Cannot be {w,x}zr */
    return &regs->x0 + reg;
#endif
}

register_t get_user_reg(struct cpu_user_regs *regs, int reg)
{
    if ( is_zero_register(reg) )
        return 0;

    return *select_user_reg(regs, reg);
}

void set_user_reg(struct cpu_user_regs *regs, int reg, register_t value)
{
    if ( is_zero_register(reg) )
        return;

    *select_user_reg(regs, reg) = value;
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

    printk("PAR: %016"PRIx64": %s stage %d%s%s\n",
           par, msg,
           stage,
           second_in_first ? " during second stage lookup" : "",
           fsc_level_str(level));

    panic("Error during Hypervisor-to-physical address translation");
}

static void cpsr_switch_mode(struct cpu_user_regs *regs, int mode)
{
    uint32_t sctlr = READ_SYSREG32(SCTLR_EL1);

    regs->cpsr &= ~(PSR_MODE_MASK|PSR_IT_MASK|PSR_JAZELLE|PSR_BIG_ENDIAN|PSR_THUMB);

    regs->cpsr |= mode;
    regs->cpsr |= PSR_IRQ_MASK;
    if ( mode == PSR_MODE_ABT )
        regs->cpsr |= PSR_ABT_MASK;
    if ( sctlr & SCTLR_TE )
        regs->cpsr |= PSR_THUMB;
    if ( sctlr & SCTLR_EE )
        regs->cpsr |= PSR_BIG_ENDIAN;
}

static vaddr_t exception_handler32(vaddr_t offset)
{
    uint32_t sctlr = READ_SYSREG32(SCTLR_EL1);

    if (sctlr & SCTLR_V)
        return 0xffff0000 + offset;
    else /* always have security exceptions */
        return READ_SYSREG(VBAR_EL1) + offset;
}

/* Injects an Undefined Instruction exception into the current vcpu,
 * PC is the exact address of the faulting instruction (without
 * pipeline adjustments). See TakeUndefInstrException pseudocode in
 * ARM ARM.
 */
static void inject_undef32_exception(struct cpu_user_regs *regs)
{
    uint32_t spsr = regs->cpsr;
    int is_thumb = (regs->cpsr & PSR_THUMB);
    /* Saved PC points to the instruction past the faulting instruction. */
    uint32_t return_offset = is_thumb ? 2 : 4;

    BUG_ON( !is_32bit_domain(current->domain) );

    /* Update processor mode */
    cpsr_switch_mode(regs, PSR_MODE_UND);

    /* Update banked registers */
    regs->spsr_und = spsr;
    regs->lr_und = regs->pc32 + return_offset;

    /* Branch to exception vector */
    regs->pc32 = exception_handler32(VECTOR32_UND);
}

/* Injects an Abort exception into the current vcpu, PC is the exact
 * address of the faulting instruction (without pipeline
 * adjustments). See TakePrefetchAbortException and
 * TakeDataAbortException pseudocode in ARM ARM.
 */
static void inject_abt32_exception(struct cpu_user_regs *regs,
                                   int prefetch,
                                   register_t addr)
{
    uint32_t spsr = regs->cpsr;
    int is_thumb = (regs->cpsr & PSR_THUMB);
    /* Saved PC points to the instruction past the faulting instruction. */
    uint32_t return_offset = is_thumb ? 4 : 0;
    register_t fsr;

    BUG_ON( !is_32bit_domain(current->domain) );

    cpsr_switch_mode(regs, PSR_MODE_ABT);

    /* Update banked registers */
    regs->spsr_abt = spsr;
    regs->lr_abt = regs->pc32 + return_offset;

    regs->pc32 = exception_handler32(prefetch ? VECTOR32_PABT : VECTOR32_DABT);

    /* Inject a debug fault, best we can do right now */
    if ( READ_SYSREG(TCR_EL1) & TTBCR_EAE )
        fsr = FSR_LPAE | FSRL_STATUS_DEBUG;
    else
        fsr = FSRS_FS_DEBUG;

    if ( prefetch )
    {
        /* Set IFAR and IFSR */
#ifdef CONFIG_ARM_32
        WRITE_SYSREG(addr, IFAR);
        WRITE_SYSREG(fsr, IFSR);
#else
        /* FAR_EL1[63:32] is AArch32 register IFAR */
        register_t far = READ_SYSREG(FAR_EL1) & 0xffffffffUL;
        far |= addr << 32;
        WRITE_SYSREG(far, FAR_EL1);
        WRITE_SYSREG(fsr, IFSR32_EL2);
#endif
    }
    else
    {
#ifdef CONFIG_ARM_32
        /* Set DFAR and DFSR */
        WRITE_SYSREG(addr, DFAR);
        WRITE_SYSREG(fsr, DFSR);
#else
        /* FAR_EL1[31:0] is AArch32 register DFAR */
        register_t far = READ_SYSREG(FAR_EL1) & ~0xffffffffUL;
        far |= addr;
        WRITE_SYSREG(far, FAR_EL1);
        /* ESR_EL1 is AArch32 register DFSR */
        WRITE_SYSREG(fsr, ESR_EL1);
#endif
    }
}

static void inject_dabt32_exception(struct cpu_user_regs *regs,
                                    register_t addr)
{
    inject_abt32_exception(regs, 0, addr);
}

static void inject_pabt32_exception(struct cpu_user_regs *regs,
                                    register_t addr)
{
    inject_abt32_exception(regs, 1, addr);
}

#ifdef CONFIG_ARM_64
/*
 * Take care to call this while regs contains the original faulting
 * state and not the (partially constructed) exception state.
 */
static vaddr_t exception_handler64(struct cpu_user_regs *regs, vaddr_t offset)
{
    vaddr_t base = READ_SYSREG(VBAR_EL1);

    if ( usr_mode(regs) )
        base += VECTOR64_LOWER32_BASE;
    else if ( psr_mode(regs->cpsr,PSR_MODE_EL0t) )
        base += VECTOR64_LOWER64_BASE;
    else /* Otherwise must be from kernel mode */
        base += VECTOR64_CURRENT_SPx_BASE;

    return base + offset;
}

/* Inject an undefined exception into a 64 bit guest */
static void inject_undef64_exception(struct cpu_user_regs *regs, int instr_len)
{
    vaddr_t handler;
    const union hsr esr = {
        .iss = 0,
        .len = instr_len,
        .ec = HSR_EC_UNKNOWN,
    };

    BUG_ON( is_32bit_domain(current->domain) );

    handler = exception_handler64(regs, VECTOR64_SYNC_OFFSET);

    regs->spsr_el1 = regs->cpsr;
    regs->elr_el1 = regs->pc;

    regs->cpsr = PSR_MODE_EL1h | PSR_ABT_MASK | PSR_FIQ_MASK | \
        PSR_IRQ_MASK | PSR_DBG_MASK;
    regs->pc = handler;

    WRITE_SYSREG32(esr.bits, ESR_EL1);
}

/* Inject an abort exception into a 64 bit guest */
static void inject_abt64_exception(struct cpu_user_regs *regs,
                                   int prefetch,
                                   register_t addr,
                                   int instr_len)
{
    vaddr_t handler;
    union hsr esr = {
        .iss = 0,
        .len = instr_len,
    };

    if ( psr_mode_is_user(regs) )
        esr.ec = prefetch
            ? HSR_EC_INSTR_ABORT_LOWER_EL : HSR_EC_DATA_ABORT_LOWER_EL;
    else
        esr.ec = prefetch
            ? HSR_EC_INSTR_ABORT_CURR_EL : HSR_EC_DATA_ABORT_CURR_EL;

    BUG_ON( is_32bit_domain(current->domain) );

    handler = exception_handler64(regs, VECTOR64_SYNC_OFFSET);

    regs->spsr_el1 = regs->cpsr;
    regs->elr_el1 = regs->pc;

    regs->cpsr = PSR_MODE_EL1h | PSR_ABT_MASK | PSR_FIQ_MASK | \
        PSR_IRQ_MASK | PSR_DBG_MASK;
    regs->pc = handler;

    WRITE_SYSREG(addr, FAR_EL1);
    WRITE_SYSREG32(esr.bits, ESR_EL1);
}

static void inject_dabt64_exception(struct cpu_user_regs *regs,
                                   register_t addr,
                                   int instr_len)
{
    inject_abt64_exception(regs, 0, addr, instr_len);
}

static void inject_iabt64_exception(struct cpu_user_regs *regs,
                                   register_t addr,
                                   int instr_len)
{
    inject_abt64_exception(regs, 1, addr, instr_len);
}

#endif

static void inject_undef_exception(struct cpu_user_regs *regs,
                                   const union hsr hsr)
{
        if ( is_32bit_domain(current->domain) )
            inject_undef32_exception(regs);
#ifdef CONFIG_ARM_64
        else
            inject_undef64_exception(regs, hsr.len);
#endif
}

static void inject_iabt_exception(struct cpu_user_regs *regs,
                                  register_t addr,
                                  int instr_len)
{
        if ( is_32bit_domain(current->domain) )
            inject_pabt32_exception(regs, addr);
#ifdef CONFIG_ARM_64
        else
            inject_iabt64_exception(regs, addr, instr_len);
#endif
}

static void inject_dabt_exception(struct cpu_user_regs *regs,
                                  register_t addr,
                                  int instr_len)
{
        if ( is_32bit_domain(current->domain) )
            inject_dabt32_exception(regs, addr);
#ifdef CONFIG_ARM_64
        else
            inject_dabt64_exception(regs, addr, instr_len);
#endif
}

struct reg_ctxt {
    /* Guest-side state */
    uint32_t sctlr_el1;
    register_t tcr_el1;
    uint64_t ttbr0_el1, ttbr1_el1;
#ifdef CONFIG_ARM_32
    uint32_t dfsr, ifsr;
    uint32_t dfar, ifar;
#else
    uint32_t esr_el1;
    uint64_t far;
    uint32_t ifsr32_el2;
#endif

    /* Hypervisor-side state */
    uint64_t vttbr_el2;
};

static const char *mode_string(uint32_t cpsr)
{
    uint32_t mode;
    static const char *mode_strings[] = {
       [PSR_MODE_USR] = "32-bit Guest USR",
       [PSR_MODE_FIQ] = "32-bit Guest FIQ",
       [PSR_MODE_IRQ] = "32-bit Guest IRQ",
       [PSR_MODE_SVC] = "32-bit Guest SVC",
       [PSR_MODE_MON] = "32-bit Monitor",
       [PSR_MODE_ABT] = "32-bit Guest ABT",
       [PSR_MODE_HYP] = "Hypervisor",
       [PSR_MODE_UND] = "32-bit Guest UND",
       [PSR_MODE_SYS] = "32-bit Guest SYS",
#ifdef CONFIG_ARM_64
       [PSR_MODE_EL3h] = "64-bit EL3h (Monitor, handler)",
       [PSR_MODE_EL3t] = "64-bit EL3t (Monitor, thread)",
       [PSR_MODE_EL2h] = "64-bit EL2h (Hypervisor, handler)",
       [PSR_MODE_EL2t] = "64-bit EL2t (Hypervisor, thread)",
       [PSR_MODE_EL1h] = "64-bit EL1h (Guest Kernel, handler)",
       [PSR_MODE_EL1t] = "64-bit EL1t (Guest Kernel, thread)",
       [PSR_MODE_EL0t] = "64-bit EL0t (Guest User)",
#endif
    };
    mode = cpsr & PSR_MODE_MASK;

    if ( mode >= ARRAY_SIZE(mode_strings) )
        return "Unknown";
    return mode_strings[mode] ? : "Unknown";
}

static void show_registers_32(struct cpu_user_regs *regs,
                              struct reg_ctxt *ctxt,
                              int guest_mode,
                              const struct vcpu *v)
{

#ifdef CONFIG_ARM_64
    BUG_ON( ! (regs->cpsr & PSR_MODE_BIT) );
    printk("PC:     %08"PRIx32"\n", regs->pc32);
#else
    printk("PC:     %08"PRIx32, regs->pc);
    if ( !guest_mode )
        printk(" %pS", _p(regs->pc));
    printk("\n");
#endif
    printk("CPSR:   %08"PRIx32" MODE:%s\n", regs->cpsr,
           mode_string(regs->cpsr));
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
        printk("     SCTLR: %08"PRIx32"\n", ctxt->sctlr_el1);
        printk("       TCR: %08"PRIregister"\n", ctxt->tcr_el1);
        printk("     TTBR0: %016"PRIx64"\n", ctxt->ttbr0_el1);
        printk("     TTBR1: %016"PRIx64"\n", ctxt->ttbr1_el1);
        printk("      IFAR: %08"PRIx32", IFSR: %08"PRIx32"\n"
               "      DFAR: %08"PRIx32", DFSR: %08"PRIx32"\n",
#ifdef CONFIG_ARM_64
               (uint32_t)(ctxt->far >> 32),
               ctxt->ifsr32_el2,
               (uint32_t)(ctxt->far & 0xffffffff),
               ctxt->esr_el1
#else
               ctxt->ifar, ctxt->ifsr, ctxt->dfar, ctxt->dfsr
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

    BUG_ON( (regs->cpsr & PSR_MODE_BIT) );

    printk("PC:     %016"PRIx64, regs->pc);
    if ( !guest_mode )
        printk(" %pS", _p(regs->pc));
    printk("\n");
    printk("LR:     %016"PRIx64"\n", regs->lr);
    if ( guest_mode )
    {
        printk("SP_EL0: %016"PRIx64"\n", regs->sp_el0);
        printk("SP_EL1: %016"PRIx64"\n", regs->sp_el1);
    }
    else
    {
        printk("SP:     %016"PRIx64"\n", regs->sp);
    }
    printk("CPSR:   %08"PRIx32" MODE:%s\n", regs->cpsr,
           mode_string(regs->cpsr));
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
    printk("    X27: %016"PRIx64" X28: %016"PRIx64"  FP: %016"PRIx64"\n",
           regs->x27, regs->x28, regs->fp);
    printk("\n");

    if ( guest_mode )
    {
        printk("   ELR_EL1: %016"PRIx64"\n", regs->elr_el1);
        printk("   ESR_EL1: %08"PRIx32"\n", ctxt->esr_el1);
        printk("   FAR_EL1: %016"PRIx64"\n", ctxt->far);
        printk("\n");
        printk(" SCTLR_EL1: %08"PRIx32"\n", ctxt->sctlr_el1);
        printk("   TCR_EL1: %08"PRIregister"\n", ctxt->tcr_el1);
        printk(" TTBR0_EL1: %016"PRIx64"\n", ctxt->ttbr0_el1);
        printk(" TTBR1_EL1: %016"PRIx64"\n", ctxt->ttbr1_el1);
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
        if ( is_32bit_domain(v->domain) )
            show_registers_32(regs, ctxt, guest_mode, v);
#ifdef CONFIG_ARM_64
        else if ( is_64bit_domain(v->domain) )
        {
            if ( psr_mode_is_32bit(regs->cpsr) )
            {
                BUG_ON(!usr_mode(regs));
                show_registers_32(regs, ctxt, guest_mode, v);
            }
            else
            {
                show_registers_64(regs, ctxt, guest_mode, v);
            }
        }
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
    printk("  VTCR_EL2: %08"PRIx32"\n", READ_SYSREG32(VTCR_EL2));
    printk(" VTTBR_EL2: %016"PRIx64"\n", ctxt->vttbr_el2);
    printk("\n");

    printk(" SCTLR_EL2: %08"PRIx32"\n", READ_SYSREG32(SCTLR_EL2));
    printk("   HCR_EL2: %016"PRIregister"\n", READ_SYSREG(HCR_EL2));
    printk(" TTBR0_EL2: %016"PRIx64"\n", READ_SYSREG64(TTBR0_EL2));
    printk("\n");
    printk("   ESR_EL2: %08"PRIx32"\n", READ_SYSREG32(ESR_EL2));
    printk(" HPFAR_EL2: %016"PRIregister"\n", READ_SYSREG(HPFAR_EL2));

#ifdef CONFIG_ARM_32
    printk("     HDFAR: %08"PRIx32"\n", READ_CP32(HDFAR));
    printk("     HIFAR: %08"PRIx32"\n", READ_CP32(HIFAR));
#else
    printk("   FAR_EL2: %016"PRIx64"\n", READ_SYSREG64(FAR_EL2));
#endif
    printk("\n");
}

void show_registers(struct cpu_user_regs *regs)
{
    struct reg_ctxt ctxt;
    ctxt.sctlr_el1 = READ_SYSREG(SCTLR_EL1);
    ctxt.tcr_el1 = READ_SYSREG(TCR_EL1);
    ctxt.ttbr0_el1 = READ_SYSREG64(TTBR0_EL1);
    ctxt.ttbr1_el1 = READ_SYSREG64(TTBR1_EL1);
#ifdef CONFIG_ARM_32
    ctxt.dfar = READ_CP32(DFAR);
    ctxt.ifar = READ_CP32(IFAR);
    ctxt.dfsr = READ_CP32(DFSR);
    ctxt.ifsr = READ_CP32(IFSR);
#else
    ctxt.far = READ_SYSREG(FAR_EL1);
    ctxt.esr_el1 = READ_SYSREG(ESR_EL1);
    if ( guest_mode(regs) && is_32bit_domain(current->domain) )
        ctxt.ifsr32_el2 = READ_SYSREG(IFSR32_EL2);
#endif
    ctxt.vttbr_el2 = READ_SYSREG64(VTTBR_EL2);

    _show_registers(regs, &ctxt, guest_mode(regs), current);
}

void vcpu_show_registers(const struct vcpu *v)
{
    struct reg_ctxt ctxt;
    ctxt.sctlr_el1 = v->arch.sctlr;
    ctxt.tcr_el1 = v->arch.ttbcr;
    ctxt.ttbr0_el1 = v->arch.ttbr0;
    ctxt.ttbr1_el1 = v->arch.ttbr1;
#ifdef CONFIG_ARM_32
    ctxt.dfar = v->arch.dfar;
    ctxt.ifar = v->arch.ifar;
    ctxt.dfsr = v->arch.dfsr;
    ctxt.ifsr = v->arch.ifsr;
#else
    ctxt.far = v->arch.far;
    ctxt.esr_el1 = v->arch.esr;
    ctxt.ifsr32_el2 = v->arch.ifsr;
#endif

    ctxt.vttbr_el2 = v->domain->arch.p2m.vttbr;

    _show_registers(&v->arch.cpu_info->guest_cpu_user_regs, &ctxt, 1, v);
}

static void show_guest_stack(struct vcpu *v, struct cpu_user_regs *regs)
{
    int i;
    vaddr_t sp;
    struct page_info *page;
    void *mapped;
    unsigned long *stack, addr;

    if ( test_bit(_VPF_down, &v->pause_flags) )
    {
        printk("No stack trace, VCPU offline\n");
        return;
    }

    switch ( regs->cpsr & PSR_MODE_MASK )
    {
    case PSR_MODE_USR:
    case PSR_MODE_SYS:
#ifdef CONFIG_ARM_64
    case PSR_MODE_EL0t:
#endif
        printk("No stack trace for guest user-mode\n");
        return;

    case PSR_MODE_FIQ:
        sp = regs->sp_fiq;
        break;
    case PSR_MODE_IRQ:
        sp = regs->sp_irq;
        break;
    case PSR_MODE_SVC:
        sp = regs->sp_svc;
        break;
    case PSR_MODE_ABT:
        sp = regs->sp_abt;
        break;
    case PSR_MODE_UND:
        sp = regs->sp_und;
        break;

#ifdef CONFIG_ARM_64
    case PSR_MODE_EL1t:
        sp = regs->sp_el0;
        break;
    case PSR_MODE_EL1h:
        sp = regs->sp_el1;
        break;
#endif

    case PSR_MODE_HYP:
    case PSR_MODE_MON:
#ifdef CONFIG_ARM_64
    case PSR_MODE_EL3h:
    case PSR_MODE_EL3t:
    case PSR_MODE_EL2h:
    case PSR_MODE_EL2t:
#endif
    default:
        BUG();
        return;
    }

    printk("Guest stack trace from sp=%"PRIvaddr":\n  ", sp);

    if ( sp & ( sizeof(long) - 1 ) )
    {
        printk("Stack is misaligned\n");
        return;
    }

    page = get_page_from_gva(v, sp, GV2M_READ);
    if ( page == NULL )
    {
        printk("Failed to convert stack to physical address\n");
        return;
    }

    mapped = __map_domain_page(page);

    stack = mapped + (sp & ~PAGE_MASK);

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line); i++ )
    {
        if ( (((long)stack - 1) ^ ((long)(stack + 1) - 1)) & PAGE_SIZE )
            break;
        addr = *stack;
        if ( (i != 0) && ((i % stack_words_per_line) == 0) )
            printk("\n  ");
        printk(" %p", _p(addr));
        stack++;
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
    unmap_domain_page(mapped);
    put_page(page);
}

#define STACK_BEFORE_EXCEPTION(regs) ((register_t*)(regs)->sp)
#ifdef CONFIG_ARM_32
/* Frame pointer points to the return address:
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
#define STACK_FRAME_BASE(fp)       ((register_t*)(fp) - 1)
#else
/* Frame pointer points to the next frame:
 * (largest address)
 * | cpu_info
 * | [...]                                   |
 * | return addr                             |
 * | fp <-------------------------------, >--'
 * | [...]                              |
 * | return addr                        |
 * | fp <--------------------------, >--'
 * | [...]                         |
 * | return addr      <- regs->fp  |
 * | fp ---------------------------'
 * |
 * v (smallest address, sp)
 */
#define STACK_FRAME_BASE(fp)       ((register_t*)(fp))
#endif
static void show_trace(struct cpu_user_regs *regs)
{
    register_t *frame, next, addr, low, high;

    printk("Xen call trace:\n");

    printk("   [<%p>] %pS (PC)\n", _p(regs->pc), _p(regs->pc));
    printk("   [<%p>] %pS (LR)\n", _p(regs->lr), _p(regs->lr));

    /* Bounds for range of valid frame pointer. */
    low  = (register_t)(STACK_BEFORE_EXCEPTION(regs));
    high = (low & ~(STACK_SIZE - 1)) +
        (STACK_SIZE - sizeof(struct cpu_info));

    /* The initial frame pointer. */
    next = regs->fp;

    for ( ; ; )
    {
        if ( (next < low) || (next >= high) )
            break;

        /* Ordinary stack frame. */
        frame = STACK_FRAME_BASE(next);
        next  = frame[0];
        addr  = frame[1];

        printk("   [<%p>] %pS\n", _p(addr), _p(addr));

        low = (register_t)&frame[1];
    }

    printk("\n");
}

void show_stack(struct cpu_user_regs *regs)
{
    register_t *stack = STACK_BEFORE_EXCEPTION(regs), addr;
    int i;

    if ( guest_mode(regs) )
        return show_guest_stack(current, regs);

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
    if ( !psr_mode_is_user(&v->arch.cpu_info->guest_cpu_user_regs) )
        show_guest_stack(v, &v->arch.cpu_info->guest_cpu_user_regs);

    vcpu_unpause(v);
}

void do_unexpected_trap(const char *msg, struct cpu_user_regs *regs)
{
    printk("CPU%d: Unexpected Trap: %s\n", smp_processor_id(), msg);
    show_execution_state(regs);
    panic("CPU%d: Unexpected Trap: %s\n", smp_processor_id(), msg);
}

int do_bug_frame(struct cpu_user_regs *regs, vaddr_t pc)
{
    const struct bug_frame *bug = NULL;
    const char *prefix = "", *filename, *predicate;
    unsigned long fixup;
    int id = -1, lineno;
    const struct virtual_region *region;

    region = find_text_region(pc);
    if ( region )
    {
        for ( id = 0; id < BUGFRAME_NR; id++ )
        {
            const struct bug_frame *b;
            unsigned int i;

            for ( i = 0, b = region->frame[id].bugs;
                  i < region->frame[id].n_bugs; b++, i++ )
            {
                if ( ((vaddr_t)bug_loc(b)) == pc )
                {
                    bug = b;
                    goto found;
                }
            }
        }
    }
 found:
    if ( !bug )
        return -ENOENT;

    /* WARN, BUG or ASSERT: decode the filename pointer and line number. */
    filename = bug_file(bug);
    if ( !is_kernel(filename) )
        return -EINVAL;
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
        return 0;

    case BUGFRAME_bug:
        printk("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

        if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
            return 0;

        show_execution_state(regs);
        panic("Xen BUG at %s%s:%d", prefix, filename, lineno);

    case BUGFRAME_assert:
        /* ASSERT: decode the predicate string pointer. */
        predicate = bug_msg(bug);
        if ( !is_kernel(predicate) )
            predicate = "<unknown>";

        printk("Assertion '%s' failed at %s%s:%d\n",
               predicate, prefix, filename, lineno);
        if ( debugger_trap_fatal(TRAP_invalid_op, regs) )
            return 0;
        show_execution_state(regs);
        panic("Assertion '%s' failed at %s%s:%d",
              predicate, prefix, filename, lineno);
    }

    return -EINVAL;
}

#ifdef CONFIG_ARM_64
static void do_trap_brk(struct cpu_user_regs *regs, const union hsr hsr)
{
    /* HCR_EL2.TGE and MDCR_EL2.TDE are not set so we never receive
     * software breakpoint exception for EL1 and EL0 here.
     */
    BUG_ON(!hyp_mode(regs));

    switch (hsr.brk.comment)
    {
    case BRK_BUG_FRAME_IMM:
        if ( do_bug_frame(regs, regs->pc) )
            goto die;

        regs->pc += 4;

        break;

    default:
die:
        do_unexpected_trap("Undefined Breakpoint Value", regs);
    }
}
#endif

static register_t do_deprecated_hypercall(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    const register_t op =
#ifdef CONFIG_ARM_64
        !is_32bit_domain(current->domain) ?
            regs->x16
        :
#endif
            regs->r12;

    gdprintk(XENLOG_DEBUG, "%pv: deprecated hypercall %lu\n",
             current, (unsigned long)op);
    return -ENOSYS;
}

typedef register_t (*arm_hypercall_fn_t)(
    register_t, register_t, register_t, register_t, register_t);

typedef struct {
    arm_hypercall_fn_t fn;
    int nr_args;
} arm_hypercall_t;

#define HYPERCALL(_name, _nr_args)                                   \
    [ __HYPERVISOR_ ## _name ] =  {                                  \
        .fn = (arm_hypercall_fn_t) &do_ ## _name,                    \
        .nr_args = _nr_args,                                         \
    }

#define HYPERCALL_ARM(_name, _nr_args)                        \
    [ __HYPERVISOR_ ## _name ] =  {                                  \
        .fn = (arm_hypercall_fn_t) &do_arm_ ## _name,                \
        .nr_args = _nr_args,                                         \
    }
/*
 * Only use this for hypercalls which were deprecated (i.e. replaced
 * by something else) before Xen on ARM was created, i.e. *not* for
 * hypercalls which are simply not yet used on ARM.
 */
#define HYPERCALL_DEPRECATED(_name, _nr_args)                   \
    [ __HYPERVISOR_##_name ] = {                                \
        .fn = (arm_hypercall_fn_t) &do_deprecated_hypercall,    \
        .nr_args = _nr_args,                                    \
    }

static arm_hypercall_t arm_hypercall_table[] = {
    HYPERCALL(memory_op, 2),
    HYPERCALL(domctl, 1),
    HYPERCALL(sched_op, 2),
    HYPERCALL_DEPRECATED(sched_op_compat, 2),
    HYPERCALL(console_io, 3),
    HYPERCALL(xen_version, 2),
    HYPERCALL(xsm_op, 1),
    HYPERCALL(event_channel_op, 2),
    HYPERCALL_DEPRECATED(event_channel_op_compat, 1),
    HYPERCALL(physdev_op, 2),
    HYPERCALL_DEPRECATED(physdev_op_compat, 1),
    HYPERCALL(sysctl, 2),
    HYPERCALL(hvm_op, 2),
    HYPERCALL(grant_table_op, 3),
    HYPERCALL(multicall, 2),
    HYPERCALL(platform_op, 1),
    HYPERCALL_ARM(vcpu_op, 3),
    HYPERCALL(vm_assist, 2),
};

#ifndef NDEBUG
static void do_debug_trap(struct cpu_user_regs *regs, unsigned int code)
{
    uint32_t reg;
    uint32_t domid = current->domain->domain_id;
    switch ( code ) {
    case 0xe0 ... 0xef:
        reg = code - 0xe0;
        printk("DOM%d: R%d = 0x%"PRIregister" at 0x%"PRIvaddr"\n",
               domid, reg, get_user_reg(regs, reg), regs->pc);
        break;
    case 0xfd:
        printk("DOM%d: Reached %"PRIvaddr"\n", domid, regs->pc);
        break;
    case 0xfe:
        printk("%c", (char)(get_user_reg(regs, 0) & 0xff));
        break;
    case 0xff:
        printk("DOM%d: DEBUG\n", domid);
        show_execution_state(regs);
        break;
    default:
        panic("DOM%d: Unhandled debug trap %#x", domid, code);
        break;
    }
}
#endif

#ifdef CONFIG_ARM_64
#define PSCI_RESULT_REG(reg) (reg)->x0
#define PSCI_ARG(reg,n) (reg)->x##n
#define PSCI_ARG32(reg,n) (uint32_t)( (reg)->x##n & 0x00000000FFFFFFFF )
#else
#define PSCI_RESULT_REG(reg) (reg)->r0
#define PSCI_ARG(reg,n) (reg)->r##n
#define PSCI_ARG32(reg,n) PSCI_ARG(reg,n)
#endif

/* helper function for checking arm mode 32/64 bit */
static inline int psci_mode_check(struct domain *d, register_t fid)
{
        return !( is_64bit_domain(d)^( (fid & PSCI_0_2_64BIT) >> 30 ) );
}

static void do_trap_psci(struct cpu_user_regs *regs)
{
    register_t fid = PSCI_ARG(regs,0);

    /* preloading in case psci_mode_check fails */
    PSCI_RESULT_REG(regs) = PSCI_INVALID_PARAMETERS;
    switch( fid )
    {
    case PSCI_cpu_off:
        {
            uint32_t pstate = PSCI_ARG32(regs,1);
            perfc_incr(vpsci_cpu_off);
            PSCI_RESULT_REG(regs) = do_psci_cpu_off(pstate);
        }
        break;
    case PSCI_cpu_on:
        {
            uint32_t vcpuid = PSCI_ARG32(regs,1);
            register_t epoint = PSCI_ARG(regs,2);
            perfc_incr(vpsci_cpu_on);
            PSCI_RESULT_REG(regs) = do_psci_cpu_on(vcpuid, epoint);
        }
        break;
    case PSCI_0_2_FN_PSCI_VERSION:
        perfc_incr(vpsci_version);
        PSCI_RESULT_REG(regs) = do_psci_0_2_version();
        break;
    case PSCI_0_2_FN_CPU_OFF:
        perfc_incr(vpsci_cpu_off);
        PSCI_RESULT_REG(regs) = do_psci_0_2_cpu_off();
        break;
    case PSCI_0_2_FN_MIGRATE_INFO_TYPE:
        perfc_incr(vpsci_migrate_info_type);
        PSCI_RESULT_REG(regs) = do_psci_0_2_migrate_info_type();
        break;
    case PSCI_0_2_FN_MIGRATE_INFO_UP_CPU:
    case PSCI_0_2_FN64_MIGRATE_INFO_UP_CPU:
        perfc_incr(vpsci_migrate_info_up_cpu);
        if ( psci_mode_check(current->domain, fid) )
            PSCI_RESULT_REG(regs) = do_psci_0_2_migrate_info_up_cpu();
        break;
    case PSCI_0_2_FN_SYSTEM_OFF:
        perfc_incr(vpsci_system_off);
        do_psci_0_2_system_off();
        PSCI_RESULT_REG(regs) = PSCI_INTERNAL_FAILURE;
        break;
    case PSCI_0_2_FN_SYSTEM_RESET:
        perfc_incr(vpsci_system_reset);
        do_psci_0_2_system_reset();
        PSCI_RESULT_REG(regs) = PSCI_INTERNAL_FAILURE;
        break;
    case PSCI_0_2_FN_CPU_ON:
    case PSCI_0_2_FN64_CPU_ON:
        perfc_incr(vpsci_cpu_on);
        if ( psci_mode_check(current->domain, fid) )
        {
            register_t vcpuid = PSCI_ARG(regs,1);
            register_t epoint = PSCI_ARG(regs,2);
            register_t cid = PSCI_ARG(regs,3);
            PSCI_RESULT_REG(regs) =
                do_psci_0_2_cpu_on(vcpuid, epoint, cid);
        }
        break;
    case PSCI_0_2_FN_CPU_SUSPEND:
    case PSCI_0_2_FN64_CPU_SUSPEND:
        perfc_incr(vpsci_cpu_suspend);
        if ( psci_mode_check(current->domain, fid) )
        {
            uint32_t pstate = PSCI_ARG32(regs,1);
            register_t epoint = PSCI_ARG(regs,2);
            register_t cid = PSCI_ARG(regs,3);
            PSCI_RESULT_REG(regs) =
                do_psci_0_2_cpu_suspend(pstate, epoint, cid);
        }
        break;
    case PSCI_0_2_FN_AFFINITY_INFO:
    case PSCI_0_2_FN64_AFFINITY_INFO:
        perfc_incr(vpsci_cpu_affinity_info);
        if ( psci_mode_check(current->domain, fid) )
        {
            register_t taff = PSCI_ARG(regs,1);
            uint32_t laff = PSCI_ARG32(regs,2);
            PSCI_RESULT_REG(regs) =
                do_psci_0_2_affinity_info(taff, laff);
        }
        break;
    case PSCI_0_2_FN_MIGRATE:
    case PSCI_0_2_FN64_MIGRATE:
        perfc_incr(vpsci_cpu_migrate);
        if ( psci_mode_check(current->domain, fid) )
        {
            uint32_t tcpu = PSCI_ARG32(regs,1);
            PSCI_RESULT_REG(regs) = do_psci_0_2_migrate(tcpu);
        }
        break;
    default:
        domain_crash_synchronous();
        return;
    }
}

#ifdef CONFIG_ARM_64
#define HYPERCALL_RESULT_REG(r) (r)->x0
#define HYPERCALL_ARG1(r) (r)->x0
#define HYPERCALL_ARG2(r) (r)->x1
#define HYPERCALL_ARG3(r) (r)->x2
#define HYPERCALL_ARG4(r) (r)->x3
#define HYPERCALL_ARG5(r) (r)->x4
#define HYPERCALL_ARGS(r) (r)->x0, (r)->x1, (r)->x2, (r)->x3, (r)->x4
#else
#define HYPERCALL_RESULT_REG(r) (r)->r0
#define HYPERCALL_ARG1(r) (r)->r0
#define HYPERCALL_ARG2(r) (r)->r1
#define HYPERCALL_ARG3(r) (r)->r2
#define HYPERCALL_ARG4(r) (r)->r3
#define HYPERCALL_ARG5(r) (r)->r4
#define HYPERCALL_ARGS(r) (r)->r0, (r)->r1, (r)->r2, (r)->r3, (r)->r4
#endif

static void do_trap_hypercall(struct cpu_user_regs *regs, register_t *nr,
                              unsigned long iss)
{
    arm_hypercall_fn_t call = NULL;
#ifndef NDEBUG
    register_t orig_pc = regs->pc;
#endif

    BUILD_BUG_ON(NR_hypercalls < ARRAY_SIZE(arm_hypercall_table) );

    if ( iss != XEN_HYPERCALL_TAG )
        domain_crash_synchronous();

    if ( *nr >= ARRAY_SIZE(arm_hypercall_table) )
    {
        perfc_incr(invalid_hypercalls);
        HYPERCALL_RESULT_REG(regs) = -ENOSYS;
        return;
    }

    perfc_incra(hypercalls, *nr);
    call = arm_hypercall_table[*nr].fn;
    if ( call == NULL )
    {
        HYPERCALL_RESULT_REG(regs) = -ENOSYS;
        return;
    }

    HYPERCALL_RESULT_REG(regs) = call(HYPERCALL_ARGS(regs));

#ifndef NDEBUG
    /*
     * Clobber argument registers only if pc is unchanged, otherwise
     * this is a hypercall continuation.
     */
    if ( orig_pc == regs->pc )
    {
        switch ( arm_hypercall_table[*nr].nr_args ) {
        case 5: HYPERCALL_ARG5(regs) = 0xDEADBEEF;
        case 4: HYPERCALL_ARG4(regs) = 0xDEADBEEF;
        case 3: HYPERCALL_ARG3(regs) = 0xDEADBEEF;
        case 2: HYPERCALL_ARG2(regs) = 0xDEADBEEF;
        case 1: /* Don't clobber x0/r0 -- it's the return value */
            break;
        default: BUG();
        }
        *nr = 0xDEADBEEF;
    }
#endif
}

static bool_t check_multicall_32bit_clean(struct multicall_entry *multi)
{
    int i;

    for ( i = 0; i < arm_hypercall_table[multi->op].nr_args; i++ )
    {
        if ( unlikely(multi->args[i] & 0xffffffff00000000ULL) )
        {
            printk("%pv: multicall argument %d is not 32-bit clean %"PRIx64"\n",
                   current, i, multi->args[i]);
            domain_crash(current->domain);
            return false;
        }
    }

    return true;
}

void arch_do_multicall_call(struct mc_state *state)
{
    struct multicall_entry *multi = &state->call;
    arm_hypercall_fn_t call = NULL;

    if ( multi->op >= ARRAY_SIZE(arm_hypercall_table) )
    {
        multi->result = -ENOSYS;
        return;
    }

    call = arm_hypercall_table[multi->op].fn;
    if ( call == NULL )
    {
        multi->result = -ENOSYS;
        return;
    }

    if ( is_32bit_domain(current->domain) &&
         !check_multicall_32bit_clean(multi) )
        return;

    multi->result = call(multi->args[0], multi->args[1],
                         multi->args[2], multi->args[3],
                         multi->args[4]);
}

/*
 * stolen from arch/arm/kernel/opcodes.c
 *
 * condition code lookup table
 * index into the table is test code: EQ, NE, ... LT, GT, AL, NV
 *
 * bit position in short is condition code: NZCV
 */
static const unsigned short cc_map[16] = {
        0xF0F0,                 /* EQ == Z set            */
        0x0F0F,                 /* NE                     */
        0xCCCC,                 /* CS == C set            */
        0x3333,                 /* CC                     */
        0xFF00,                 /* MI == N set            */
        0x00FF,                 /* PL                     */
        0xAAAA,                 /* VS == V set            */
        0x5555,                 /* VC                     */
        0x0C0C,                 /* HI == C set && Z clear */
        0xF3F3,                 /* LS == C clear || Z set */
        0xAA55,                 /* GE == (N==V)           */
        0x55AA,                 /* LT == (N!=V)           */
        0x0A05,                 /* GT == (!Z && (N==V))   */
        0xF5FA,                 /* LE == (Z || (N!=V))    */
        0xFFFF,                 /* AL always              */
        0                       /* NV                     */
};

static int check_conditional_instr(struct cpu_user_regs *regs,
                                   const union hsr hsr)
{
    unsigned long cpsr, cpsr_cond;
    int cond;

    /* Unconditional Exception classes */
    if ( hsr.ec >= 0x10 )
        return 1;

    /* Check for valid condition in hsr */
    cond = hsr.cond.ccvalid ? hsr.cond.cc : -1;

    /* Unconditional instruction */
    if ( cond == 0xe )
        return 1;

    cpsr = regs->cpsr;

    /* If cc is not valid then we need to examine the IT state */
    if ( cond < 0 )
    {
        unsigned long it;

        BUG_ON( !psr_mode_is_32bit(regs->cpsr) || !(cpsr&PSR_THUMB) );

        it = ( (cpsr >> (10-2)) & 0xfc) | ((cpsr >> 25) & 0x3 );

        /* it == 0 => unconditional. */
        if ( it == 0 )
            return 1;

        /* The cond for this instruction works out as the top 4 bits. */
        cond = ( it >> 4 );
    }

    cpsr_cond = cpsr >> 28;

    if ( !((cc_map[cond] >> cpsr_cond) & 1) )
    {
        perfc_incr(trap_uncond);
        return 0;
    }
    return 1;
}

static void advance_pc(struct cpu_user_regs *regs, const union hsr hsr)
{
    unsigned long itbits, cond, cpsr = regs->cpsr;

    /* PSR_IT_MASK bits can only be set for 32-bit processors in Thumb mode. */
    BUG_ON( (!psr_mode_is_32bit(cpsr)||!(cpsr&PSR_THUMB))
            && (cpsr&PSR_IT_MASK) );

    if ( cpsr&PSR_IT_MASK )
    {
        /* The ITSTATE[7:0] block is contained in CPSR[15:10],CPSR[26:25]
         *
         * ITSTATE[7:5] are the condition code
         * ITSTATE[4:0] are the IT bits
         *
         * If the condition is non-zero then the IT state machine is
         * advanced by shifting the IT bits left.
         *
         * See A2-51 and B1-1148 of DDI 0406C.b.
         */
        cond = (cpsr & 0xe000) >> 13;
        itbits = (cpsr & 0x1c00) >> (10 - 2);
        itbits |= (cpsr & (0x3 << 25)) >> 25;

        if ( (itbits & 0x7) == 0 )
            itbits = cond = 0;
        else
            itbits = (itbits << 1) & 0x1f;

        cpsr &= ~PSR_IT_MASK;
        cpsr |= cond << 13;
        cpsr |= (itbits & 0x1c) << (10 - 2);
        cpsr |= (itbits & 0x3) << 25;

        regs->cpsr = cpsr;
    }

    regs->pc += hsr.len ? 4 : 2;
}

/* Read as zero and write ignore */
static void handle_raz_wi(struct cpu_user_regs *regs,
                          int regidx,
                          bool_t read,
                          const union hsr hsr,
                          int min_el)
{
    ASSERT((min_el == 0) || (min_el == 1));

    if ( min_el > 0 && psr_mode_is_user(regs) )
        return inject_undef_exception(regs, hsr);

    if ( read )
        set_user_reg(regs, regidx, 0);
    /* else: write ignored */

    advance_pc(regs, hsr);
}

/* Write only as write ignore */
static void handle_wo_wi(struct cpu_user_regs *regs,
                         int regidx,
                         bool_t read,
                         const union hsr hsr,
                         int min_el)
{
    ASSERT((min_el == 0) || (min_el == 1));

    if ( min_el > 0 && psr_mode_is_user(regs) )
        return inject_undef_exception(regs, hsr);

    if ( read )
        return inject_undef_exception(regs, hsr);
    /* else: ignore */

    advance_pc(regs, hsr);
}

/* Read only as read as zero */
static void handle_ro_raz(struct cpu_user_regs *regs,
                          int regidx,
                          bool_t read,
                          const union hsr hsr,
                          int min_el)
{
    ASSERT((min_el == 0) || (min_el == 1));

    if ( min_el > 0 && psr_mode_is_user(regs) )
        return inject_undef_exception(regs, hsr);

    if ( !read )
        return inject_undef_exception(regs, hsr);
    /* else: raz */

    set_user_reg(regs, regidx, 0);

    advance_pc(regs, hsr);
}

static void do_cp15_32(struct cpu_user_regs *regs,
                       const union hsr hsr)
{
    const struct hsr_cp32 cp32 = hsr.cp32;
    int regidx = cp32.reg;
    struct vcpu *v = current;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    /*
     * !CNTHCTL_EL2.EL1PCEN / !CNTHCTL.PL1PCEN
     *
     * ARMv7 (DDI 0406C.b): B4.1.22
     * ARMv8 (DDI 0487A.d): D1-1510 Table D1-60
     */
    case HSR_CPREG32(CNTP_CTL):
    case HSR_CPREG32(CNTP_TVAL):
        if ( !vtimer_emulate(regs, hsr) )
            return inject_undef_exception(regs, hsr);
        break;

    /*
     * HCR_EL2.TACR / HCR.TAC
     *
     * ARMv7 (DDI 0406C.b): B1.14.6
     * ARMv8 (DDI 0487A.d): G6.2.1
     */
    case HSR_CPREG32(ACTLR):
        if ( psr_mode_is_user(regs) )
            return inject_undef_exception(regs, hsr);
        if ( cp32.read )
            set_user_reg(regs, regidx, v->arch.actlr);
        break;

    /*
     * MDCR_EL2.TPM
     *
     * ARMv7 (DDI 0406C.b): B1.14.17
     * ARMv8 (DDI 0487A.d): D1-1511 Table D1-61
     *
     * Unhandled:
     *    PMEVCNTR<n>
     *    PMEVTYPER<n>
     *    PMCCFILTR
     *
     * MDCR_EL2.TPMCR
     *
     * ARMv7 (DDI 0406C.b): B1.14.17
     * ARMv8 (DDI 0487A.d): D1-1511 Table D1-62
     *
     * NB: Both MDCR_EL2.TPM and MDCR_EL2.TPMCR cause trapping of PMCR.
     */
    /* We could trap ID_DFR0 and tell the guest we don't support
     * performance monitoring, but Linux doesn't check the ID_DFR0.
     * Therefore it will read PMCR.
     *
     * We tell the guest we have 0 counters. Unfortunately we must
     * always support PMCCNTR (the cyle counter): we just RAZ/WI for all
     * PM register, which doesn't crash the kernel at least
     */
    case HSR_CPREG32(PMUSERENR):
        /* RO at EL0. RAZ/WI at EL1 */
        if ( psr_mode_is_user(regs) )
            return handle_ro_raz(regs, regidx, cp32.read, hsr, 0);
        else
            return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);
    case HSR_CPREG32(PMINTENSET):
    case HSR_CPREG32(PMINTENCLR):
        /* EL1 only, however MDCR_EL2.TPM==1 means EL0 may trap here also. */
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);
    case HSR_CPREG32(PMCR):
    case HSR_CPREG32(PMCNTENSET):
    case HSR_CPREG32(PMCNTENCLR):
    case HSR_CPREG32(PMOVSR):
    case HSR_CPREG32(PMSWINC):
    case HSR_CPREG32(PMSELR):
    case HSR_CPREG32(PMCEID0):
    case HSR_CPREG32(PMCEID1):
    case HSR_CPREG32(PMCCNTR):
    case HSR_CPREG32(PMXEVTYPER):
    case HSR_CPREG32(PMXEVCNTR):
    case HSR_CPREG32(PMOVSSET):
        /*
         * Accessible at EL0 only if PMUSERENR_EL0.EN is set. We
         * emulate that register as 0 above.
         */
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);

    /*
     * HCR_EL2.TIDCP
     *
     * ARMv7 (DDI 0406C.b): B1.14.3
     * ARMv8 (DDI 0487A.d): D1-1501 Table D1-43
     *
     *  - CRn==c9, opc1=={0-7}, CRm=={c0-c2, c5-c8}, opc2=={0-7}
     *    (Cache and TCM lockdown registers)
     *  - CRn==c10, opc1=={0-7}, CRm=={c0, c1, c4, c8}, opc2=={0-7}
     *    (VMSA CP15 c10 registers)
     *  - CRn==c11, opc1=={0-7}, CRm=={c0-c8, c15}, opc2=={0-7}
     *    (VMSA CP15 c11 registers)
     *
     * CPTR_EL2.T{0..9,12..13}
     *
     * ARMv7 (DDI 0406C.b): B1.14.12
     * ARMv8 (DDI 0487A.d): N/A
     *
     *  - All accesses to coprocessors 0..9 and 12..13
     *
     * HSTR_EL2.T15
     *
     * ARMv7 (DDI 0406C.b): B1.14.14
     * ARMv8 (DDI 0487A.d): D1-1507 Table D1-55
     *
     *  - All accesses to cp15, c15 registers.
     *
     * And all other unknown registers.
     */
    default:
        gdprintk(XENLOG_ERR,
                 "%s p15, %d, r%d, cr%d, cr%d, %d @ 0x%"PRIregister"\n",
                 cp32.read ? "mrc" : "mcr",
                 cp32.op1, cp32.reg, cp32.crn, cp32.crm, cp32.op2, regs->pc);
        gdprintk(XENLOG_ERR, "unhandled 32-bit CP15 access %#x\n",
                 hsr.bits & HSR_CP32_REGS_MASK);
        inject_undef_exception(regs, hsr);
        return;
    }
    advance_pc(regs, hsr);
}

static void do_cp15_64(struct cpu_user_regs *regs,
                       const union hsr hsr)
{
    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    switch ( hsr.bits & HSR_CP64_REGS_MASK )
    {
    /*
     * !CNTHCTL_EL2.EL1PCEN / !CNTHCTL.PL1PCEN
     *
     * ARMv7 (DDI 0406C.b): B4.1.22
     * ARMv8 (DDI 0487A.d): D1-1510 Table D1-60
     */
    case HSR_CPREG64(CNTP_CVAL):
        if ( !vtimer_emulate(regs, hsr) )
            return inject_undef_exception(regs, hsr);
        break;

    /*
     * CPTR_EL2.T{0..9,12..13}
     *
     * ARMv7 (DDI 0406C.b): B1.14.12
     * ARMv8 (DDI 0487A.d): N/A
     *
     *  - All accesses to coprocessors 0..9 and 12..13
     *
     * HSTR_EL2.T15
     *
     * ARMv7 (DDI 0406C.b): B1.14.14
     * ARMv8 (DDI 0487A.d): D1-1507 Table D1-55
     *
     *  - All accesses to cp15, c15 registers.
     *
     * And all other unknown registers.
     */
    default:
        {
            const struct hsr_cp64 cp64 = hsr.cp64;

            gdprintk(XENLOG_ERR,
                     "%s p15, %d, r%d, r%d, cr%d @ 0x%"PRIregister"\n",
                     cp64.read ? "mrrc" : "mcrr",
                     cp64.op1, cp64.reg1, cp64.reg2, cp64.crm, regs->pc);
            gdprintk(XENLOG_ERR, "unhandled 64-bit CP15 access %#x\n",
                     hsr.bits & HSR_CP64_REGS_MASK);
            inject_undef_exception(regs, hsr);
            return;
        }
    }
    advance_pc(regs, hsr);
}

static void do_cp14_32(struct cpu_user_regs *regs, const union hsr hsr)
{
    const struct hsr_cp32 cp32 = hsr.cp32;
    int regidx = cp32.reg;
    struct domain *d = current->domain;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    /*
     * MDCR_EL2.TDOSA
     *
     * ARMv7 (DDI 0406C.b): B1.14.15
     * ARMv8 (DDI 0487A.d): D1-1509 Table D1-58
     *
     * Unhandled:
     *    DBGOSLSR
     *    DBGPRCR
     */
    case HSR_CPREG32(DBGOSLAR):
        return handle_wo_wi(regs, regidx, cp32.read, hsr, 1);
    case HSR_CPREG32(DBGOSDLR):
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);

    /*
     * MDCR_EL2.TDA
     *
     * ARMv7 (DDI 0406C.b): B1.14.15
     * ARMv8 (DDI 0487A.d): D1-1510 Table D1-59
     *
     * Unhandled:
     *    DBGDCCINT
     *    DBGDTRRXint
     *    DBGDTRTXint
     *    DBGWFAR
     *    DBGDTRTXext
     *    DBGDTRRXext,
     *    DBGBXVR<n>
     *    DBGCLAIMSET
     *    DBGCLAIMCLR
     *    DBGAUTHSTATUS
     *    DBGDEVID
     *    DBGDEVID1
     *    DBGDEVID2
     *    DBGOSECCR
     */
    case HSR_CPREG32(DBGDIDR):
    {
        uint32_t val;

        /*
         * Read-only register. Accessible by EL0 if DBGDSCRext.UDCCdis
         * is set to 0, which we emulated below.
         */
        if ( !cp32.read )
            return inject_undef_exception(regs, hsr);

        /* Implement the minimum requirements:
         *  - Number of watchpoints: 1
         *  - Number of breakpoints: 2
         *  - Version: ARMv7 v7.1
         *  - Variant and Revision bits match MDIR
         */
        val = (1 << 24) | (5 << 16);
        val |= ((d->arch.vpidr >> 20) & 0xf) | (d->arch.vpidr & 0xf);
        set_user_reg(regs, regidx, val);

        break;
    }

    case HSR_CPREG32(DBGDSCRINT):
        /*
         * Read-only register. Accessible by EL0 if DBGDSCRext.UDCCdis
         * is set to 0, which we emulated below.
         */
        return handle_ro_raz(regs, regidx, cp32.read, hsr, 1);

    case HSR_CPREG32(DBGDSCREXT):
        /*
         * Implement debug status and control register as RAZ/WI.
         * The OS won't use Hardware debug if MDBGen not set.
         */
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);

    case HSR_CPREG32(DBGVCR):
    case HSR_CPREG32(DBGBVR0):
    case HSR_CPREG32(DBGBCR0):
    case HSR_CPREG32(DBGWVR0):
    case HSR_CPREG32(DBGWCR0):
    case HSR_CPREG32(DBGBVR1):
    case HSR_CPREG32(DBGBCR1):
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);

    /*
     * CPTR_EL2.TTA
     *
     * ARMv7 (DDI 0406C.b): B1.14.16
     * ARMv8 (DDI 0487A.d): D1-1507 Table D1-54
     *
     *  - All implemented trace registers.
     *
     * MDCR_EL2.TDRA
     *
     * ARMv7 (DDI 0406C.b): B1.14.15
     * ARMv8 (DDI 0487A.d): D1-1508 Table D1-57
     *
     * Unhandled:
     *    DBGDRAR (32-bit accesses)
     *    DBGDSAR (32-bit accesses)
     *
     * And all other unknown registers.
     */
    default:
        gdprintk(XENLOG_ERR,
                 "%s p14, %d, r%d, cr%d, cr%d, %d @ 0x%"PRIregister"\n",
                  cp32.read ? "mrc" : "mcr",
                  cp32.op1, cp32.reg, cp32.crn, cp32.crm, cp32.op2, regs->pc);
        gdprintk(XENLOG_ERR, "unhandled 32-bit cp14 access %#x\n",
                 hsr.bits & HSR_CP32_REGS_MASK);
        inject_undef_exception(regs, hsr);
        return;
    }

    advance_pc(regs, hsr);
}

static void do_cp14_64(struct cpu_user_regs *regs, const union hsr hsr)
{
    const struct hsr_cp64 cp64 = hsr.cp64;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    /*
     * CPTR_EL2.TTA
     *
     * ARMv7 (DDI 0406C.b): B1.14.16
     * ARMv8 (DDI 0487A.d): D1-1507 Table D1-54
     *
     *  - All implemented trace registers.
     *
     * MDCR_EL2.TDRA
     *
     * ARMv7 (DDI 0406C.b): B1.14.15
     * ARMv8 (DDI 0487A.d): D1-1508 Table D1-57
     *
     * Unhandled:
     *    DBGDRAR (64-bit accesses)
     *    DBGDSAR (64-bit accesses)
     *
     * And all other unknown registers.
     */
    gdprintk(XENLOG_ERR,
             "%s p14, %d, r%d, r%d, cr%d @ 0x%"PRIregister"\n",
             cp64.read ? "mrrc" : "mcrr",
             cp64.op1, cp64.reg1, cp64.reg2, cp64.crm, regs->pc);
    gdprintk(XENLOG_ERR, "unhandled 64-bit CP14 access %#x\n",
             hsr.bits & HSR_CP64_REGS_MASK);
    inject_undef_exception(regs, hsr);
}

static void do_cp14_dbg(struct cpu_user_regs *regs, const union hsr hsr)
{
    struct hsr_cp64 cp64 = hsr.cp64;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    /*
     * MDCR_EL2.TDOSA
     *
     * ARMv7 (DDI 0406C.b): B1.14.15
     * ARMv8 (DDI 0487A.d): D1-1509 Table D1-58
     *
     * Unhandled:
     *    DBGDTRTXint
     *    DBGDTRRXint
     *
     * And all other unknown registers.
     */
    gdprintk(XENLOG_ERR,
             "%s p14, %d, r%d, r%d, cr%d @ 0x%"PRIregister"\n",
             cp64.read ? "mrrc" : "mcrr",
             cp64.op1, cp64.reg1, cp64.reg2, cp64.crm, regs->pc);
    gdprintk(XENLOG_ERR, "unhandled 64-bit CP14 DBG access %#x\n",
             hsr.bits & HSR_CP64_REGS_MASK);

    inject_undef_exception(regs, hsr);
}

static void do_cp(struct cpu_user_regs *regs, const union hsr hsr)
{
    const struct hsr_cp cp = hsr.cp;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    ASSERT(!cp.tas); /* We don't trap SIMD instruction */
    gdprintk(XENLOG_ERR, "unhandled CP%d access\n", cp.coproc);
    inject_undef_exception(regs, hsr);
}

#ifdef CONFIG_ARM_64
static void do_sysreg(struct cpu_user_regs *regs,
                      const union hsr hsr)
{
    int regidx = hsr.sysreg.reg;
    struct vcpu *v = current;

    switch ( hsr.bits & HSR_SYSREG_REGS_MASK )
    {
    /*
     * HCR_EL2.TACR
     *
     * ARMv8 (DDI 0487A.d): D7.2.1
     */
    case HSR_SYSREG_ACTLR_EL1:
        if ( psr_mode_is_user(regs) )
            return inject_undef_exception(regs, hsr);
        if ( hsr.sysreg.read )
            set_user_reg(regs, regidx, v->arch.actlr);
        break;

    /*
     * MDCR_EL2.TDRA
     *
     * ARMv8 (DDI 0487A.d): D1-1508 Table D1-57
     */
    case HSR_SYSREG_MDRAR_EL1:
        return handle_ro_raz(regs, regidx, hsr.sysreg.read, hsr, 1);

    /*
     * MDCR_EL2.TDOSA
     *
     * ARMv8 (DDI 0487A.d): D1-1509 Table D1-58
     *
     * Unhandled:
     *    OSLSR_EL1
     *    DBGPRCR_EL1
     */
    case HSR_SYSREG_OSLAR_EL1:
        return handle_wo_wi(regs, regidx, hsr.sysreg.read, hsr, 1);
    case HSR_SYSREG_OSDLR_EL1:
        return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);

    /*
     * MDCR_EL2.TDA
     *
     * ARMv8 (DDI 0487A.d): D1-1510 Table D1-59
     *
     * Unhandled:
     *    MDCCINT_EL1
     *    DBGDTR_EL0
     *    DBGDTRRX_EL0
     *    DBGDTRTX_EL0
     *    OSDTRRX_EL1
     *    OSDTRTX_EL1
     *    OSECCR_EL1
     *    DBGCLAIMSET_EL1
     *    DBGCLAIMCLR_EL1
     *    DBGAUTHSTATUS_EL1
     */
    case HSR_SYSREG_MDSCR_EL1:
        return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);
    case HSR_SYSREG_MDCCSR_EL0:
        /*
         * Accessible at EL0 only if MDSCR_EL1.TDCC is set to 0. We emulate that
         * register as RAZ/WI above. So RO at both EL0 and EL1.
         */
        return handle_ro_raz(regs, regidx, hsr.sysreg.read, hsr, 0);
    HSR_SYSREG_DBG_CASES(DBGBVR):
    HSR_SYSREG_DBG_CASES(DBGBCR):
    HSR_SYSREG_DBG_CASES(DBGWVR):
    HSR_SYSREG_DBG_CASES(DBGWCR):
        return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);

    /*
     * MDCR_EL2.TPM
     *
     * ARMv8 (DDI 0487A.d): D1-1511 Table D1-61
     *
     * Unhandled:
     *    PMEVCNTR<n>_EL0
     *    PMEVTYPER<n>_EL0
     *    PMCCFILTR_EL0
     * MDCR_EL2.TPMCR
     *
     * ARMv7 (DDI 0406C.b): B1.14.17
     * ARMv8 (DDI 0487A.d): D1-1511 Table D1-62
     *
     * NB: Both MDCR_EL2.TPM and MDCR_EL2.TPMCR cause trapping of PMCR.
     */
    case HSR_SYSREG_PMINTENSET_EL1:
    case HSR_SYSREG_PMINTENCLR_EL1:
        /*
         * Accessible from EL1 only, but if EL0 trap happens handle as
         * undef.
         */
        return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);
    case HSR_SYSREG_PMUSERENR_EL0:
        /* RO at EL0. RAZ/WI at EL1 */
        if ( psr_mode_is_user(regs) )
            return handle_ro_raz(regs, regidx, hsr.sysreg.read, hsr, 0);
        else
            return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);
    case HSR_SYSREG_PMCR_EL0:
    case HSR_SYSREG_PMCNTENSET_EL0:
    case HSR_SYSREG_PMCNTENCLR_EL0:
    case HSR_SYSREG_PMOVSCLR_EL0:
    case HSR_SYSREG_PMSWINC_EL0:
    case HSR_SYSREG_PMSELR_EL0:
    case HSR_SYSREG_PMCEID0_EL0:
    case HSR_SYSREG_PMCEID1_EL0:
    case HSR_SYSREG_PMCCNTR_EL0:
    case HSR_SYSREG_PMXEVTYPER_EL0:
    case HSR_SYSREG_PMXEVCNTR_EL0:
    case HSR_SYSREG_PMOVSSET_EL0:
        /*
         * Accessible at EL0 only if PMUSERENR_EL0.EN is set. We
         * emulate that register as 0 above.
         */
        return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);

    /*
     * !CNTHCTL_EL2.EL1PCEN
     *
     * ARMv8 (DDI 0487A.d): D1-1510 Table D1-60
     */
    case HSR_SYSREG_CNTP_CTL_EL0:
    case HSR_SYSREG_CNTP_TVAL_EL0:
    case HSR_SYSREG_CNTP_CVAL_EL0:
        if ( !vtimer_emulate(regs, hsr) )
            return inject_undef_exception(regs, hsr);
        break;

    /*
     * HCR_EL2.FMO or HCR_EL2.IMO
     *
     * ARMv8: GIC Architecture Specification (PRD03-GENC-010745 24.0)
     *        Section 4.6.8.
     */
    case HSR_SYSREG_ICC_SGI1R_EL1:
        if ( !vgic_emulate(regs, hsr) )
        {
            dprintk(XENLOG_WARNING,
                    "failed emulation of sysreg ICC_SGI1R_EL1 access\n");
            return inject_undef64_exception(regs, hsr.len);
        }
        break;
    case HSR_SYSREG_ICC_SGI0R_EL1:
    case HSR_SYSREG_ICC_ASGI1R_EL1:
        /* TBD: Implement to support secure grp0/1 SGI forwarding */
        dprintk(XENLOG_WARNING,
                "Emulation of sysreg ICC_SGI0R_EL1/ASGI1R_EL1 not supported\n");
        return inject_undef64_exception(regs, hsr.len);

    /*
     *  ICC_SRE_EL2.Enable = 0
     *
     *  GIC Architecture Specification (IHI 0069C): Section 8.1.9
     */
    case HSR_SYSREG_ICC_SRE_EL1:
        /*
         * Trapped when the guest is using GICv2 whilst the platform
         * interrupt controller is GICv3. In this case, the register
         * should be emulate as RAZ/WI to tell the guest to use the GIC
         * memory mapped interface (i.e GICv2 compatibility).
         */
        return handle_raz_wi(regs, regidx, hsr.sysreg.read, hsr, 1);

    /*
     * HCR_EL2.TIDCP
     *
     * ARMv8 (DDI 0487A.d): D1-1501 Table D1-43
     *
     *  - Reserved control space for IMPLEMENTATION DEFINED functionality.
     *
     * CPTR_EL2.TTA
     *
     * ARMv8 (DDI 0487A.d): D1-1507 Table D1-54
     *
     *  - All implemented trace registers.
     *
     * And all other unknown registers.
     */
    default:
        {
            const struct hsr_sysreg sysreg = hsr.sysreg;

            gdprintk(XENLOG_ERR,
                     "%s %d, %d, c%d, c%d, %d %s x%d @ 0x%"PRIregister"\n",
                     sysreg.read ? "mrs" : "msr",
                     sysreg.op0, sysreg.op1,
                     sysreg.crn, sysreg.crm,
                     sysreg.op2,
                     sysreg.read ? "=>" : "<=",
                     sysreg.reg, regs->pc);
            gdprintk(XENLOG_ERR, "unhandled 64-bit sysreg access %#x\n",
                     hsr.bits & HSR_SYSREG_REGS_MASK);
            inject_undef_exception(regs, hsr);
            return;
        }
    }

    regs->pc += 4;
}
#endif

void dump_guest_s1_walk(struct domain *d, vaddr_t addr)
{
    register_t ttbcr = READ_SYSREG(TCR_EL1);
    uint64_t ttbr0 = READ_SYSREG64(TTBR0_EL1);
    uint32_t offset;
    uint32_t *first = NULL, *second = NULL;
    mfn_t mfn;

    mfn = p2m_lookup(d, _gfn(paddr_to_pfn(ttbr0)), NULL);

    printk("dom%d VA 0x%08"PRIvaddr"\n", d->domain_id, addr);
    printk("    TTBCR: 0x%08"PRIregister"\n", ttbcr);
    printk("    TTBR0: 0x%016"PRIx64" = 0x%"PRIpaddr"\n",
           ttbr0, pfn_to_paddr(mfn_x(mfn)));

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

    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        printk("Failed TTBR0 maddr lookup\n");
        goto done;
    }
    first = map_domain_page(mfn);

    offset = addr >> (12+8);
    printk("1ST[0x%"PRIx32"] (0x%"PRIpaddr") = 0x%08"PRIx32"\n",
           offset, pfn_to_paddr(mfn_x(mfn)), first[offset]);
    if ( !(first[offset] & 0x1) ||
          (first[offset] & 0x2) )
        goto done;

    mfn = p2m_lookup(d, _gfn(paddr_to_pfn(first[offset])), NULL);

    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        printk("Failed L1 entry maddr lookup\n");
        goto done;
    }
    second = map_domain_page(mfn);
    offset = (addr >> 12) & 0x3FF;
    printk("2ND[0x%"PRIx32"] (0x%"PRIpaddr") = 0x%08"PRIx32"\n",
           offset, pfn_to_paddr(mfn_x(mfn)), second[offset]);

done:
    if (second) unmap_domain_page(second);
    if (first) unmap_domain_page(first);
}

static inline paddr_t get_faulting_ipa(vaddr_t gva)
{
    register_t hpfar = READ_SYSREG(HPFAR_EL2);
    paddr_t ipa;

    ipa = (paddr_t)(hpfar & HPFAR_MASK) << (12 - 4);
    ipa |= gva & ~PAGE_MASK;

    return ipa;
}

static inline bool hpfar_is_valid(bool s1ptw, uint8_t fsc)
{
    /*
     * HPFAR is valid if one of the following cases are true:
     *  1. the stage 2 fault happen during a stage 1 page table walk
     *  (the bit ESR_EL2.S1PTW is set)
     *  2. the fault was due to a translation fault and the processor
     *  does not carry erratum #8342220
     *
     * Note that technically HPFAR is valid for other cases, but they
     * are currently not supported by Xen.
     */
    return s1ptw || (fsc == FSC_FLT_TRANS && !check_workaround_834220());
}

static void do_trap_instr_abort_guest(struct cpu_user_regs *regs,
                                      const union hsr hsr)
{
    int rc;
    register_t gva = READ_SYSREG(FAR_EL2);
    uint8_t fsc = hsr.iabt.ifsc & ~FSC_LL_MASK;
    paddr_t gpa;
    mfn_t mfn;

    /*
     * If this bit has been set, it means that this instruction abort is caused
     * by a guest external abort. Currently we crash the guest to protect the
     * hypervisor. In future one can better handle this by injecting a virtual
     * abort to the guest.
     */
    if ( hsr.iabt.eat )
        domain_crash_synchronous();

    if ( hpfar_is_valid(hsr.iabt.s1ptw, fsc) )
        gpa = get_faulting_ipa(gva);
    else
    {
        /*
         * Flush the TLB to make sure the DTLB is clear before
         * doing GVA->IPA translation. If we got here because of
         * an entry only present in the ITLB, this translation may
         * still be inaccurate.
         */
        flush_tlb_local();

        /*
         * We may not be able to translate because someone is
         * playing with the Stage-2 page table of the domain.
         * Return to the guest.
         */
        rc = gva_to_ipa(gva, &gpa, GV2M_READ);
        if ( rc == -EFAULT )
            return; /* Try again */
    }

    switch ( fsc )
    {
    case FSC_FLT_PERM:
    {
        const struct npfec npfec = {
            .insn_fetch = 1,
            .gla_valid = 1,
            .kind = hsr.iabt.s1ptw ? npfec_kind_in_gpt : npfec_kind_with_gla
        };

        p2m_mem_access_check(gpa, gva, npfec);
        /*
         * The only way to get here right now is because of mem_access,
         * thus reinjecting the exception to the guest is never required.
         */
        return;
    }
    case FSC_FLT_TRANS:
        /*
         * The PT walk may have failed because someone was playing
         * with the Stage-2 page table. Walk the Stage-2 PT to check
         * if the entry exists. If it's the case, return to the guest
         */
        mfn = p2m_lookup(current->domain, _gfn(paddr_to_pfn(gpa)), NULL);
        if ( !mfn_eq(mfn, INVALID_MFN) )
            return;
    }

    inject_iabt_exception(regs, gva, hsr.len);
}

static bool try_handle_mmio(struct cpu_user_regs *regs,
                            mmio_info_t *info)
{
    const struct hsr_dabt dabt = info->dabt;
    int rc;

    /* stage-1 page table should never live in an emulated MMIO region */
    if ( dabt.s1ptw )
        return false;

    /* All the instructions used on emulated MMIO region should be valid */
    if ( !dabt.valid )
        return false;

    /*
     * Erratum 766422: Thumb store translation fault to Hypervisor may
     * not have correct HSR Rt value.
     */
    if ( check_workaround_766422() && (regs->cpsr & PSR_THUMB) &&
         dabt.write )
    {
        rc = decode_instruction(regs, &info->dabt);
        if ( rc )
        {
            gprintk(XENLOG_DEBUG, "Unable to decode instruction\n");
            return false;
        }
    }

    return !!handle_mmio(info);
}

static void do_trap_data_abort_guest(struct cpu_user_regs *regs,
                                     const union hsr hsr)
{
    const struct hsr_dabt dabt = hsr.dabt;
    int rc;
    mmio_info_t info;
    uint8_t fsc = hsr.dabt.dfsc & ~FSC_LL_MASK;
    mfn_t mfn;

    /*
     * If this bit has been set, it means that this data abort is caused
     * by a guest external abort. Currently we crash the guest to protect the
     * hypervisor. In future one can better handle this by injecting a virtual
     * abort to the guest.
     */
    if ( dabt.eat )
        domain_crash_synchronous();

    info.dabt = dabt;
#ifdef CONFIG_ARM_32
    info.gva = READ_CP32(HDFAR);
#else
    info.gva = READ_SYSREG64(FAR_EL2);
#endif

    if ( hpfar_is_valid(dabt.s1ptw, fsc) )
        info.gpa = get_faulting_ipa(info.gva);
    else
    {
        rc = gva_to_ipa(info.gva, &info.gpa, GV2M_READ);
        /*
         * We may not be able to translate because someone is
         * playing with the Stage-2 page table of the domain.
         * Return to the guest.
         */
        if ( rc == -EFAULT )
            return; /* Try again */
    }

    switch ( fsc )
    {
    case FSC_FLT_PERM:
    {
        const struct npfec npfec = {
            .read_access = !dabt.write,
            .write_access = dabt.write,
            .gla_valid = 1,
            .kind = dabt.s1ptw ? npfec_kind_in_gpt : npfec_kind_with_gla
        };

        p2m_mem_access_check(info.gpa, info.gva, npfec);
        /*
         * The only way to get here right now is because of mem_access,
         * thus reinjecting the exception to the guest is never required.
         */
        return;
    }
    case FSC_FLT_TRANS:
        /*
         * Attempt first to emulate the MMIO as the data abort will
         * likely happen in an emulated region.
         */
        if ( try_handle_mmio(regs, &info) )
        {
            advance_pc(regs, hsr);
            return;
        }

        /*
         * The PT walk may have failed because someone was playing
         * with the Stage-2 page table. Walk the Stage-2 PT to check
         * if the entry exists. If it's the case, return to the guest
         */
        mfn = p2m_lookup(current->domain, _gfn(paddr_to_pfn(info.gpa)), NULL);
        if ( !mfn_eq(mfn, INVALID_MFN) )
            return;

        break;
    default:
        gprintk(XENLOG_WARNING, "Unsupported DFSC: HSR=%#x DFSC=%#x\n",
                hsr.bits, dabt.dfsc);
    }

    gdprintk(XENLOG_DEBUG, "HSR=0x%x pc=%#"PRIregister" gva=%#"PRIvaddr
             " gpa=%#"PRIpaddr"\n", hsr.bits, regs->pc, info.gva, info.gpa);
    inject_dabt_exception(regs, info.gva, hsr.len);
}

static void do_trap_smc(struct cpu_user_regs *regs, const union hsr hsr)
{
    int rc = 0;

    if ( current->domain->arch.monitor.privileged_call_enabled )
        rc = monitor_smc();

    if ( rc != 1 )
        inject_undef_exception(regs, hsr);
}

static void enter_hypervisor_head(struct cpu_user_regs *regs)
{
    if ( guest_mode(regs) )
        gic_clear_lrs(current);
}

asmlinkage void do_trap_hypervisor(struct cpu_user_regs *regs)
{
    const union hsr hsr = { .bits = READ_SYSREG32(ESR_EL2) };

    enter_hypervisor_head(regs);

    switch (hsr.ec) {
    case HSR_EC_WFI_WFE:
        /*
         * HCR_EL2.TWI, HCR_EL2.TWE
         *
         * ARMv7 (DDI 0406C.b): B1.14.9
         * ARMv8 (DDI 0487A.d): D1-1505 Table D1-51
         */
        if ( !check_conditional_instr(regs, hsr) )
        {
            advance_pc(regs, hsr);
            return;
        }
        if ( hsr.wfi_wfe.ti ) {
            /* Yield the VCPU for WFE */
            perfc_incr(trap_wfe);
            vcpu_yield();
        } else {
            /* Block the VCPU for WFI */
            perfc_incr(trap_wfi);
            vcpu_block_unless_event_pending(current);
        }
        advance_pc(regs, hsr);
        break;
    case HSR_EC_CP15_32:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_cp15_32);
        do_cp15_32(regs, hsr);
        break;
    case HSR_EC_CP15_64:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_cp15_64);
        do_cp15_64(regs, hsr);
        break;
    case HSR_EC_CP14_32:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_cp14_32);
        do_cp14_32(regs, hsr);
        break;
    case HSR_EC_CP14_64:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_cp14_64);
        do_cp14_64(regs, hsr);
        break;
    case HSR_EC_CP14_DBG:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_cp14_dbg);
        do_cp14_dbg(regs, hsr);
        break;
    case HSR_EC_CP:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_cp);
        do_cp(regs, hsr);
        break;
    case HSR_EC_SMC32:
        /*
         * HCR_EL2.TSC
         *
         * ARMv7 (DDI 0406C.b): B1.14.8
         * ARMv8 (DDI 0487A.d): D1-1501 Table D1-44
         */
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_smc32);
        do_trap_smc(regs, hsr);
        break;
    case HSR_EC_HVC32:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_hvc32);
#ifndef NDEBUG
        if ( (hsr.iss & 0xff00) == 0xff00 )
            return do_debug_trap(regs, hsr.iss & 0x00ff);
#endif
        if ( hsr.iss == 0 )
            return do_trap_psci(regs);
        do_trap_hypercall(regs, (register_t *)&regs->r12, hsr.iss);
        break;
#ifdef CONFIG_ARM_64
    case HSR_EC_HVC64:
        GUEST_BUG_ON(psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_hvc64);
#ifndef NDEBUG
        if ( (hsr.iss & 0xff00) == 0xff00 )
            return do_debug_trap(regs, hsr.iss & 0x00ff);
#endif
        if ( hsr.iss == 0 )
            return do_trap_psci(regs);
        do_trap_hypercall(regs, &regs->x16, hsr.iss);
        break;
    case HSR_EC_SMC64:
        /*
         * HCR_EL2.TSC
         *
         * ARMv8 (DDI 0487A.d): D1-1501 Table D1-44
         */
        GUEST_BUG_ON(psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_smc64);
        do_trap_smc(regs, hsr);
        break;
    case HSR_EC_SYSREG:
        GUEST_BUG_ON(psr_mode_is_32bit(regs->cpsr));
        perfc_incr(trap_sysreg);
        do_sysreg(regs, hsr);
        break;
#endif

    case HSR_EC_INSTR_ABORT_LOWER_EL:
        perfc_incr(trap_iabt);
        do_trap_instr_abort_guest(regs, hsr);
        break;
    case HSR_EC_DATA_ABORT_LOWER_EL:
        perfc_incr(trap_dabt);
        do_trap_data_abort_guest(regs, hsr);
        break;

#ifdef CONFIG_ARM_64
    case HSR_EC_BRK:
        do_trap_brk(regs, hsr);
        break;
#endif

    default:
        printk("Hypervisor Trap. HSR=0x%x EC=0x%x IL=%x Syndrome=0x%"PRIx32"\n",
               hsr.bits, hsr.ec, hsr.len, hsr.iss);
        do_unexpected_trap("Hypervisor", regs);
    }
}

asmlinkage void do_trap_guest_error(struct cpu_user_regs *regs)
{
    enter_hypervisor_head(regs);

    /*
     * Currently, to ensure hypervisor safety, when we received a
     * guest-generated vSerror/vAbort, we just crash the guest to protect
     * the hypervisor. In future we can better handle this by injecting
     * a vSerror/vAbort to the guest.
     */
    gdprintk(XENLOG_WARNING, "Guest(Dom-%u) will be crashed by vSError\n",
             current->domain->domain_id);
    domain_crash_synchronous();
}

asmlinkage void do_trap_irq(struct cpu_user_regs *regs)
{
    enter_hypervisor_head(regs);
    gic_interrupt(regs, 0);
}

asmlinkage void do_trap_fiq(struct cpu_user_regs *regs)
{
    enter_hypervisor_head(regs);
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
        /*
         * Must be the last one - as the IPI will trigger us to come here
         * and we want to patch the hypervisor with almost no stack.
         */
        check_for_livepatch_work();
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
