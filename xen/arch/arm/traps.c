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

#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/livepatch.h>
#include <xen/mem_access.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/perfc.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/string.h>
#include <xen/symbols.h>
#include <xen/version.h>
#include <xen/virtual_region.h>

#include <public/sched.h>
#include <public/xen.h>

#include <asm/acpi.h>
#include <asm/cpuerrata.h>
#include <asm/cpufeature.h>
#include <asm/debugger.h>
#include <asm/event.h>
#include <asm/hsr.h>
#include <asm/mmio.h>
#include <asm/regs.h>
#include <asm/smccc.h>
#include <asm/traps.h>
#include <asm/vgic.h>
#include <asm/vtimer.h>

/* The base of the stack must always be double-word aligned, which means
 * that both the kernel half of struct cpu_user_regs (which is pushed in
 * entry.S) and struct cpu_info (which lives at the bottom of a Xen
 * stack) must be doubleword-aligned in size.  */
static void __init __maybe_unused build_assertions(void)
{
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

static int __init parse_vwfi(const char *s)
{
	if ( !strcmp(s, "native") )
		vwfi = NATIVE;
	else
		vwfi = TRAP;

	return 0;
}
custom_param("vwfi", parse_vwfi);

register_t get_default_hcr_flags(void)
{
    return  (HCR_PTW|HCR_BSU_INNER|HCR_AMO|HCR_IMO|HCR_FMO|HCR_VM|
             (vwfi != NATIVE ? (HCR_TWI|HCR_TWE) : 0) |
             HCR_TSC|HCR_TAC|HCR_SWIO|HCR_TIDCP|HCR_FB|HCR_TSW);
}

static enum {
    SERRORS_DIVERSE,
    SERRORS_PANIC,
} serrors_op = SERRORS_DIVERSE;

static int __init parse_serrors_behavior(const char *str)
{
    if ( !strcmp(str, "panic") )
        serrors_op = SERRORS_PANIC;
    else if ( !strcmp(str, "diverse") )
        serrors_op = SERRORS_DIVERSE;
    else
        return -EINVAL;

    return 0;
}
custom_param("serrors", parse_serrors_behavior);

static int __init update_serrors_cpu_caps(void)
{
    if ( serrors_op != SERRORS_DIVERSE )
        cpus_set_cap(SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT);

    return 0;
}
__initcall(update_serrors_cpu_caps);

void init_traps(void)
{
    /*
     * Setup Hyp vector base. Note they might get updated with the
     * branch predictor hardening.
     */
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

    /*
     * Configure HCR_EL2 with the bare minimum to run Xen until a guest
     * is scheduled. {A,I,F}MO bits are set to allow EL2 receiving
     * interrupts.
     */
    WRITE_SYSREG(HCR_AMO | HCR_FMO | HCR_IMO, HCR_EL2);
    isb();
}

void __div0(void)
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
static inline bool is_zero_register(int reg)
{
    /* There is no zero register for ARM32 */
    return false;
}
#else
static inline bool is_zero_register(int reg)
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

    switch ( reg )
    {
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

    panic("Error during Hypervisor-to-physical address translation\n");
}

static void cpsr_switch_mode(struct cpu_user_regs *regs, int mode)
{
    register_t sctlr = READ_SYSREG(SCTLR_EL1);

    regs->cpsr &= ~(PSR_MODE_MASK|PSR_IT_MASK|PSR_JAZELLE|PSR_BIG_ENDIAN|PSR_THUMB);

    regs->cpsr |= mode;
    regs->cpsr |= PSR_IRQ_MASK;
    if ( mode == PSR_MODE_ABT )
        regs->cpsr |= PSR_ABT_MASK;
    if ( sctlr & SCTLR_A32_ELx_TE )
        regs->cpsr |= PSR_THUMB;
    if ( sctlr & SCTLR_Axx_ELx_EE )
        regs->cpsr |= PSR_BIG_ENDIAN;
}

static vaddr_t exception_handler32(vaddr_t offset)
{
    register_t sctlr = READ_SYSREG(SCTLR_EL1);

    if ( sctlr & SCTLR_A32_EL1_V )
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
void inject_undef64_exception(struct cpu_user_regs *regs, int instr_len)
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

void inject_undef_exception(struct cpu_user_regs *regs, const union hsr hsr)
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

/*
 * Inject a virtual Abort/SError into the guest.
 *
 * This should only be called with 'current'.
 */
static void inject_vabt_exception(struct vcpu *v)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    const union hsr hsr = { .bits = regs->hsr };

    ASSERT(v == current);

    /*
     * SVC/HVC/SMC already have an adjusted PC (See ARM ARM DDI 0487A.j
     * D1.10.1 for more details), which we need to correct in order to
     * return to after having injected the SError.
     */
    switch ( hsr.ec )
    {
    case HSR_EC_SVC32:
    case HSR_EC_HVC32:
    case HSR_EC_SMC32:
#ifdef CONFIG_ARM_64
    case HSR_EC_SVC64:
    case HSR_EC_HVC64:
    case HSR_EC_SMC64:
#endif
        regs->pc -= hsr.len ? 4 : 2;
        break;

    default:
        break;
    }

    vcpu_hcr_set_flags(v, HCR_VA);
}

/*
 * SError exception handler.
 *
 * A true parameter "guest" means that the SError is type#1 or type#2.
 *
 * @guest indicates whether this is a SError generated by the guest.
 *
 * If true, the SError was generated by the guest, so it is safe to continue
 * and forward to the guest (if requested).
 *
 * If false, the SError was likely generated by the hypervisor. As we cannot
 * distinguish between precise and imprecise SErrors, it is not safe to
 * continue.
 *
 * Note that Arm32 asynchronous external abort generated by the
 * hypervisor will be handled in do_trap_data_abort().
 */
static void __do_trap_serror(struct cpu_user_regs *regs, bool guest)
{
    /*
     * When using "DIVERSE", the SErrors generated by the guest will be
     * forwarded to the currently running vCPU.
     */
    if ( serrors_op == SERRORS_DIVERSE && guest )
            return inject_vabt_exception(current);

    do_unexpected_trap("SError", regs);
}

struct reg_ctxt {
    /* Guest-side state */
    register_t sctlr_el1;
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

static void show_registers_32(const struct cpu_user_regs *regs,
                              const struct reg_ctxt *ctxt,
                              bool guest_mode,
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
        printk("USR: SP: %08"PRIx32" LR: %"PRIregister"\n",
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
        printk("HYP: SP: %08"PRIx32" LR: %"PRIregister"\n", regs->sp, regs->lr);
    }
#endif
    printk("\n");

    if ( guest_mode )
    {
        printk("     SCTLR: %"PRIregister"\n", ctxt->sctlr_el1);
        printk("       TCR: %"PRIregister"\n", ctxt->tcr_el1);
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
static void show_registers_64(const struct cpu_user_regs *regs,
                              const struct reg_ctxt *ctxt,
                              bool guest_mode,
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
        printk(" SCTLR_EL1: %"PRIregister"\n", ctxt->sctlr_el1);
        printk("   TCR_EL1: %"PRIregister"\n", ctxt->tcr_el1);
        printk(" TTBR0_EL1: %016"PRIx64"\n", ctxt->ttbr0_el1);
        printk(" TTBR1_EL1: %016"PRIx64"\n", ctxt->ttbr1_el1);
        printk("\n");
    }
}
#endif

static void _show_registers(const struct cpu_user_regs *regs,
                            const struct reg_ctxt *ctxt,
                            bool guest_mode,
                            const struct vcpu *v)
{
    print_xen_info();

    printk("CPU:    %d\n", smp_processor_id());

    if ( guest_mode )
    {
        if ( psr_mode_is_32bit(regs) )
            show_registers_32(regs, ctxt, guest_mode, v);
#ifdef CONFIG_ARM_64
        else
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
    printk("  VTCR_EL2: %08"PRIx32"\n", READ_SYSREG32(VTCR_EL2));
    printk(" VTTBR_EL2: %016"PRIx64"\n", ctxt->vttbr_el2);
    printk("\n");

    printk(" SCTLR_EL2: %08"PRIx32"\n", READ_SYSREG32(SCTLR_EL2));
    printk("   HCR_EL2: %"PRIregister"\n", READ_SYSREG(HCR_EL2));
    printk(" TTBR0_EL2: %016"PRIx64"\n", READ_SYSREG64(TTBR0_EL2));
    printk("\n");
    printk("   ESR_EL2: %08"PRIx32"\n", regs->hsr);
    printk(" HPFAR_EL2: %"PRIregister"\n", READ_SYSREG(HPFAR_EL2));

#ifdef CONFIG_ARM_32
    printk("     HDFAR: %08"PRIx32"\n", READ_CP32(HDFAR));
    printk("     HIFAR: %08"PRIx32"\n", READ_CP32(HIFAR));
#else
    printk("   FAR_EL2: %016"PRIx64"\n", READ_SYSREG64(FAR_EL2));
#endif
    printk("\n");
}

void show_registers(const struct cpu_user_regs *regs)
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

static void show_guest_stack(struct vcpu *v, const struct cpu_user_regs *regs)
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
static void show_trace(const struct cpu_user_regs *regs)
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

void show_stack(const struct cpu_user_regs *regs)
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

void show_execution_state(const struct cpu_user_regs *regs)
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

void do_unexpected_trap(const char *msg, const struct cpu_user_regs *regs)
{
    printk("CPU%d: Unexpected Trap: %s\n", smp_processor_id(), msg);
    show_execution_state(regs);
    panic("CPU%d: Unexpected Trap: %s\n", smp_processor_id(), msg);
}

int do_bug_frame(const struct cpu_user_regs *regs, vaddr_t pc)
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
        panic("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

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
        panic("Assertion '%s' failed at %s%s:%d\n",
              predicate, prefix, filename, lineno);
    }

    return -EINVAL;
}

#ifdef CONFIG_ARM_64
static void do_trap_brk(struct cpu_user_regs *regs, const union hsr hsr)
{
    /*
     * HCR_EL2.TGE and MDCR_EL2.TDR are currently not set. So we should
     * never receive software breakpoing exception for EL1 and EL0 here.
     */
    if ( !hyp_mode(regs) )
    {
        domain_crash(current->domain);
        return;
    }

    switch ( hsr.brk.comment )
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
#ifdef CONFIG_GRANT_TABLE
    HYPERCALL(grant_table_op, 3),
#endif
    HYPERCALL(multicall, 2),
    HYPERCALL(platform_op, 1),
    HYPERCALL_ARM(vcpu_op, 3),
    HYPERCALL(vm_assist, 2),
#ifdef CONFIG_ARGO
    HYPERCALL(argo_op, 5),
#endif
};

#ifndef NDEBUG
static void do_debug_trap(struct cpu_user_regs *regs, unsigned int code)
{
    uint32_t reg;
    uint32_t domid = current->domain->domain_id;

    switch ( code )
    {
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
        panic("DOM%d: Unhandled debug trap %#x\n", domid, code);
        break;
    }
}
#endif

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
                              const union hsr hsr)
{
    arm_hypercall_fn_t call = NULL;

    BUILD_BUG_ON(NR_hypercalls < ARRAY_SIZE(arm_hypercall_table) );

    if ( hsr.iss != XEN_HYPERCALL_TAG )
    {
        gprintk(XENLOG_WARNING, "Invalid HVC imm 0x%x\n", hsr.iss);
        return inject_undef_exception(regs, hsr);
    }

    if ( *nr >= ARRAY_SIZE(arm_hypercall_table) )
    {
        perfc_incr(invalid_hypercalls);
        HYPERCALL_RESULT_REG(regs) = -ENOSYS;
        return;
    }

    current->hcall_preempted = false;

    perfc_incra(hypercalls, *nr);
    call = arm_hypercall_table[*nr].fn;
    if ( call == NULL )
    {
        HYPERCALL_RESULT_REG(regs) = -ENOSYS;
        return;
    }

    HYPERCALL_RESULT_REG(regs) = call(HYPERCALL_ARGS(regs));

#ifndef NDEBUG
    if ( !current->hcall_preempted )
    {
        /* Deliberately corrupt parameter regs used by this hypercall. */
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

    /* Ensure the hypercall trap instruction is re-executed. */
    if ( current->hcall_preempted )
        regs->pc -= 4;  /* re-execute 'hvc #XEN_HYPERCALL_TAG' */
}

void arch_hypercall_tasklet_result(struct vcpu *v, long res)
{
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    HYPERCALL_RESULT_REG(regs) = res;
}

static bool check_multicall_32bit_clean(struct multicall_entry *multi)
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

enum mc_disposition arch_do_multicall_call(struct mc_state *state)
{
    struct multicall_entry *multi = &state->call;
    arm_hypercall_fn_t call = NULL;

    if ( multi->op >= ARRAY_SIZE(arm_hypercall_table) )
    {
        multi->result = -ENOSYS;
        return mc_continue;
    }

    call = arm_hypercall_table[multi->op].fn;
    if ( call == NULL )
    {
        multi->result = -ENOSYS;
        return mc_continue;
    }

    if ( is_32bit_domain(current->domain) &&
         !check_multicall_32bit_clean(multi) )
        return mc_continue;

    multi->result = call(multi->args[0], multi->args[1],
                         multi->args[2], multi->args[3],
                         multi->args[4]);

    return likely(!psr_mode_is_user(guest_cpu_user_regs()))
           ? mc_continue : mc_preempt;
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

int check_conditional_instr(struct cpu_user_regs *regs, const union hsr hsr)
{
    unsigned long cpsr, cpsr_cond;
    int cond;

    /*
     * SMC32 instruction case is special. Under SMC32 we mean SMC
     * instruction on ARMv7 or SMC instruction originating from
     * AArch32 state on ARMv8.
     * On ARMv7 it will be trapped only if it passed condition check
     * (ARM DDI 0406C.c page B3-1431), but we need to check condition
     * flags on ARMv8 (ARM DDI 0487B.a page D7-2271).
     * Encoding for HSR.ISS on ARMv8 is backwards compatible with ARMv7:
     * HSR.ISS is defined as UNK/SBZP on ARMv7 which means, that it
     * will be read as 0. This includes CCKNOWNPASS field.
     * If CCKNOWNPASS == 0 then this was an unconditional instruction or
     * it has passed conditional check (ARM DDI 0487B.a page D7-2272).
     */
    if ( hsr.ec == HSR_EC_SMC32 && hsr.smc32.ccknownpass == 0 )
        return 1;

    /* Unconditional Exception classes */
    if ( hsr.ec == HSR_EC_UNKNOWN ||
         (hsr.ec >= 0x10 && hsr.ec != HSR_EC_SMC32) )
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

        BUG_ON( !psr_mode_is_32bit(regs) || !(cpsr & PSR_THUMB) );

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

void advance_pc(struct cpu_user_regs *regs, const union hsr hsr)
{
    unsigned long itbits, cond, cpsr = regs->cpsr;
    bool is_thumb = psr_mode_is_32bit(regs) && (cpsr & PSR_THUMB);

    if ( is_thumb && (cpsr & PSR_IT_MASK) )
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
void handle_raz_wi(struct cpu_user_regs *regs,
                   int regidx,
                   bool read,
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

/* write only as write ignore */
void handle_wo_wi(struct cpu_user_regs *regs,
                  int regidx,
                  bool read,
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

/* Read only as value provided with 'val' argument of this function */
void handle_ro_read_val(struct cpu_user_regs *regs,
                        int regidx,
                        bool read,
                        const union hsr hsr,
                        int min_el,
                        register_t val)
{
    ASSERT((min_el == 0) || (min_el == 1));

    if ( min_el > 0 && psr_mode_is_user(regs) )
        return inject_undef_exception(regs, hsr);

    if ( !read )
        return inject_undef_exception(regs, hsr);

    set_user_reg(regs, regidx, val);

    advance_pc(regs, hsr);
}

/* Read only as read as zero */
inline void handle_ro_raz(struct cpu_user_regs *regs,
                          int regidx,
                          bool read,
                          const union hsr hsr,
                          int min_el)
{
    handle_ro_read_val(regs, regidx, read, hsr, min_el, 0);
}

void dump_guest_s1_walk(struct domain *d, vaddr_t addr)
{
    register_t ttbcr = READ_SYSREG(TCR_EL1);
    uint64_t ttbr0 = READ_SYSREG64(TTBR0_EL1);
    uint32_t offset;
    uint32_t *first = NULL, *second = NULL;
    mfn_t mfn;

    mfn = gfn_to_mfn(d, gaddr_to_gfn(ttbr0));

    printk("dom%d VA 0x%08"PRIvaddr"\n", d->domain_id, addr);
    printk("    TTBCR: 0x%"PRIregister"\n", ttbcr);
    printk("    TTBR0: 0x%016"PRIx64" = 0x%"PRIpaddr"\n",
           ttbr0, mfn_to_maddr(mfn));

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
           offset, mfn_to_maddr(mfn), first[offset]);
    if ( !(first[offset] & 0x1) ||
          (first[offset] & 0x2) )
        goto done;

    mfn = gfn_to_mfn(d, gaddr_to_gfn(first[offset]));

    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        printk("Failed L1 entry maddr lookup\n");
        goto done;
    }
    second = map_domain_page(mfn);
    offset = (addr >> 12) & 0x3FF;
    printk("2ND[0x%"PRIx32"] (0x%"PRIpaddr") = 0x%08"PRIx32"\n",
           offset, mfn_to_maddr(mfn), second[offset]);

done:
    if ( second ) unmap_domain_page(second);
    if ( first ) unmap_domain_page(first);
}

/*
 * Return the value of the hypervisor fault address register.
 *
 * On ARM32, the register will be different depending whether the
 * fault is a prefetch abort or data abort.
 */
static inline vaddr_t get_hfar(bool is_data)
{
    vaddr_t gva;

#ifdef CONFIG_ARM_32
    if ( is_data )
        gva = READ_CP32(HDFAR);
    else
        gva = READ_CP32(HIFAR);
#else
    gva =  READ_SYSREG(FAR_EL2);
#endif

    return gva;
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

/*
 * When using ACPI, most of the MMIO regions will be mapped on-demand
 * in stage-2 page tables for the hardware domain because Xen is not
 * able to know from the EFI memory map the MMIO regions.
 */
static bool try_map_mmio(gfn_t gfn)
{
    struct domain *d = current->domain;

    /* For the hardware domain, all MMIOs are mapped with GFN == MFN */
    mfn_t mfn = _mfn(gfn_x(gfn));

    /*
     * Device-Tree should already have everything mapped when building
     * the hardware domain.
     */
    if ( acpi_disabled )
        return false;

    if ( !is_hardware_domain(d) )
        return false;

    /* The hardware domain can only map permitted MMIO regions */
    if ( !iomem_access_permitted(d, mfn_x(mfn), mfn_x(mfn) + 1) )
        return false;

    return !map_regions_p2mt(d, gfn, 1, mfn, p2m_mmio_direct_c);
}

static void do_trap_stage2_abort_guest(struct cpu_user_regs *regs,
                                       const union hsr hsr)
{
    /*
     * The encoding of hsr_iabt is a subset of hsr_dabt. So use
     * hsr_dabt to represent an abort fault.
     */
    const struct hsr_xabt xabt = hsr.xabt;
    int rc;
    vaddr_t gva;
    paddr_t gpa;
    uint8_t fsc = xabt.fsc & ~FSC_LL_MASK;
    bool is_data = (hsr.ec == HSR_EC_DATA_ABORT_LOWER_EL);

    /*
     * If this bit has been set, it means that this stage-2 abort is caused
     * by a guest external abort. We treat this stage-2 abort as guest SError.
     */
    if ( xabt.eat )
        return __do_trap_serror(regs, true);

    gva = get_hfar(is_data);

    if ( hpfar_is_valid(xabt.s1ptw, fsc) )
        gpa = get_faulting_ipa(gva);
    else
    {
        /*
         * Flush the TLB to make sure the DTLB is clear before
         * doing GVA->IPA translation. If we got here because of
         * an entry only present in the ITLB, this translation may
         * still be inaccurate.
         */
        if ( !is_data )
            flush_guest_tlb_local();

        rc = gva_to_ipa(gva, &gpa, GV2M_READ);
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
            .insn_fetch = !is_data,
            .read_access = is_data && !hsr.dabt.write,
            .write_access = is_data && hsr.dabt.write,
            .gla_valid = 1,
            .kind = xabt.s1ptw ? npfec_kind_in_gpt : npfec_kind_with_gla
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
         * Attempt first to emulate the MMIO as the data abort will
         * likely happen in an emulated region.
         *
         * Note that emulated region cannot be executed
         */
        if ( is_data )
        {
            enum io_state state = try_handle_mmio(regs, hsr, gpa);

            switch ( state )
            {
            case IO_ABORT:
                goto inject_abt;
            case IO_HANDLED:
                advance_pc(regs, hsr);
                return;
            case IO_UNHANDLED:
                /* IO unhandled, try another way to handle it. */
                break;
            }
        }

        /*
         * First check if the translation fault can be resolved by the
         * P2M subsystem. If that's the case nothing else to do.
         */
        if ( p2m_resolve_translation_fault(current->domain,
                                           gaddr_to_gfn(gpa)) )
            return;

        if ( is_data && try_map_mmio(gaddr_to_gfn(gpa)) )
            return;

        break;
    default:
        gprintk(XENLOG_WARNING, "Unsupported FSC: HSR=%#x DFSC=%#x\n",
                hsr.bits, xabt.fsc);
    }

inject_abt:
    gdprintk(XENLOG_DEBUG, "HSR=0x%x pc=%#"PRIregister" gva=%#"PRIvaddr
             " gpa=%#"PRIpaddr"\n", hsr.bits, regs->pc, gva, gpa);
    if ( is_data )
        inject_dabt_exception(regs, gva, hsr.len);
    else
        inject_iabt_exception(regs, gva, hsr.len);
}

static inline bool needs_ssbd_flip(struct vcpu *v)
{
    if ( !check_workaround_ssbd() )
        return false;

    return !(v->arch.cpu_info->flags & CPUINFO_WORKAROUND_2_FLAG) &&
             cpu_require_ssbd_mitigation();
}

/*
 * Actions that needs to be done after entering the hypervisor from the
 * guest and before the interrupts are unmasked.
 */
void enter_hypervisor_from_guest_preirq(void)
{
    struct vcpu *v = current;

    /* If the guest has disabled the workaround, bring it back on. */
    if ( needs_ssbd_flip(v) )
        arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_2_FID, 1, NULL);
}

/*
 * Actions that needs to be done after entering the hypervisor from the
 * guest and before we handle any request. Depending on the exception trap,
 * this may be called with interrupts unmasked.
 */
void enter_hypervisor_from_guest(void)
{
    struct vcpu *v = current;

    /*
     * If we pended a virtual abort, preserve it until it gets cleared.
     * See ARM ARM DDI 0487A.j D1.14.3 (Virtual Interrupts) for details,
     * but the crucial bit is "On taking a vSError interrupt, HCR_EL2.VSE
     * (alias of HCR.VA) is cleared to 0."
     */
    if ( v->arch.hcr_el2 & HCR_VA )
        v->arch.hcr_el2 = READ_SYSREG(HCR_EL2);

#ifdef CONFIG_NEW_VGIC
    /*
     * We need to update the state of our emulated devices using level
     * triggered interrupts before syncing back the VGIC state.
     *
     * TODO: Investigate whether this is necessary to do on every
     * trap and how it can be optimised.
     */
    vtimer_update_irqs(v);
    vcpu_update_evtchn_irq(v);
#endif

    vgic_sync_from_lrs(v);
}

void do_trap_guest_sync(struct cpu_user_regs *regs)
{
    const union hsr hsr = { .bits = regs->hsr };

    switch ( hsr.ec )
    {
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
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_cp15_32);
        do_cp15_32(regs, hsr);
        break;
    case HSR_EC_CP15_64:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_cp15_64);
        do_cp15_64(regs, hsr);
        break;
    case HSR_EC_CP14_32:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_cp14_32);
        do_cp14_32(regs, hsr);
        break;
    case HSR_EC_CP14_64:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_cp14_64);
        do_cp14_64(regs, hsr);
        break;
    case HSR_EC_CP14_DBG:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_cp14_dbg);
        do_cp14_dbg(regs, hsr);
        break;
    case HSR_EC_CP:
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
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
        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_smc32);
        do_trap_smc(regs, hsr);
        break;
    case HSR_EC_HVC32:
    {
        register_t nr;

        GUEST_BUG_ON(!psr_mode_is_32bit(regs));
        perfc_incr(trap_hvc32);
#ifndef NDEBUG
        if ( (hsr.iss & 0xff00) == 0xff00 )
            return do_debug_trap(regs, hsr.iss & 0x00ff);
#endif
        if ( hsr.iss == 0 )
            return do_trap_hvc_smccc(regs);
        nr = regs->r12;
        do_trap_hypercall(regs, &nr, hsr);
        regs->r12 = (uint32_t)nr;
        break;
    }
#ifdef CONFIG_ARM_64
    case HSR_EC_HVC64:
        GUEST_BUG_ON(psr_mode_is_32bit(regs));
        perfc_incr(trap_hvc64);
#ifndef NDEBUG
        if ( (hsr.iss & 0xff00) == 0xff00 )
            return do_debug_trap(regs, hsr.iss & 0x00ff);
#endif
        if ( hsr.iss == 0 )
            return do_trap_hvc_smccc(regs);
        do_trap_hypercall(regs, &regs->x16, hsr);
        break;
    case HSR_EC_SMC64:
        /*
         * HCR_EL2.TSC
         *
         * ARMv8 (DDI 0487A.d): D1-1501 Table D1-44
         */
        GUEST_BUG_ON(psr_mode_is_32bit(regs));
        perfc_incr(trap_smc64);
        do_trap_smc(regs, hsr);
        break;
    case HSR_EC_SYSREG:
        GUEST_BUG_ON(psr_mode_is_32bit(regs));
        perfc_incr(trap_sysreg);
        do_sysreg(regs, hsr);
        break;
#endif

    case HSR_EC_INSTR_ABORT_LOWER_EL:
        perfc_incr(trap_iabt);
        do_trap_stage2_abort_guest(regs, hsr);
        break;
    case HSR_EC_DATA_ABORT_LOWER_EL:
        perfc_incr(trap_dabt);
        do_trap_stage2_abort_guest(regs, hsr);
        break;

    default:
        gprintk(XENLOG_WARNING,
                "Unknown Guest Trap. HSR=0x%x EC=0x%x IL=%x Syndrome=0x%"PRIx32"\n",
                hsr.bits, hsr.ec, hsr.len, hsr.iss);
        inject_undef_exception(regs, hsr);
    }
}

void do_trap_hyp_sync(struct cpu_user_regs *regs)
{
    const union hsr hsr = { .bits = regs->hsr };

    switch ( hsr.ec )
    {
#ifdef CONFIG_ARM_64
    case HSR_EC_BRK:
        do_trap_brk(regs, hsr);
        break;
#endif
    case HSR_EC_DATA_ABORT_CURR_EL:
    case HSR_EC_INSTR_ABORT_CURR_EL:
    {
        bool is_data = (hsr.ec == HSR_EC_DATA_ABORT_CURR_EL);
        const char *fault = (is_data) ? "Data Abort" : "Instruction Abort";

        printk("%s Trap. Syndrome=%#x\n", fault, hsr.iss);
        /*
         * FAR may not be valid for a Synchronous External abort other
         * than translation table walk.
         */
        if ( hsr.xabt.fsc == FSC_SEA && hsr.xabt.fnv )
            printk("Invalid FAR, not walking the hypervisor tables\n");
        else
            dump_hyp_walk(get_hfar(is_data));

        do_unexpected_trap(fault, regs);

        break;
    }
    default:
        printk("Hypervisor Trap. HSR=0x%x EC=0x%x IL=%x Syndrome=0x%"PRIx32"\n",
               hsr.bits, hsr.ec, hsr.len, hsr.iss);
        do_unexpected_trap("Hypervisor", regs);
    }
}

void do_trap_hyp_serror(struct cpu_user_regs *regs)
{
    __do_trap_serror(regs, VABORT_GEN_BY_GUEST(regs));
}

void do_trap_guest_serror(struct cpu_user_regs *regs)
{
    __do_trap_serror(regs, true);
}

void do_trap_irq(struct cpu_user_regs *regs)
{
    gic_interrupt(regs, 0);
}

void do_trap_fiq(struct cpu_user_regs *regs)
{
    gic_interrupt(regs, 1);
}

static void check_for_pcpu_work(void)
{
    ASSERT(!local_irq_is_enabled());

    while ( softirq_pending(smp_processor_id()) )
    {
        local_irq_enable();
        do_softirq();
        /*
         * Must be the last one - as the IPI will trigger us to come here
         * and we want to patch the hypervisor with almost no stack.
         */
        check_for_livepatch_work();
        local_irq_disable();
    }
}

/*
 * Process pending work for the vCPU. Any call should be fast or
 * implement preemption.
 */
static void check_for_vcpu_work(void)
{
    struct vcpu *v = current;

    if ( likely(!v->arch.need_flush_to_ram) )
        return;

    /*
     * Give a chance for the pCPU to process work before handling the vCPU
     * pending work.
     */
    check_for_pcpu_work();

    local_irq_enable();
    p2m_flush_vm(v);
    local_irq_disable();
}

/*
 * Actions that needs to be done before entering the guest. This is the
 * last thing executed before the guest context is fully restored.
 *
 * The function will return with IRQ masked.
 */
void leave_hypervisor_to_guest(void)
{
    local_irq_disable();

    check_for_vcpu_work();
    check_for_pcpu_work();

    vgic_sync_to_lrs();

    /*
     * If the SErrors handle option is "DIVERSE", we have to prevent
     * slipping the hypervisor SError to guest. In this option, before
     * returning from trap, we have to synchronize SErrors to guarantee
     * that the pending SError would be caught in hypervisor.
     *
     * If option is NOT "DIVERSE", SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT
     * will be set to cpu_hwcaps. This means we can use the alternative
     * to skip synchronizing SErrors for other SErrors handle options.
     */
    SYNCHRONIZE_SERROR(SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT);

    /*
     * The hypervisor runs with the workaround always present.
     * If the guest wants it disabled, so be it...
     */
    if ( needs_ssbd_flip(current) )
        arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_2_FID, 0, NULL);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
