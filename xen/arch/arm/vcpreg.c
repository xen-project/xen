/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/arm64/vcpreg.c
 *
 * Emulate co-processor registers trapped.
 *
 * Copyright (c) 2011 Citrix Systems.
 */

#include <xen/sched.h>

#include <asm/cpufeature.h>
#include <asm/cpregs.h>
#include <asm/current.h>
#include <asm/regs.h>
#include <asm/traps.h>
#include <asm/vreg.h>
#include <asm/vtimer.h>

/*
 * Macros to help generating helpers for registers trapped when
 * HCR_EL2.TVM is set.
 *
 * Note that it only traps NS write access from EL1.
 *
 *  - TVM_REG() should not be used outside of the macros. It is there to
 *    help defining TVM_REG32() and TVM_REG64()
 *  - TVM_REG32(regname, xreg) and TVM_REG64(regname, xreg) are used to
 *    resp. generate helper accessing 32-bit and 64-bit register. "regname"
 *    is the Arm32 name and "xreg" the Arm64 name.
 *  - TVM_REG32_COMBINED(lowreg, hireg, xreg) are used to generate a
 *    pair of register sharing the same Arm64 register, but are 2 distinct
 *    Arm32 registers. "lowreg" and "hireg" contains the name for on Arm32
 *    registers, "xreg" contains the name for the combined register on Arm64.
 *    The definition of "lowreg" and "higreg" match the Armv8 specification,
 *    this means "lowreg" is an alias to xreg[31:0] and "high" is an alias to
 *    xreg[63:32].
 *
 */

#ifdef CONFIG_ARM_64
#define WRITE_SYSREG_SZ(sz, val, sysreg) \
    WRITE_SYSREG((uint##sz##_t)(val), sysreg)
#else
/*
 * WRITE_SYSREG{32/64} on arm32 is defined as variadic macro which imposes
 * on the below macro to be defined like that as well.
 */
#define WRITE_SYSREG_SZ(sz, val, sysreg...)  WRITE_SYSREG##sz(val, sysreg)
#endif

/*
 * type32_t is defined as register_t due to the vreg_emulate_cp32 and
 * vreg_emulate_sysreg taking function pointer with register_t type used for
 * passing register's value.
 */
typedef register_t type32_t;
typedef uint64_t type64_t;

/* The name is passed from the upper macro to workaround macro expansion. */
#define TVM_REG(sz, func, reg...)                                           \
static bool func(struct cpu_user_regs *regs, type##sz##_t *r, bool read)    \
{                                                                           \
    struct vcpu *v = current;                                               \
    bool cache_enabled = vcpu_has_cache_enabled(v);                         \
                                                                            \
    GUEST_BUG_ON(read);                                                     \
    WRITE_SYSREG_SZ(sz, *(r), reg);                                         \
                                                                            \
    p2m_toggle_cache(v, cache_enabled);                                     \
                                                                            \
    return true;                                                            \
}

#define TVM_REG32(regname, xreg) TVM_REG(32, vreg_emulate_##regname, xreg)
#define TVM_REG64(regname, xreg) TVM_REG(64, vreg_emulate_##regname, xreg)

#ifdef CONFIG_ARM_32
#define TVM_REG32_COMBINED(lowreg, hireg, xreg)                     \
    /* Use TVM_REG directly to workaround macro expansion. */       \
    TVM_REG(32, vreg_emulate_##lowreg, lowreg)                      \
    TVM_REG(32, vreg_emulate_##hireg, hireg)

#else /* CONFIG_ARM_64 */
#define TVM_REG32_COMBINED(lowreg, hireg, xreg)                             \
static bool vreg_emulate_##xreg(struct cpu_user_regs *regs, register_t *r,  \
                                bool read, bool hi)                         \
{                                                                           \
    struct vcpu *v = current;                                               \
    bool cache_enabled = vcpu_has_cache_enabled(v);                         \
    register_t reg = READ_SYSREG(xreg);                                     \
                                                                            \
    GUEST_BUG_ON(read);                                                     \
    if ( hi ) /* reg[63:32] is AArch32 register hireg */                    \
    {                                                                       \
        reg &= GENMASK(31, 0);                                              \
        reg |= ((uint64_t)*r) << 32;                                        \
    }                                                                       \
    else /* reg[31:0] is AArch32 register lowreg. */                        \
    {                                                                       \
        reg &= GENMASK(63, 32);                                             \
        reg |= *r;                                                          \
    }                                                                       \
    WRITE_SYSREG(reg, xreg);                                                \
                                                                            \
    p2m_toggle_cache(v, cache_enabled);                                     \
                                                                            \
    return true;                                                            \
}                                                                           \
                                                                            \
static bool vreg_emulate_##lowreg(struct cpu_user_regs *regs, register_t *r,\
                                  bool read)                                \
{                                                                           \
    return vreg_emulate_##xreg(regs, r, read, false);                       \
}                                                                           \
                                                                            \
static bool vreg_emulate_##hireg(struct cpu_user_regs *regs, register_t *r, \
                                 bool read)                                 \
{                                                                           \
    return vreg_emulate_##xreg(regs, r, read, true);                        \
}
#endif

/* Defining helpers for emulating co-processor registers. */
TVM_REG32(SCTLR, SCTLR_EL1)
/*
 * AArch32 provides two way to access TTBR* depending on the access
 * size, whilst AArch64 provides one way.
 *
 * When using AArch32, for simplicity, use the same access size as the
 * guest.
 */
#ifdef CONFIG_ARM_32
TVM_REG32(TTBR0_32, TTBR0_32)
TVM_REG32(TTBR1_32, TTBR1_32)
#else
TVM_REG32(TTBR0_32, TTBR0_EL1)
TVM_REG32(TTBR1_32, TTBR1_EL1)
#endif
TVM_REG64(TTBR0, TTBR0_EL1)
TVM_REG64(TTBR1, TTBR1_EL1)
/* AArch32 registers TTBCR and TTBCR2 share AArch64 register TCR_EL1. */
TVM_REG32_COMBINED(TTBCR, TTBCR2, TCR_EL1)
TVM_REG32(DACR, DACR32_EL2)
TVM_REG32(DFSR, ESR_EL1)
TVM_REG32(IFSR, IFSR32_EL2)
/* AArch32 registers DFAR and IFAR shares AArch64 register FAR_EL1. */
TVM_REG32_COMBINED(DFAR, IFAR, FAR_EL1)
TVM_REG32(ADFSR, AFSR0_EL1)
TVM_REG32(AIFSR, AFSR1_EL1)
/* AArch32 registers MAIR0 and MAIR1 share AArch64 register MAIR_EL1. */
TVM_REG32_COMBINED(MAIR0, MAIR1, MAIR_EL1)
/* AArch32 registers AMAIR0 and AMAIR1 share AArch64 register AMAIR_EL1. */
TVM_REG32_COMBINED(AMAIR0, AMAIR1, AMAIR_EL1)
TVM_REG32(CONTEXTIDR, CONTEXTIDR_EL1)

/* Macro to generate easily case for co-processor emulation. */
#define GENERATE_CASE(reg, sz)                                      \
    case HSR_CPREG##sz(reg):                                        \
    {                                                               \
        bool res;                                                   \
                                                                    \
        res = vreg_emulate_cp##sz(regs, hsr, vreg_emulate_##reg);   \
        ASSERT(res);                                                \
        break;                                                      \
    }

/* Macro to generate easily case for ID co-processor emulation */
#define GENERATE_TID3_INFO(reg, field, offset)                      \
    case HSR_CPREG32(reg):                                          \
    {                                                               \
        return handle_ro_read_val(regs, regidx, cp32.read, hsr, 1,  \
                                  domain_cpuinfo.field.bits[offset]);\
    }

/* helper to define cases for all registers for one CRm value */
#define HSR_CPREG32_TID3_CASES(REG)     case HSR_CPREG32(p15,0,c0,REG,0): \
                                        case HSR_CPREG32(p15,0,c0,REG,1): \
                                        case HSR_CPREG32(p15,0,c0,REG,2): \
                                        case HSR_CPREG32(p15,0,c0,REG,3): \
                                        case HSR_CPREG32(p15,0,c0,REG,4): \
                                        case HSR_CPREG32(p15,0,c0,REG,5): \
                                        case HSR_CPREG32(p15,0,c0,REG,6): \
                                        case HSR_CPREG32(p15,0,c0,REG,7)

void do_cp15_32(struct cpu_user_regs *regs, const union hsr hsr)
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
            return inject_undef_exception(regs);
        break;

    /*
     * HCR_EL2.TACR / HCR.TAC
     *
     * ARMv7 (DDI 0406C.b): B1.14.6
     * ARMv8 (DDI 0487A.d): G6.2.1
     */
    case HSR_CPREG32(ACTLR):
        if ( regs_mode_is_user(regs) )
            return inject_undef_exception(regs);
        if ( cp32.read )
            set_user_reg(regs, regidx, v->arch.actlr);
        break;

    /*
     * HCR_EL2.TSW
     *
     * ARMv7 (DDI 0406C.b): B1.14.6
     * ARMv8 (DDI 0487B.b): Table D1-42
     */
    case HSR_CPREG32(DCISW):
    case HSR_CPREG32(DCCSW):
    case HSR_CPREG32(DCCISW):
        if ( !cp32.read )
            p2m_set_way_flush(current, regs);
        break;

    /*
     * HCR_EL2.TVM
     *
     * ARMv8 (DDI 0487D.a): Table D1-38
     */
    GENERATE_CASE(SCTLR, 32)
    GENERATE_CASE(TTBR0_32, 32)
    GENERATE_CASE(TTBR1_32, 32)
    GENERATE_CASE(TTBCR, 32)
    GENERATE_CASE(TTBCR2, 32)
    GENERATE_CASE(DACR, 32)
    GENERATE_CASE(DFSR, 32)
    GENERATE_CASE(IFSR, 32)
    GENERATE_CASE(DFAR, 32)
    GENERATE_CASE(IFAR, 32)
    GENERATE_CASE(ADFSR, 32)
    GENERATE_CASE(AIFSR, 32)
    /* AKA PRRR */
    GENERATE_CASE(MAIR0, 32)
    /* AKA NMRR */
    GENERATE_CASE(MAIR1, 32)
    GENERATE_CASE(AMAIR0, 32)
    GENERATE_CASE(AMAIR1, 32)
    GENERATE_CASE(CONTEXTIDR, 32)

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
        if ( regs_mode_is_user(regs) )
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
     * HCR_EL2.TID3
     *
     * This is trapping most Identification registers used by a guest
     * to identify the processor features
     */
    GENERATE_TID3_INFO(ID_PFR0, pfr32, 0)
    GENERATE_TID3_INFO(ID_PFR1, pfr32, 1)
    GENERATE_TID3_INFO(ID_PFR2, pfr32, 2)
    GENERATE_TID3_INFO(ID_DFR0, dbg32, 0)
    GENERATE_TID3_INFO(ID_DFR1, dbg32, 1)
    GENERATE_TID3_INFO(ID_AFR0, aux32, 0)
    GENERATE_TID3_INFO(ID_MMFR0, mm32, 0)
    GENERATE_TID3_INFO(ID_MMFR1, mm32, 1)
    GENERATE_TID3_INFO(ID_MMFR2, mm32, 2)
    GENERATE_TID3_INFO(ID_MMFR3, mm32, 3)
    GENERATE_TID3_INFO(ID_MMFR4, mm32, 4)
    GENERATE_TID3_INFO(ID_MMFR5, mm32, 5)
    GENERATE_TID3_INFO(ID_ISAR0, isa32, 0)
    GENERATE_TID3_INFO(ID_ISAR1, isa32, 1)
    GENERATE_TID3_INFO(ID_ISAR2, isa32, 2)
    GENERATE_TID3_INFO(ID_ISAR3, isa32, 3)
    GENERATE_TID3_INFO(ID_ISAR4, isa32, 4)
    GENERATE_TID3_INFO(ID_ISAR5, isa32, 5)
    GENERATE_TID3_INFO(ID_ISAR6, isa32, 6)
    /* MVFR registers are in cp10 not cp15 */

    /*
     * Those cases are catching all Reserved registers trapped by TID3 which
     * currently have no assignment.
     * HCR.TID3 is trapping all registers in the group 3:
     * coproc == p15, opc1 == 0, CRn == c0, CRm == {c2-c7}, opc2 == {0-7}.
     * Those registers are defined as being RO in the Arm Architecture
     * Reference manual Armv8 (Chapter D12.3.2 of issue F.c) so handle them
     * as Read-only read as zero.
     */
    case HSR_CPREG32(p15,0,c0,c3,0):
    case HSR_CPREG32(p15,0,c0,c3,1):
    case HSR_CPREG32(p15,0,c0,c3,2):
    case HSR_CPREG32(p15,0,c0,c3,3):
    case HSR_CPREG32(p15,0,c0,c3,7):
    HSR_CPREG32_TID3_CASES(c4):
    HSR_CPREG32_TID3_CASES(c5):
    HSR_CPREG32_TID3_CASES(c6):
    HSR_CPREG32_TID3_CASES(c7):
        return handle_ro_raz(regs, regidx, cp32.read, hsr, 1);

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
        gdprintk(XENLOG_ERR, "unhandled 32-bit CP15 access %#"PRIregister"\n",
                 hsr.bits & HSR_CP32_REGS_MASK);
        inject_undef_exception(regs);
        return;
    }
    advance_pc(regs, hsr);
}

void do_cp15_64(struct cpu_user_regs *regs, const union hsr hsr)
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
            return inject_undef_exception(regs);
        break;

    /*
     * HCR_EL2.FMO or HCR_EL2.IMO
     *
     * GIC Architecture Specification (IHI 0069C): Section 4.6.3
     */
    case HSR_CPREG64(ICC_SGI1R):
    case HSR_CPREG64(ICC_ASGI1R):
    case HSR_CPREG64(ICC_SGI0R):
        if ( !vgic_emulate(regs, hsr) )
            return inject_undef_exception(regs);
        break;

    GENERATE_CASE(TTBR0, 64)
    GENERATE_CASE(TTBR1, 64)

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
            gdprintk(XENLOG_ERR,
                     "unhandled 64-bit CP15 access %#"PRIregister"\n",
                     hsr.bits & HSR_CP64_REGS_MASK);
            inject_undef_exception(regs);
            return;
        }
    }
    advance_pc(regs, hsr);
}

void do_cp14_32(struct cpu_user_regs *regs, const union hsr hsr)
{
    const struct hsr_cp32 cp32 = hsr.cp32;
    int regidx = cp32.reg;

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
     *    DBGPRCR
     */
    case HSR_CPREG32(DBGOSLAR):
        return handle_wo_wi(regs, regidx, cp32.read, hsr, 1);
    case HSR_CPREG32(DBGOSLSR):
        return handle_ro_read_val(regs, regidx, cp32.read, hsr, 1, 1U << 3);
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
            return inject_undef_exception(regs);

        /* Implement the minimum requirements:
         *  - Number of watchpoints: 1
         *  - Number of breakpoints: 2
         *  - Version: ARMv7 v7.1
         *  - Variant and Revision bits match MDIR
         */
        val = (1 << 24) | (5 << 16);
        val |= ((current_cpu_data.midr.bits >> 20) & 0xf) |
                (current_cpu_data.midr.bits & 0xf);
        set_user_reg(regs, regidx, val);

        break;
    }

    /*
     * Xen doesn't expose a real (or emulated) Debug Communications Channel
     * (DCC) to a domain. Yet the Arm ARM implies this is not an optional
     * feature. So some domains may start to probe it. For instance, the
     * HVC_DCC driver in Linux (since f377775dc083 and at least up to v6.7),
     * will try to write some characters and check if the transmit buffer has
     * emptied.
     */
    case HSR_CPREG32(DBGDSCRINT):
        /*
         * By setting TX status bit (only if partial emulation is enabled) to
         * indicate the transmit buffer is full, we would hint the OS that the
         * DCC is probably not working.
         *
         * Bit 29: TX full
         *
         * Accessible at EL0 only if DBGDSCRext.UDCCdis is set to 0. We emulate
         * this as RAZ/WI in the next case. So RO at both EL0 and EL1.
         */
        return handle_ro_read_val(regs, regidx, cp32.read, hsr, 0,
                                  partial_emulation ? (1U << 29) : 0);

    case HSR_CPREG32(DBGDSCREXT):
        /*
         * Implement debug status and control register as RAZ/WI.
         * The OS won't use Hardware debug if MDBGen not set.
         */
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 1);

    /* DBGDTR[TR]XINT share the same encoding */
    case HSR_CPREG32(DBGDTRTXINT):
        /*
         * Emulate as RAZ/WI (only if partial emulation is enabled) to prevent
         * injecting undefined exception.
         * Accessible at EL0 only if DBGDSCREXT is set to 0. We emulate that
         * register as RAZ/WI.
         */
        if ( !partial_emulation )
            goto fail;
        return handle_raz_wi(regs, regidx, cp32.read, hsr, 0);

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
        goto fail;
    }

    advance_pc(regs, hsr);
    return;

 fail:
    gdprintk(XENLOG_ERR,
             "%s p14, %d, r%d, cr%d, cr%d, %d @ 0x%"PRIregister"\n",
             cp32.read ? "mrc" : "mcr",
             cp32.op1, cp32.reg, cp32.crn, cp32.crm, cp32.op2, regs->pc);
    gdprintk(XENLOG_ERR, "unhandled 32-bit cp14 access %#"PRIregister"\n",
             hsr.bits & HSR_CP32_REGS_MASK);
    inject_undef_exception(regs);
}

void do_cp14_64(struct cpu_user_regs *regs, const union hsr hsr)
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
    gdprintk(XENLOG_ERR, "unhandled 64-bit CP14 access %#"PRIregister"\n",
             hsr.bits & HSR_CP64_REGS_MASK);
    inject_undef_exception(regs);
}

void do_cp14_dbg(struct cpu_user_regs *regs, const union hsr hsr)
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
     * All unknown registers.
     */
    gdprintk(XENLOG_ERR,
             "%s p14, %d, r%d, r%d, cr%d @ 0x%"PRIregister"\n",
             cp64.read ? "mrrc" : "mcrr",
             cp64.op1, cp64.reg1, cp64.reg2, cp64.crm, regs->pc);
    gdprintk(XENLOG_ERR, "unhandled 64-bit CP14 DBG access %#"PRIregister"\n",
             hsr.bits & HSR_CP64_REGS_MASK);

    inject_undef_exception(regs);
}

void do_cp10(struct cpu_user_regs *regs, const union hsr hsr)
{
    const struct hsr_cp32 cp32 = hsr.cp32;
    int regidx = cp32.reg;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    /*
     * HCR.TID3 is trapping access to MVFR register used to identify the
     * VFP/Simd using VMRS/VMSR instructions.
     * Exception encoding is using MRC/MCR standard with the reg field in Crn
     * as are declared MVFR0 and MVFR1 in cpregs.h
     */
    GENERATE_TID3_INFO(MVFR0, mvfr, 0)
    GENERATE_TID3_INFO(MVFR1, mvfr, 1)
    GENERATE_TID3_INFO(MVFR2, mvfr, 2)

    default:
        gdprintk(XENLOG_ERR,
                 "%s p10, %d, r%d, cr%d, cr%d, %d @ 0x%"PRIregister"\n",
                 cp32.read ? "mrc" : "mcr",
                 cp32.op1, cp32.reg, cp32.crn, cp32.crm, cp32.op2, regs->pc);
        gdprintk(XENLOG_ERR, "unhandled 32-bit CP10 access %#"PRIregister"\n",
                 hsr.bits & HSR_CP32_REGS_MASK);
        inject_undef_exception(regs);
        return;
    }
    
    /*
     * All the cases in the switch should return. If this is not the
     * case, then something went wrong and it is best to crash the
     * domain.
     */
    ASSERT_UNREACHABLE();
    domain_crash(current->domain);
}

void do_cp(struct cpu_user_regs *regs, const union hsr hsr)
{
    const struct hsr_cp cp = hsr.cp;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    ASSERT(!cp.tas); /* We don't trap SIMD instruction */
    gdprintk(XENLOG_ERR, "unhandled CP%d access\n", cp.coproc);
    inject_undef_exception(regs);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
