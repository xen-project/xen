/*
 * xen/arch/arm/arm64/vcpreg.c
 *
 * Emulate co-processor registers trapped.
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

#include <xen/sched.h>

#include <asm/cpregs.h>
#include <asm/current.h>
#include <asm/regs.h>
#include <asm/traps.h>
#include <asm/vtimer.h>

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
            return inject_undef_exception(regs, hsr);
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

void do_cp14_32(struct cpu_user_regs *regs, const union hsr hsr)
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
    gdprintk(XENLOG_ERR, "unhandled 64-bit CP14 access %#x\n",
             hsr.bits & HSR_CP64_REGS_MASK);
    inject_undef_exception(regs, hsr);
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
    inject_undef_exception(regs, hsr);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
