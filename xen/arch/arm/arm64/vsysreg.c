/*
 * xen/arch/arm/arm64/sysreg.c
 *
 * Emulate system registers trapped.
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

#include <asm/current.h>
#include <asm/regs.h>
#include <asm/traps.h>
#include <asm/vtimer.h>

void do_sysreg(struct cpu_user_regs *regs,
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
     * GIC Architecture Specification (IHI 0069C): Section 4.6.3
     */
    case HSR_SYSREG_ICC_SGI1R_EL1:
    case HSR_SYSREG_ICC_ASGI1R_EL1:
    case HSR_SYSREG_ICC_SGI0R_EL1:

        if ( !vgic_emulate(regs, hsr) )
            return inject_undef64_exception(regs, hsr.len);
        break;

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
