/*
 * common MCA implementation for AMD CPUs.
 * Copyright (c) 2012-2014 Advanced Micro Devices, Inc.
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

/* K8 common MCA documentation published at
 *
 * AMD64 Architecture Programmer's Manual Volume 2:
 * System Programming
 * Publication # 24593 Revision: 3.24
 * Issue Date: October 2013
 *
 * URL:
 * http://support.amd.com/TechDocs/24593.pdf 
 */

/* The related documentation for K8 Revisions A - E is:
 *
 * BIOS and Kernel Developer's Guide for
 * AMD Athlon 64 and AMD Opteron Processors
 * Publication # 26094 Revision: 3.30
 * Issue Date: February 2006
 *
 * URL:
 * http://support.amd.com/TechDocs/26094.PDF 
 */

/* The related documentation for K8 Revisions F - G is:
 *
 * BIOS and Kernel Developer's Guide for
 * AMD NPT Family 0Fh Processors
 * Publication # 32559 Revision: 3.08
 * Issue Date: July 2007
 *
 * URL:
 * http://support.amd.com/TechDocs/32559.pdf 
 */

/* Family10 MCA documentation published at
 *
 * BIOS and Kernel Developer's Guide
 * For AMD Family 10h Processors
 * Publication # 31116 Revision: 3.62
 * Isse Date: January 11, 2013
 *
 * URL:
 * http://support.amd.com/TechDocs/31116.pdf 
 */

#include <xen/init.h>
#include <xen/types.h>

#include <asm/msr.h>
#include <asm/processor.h>

#include "mce.h"
#include "x86_mca.h"
#include "mce_amd.h"
#include "mcaction.h"
#include "mce_quirks.h"
#include "vmce.h"

#define ANY -1

static const struct mce_quirkdata mce_amd_quirks[] = {
    { 0xf /* cpu family */, ANY /* all models */, ANY /* all steppings */,
      MCEQUIRK_K8_GART },
    { 0x10 /* cpu family */, ANY /* all models */, ANY /* all steppings */,
      MCEQUIRK_F10_GART },
};

/* Error Code Types */
enum mc_ec_type {
    MC_EC_TLB_TYPE = 0x0010,
    MC_EC_MEM_TYPE = 0x0100,
    MC_EC_BUS_TYPE = 0x0800,
};

enum mc_ec_type
mc_ec2type(uint16_t errorcode)
{
    if ( errorcode & MC_EC_BUS_TYPE )
        return MC_EC_BUS_TYPE;
    if ( errorcode & MC_EC_MEM_TYPE )
        return MC_EC_MEM_TYPE;
    if ( errorcode & MC_EC_TLB_TYPE )
        return MC_EC_TLB_TYPE;
    /* Unreached */
    BUG();
    return 0;
}

int
mc_amd_recoverable_scan(uint64_t status)
{
    int ret = 0;
    enum mc_ec_type ectype;
    uint16_t errorcode;

    if ( !(status & MCi_STATUS_UC) )
        return 1;

    errorcode = status & (MCi_STATUS_MCA | MCi_STATUS_MSEC);
    ectype = mc_ec2type(errorcode);

    switch ( ectype )
    {
    case MC_EC_BUS_TYPE: /* value in addr MSR is physical */
        /* should run cpu offline action */
        break;
    case MC_EC_MEM_TYPE: /* value in addr MSR is physical */
        ret = 1; /* run memory page offline action */
        break;
    case MC_EC_TLB_TYPE: /* value in addr MSR is virtual */
        /* should run tlb flush action and retry */
        break;
    }

    return ret;
}

int
mc_amd_addrcheck(uint64_t status, uint64_t misc, int addrtype)
{
    enum mc_ec_type ectype;
    uint16_t errorcode;

    errorcode = status & (MCi_STATUS_MCA | MCi_STATUS_MSEC);
    ectype = mc_ec2type(errorcode);

    switch ( ectype )
    {
    case MC_EC_BUS_TYPE: /* value in addr MSR is physical */
    case MC_EC_MEM_TYPE: /* value in addr MSR is physical */
        return (addrtype == MC_ADDR_PHYSICAL);
    case MC_EC_TLB_TYPE: /* value in addr MSR is virtual */
        return (addrtype == MC_ADDR_VIRTUAL);
    }

    /* unreached */
    BUG();
    return 0;
}

/* MC quirks */
enum mcequirk_amd_flags
mcequirk_lookup_amd_quirkdata(struct cpuinfo_x86 *c)
{
    int i;

    BUG_ON(c->x86_vendor != X86_VENDOR_AMD);

    for ( i = 0; i < ARRAY_SIZE(mce_amd_quirks); i++ )
    {
        if ( c->x86 != mce_amd_quirks[i].cpu_family )
            continue;
        if ( (mce_amd_quirks[i].cpu_model != ANY) &&
             (mce_amd_quirks[i].cpu_model != c->x86_model) )
            continue;
        if ( (mce_amd_quirks[i].cpu_stepping != ANY) &&
             (mce_amd_quirks[i].cpu_stepping != c->x86_mask) )
                continue;
        return mce_amd_quirks[i].quirk;
    }
    return 0;
}

int mcequirk_amd_apply(enum mcequirk_amd_flags flags)
{
    uint64_t val;

    switch ( flags )
    {
    case MCEQUIRK_K8_GART:
        /*
         * Enable error reporting for all errors except for GART
         * TBL walk error reporting, which trips off incorrectly
         * with AGP GART & 3ware & Cerberus.
         */
        wrmsrl(MSR_IA32_MCx_CTL(4), ~(1ULL << 10));
        wrmsrl(MSR_IA32_MCx_STATUS(4), 0ULL);
        break;
    case MCEQUIRK_F10_GART:
        if ( rdmsr_safe(MSR_AMD64_MCx_MASK(4), val) == 0 )
                wrmsr_safe(MSR_AMD64_MCx_MASK(4), val | (1 << 10));
        break;
    }

    return 0;
}

static struct mcinfo_extended *
amd_f10_handler(struct mc_info *mi, uint16_t bank, uint64_t status)
{
    struct mcinfo_extended *mc_ext;

    /* Family 0x10 introduced additional MSR that belong to the
     * northbridge bank (4). */
    if ( mi == NULL || bank != 4 )
        return NULL;

    if ( !(status & MCi_STATUS_VAL) )
        return NULL;

    if ( !(status & MCi_STATUS_MISCV) )
        return NULL;

    mc_ext = x86_mcinfo_reserve(mi, sizeof(*mc_ext));
    if ( !mc_ext )
    {
        mi->flags |= MCINFO_FLAGS_UNCOMPLETE;
        return NULL;
    }

    mc_ext->common.type = MC_TYPE_EXTENDED;
    mc_ext->common.size = sizeof(*mc_ext);
    mc_ext->mc_msrs = 3;

    mc_ext->mc_msr[0].reg = MSR_F10_MC4_MISC1;
    mc_ext->mc_msr[1].reg = MSR_F10_MC4_MISC2;
    mc_ext->mc_msr[2].reg = MSR_F10_MC4_MISC3;

    mc_ext->mc_msr[0].value = mca_rdmsr(MSR_F10_MC4_MISC1);
    mc_ext->mc_msr[1].value = mca_rdmsr(MSR_F10_MC4_MISC2);
    mc_ext->mc_msr[2].value = mca_rdmsr(MSR_F10_MC4_MISC3);

    return mc_ext;
}

static int amd_need_clearbank_scan(enum mca_source who, uint64_t status)
{
    if ( who != MCA_MCE_SCAN )
        return 1;

    /*
     * For fatal error, it shouldn't be cleared so that sticky bank
     * have a chance to be handled after reboot by polling.
     */
    if ( (status & MCi_STATUS_UC) && (status & MCi_STATUS_PCC) )
        return 0;

    return 1;
}

/* AMD specific MCA MSR */
int vmce_amd_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val)
{
    /* Do nothing as we don't emulate this MC bank currently */
    mce_printk(MCE_VERBOSE, "MCE: wr msr %#"PRIx64"\n", val);
    return 1;
}

int vmce_amd_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val)
{
    /* Assign '0' as we don't emulate this MC bank currently */
    *val = 0;
    return 1;
}

enum mcheck_type
amd_mcheck_init(struct cpuinfo_x86 *ci)
{
    uint32_t i;
    enum mcequirk_amd_flags quirkflag = mcequirk_lookup_amd_quirkdata(ci);

    /* Assume that machine check support is available.
     * The minimum provided support is at least the K8. */
    mce_handler_init();
    x86_mce_vector_register(mcheck_cmn_handler);
    mce_need_clearbank_register(amd_need_clearbank_scan);

    for ( i = 0; i < nr_mce_banks; i++ )
    {
        if ( quirkflag == MCEQUIRK_K8_GART && i == 4 )
            mcequirk_amd_apply(quirkflag);
        else
        {
            /* Enable error reporting of all errors */
            wrmsrl(MSR_IA32_MCx_CTL(i), 0xffffffffffffffffULL);
            wrmsrl(MSR_IA32_MCx_STATUS(i), 0x0ULL);
        }
    }

    if ( ci->x86 == 0xf )
        return mcheck_amd_k8;

    if ( quirkflag == MCEQUIRK_F10_GART )
        mcequirk_amd_apply(quirkflag);

    x86_mce_callback_register(amd_f10_handler);
    mce_recoverable_register(mc_amd_recoverable_scan);
    mce_register_addrcheck(mc_amd_addrcheck);

    return mcheck_amd_famXX;
}
