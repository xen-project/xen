/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * common MCA implementation for AMD CPUs.
 * Copyright (c) 2012-2014 Advanced Micro Devices, Inc.
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
#include "vmce.h"

#define ANY (~0U)

enum mcequirk_amd_flags {
    MCEQUIRK_NONE,
    MCEQUIRK_K8_GART,
    MCEQUIRK_F10_GART,
};

static const struct mce_quirkdata {
    unsigned int cpu_family;
    unsigned int cpu_model;
    unsigned int cpu_stepping;
    enum mcequirk_amd_flags quirk;
} mce_amd_quirks[] = {
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

static enum mc_ec_type
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

bool cf_check mc_amd_recoverable_scan(uint64_t status)
{
    bool ret = false;
    enum mc_ec_type ectype;
    uint16_t errorcode;

    if ( !(status & MCi_STATUS_UC) )
        return true;

    errorcode = status & (MCi_STATUS_MCA | MCi_STATUS_MSEC);
    ectype = mc_ec2type(errorcode);

    switch ( ectype )
    {
    case MC_EC_BUS_TYPE: /* value in addr MSR is physical */
        /* should run cpu offline action */
        break;

    case MC_EC_MEM_TYPE: /* value in addr MSR is physical */
        ret = true; /* run memory page offline action */
        break;

    case MC_EC_TLB_TYPE: /* value in addr MSR is virtual */
        /* should run tlb flush action and retry */
        break;
    }

    return ret;
}

bool cf_check mc_amd_addrcheck(uint64_t status, uint64_t misc, int addrtype)
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
    return false;
}

/* MC quirks */
static enum mcequirk_amd_flags
mcequirk_lookup_amd_quirkdata(const struct cpuinfo_x86 *c)
{
    unsigned int i;

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

    return MCEQUIRK_NONE;
}

static void mcequirk_amd_apply(enum mcequirk_amd_flags flags)
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

    default:
        ASSERT(flags == MCEQUIRK_NONE);
        break;
    }
}

static struct mcinfo_extended *cf_check
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

    mc_ext = x86_mcinfo_reserve(mi, sizeof(*mc_ext), MC_TYPE_EXTENDED);
    if ( !mc_ext )
    {
        mi->flags |= MCINFO_FLAGS_UNCOMPLETE;
        return NULL;
    }

    mc_ext->mc_msrs = 3;

    mc_ext->mc_msr[0].reg = MSR_F10_MC4_MISC1;
    mc_ext->mc_msr[1].reg = MSR_F10_MC4_MISC2;
    mc_ext->mc_msr[2].reg = MSR_F10_MC4_MISC3;

    mc_ext->mc_msr[0].value = mca_rdmsr(MSR_F10_MC4_MISC1);
    mc_ext->mc_msr[1].value = mca_rdmsr(MSR_F10_MC4_MISC2);
    mc_ext->mc_msr[2].value = mca_rdmsr(MSR_F10_MC4_MISC3);

    return mc_ext;
}

static bool cf_check amd_need_clearbank_scan(
    enum mca_source who, uint64_t status)
{
    if ( who != MCA_MCE_SCAN )
        return true;

    /*
     * For fatal error, it shouldn't be cleared so that sticky bank
     * have a chance to be handled after reboot by polling.
     */
    if ( (status & MCi_STATUS_UC) && (status & MCi_STATUS_PCC) )
        return false;

    return true;
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

static const struct mce_callbacks __initconst_cf_clobber k8_callbacks = {
    .handler = mcheck_cmn_handler,
    .need_clearbank_scan = amd_need_clearbank_scan,
};

static const struct mce_callbacks __initconst_cf_clobber k10_callbacks = {
    .handler = mcheck_cmn_handler,
    .check_addr = mc_amd_addrcheck,
    .recoverable_scan = mc_amd_recoverable_scan,
    .need_clearbank_scan = amd_need_clearbank_scan,
    .info_collect = amd_f10_handler,
};

enum mcheck_type
amd_mcheck_init(const struct cpuinfo_x86 *c, bool bsp)
{
    uint32_t i;
    enum mcequirk_amd_flags quirkflag = 0;

    if ( c->x86_vendor != X86_VENDOR_HYGON )
        quirkflag = mcequirk_lookup_amd_quirkdata(c);

    /* Assume that machine check support is available.
     * The minimum provided support is at least the K8. */
    if ( bsp )
        mce_handler_init(c->x86 == 0xf ? &k8_callbacks : &k10_callbacks);

    for ( i = 0; i < this_cpu(nr_mce_banks); i++ )
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

    if ( c->x86 == 0xf )
        return mcheck_amd_k8;

    if ( quirkflag == MCEQUIRK_F10_GART )
        mcequirk_amd_apply(quirkflag);

    if ( cpu_has(c, X86_FEATURE_AMD_PPIN) &&
         (c == &boot_cpu_data || ppin_msr) )
    {
        uint64_t val;

        rdmsrl(MSR_AMD_PPIN_CTL, val);

        /* If PPIN is disabled, but not locked, try to enable. */
        if ( !(val & (PPIN_ENABLE | PPIN_LOCKOUT)) )
        {
            wrmsr_safe(MSR_PPIN_CTL, val | PPIN_ENABLE);
            rdmsrl(MSR_AMD_PPIN_CTL, val);
        }

        if ( !(val & PPIN_ENABLE) )
            ppin_msr = 0;
        else if ( c == &boot_cpu_data )
            ppin_msr = MSR_AMD_PPIN;
    }

    return c->x86_vendor == X86_VENDOR_HYGON ?
            mcheck_hygon : mcheck_amd_famXX;
}
