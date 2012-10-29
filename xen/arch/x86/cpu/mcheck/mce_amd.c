/*
 * common MCA implementation for AMD CPUs.
 * Copyright (c) 2012 Advanced Micro Devices, Inc.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

    switch (ectype) {
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

enum mcheck_type
amd_mcheck_init(struct cpuinfo_x86 *ci)
{
    enum mcheck_type rc = mcheck_none;

    switch ( ci->x86 )
    {
    default:
        /* Assume that machine check support is available.
         * The minimum provided support is at least the K8. */
    case 0xf:
        rc = amd_k8_mcheck_init(ci);
        break;

    case 0x10 ... 0x17:
        rc = amd_f10_mcheck_init(ci);
        break;
    }

    return rc;
}
