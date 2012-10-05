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

#include "mce.h"
#include "x86_mca.h"
#include "mce_amd.h"

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
