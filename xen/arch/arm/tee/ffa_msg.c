/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/sizes.h>
#include <xen/types.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

void ffa_handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    struct arm_smccc_1_2_regs resp = { };
    struct domain *d = current->domain;
    uint32_t src_dst;
    uint64_t mask;

    if ( smccc_is_conv_64(fid) )
        mask = GENMASK_ULL(63, 0);
    else
        mask = GENMASK_ULL(31, 0);

    if ( !ffa_fw_supports_fid(fid) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != ffa_get_vm_id(d) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    /* we do not support direct messages to VMs */
    if ( !FFA_ID_IS_SECURE(src_dst & GENMASK(15,0)) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    arg.a1 = src_dst;
    arg.a2 = get_user_reg(regs, 2) & mask;
    arg.a3 = get_user_reg(regs, 3) & mask;
    arg.a4 = get_user_reg(regs, 4) & mask;
    arg.a5 = get_user_reg(regs, 5) & mask;
    arg.a6 = get_user_reg(regs, 6) & mask;
    arg.a7 = get_user_reg(regs, 7) & mask;

    arm_smccc_1_2_smc(&arg, &resp);
    switch ( resp.a0 )
    {
    case FFA_ERROR:
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
    case FFA_MSG_SEND_DIRECT_RESP_32:
    case FFA_MSG_SEND_DIRECT_RESP_64:
        break;
    default:
        /* Bad fid, report back to the caller. */
        memset(&resp, 0, sizeof(resp));
        resp.a0 = FFA_ERROR;
        resp.a1 = src_dst;
        resp.a2 = FFA_RET_ABORTED;
    }

out:
    ffa_set_regs(regs, resp.a0, resp.a1 & mask, resp.a2 & mask, resp.a3 & mask,
                 resp.a4 & mask, resp.a5 & mask, resp.a6 & mask,
                 resp.a7 & mask);
}
