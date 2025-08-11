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

/* Encoding of partition message in RX/TX buffer */
struct ffa_part_msg_rxtx {
    uint32_t flags;
    uint32_t reserved;
    uint32_t msg_offset;
    uint32_t send_recv_id;
    uint32_t msg_size;
};

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

static int32_t ffa_msg_send2_vm(uint16_t dst_id, const void *src_buf,
                                struct ffa_part_msg_rxtx *src_msg)
{
    struct domain *dst_d;
    struct ffa_ctx *dst_ctx;
    struct ffa_part_msg_rxtx *dst_msg;
    int err;
    int32_t ret;

    if ( dst_id == 0 )
        /* FF-A ID 0 is the hypervisor, this is not valid */
        return FFA_RET_INVALID_PARAMETERS;

    /* This is also checking that dest is not src */
    err = rcu_lock_live_remote_domain_by_id(dst_id - 1, &dst_d);
    if ( err )
        return FFA_RET_INVALID_PARAMETERS;

    if ( dst_d->arch.tee == NULL )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    dst_ctx = dst_d->arch.tee;
    if ( !dst_ctx->guest_vers )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    /* This also checks that destination has set a Rx buffer */
    ret = ffa_rx_acquire(dst_d);
    if ( ret )
        goto out_unlock;

    /* we need to have enough space in the destination buffer */
    if ( (dst_ctx->page_count * FFA_PAGE_SIZE -
          sizeof(struct ffa_part_msg_rxtx)) < src_msg->msg_size )
    {
        ret = FFA_RET_NO_MEMORY;
        ffa_rx_release(dst_d);
        goto out_unlock;
    }

    dst_msg = dst_ctx->rx;

    /* prepare destination header */
    dst_msg->flags = 0;
    dst_msg->reserved = 0;
    dst_msg->msg_offset = sizeof(struct ffa_part_msg_rxtx);
    dst_msg->send_recv_id = src_msg->send_recv_id;
    dst_msg->msg_size = src_msg->msg_size;

    memcpy(dst_ctx->rx + sizeof(struct ffa_part_msg_rxtx),
           src_buf + src_msg->msg_offset, src_msg->msg_size);

    /* receiver rx buffer will be released by the receiver*/

out_unlock:
    rcu_unlock_domain(dst_d);
    if ( !ret )
        ffa_raise_rx_buffer_full(dst_d);

    return ret;
}

int32_t ffa_handle_msg_send2(struct cpu_user_regs *regs)
{
    struct domain *src_d = current->domain;
    struct ffa_ctx *src_ctx = src_d->arch.tee;
    struct ffa_part_msg_rxtx src_msg;
    uint16_t dst_id, src_id;
    int32_t ret;

    BUILD_BUG_ON(sizeof(struct ffa_part_msg_rxtx) >= FFA_PAGE_SIZE);

    if ( !spin_trylock(&src_ctx->tx_lock) )
        return FFA_RET_BUSY;

    /* create a copy of the message header */
    memcpy(&src_msg, src_ctx->tx, sizeof(src_msg));

    src_id = src_msg.send_recv_id >> 16;
    dst_id = src_msg.send_recv_id & GENMASK(15,0);

    if ( src_id != ffa_get_vm_id(src_d) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    /* check source message fits in buffer */
    if ( src_msg.msg_offset < sizeof(struct ffa_part_msg_rxtx) ||
            src_msg.msg_size == 0 ||
            src_msg.msg_offset > src_ctx->page_count * FFA_PAGE_SIZE ||
            src_msg.msg_size > (src_ctx->page_count * FFA_PAGE_SIZE -
                                src_msg.msg_offset) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    if ( FFA_ID_IS_SECURE(dst_id) )
    {
        /* Message for a secure partition */
        if ( !ffa_fw_supports_fid(FFA_MSG_SEND2) )
        {
            ret = FFA_RET_NOT_SUPPORTED;
            goto out;
        }

        ret = ffa_simple_call(FFA_MSG_SEND2,
                              ((uint32_t)ffa_get_vm_id(src_d)) << 16, 0, 0, 0);
    }
    else if ( IS_ENABLED(CONFIG_FFA_VM_TO_VM) )
    {
        /* Message for a VM */
        ret = ffa_msg_send2_vm(dst_id, src_ctx->tx, &src_msg);
    }
    else
        ret = FFA_RET_INVALID_PARAMETERS;

out:
    spin_unlock(&src_ctx->tx_lock);
    return ret;
}
