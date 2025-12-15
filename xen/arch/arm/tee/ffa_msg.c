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

static void ffa_finish_direct_req_run(struct cpu_user_regs *regs,
                                      struct arm_smccc_1_2_regs *req)
{
    struct arm_smccc_1_2_regs resp = { };
    uint64_t mask;

    arm_smccc_1_2_smc(req, &resp);

    switch ( resp.a0 )
    {
    case FFA_ERROR:
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
    case FFA_MSG_SEND_DIRECT_RESP_32:
    case FFA_MSG_SEND_DIRECT_RESP_64:
    case FFA_MSG_YIELD:
    case FFA_INTERRUPT:
        break;
    default:
        /* Bad fid, report back to the caller. */
        ffa_set_regs_error(regs, FFA_RET_ABORTED);
        return;
    }

    if ( smccc_is_conv_64(resp.a0) )
        mask = GENMASK_ULL(63, 0);
    else
        mask = GENMASK_ULL(31, 0);

    ffa_set_regs(regs, resp.a0, resp.a1 & mask, resp.a2 & mask, resp.a3 & mask,
                 resp.a4 & mask, resp.a5 & mask, resp.a6 & mask,
                 resp.a7 & mask);
}

void ffa_handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    struct domain *d = current->domain;
    uint32_t src_dst;
    uint64_t mask;
    int32_t ret;

    if ( !ffa_fw_supports_fid(fid) )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != ffa_get_vm_id(d) ||
         (src_dst & GENMASK(15,0)) == ffa_get_vm_id(d) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    /* we do not support direct messages to VMs */
    if ( !FFA_ID_IS_SECURE(src_dst & GENMASK(15,0)) )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    if ( smccc_is_conv_64(fid) )
        mask = GENMASK_ULL(63, 0);
    else
        mask = GENMASK_ULL(31, 0);

    arg.a1 = src_dst;
    arg.a2 = get_user_reg(regs, 2) & mask;
    arg.a3 = get_user_reg(regs, 3) & mask;
    arg.a4 = get_user_reg(regs, 4) & mask;
    arg.a5 = get_user_reg(regs, 5) & mask;
    arg.a6 = get_user_reg(regs, 6) & mask;
    arg.a7 = get_user_reg(regs, 7) & mask;

    ffa_finish_direct_req_run(regs, &arg);
    return;

out:
    ffa_set_regs_error(regs, ret);
}

static int32_t ffa_msg_send2_vm(uint16_t dst_id, const void *src_buf,
                                struct ffa_part_msg_rxtx *src_msg)
{
    struct domain *dst_d;
    struct ffa_ctx *dst_ctx;
    struct ffa_part_msg_rxtx *dst_msg;
    void *rx_buf;
    size_t rx_size;
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
    if ( !ACCESS_ONCE(dst_ctx->guest_vers) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    /* This also checks that destination has set a Rx buffer */
    ret = ffa_rx_acquire(dst_ctx , &rx_buf, &rx_size);
    if ( ret )
        goto out_unlock;

    /* we need to have enough space in the destination buffer */
    if ( (rx_size - sizeof(struct ffa_part_msg_rxtx)) < src_msg->msg_size )
    {
        ret = FFA_RET_NO_MEMORY;
        ffa_rx_release(dst_ctx);
        goto out_unlock;
    }

    dst_msg = rx_buf;

    /* prepare destination header */
    dst_msg->flags = 0;
    dst_msg->reserved = 0;
    dst_msg->msg_offset = sizeof(struct ffa_part_msg_rxtx);
    dst_msg->send_recv_id = src_msg->send_recv_id;
    dst_msg->msg_size = src_msg->msg_size;

    memcpy(rx_buf + sizeof(struct ffa_part_msg_rxtx),
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
    const void *tx_buf;
    size_t tx_size;
    struct ffa_part_msg_rxtx src_msg;
    uint16_t dst_id, src_id;
    int32_t ret;

    BUILD_BUG_ON(sizeof(struct ffa_part_msg_rxtx) >= FFA_PAGE_SIZE);

    ret = ffa_tx_acquire(src_ctx, &tx_buf, &tx_size);
    if ( ret != FFA_RET_OK )
        return ret;

    /* create a copy of the message header */
    memcpy(&src_msg, tx_buf, sizeof(src_msg));

    src_id = src_msg.send_recv_id >> 16;
    dst_id = src_msg.send_recv_id & GENMASK(15,0);

    if ( src_id != ffa_get_vm_id(src_d) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    /* check source message fits in buffer */
    if ( src_msg.msg_offset < sizeof(struct ffa_part_msg_rxtx) ||
            src_msg.msg_size == 0 || src_msg.msg_offset > tx_size ||
            src_msg.msg_size > (tx_size - src_msg.msg_offset) )
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
        ret = ffa_msg_send2_vm(dst_id, tx_buf, &src_msg);
    }
    else
        ret = FFA_RET_INVALID_PARAMETERS;

out:
    ffa_tx_release(src_ctx);
    return ret;
}

void ffa_handle_run(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    uint32_t dst = get_user_reg(regs, 1);
    int32_t ret;

    if ( !ffa_fw_supports_fid(fid) )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    /*
     * We do not support FFA_RUN to VMs.
     * Destination endpoint ID is in bits [31:16], bits[15:0] contain the
     * vCPU ID.
     */
    if ( !FFA_ID_IS_SECURE(dst >> 16) )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    arg.a1 = dst;

    ffa_finish_direct_req_run(regs, &arg);

    return;

out:
    ffa_set_regs_error(regs, ret);
}
