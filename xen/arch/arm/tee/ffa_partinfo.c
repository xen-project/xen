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

/* Partition information descriptor defined in FF-A-1.0-REL */
struct ffa_partition_info_1_0 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
};

/* Partition information descriptor defined in FF-A-1.1-REL0 */
struct ffa_partition_info_1_1 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
    uint8_t uuid[16];
};

/* SPs subscribing to VM_CREATE and VM_DESTROYED events */
static uint16_t *subscr_vm_created __read_mostly;
static uint16_t subscr_vm_created_count __read_mostly;
static uint16_t *subscr_vm_destroyed __read_mostly;
static uint16_t subscr_vm_destroyed_count __read_mostly;

static int32_t ffa_partition_info_get(uint32_t *uuid, uint32_t flags,
                                      uint32_t *count, uint32_t *fpi_size)
{
    struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_PARTITION_INFO_GET,
        .a5 = flags,
    };
    struct arm_smccc_1_2_regs resp;
    uint32_t ret;

    if ( uuid )
    {
        arg.a1 = uuid[0];
        arg.a2 = uuid[1];
        arg.a3 = uuid[2];
        arg.a4 = uuid[3];
    }

    arm_smccc_1_2_smc(&arg, &resp);

    ret = ffa_get_ret_code(&resp);
    if ( !ret )
    {
        *count = resp.a2;
        *fpi_size = resp.a3;
    }

    return ret;
}

static int32_t ffa_get_sp_count(uint32_t *uuid, uint32_t *sp_count)
{
    uint32_t src_size;

    return ffa_partition_info_get(uuid, FFA_PARTITION_INFO_GET_COUNT_FLAG,
                                  sp_count, &src_size);
}

static int32_t ffa_get_sp_partinfo(uint32_t *uuid, uint32_t *sp_count,
                                   void *dst_buf, void *end_buf,
                                   uint32_t dst_size)
{
    int32_t ret;
    uint32_t src_size, real_sp_count;
    void *src_buf = ffa_rx;
    uint32_t count = 0;

    /* Do we have a RX buffer with the SPMC */
    if ( !ffa_rx )
        return FFA_RET_DENIED;

    /* We need to use the RX buffer to receive the list */
    spin_lock(&ffa_rx_buffer_lock);

    ret = ffa_partition_info_get(uuid, 0, &real_sp_count, &src_size);
    if ( ret )
        goto out;

    /* We now own the RX buffer */

    /* Validate the src_size we got */
    if ( src_size < sizeof(struct ffa_partition_info_1_0) ||
         src_size >= FFA_PAGE_SIZE )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_release;
    }

    /*
     * Limit the maximum time we hold the CPU by limiting the number of SPs.
     * We just ignore the extra ones as this is tested during init in
     * ffa_partinfo_init so the only possible reason is SP have been added
     * since boot.
     */
    if ( real_sp_count > FFA_MAX_NUM_SP )
        real_sp_count = FFA_MAX_NUM_SP;

    /* Make sure the data fits in our buffer */
    if ( real_sp_count > (FFA_RXTX_PAGE_COUNT * FFA_PAGE_SIZE) / src_size )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_release;
    }

    for ( uint32_t sp_num = 0; sp_num < real_sp_count; sp_num++ )
    {
        struct ffa_partition_info_1_1 *fpi = src_buf;

        /* filter out SP not following bit 15 convention if any */
        if ( FFA_ID_IS_SECURE(fpi->id) )
        {
            if ( dst_buf > (end_buf - dst_size) )
            {
                ret = FFA_RET_NO_MEMORY;
                goto out_release;
            }

            memcpy(dst_buf, src_buf, MIN(src_size, dst_size));
            if ( dst_size > src_size )
                memset(dst_buf + src_size, 0, dst_size - src_size);

            dst_buf += dst_size;
            count++;
        }

        src_buf += src_size;
    }

    *sp_count = count;

out_release:
    ffa_hyp_rx_release();
out:
    spin_unlock(&ffa_rx_buffer_lock);
    return ret;
}

void ffa_handle_partition_info_get(struct cpu_user_regs *regs)
{
    int32_t ret = FFA_RET_OK;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t flags = get_user_reg(regs, 5);
    uint32_t uuid[4] = {
        get_user_reg(regs, 1),
        get_user_reg(regs, 2),
        get_user_reg(regs, 3),
        get_user_reg(regs, 4),
    };
    uint32_t dst_size = 0;
    void *dst_buf, *end_buf;
    uint32_t ffa_sp_count = 0;

    /*
     * If the guest is v1.0, he does not get back the entry size so we must
     * use the v1.0 structure size in the destination buffer.
     * Otherwise use the size of the highest version we support, here 1.1.
     */
    if ( ctx->guest_vers == FFA_VERSION_1_0 )
        dst_size = sizeof(struct ffa_partition_info_1_0);
    else
        dst_size = sizeof(struct ffa_partition_info_1_1);

    /* Only count requested */
    if ( flags )
    {
        /*
         * FF-A v1.0 has w5 MBZ while v1.1 allows
         * FFA_PARTITION_INFO_GET_COUNT_FLAG to be non-zero.
         */
        if ( ctx->guest_vers == FFA_VERSION_1_0 ||
                flags != FFA_PARTITION_INFO_GET_COUNT_FLAG )
        {
            ret = FFA_RET_INVALID_PARAMETERS;
            goto out;
        }

        if ( ffa_fw_supports_fid(FFA_PARTITION_INFO_GET) )
            ret = ffa_get_sp_count(uuid, &ffa_sp_count);

        goto out;
    }

    if ( !ffa_fw_supports_fid(FFA_PARTITION_INFO_GET) )
    {
        /* Just give an empty partition list to the caller */
        ret = FFA_RET_OK;
        goto out;
    }

    /* Get the RX buffer to write the list of partitions */
    ret = ffa_rx_acquire(d);
    if ( ret != FFA_RET_OK )
        goto out;

    dst_buf = ctx->rx;
    end_buf = ctx->rx + ctx->page_count * FFA_PAGE_SIZE;

    /* An entry should be smaller than a page */
    BUILD_BUG_ON(sizeof(struct ffa_partition_info_1_1) > FFA_PAGE_SIZE);

    /*
     * Check for overflow and that we can at least store one entry.
     * page_count cannot be 0 so we have at least one page.
     */
    if ( dst_buf >= end_buf || dst_buf > (end_buf - dst_size) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_rx_release;
    }

    ret = ffa_get_sp_partinfo(uuid, &ffa_sp_count, dst_buf, end_buf,
                              dst_size);


out_rx_release:
    if ( ret )
        ffa_rx_release(d);
out:
    if ( ret )
        ffa_set_regs_error(regs, ret);
    else
        ffa_set_regs_success(regs, ffa_sp_count, dst_size);
}

static int32_t ffa_direct_req_send_vm(uint16_t sp_id, uint16_t vm_id,
                                      uint8_t msg)
{
    uint32_t exp_resp = FFA_MSG_FLAG_FRAMEWORK;
    unsigned int retry_count = 0;
    int32_t res;

    if ( msg == FFA_MSG_SEND_VM_CREATED )
        exp_resp |= FFA_MSG_RESP_VM_CREATED;
    else if ( msg == FFA_MSG_SEND_VM_DESTROYED )
        exp_resp |= FFA_MSG_RESP_VM_DESTROYED;
    else
        return FFA_RET_INVALID_PARAMETERS;

    do {
        const struct arm_smccc_1_2_regs arg = {
            .a0 = FFA_MSG_SEND_DIRECT_REQ_32,
            .a1 = sp_id,
            .a2 = FFA_MSG_FLAG_FRAMEWORK | msg,
            .a5 = vm_id,
        };
        struct arm_smccc_1_2_regs resp;

        arm_smccc_1_2_smc(&arg, &resp);
        if ( resp.a0 != FFA_MSG_SEND_DIRECT_RESP_32 || resp.a2 != exp_resp )
        {
            /*
             * This is an invalid response, likely due to some error in the
             * implementation of the ABI.
             */
            return FFA_RET_INVALID_PARAMETERS;
        }
        res = resp.a3;
        if ( ++retry_count > 10 )
        {
            /*
             * TODO
             * FFA_RET_INTERRUPTED means that the SPMC has a pending
             * non-secure interrupt, we need a way of delivering that
             * non-secure interrupt.
             * FFA_RET_RETRY is the SP telling us that it's temporarily
             * blocked from handling the direct request, we need a generic
             * way to deal with this.
             * For now in both cases, give up after a few retries.
             */
            return res;
        }
    } while ( res == FFA_RET_INTERRUPTED || res == FFA_RET_RETRY );

    return res;
}

static void uninit_subscribers(void)
{
        subscr_vm_created_count = 0;
        subscr_vm_destroyed_count = 0;
        XFREE(subscr_vm_created);
        XFREE(subscr_vm_destroyed);
}

static bool init_subscribers(uint16_t count, uint32_t fpi_size)
{
    uint16_t n;
    uint16_t c_pos;
    uint16_t d_pos;
    struct ffa_partition_info_1_1 *fpi;

    if ( fpi_size < sizeof(struct ffa_partition_info_1_1) )
    {
        printk(XENLOG_ERR "ffa: partition info size invalid: %u\n", fpi_size);
        return false;
    }

    subscr_vm_created_count = 0;
    subscr_vm_destroyed_count = 0;
    for ( n = 0; n < count; n++ )
    {
        fpi = ffa_rx + n * fpi_size;

        /*
         * We need to have secure partitions using bit 15 set convention for
         * secure partition IDs.
         * Inform the user with a log and discard giving created or destroy
         * event to those IDs.
         */
        if ( !FFA_ID_IS_SECURE(fpi->id) )
        {
            printk(XENLOG_ERR "ffa: Firmware is not using bit 15 convention for IDs !!\n"
                              "ffa: Secure partition with id 0x%04x cannot be used\n",
                              fpi->id);
        }
        else
        {
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_CREATED )
                subscr_vm_created_count++;
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
                subscr_vm_destroyed_count++;
        }
    }

    if ( subscr_vm_created_count )
        subscr_vm_created = xzalloc_array(uint16_t, subscr_vm_created_count);
    if ( subscr_vm_destroyed_count )
        subscr_vm_destroyed = xzalloc_array(uint16_t,
                                            subscr_vm_destroyed_count);
    if ( (subscr_vm_created_count && !subscr_vm_created) ||
         (subscr_vm_destroyed_count && !subscr_vm_destroyed) )
    {
        printk(XENLOG_ERR "ffa: Failed to allocate subscription lists\n");
        uninit_subscribers();
        return false;
    }

    for ( c_pos = 0, d_pos = 0, n = 0; n < count; n++ )
    {
        fpi = ffa_rx + n * fpi_size;

        if ( FFA_ID_IS_SECURE(fpi->id) )
        {
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_CREATED )
                subscr_vm_created[c_pos++] = fpi->id;
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
                subscr_vm_destroyed[d_pos++] = fpi->id;
        }
    }

    return true;
}



bool ffa_partinfo_init(void)
{
    bool ret = false;
    uint32_t fpi_size;
    uint32_t count;
    int e;

    if ( !ffa_fw_supports_fid(FFA_PARTITION_INFO_GET) ||
         !ffa_fw_supports_fid(FFA_MSG_SEND_DIRECT_REQ_32) ||
         !ffa_rx || !ffa_tx )
        return false;

    e = ffa_partition_info_get(NULL, 0, &count, &fpi_size);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to get list of SPs: %d\n", e);
        goto out;
    }

    if ( count >= FFA_MAX_NUM_SP )
    {
        printk(XENLOG_ERR "ffa: More SPs than the maximum supported: %u - %u\n",
               count, FFA_MAX_NUM_SP);
        goto out;
    }

    ret = init_subscribers(count, fpi_size);

out:
    ffa_hyp_rx_release();
    return ret;
}

static bool is_in_subscr_list(const uint16_t *subscr, uint16_t start,
                              uint16_t end, uint16_t sp_id)
{
    unsigned int n;

    for ( n = start; n < end; n++ )
    {
        if ( subscr[n] == sp_id )
            return true;
    }

    return false;
}

static void vm_destroy_bitmap_init(struct ffa_ctx *ctx,
                                   unsigned int create_signal_count)
{
    unsigned int n;

    for ( n = 0; n < subscr_vm_destroyed_count; n++ )
    {
        /*
         * Skip SPs subscribed to the VM created event that never was
         * notified of the VM creation due to an error during
         * ffa_domain_init().
         */
        if ( is_in_subscr_list(subscr_vm_created, create_signal_count,
                               subscr_vm_created_count,
                               subscr_vm_destroyed[n]) )
            continue;

        set_bit(n, ctx->vm_destroy_bitmap);
    }
}

int ffa_partinfo_domain_init(struct domain *d)
{
    unsigned int count = BITS_TO_LONGS(subscr_vm_destroyed_count);
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

    if ( !ffa_fw_supports_fid(FFA_MSG_SEND_DIRECT_REQ_32) )
        return 0;

    ctx->vm_destroy_bitmap = xzalloc_array(unsigned long, count);
    if ( !ctx->vm_destroy_bitmap )
        return -ENOMEM;

    for ( n = 0; n < subscr_vm_created_count; n++ )
    {
        res = ffa_direct_req_send_vm(subscr_vm_created[n], ffa_get_vm_id(d),
                                     FFA_MSG_SEND_VM_CREATED);
        if ( res )
        {
            printk(XENLOG_ERR "ffa: Failed to report creation of vm_id %u to  %u: res %d\n",
                   ffa_get_vm_id(d), subscr_vm_created[n], res);
            break;
        }
    }
    vm_destroy_bitmap_init(ctx, n);

    if ( n != subscr_vm_created_count )
        return -EIO;

    return 0;
}

bool ffa_partinfo_domain_destroy(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

    if ( !ctx->vm_destroy_bitmap )
        return true;

    for ( n = 0; n < subscr_vm_destroyed_count; n++ )
    {
        if ( !test_bit(n, ctx->vm_destroy_bitmap) )
            continue;

        res = ffa_direct_req_send_vm(subscr_vm_destroyed[n], ffa_get_vm_id(d),
                                     FFA_MSG_SEND_VM_DESTROYED);

        if ( res )
        {
            printk(XENLOG_ERR "%pd: ffa: Failed to report destruction of vm_id %u to %u: res %d\n",
                   d, ffa_get_vm_id(d), subscr_vm_destroyed[n], res);
        }

        /*
         * For these two error codes the hypervisor is expected to resend
         * the destruction message. For the rest it is expected that the
         * error is permanent and that is doesn't help to resend the
         * destruction message.
         */
        if ( res != FFA_RET_INTERRUPTED && res != FFA_RET_RETRY )
            clear_bit(n, ctx->vm_destroy_bitmap);
    }

    if ( bitmap_empty(ctx->vm_destroy_bitmap, subscr_vm_destroyed_count) )
        XFREE(ctx->vm_destroy_bitmap);

    return !ctx->vm_destroy_bitmap;
}
