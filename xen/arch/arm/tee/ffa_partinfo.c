/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/sizes.h>
#include <xen/types.h>
#include <xen/unaligned.h>
#include <xen/xmalloc.h>

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

/* SP list cache (secure endpoints only); populated at init. */
static void *sp_list __read_mostly;
static uint32_t sp_list_count __read_mostly;
static uint32_t sp_list_entry_size __read_mostly;
static int32_t ffa_partition_info_get(struct ffa_uuid uuid, uint32_t flags,
                                      uint32_t *count, uint32_t *fpi_size)
{
    struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_PARTITION_INFO_GET,
        .a5 = flags,
    };
    struct arm_smccc_1_2_regs resp;
    int32_t ret;

    arg.a1 = uuid.val[0] & GENMASK(31, 0);
    arg.a2 = (uuid.val[0] >> 32) & GENMASK(31, 0);
    arg.a3 = uuid.val[1] & GENMASK(31, 0);
    arg.a4 = (uuid.val[1] >> 32) & GENMASK(31, 0);

    arm_smccc_1_2_smc(&arg, &resp);

    ret = ffa_get_ret_code(&resp);
    if ( !ret )
    {
        *count = resp.a2;
        *fpi_size = resp.a3;
    }

    return ret;
}

static int32_t ffa_copy_info(void **dst, void *dst_end, const void *src,
                             uint32_t dst_size, uint32_t src_size)
{
    uint8_t *pos = *dst;
    uint8_t *end = dst_end;

    if ( pos > end - dst_size )
        return FFA_RET_NO_MEMORY;

    memcpy(pos, src, MIN(dst_size, src_size));

    if ( dst_size > src_size )
        memset(pos + src_size, 0, dst_size - src_size);

    *dst = pos + dst_size;

    return FFA_RET_OK;
}

static uint16_t ffa_sp_entry_read_id(const void *entry)
{
    return get_unaligned_t(uint16_t,
                           (const uint8_t *)entry +
                           offsetof(struct ffa_partition_info_1_0, id));
}

static uint32_t ffa_sp_entry_read_partition_properties(const void *entry)
{
    return get_unaligned_t(uint32_t,
                           (const uint8_t *)entry +
                           offsetof(struct ffa_partition_info_1_0,
                                    partition_properties));
}

static bool ffa_sp_entry_matches_uuid(const void *entry, struct ffa_uuid uuid)
{
    struct ffa_uuid sp_uuid;

    if ( ffa_uuid_is_nil(uuid) )
        return true;

    memcpy(&sp_uuid,
           (const uint8_t *)entry +
           offsetof(struct ffa_partition_info_1_1, uuid),
           sizeof(sp_uuid));
    return ffa_uuid_equal(uuid, sp_uuid);
}

static int32_t ffa_get_sp_count(struct ffa_uuid uuid, uint32_t *sp_count)
{
    uint32_t count = 0;
    uint32_t n;

    for ( n = 0; n < sp_list_count; n++ )
    {
        void *entry = sp_list + n * sp_list_entry_size;

        if ( ffa_sp_entry_matches_uuid(entry, uuid) )
            count++;
    }

    *sp_count = count;

    if ( !ffa_uuid_is_nil(uuid) && !count )
        return FFA_RET_INVALID_PARAMETERS;

    return FFA_RET_OK;
}

static int32_t ffa_get_sp_partinfo(struct ffa_uuid uuid, uint32_t *sp_count,
                                   void **dst_buf, void *end_buf,
                                   uint32_t dst_size)
{
    int32_t ret;
    uint32_t count = 0;
    uint32_t n;

    for ( n = 0; n < sp_list_count; n++ )
    {
        void *entry = sp_list + n * sp_list_entry_size;

        if ( !ffa_sp_entry_matches_uuid(entry, uuid) )
            continue;

        /*
         * If VM is 1.0 but firmware is 1.1 we could have several entries
         * with the same ID but different UUIDs. In this case the VM will
         * get a list with several time the same ID.
         * This is a non-compliance to the specification but 1.0 VMs should
         * handle that on their own to simplify Xen implementation.
         */
        ret = ffa_copy_info(dst_buf, end_buf, entry, dst_size,
                            sp_list_entry_size);
        if ( ret )
            return ret;

        count++;
    }

    *sp_count = count;

    if ( !ffa_uuid_is_nil(uuid) && !count )
        return FFA_RET_INVALID_PARAMETERS;

    return FFA_RET_OK;
}

static int32_t ffa_get_vm_partinfo(struct ffa_uuid uuid, uint32_t start_index,
                                   uint32_t *vm_count, void **dst_buf,
                                   void *end_buf, uint32_t dst_size)
{
    struct domain *d = current->domain;
    struct ffa_ctx *curr_ctx = d->arch.tee;
    struct ffa_ctx *dest_ctx;
    uint32_t count = 0;
    uint32_t idx = 0;
    int32_t ret = FFA_RET_OK;
    /*
     * We do not have UUID info for VMs so use the 1.0 structure so that we set
     * UUIDs to zero using memset
     */
    struct ffa_partition_info_1_0 info;

    /*
     * We do not have protocol UUIDs for VMs so if a request has non Nil UUID
     * we must return an empty list.
     */
    if ( !ffa_uuid_is_nil(uuid) )
    {
        *vm_count = 0;
        return FFA_RET_OK;
    }

    /*
     * Workaround for Linux FF-A Driver not accepting to have its own
     * entry in the list before FF-A v1.2 was supported.
     * This workaround is generally acceptable for other implementations
     * as the specification was not completely clear on wether or not
     * the requester endpoint information should be included or not
     */
    if ( ACCESS_ONCE(curr_ctx->guest_vers) >= FFA_VERSION_1_2 )
    {
        /* Add caller VM information */
        if ( start_index == 0)
        {
            info.id = curr_ctx->ffa_id;
            info.execution_context = curr_ctx->num_vcpus;
            info.partition_properties = FFA_PART_VM_PROP;
            if ( is_64bit_domain(d) )
                info.partition_properties |= FFA_PART_PROP_AARCH64_STATE;

            ret = ffa_copy_info(dst_buf, end_buf, &info, dst_size,
                                sizeof(info));
            if ( ret )
                return ret;
            count++;
        }
        idx++;
    }

    if ( IS_ENABLED(CONFIG_FFA_VM_TO_VM) )
    {
        /*
         * There could potentially be a lot of VMs in the system and we could
         * hold the CPU for long here.
         * Right now there is no solution in FF-A specification to split
         * the work in this case.
         * TODO: Check how we could delay the work or have preemption checks.
         */
        read_lock(&ffa_ctx_list_rwlock);
        list_for_each_entry(dest_ctx, &ffa_ctx_head, ctx_list)
        {
            /* Ignore the caller entry as it was already added */
            if ( dest_ctx == curr_ctx )
                continue;

            if ( idx >= start_index )
            {
                info.id = dest_ctx->ffa_id;
                info.execution_context = dest_ctx->num_vcpus;
                info.partition_properties = FFA_PART_VM_PROP;
                if ( dest_ctx->is_64bit )
                    info.partition_properties |= FFA_PART_PROP_AARCH64_STATE;

                ret = ffa_copy_info(dst_buf, end_buf, &info, dst_size,
                                    sizeof(info));
                if ( ret )
                {
                    read_unlock(&ffa_ctx_list_rwlock);
                    return ret;
                }
                count++;
            }

            idx++;
        }
        read_unlock(&ffa_ctx_list_rwlock);
    }

    *vm_count = count;

    return ret;
}

void ffa_handle_partition_info_get(struct cpu_user_regs *regs)
{
    int32_t ret = FFA_RET_OK;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t flags = get_user_reg(regs, 5);
    struct ffa_uuid uuid;
    uint32_t dst_size = 0;
    size_t buf_size;
    void *dst_buf, *end_buf;
    uint32_t ffa_vm_count = 0, ffa_sp_count = 0;

    ffa_uuid_set(&uuid,
             get_user_reg(regs, 1),
             get_user_reg(regs, 2),
             get_user_reg(regs, 3),
             get_user_reg(regs, 4));

    /*
     * If the guest is v1.0, he does not get back the entry size so we must
     * use the v1.0 structure size in the destination buffer.
     * Otherwise use the size of the highest version we support, here 1.1.
     */
    if ( ACCESS_ONCE(ctx->guest_vers) == FFA_VERSION_1_0 )
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
        if ( ACCESS_ONCE(ctx->guest_vers) == FFA_VERSION_1_0 ||
                flags != FFA_PARTITION_INFO_GET_COUNT_FLAG )
        {
            ret = FFA_RET_INVALID_PARAMETERS;
            goto out;
        }

        if ( ffa_fw_supports_fid(FFA_PARTITION_INFO_GET) )
        {
            ret = ffa_get_sp_count(uuid, &ffa_sp_count);
            if ( ret )
                goto out;
        }

        /*
         * We do not have protocol UUIDs for VMs so if a request has non Nil
         * UUID we must return a vm_count of 0
         */
        if ( ffa_uuid_is_nil(uuid) )
        {
            ffa_vm_count = get_ffa_vm_count();

            /*
             * Workaround for Linux FF-A Driver not accepting to have its own
             * entry in the list before FF-A v1.2 was supported.
             * This workaround is generally acceptable for other implementations
             * as the specification was not completely clear on wether or not
             * the requester endpoint information should be included or not
             */
            if ( ACCESS_ONCE(ctx->guest_vers) < FFA_VERSION_1_2 )
                ffa_vm_count -= 1;
        }

        goto out;
    }

    /* Get the RX buffer to write the list of partitions */
    ret = ffa_rx_acquire(ctx, &dst_buf, &buf_size);
    if ( ret != FFA_RET_OK )
        goto out;

    end_buf = dst_buf + buf_size;

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

    if ( ffa_fw_supports_fid(FFA_PARTITION_INFO_GET) )
    {
        ret = ffa_get_sp_partinfo(uuid, &ffa_sp_count, &dst_buf, end_buf,
                                  dst_size);

        if ( ret )
            goto out_rx_release;
    }

    ret = ffa_get_vm_partinfo(uuid, 0, &ffa_vm_count, &dst_buf, end_buf,
                              dst_size);

out_rx_release:
    if ( ret )
        ffa_rx_release(ctx);
out:
    if ( ret )
        ffa_set_regs_error(regs, ret);
    else
    {
        /* Size should be 0 on count request and was not supported in 1.0 */
        if ( flags || ACCESS_ONCE(ctx->guest_vers) == FFA_VERSION_1_0 )
            dst_size = 0;

        ffa_set_regs_success(regs, ffa_sp_count + ffa_vm_count, dst_size);
    }
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

static void ffa_sp_list_cache_free(void)
{
    XFREE(sp_list);
    sp_list_count = 0;
    sp_list_entry_size = 0;
}

static bool ffa_sp_list_cache_init(const void *buf, uint32_t count,
                                   uint32_t fpi_size)
{
    const uint8_t *src = buf;
    uint32_t secure_count = 0;
    uint32_t n, idx = 0;

    if ( fpi_size < sizeof(struct ffa_partition_info_1_1) ||
         fpi_size >= FFA_PAGE_SIZE )
        return false;

    if ( count > (FFA_RXTX_PAGE_COUNT * FFA_PAGE_SIZE) / fpi_size )
        return false;

    for ( n = 0; n < count; n++ )
    {
        const uint8_t *entry = src + n * fpi_size;
        uint16_t id = ffa_sp_entry_read_id(entry);

        if ( !FFA_ID_IS_SECURE(id) )
        {
            printk_once(XENLOG_ERR
                        "ffa: Firmware is not using bit 15 convention for IDs !!\n");
            printk(XENLOG_ERR
                   "ffa: Secure partition with id 0x%04x cannot be used\n",
                   id);
            continue;
        }

        secure_count++;
    }

    if ( secure_count )
    {
        sp_list = xzalloc_bytes(secure_count * fpi_size);
        if ( !sp_list )
            return false;
    }

    sp_list_count = secure_count;
    sp_list_entry_size = fpi_size;

    for ( n = 0; n < count; n++ )
    {
        const uint8_t *entry = src + n * fpi_size;
        uint16_t id = ffa_sp_entry_read_id(entry);

        if ( !FFA_ID_IS_SECURE(id) )
            continue;

        memcpy(sp_list + idx * fpi_size, entry, fpi_size);
        idx++;
    }

    return true;
}

bool ffa_partinfo_init(void)
{
    bool ret = false;
    uint32_t fpi_size;
    uint32_t count;
    int32_t e;
    void *spmc_rx;
    struct ffa_uuid nil_uuid = { .val = { 0ULL, 0ULL } };
    bool notify_fw = false;

    if ( !ffa_fw_supports_fid(FFA_PARTITION_INFO_GET) ||
         !ffa_fw_supports_fid(FFA_MSG_SEND_DIRECT_REQ_32))
        return false;

    spmc_rx = ffa_rxtx_spmc_rx_acquire();
    if (!spmc_rx)
        return false;

    e = ffa_partition_info_get(nil_uuid, 0, &count, &fpi_size);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to get list of SPs: %d\n", e);
        goto out_release_rx;
    }
    notify_fw = true;

    if ( count >= FFA_MAX_NUM_SP )
    {
        printk(XENLOG_ERR "ffa: More SPs than the maximum supported: %u - %u\n",
               count, FFA_MAX_NUM_SP);
        goto out_release_rx;
    }

    if ( !ffa_sp_list_cache_init(spmc_rx, count, fpi_size) )
    {
        printk(XENLOG_ERR "ffa: Failed to cache SP list\n");
        goto out_release_rx;
    }

    ret = true;
    goto out_release_rx;

out_release_rx:
    e = ffa_rxtx_spmc_rx_release(notify_fw);
    if ( e )
        printk(XENLOG_WARNING "ffa: Error releasing SPMC RX buffer: %d\n", e);
    if ( !ret )
        ffa_sp_list_cache_free();
    return ret;
}

static void vm_destroy_bitmap_init(struct ffa_ctx *ctx,
                                   unsigned int first_unnotified)
{
    unsigned int n;

    for ( n = 0; n < sp_list_count; n++ )
    {
        const void *entry = sp_list + n * sp_list_entry_size;
        uint32_t partition_props =
            ffa_sp_entry_read_partition_properties(entry);

        if ( !(partition_props & FFA_PART_PROP_NOTIF_DESTROYED) )
            continue;

        /*
         * Skip SPs subscribed to the VM created event that never was
         * notified of the VM creation due to an error during
         * ffa_domain_init().
         */
        if ( (partition_props & FFA_PART_PROP_NOTIF_CREATED) &&
             n >= first_unnotified )
            continue;

        set_bit(n, ctx->vm_destroy_bitmap);
    }
}

int32_t ffa_partinfo_domain_init(struct domain *d)
{
    unsigned int count = BITS_TO_LONGS(sp_list_count);
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    unsigned int first_unnotified = sp_list_count;
    int32_t res;

    if ( !ffa_fw_supports_fid(FFA_MSG_SEND_DIRECT_REQ_32) || !sp_list_count )
        return 0;

    ctx->vm_destroy_bitmap = xzalloc_array(unsigned long, count);
    if ( !ctx->vm_destroy_bitmap )
        return -ENOMEM;

    for ( n = 0; n < sp_list_count; n++ )
    {
        const void *entry = sp_list + n * sp_list_entry_size;
        uint32_t partition_props =
            ffa_sp_entry_read_partition_properties(entry);
        uint16_t id = ffa_sp_entry_read_id(entry);

        if ( !(partition_props & FFA_PART_PROP_NOTIF_CREATED) )
            continue;

        res = ffa_direct_req_send_vm(id, ffa_get_vm_id(d),
                                     FFA_MSG_SEND_VM_CREATED);
        if ( res )
        {
            printk(XENLOG_ERR "ffa: Failed to report creation of vm_id %u to  %u: res %d\n",
                   ffa_get_vm_id(d), id, res);
            first_unnotified = n;
            break;
        }
    }
    vm_destroy_bitmap_init(ctx, first_unnotified);

    if ( first_unnotified != sp_list_count )
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

    for ( n = 0; n < sp_list_count; n++ )
    {
        const void *entry;
        uint16_t id;

        if ( !test_bit(n, ctx->vm_destroy_bitmap) )
            continue;

        entry = sp_list + n * sp_list_entry_size;
        id = ffa_sp_entry_read_id(entry);

        res = ffa_direct_req_send_vm(id, ffa_get_vm_id(d),
                                     FFA_MSG_SEND_VM_DESTROYED);

        if ( res && printk_ratelimit() )
            printk(XENLOG_WARNING
                   "%pd: ffa: Failed to report destruction of vm_id %u to %u: res %d\n",
                   d, ffa_get_vm_id(d), id, res);

        /*
         * For these two error codes the hypervisor is expected to resend
         * the destruction message. For the rest it is expected that the
         * error is permanent and that is doesn't help to resend the
         * destruction message.
         */
        if ( res != FFA_RET_INTERRUPTED && res != FFA_RET_RETRY )
            clear_bit(n, ctx->vm_destroy_bitmap);
    }

    if ( bitmap_empty(ctx->vm_destroy_bitmap, sp_list_count) )
        XFREE(ctx->vm_destroy_bitmap);

    return !ctx->vm_destroy_bitmap;
}
