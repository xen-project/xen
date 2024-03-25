/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/tee/ffa.c
 *
 * Arm Firmware Framework for ARMv8-A (FF-A) mediator
 *
 * Copyright (C) 2023-2024  Linaro Limited
 *
 * References:
 * FF-A-1.0-REL: FF-A specification version 1.0 available at
 *               https://developer.arm.com/documentation/den0077/a
 * FF-A-1.1-REL0: FF-A specification version 1.1 available at
 *                https://developer.arm.com/documentation/den0077/e
 * TEEC-1.0C: TEE Client API Specification version 1.0c available at
 *            https://globalplatform.org/specs-library/tee-client-api-specification/
 *
 * Notes on the the current implementation.
 *
 * Unsupported FF-A interfaces:
 * o FFA_MSG_POLL and FFA_MSG_SEND - deprecated in FF-A-1.1-REL0
 * o FFA_MEM_RETRIEVE_* - Used when sharing memory from an SP to a VM
 * o FFA_MEM_DONATE_* and FFA_MEM_LEND_* - Used when tranferring ownership
 *   or access of a memory region
 * o FFA_MSG_SEND2 and FFA_MSG_WAIT - Used for indirect messaging
 * o FFA_MSG_YIELD
 * o FFA_INTERRUPT - Used to report preemption
 * o FFA_RUN
 *
 * Limitations in the implemented FF-A interfaces:
 * o FFA_RXTX_MAP_*:
 *   - Maps only one 4k page as RX and TX buffers
 *   - Doesn't support forwarding this call on behalf of an endpoint
 * o FFA_MEM_SHARE_*: only supports sharing
 *   - from a VM to an SP
 *   - with one borrower
 *   - with the memory transaction descriptor in the RX/TX buffer
 *   - normal memory
 *   - at most 512 kB large memory regions
 *   - at most 32 shared memory regions per guest
 * o FFA_MSG_SEND_DIRECT_REQ:
 *   - only supported from a VM to an SP
 *
 * There are some large locked sections with ffa_tx_buffer_lock and
 * ffa_rx_buffer_lock. Especially the ffa_tx_buffer_lock spinlock used
 * around share_shm() is a very large locked section which can let one VM
 * affect another VM.
 */

#include <xen/bitops.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/timer.h>
#include <xen/types.h>

#include <asm/event.h>
#include <asm/regs.h>
#include <asm/smccc.h>
#include <asm/tee/ffa.h>
#include <asm/tee/tee.h>

#include "ffa_private.h"

/*
 * Structs below ending with _1_0 are defined in FF-A-1.0-REL and
 * structs ending with _1_1 are defined in FF-A-1.1-REL0.
 */

/* Partition information descriptor */
struct ffa_partition_info_1_0 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
};

struct ffa_partition_info_1_1 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
    uint8_t uuid[16];
};

/* Endpoint RX/TX descriptor */
struct ffa_endpoint_rxtx_descriptor_1_0 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_range_count;
    uint32_t tx_range_count;
};

struct ffa_endpoint_rxtx_descriptor_1_1 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_region_offs;
    uint32_t tx_region_offs;
};

/* Negotiated FF-A version to use with the SPMC */
static uint32_t __ro_after_init ffa_version;

/* SPs subscribing to VM_CREATE and VM_DESTROYED events */
static uint16_t *subscr_vm_created __read_mostly;
static uint16_t subscr_vm_created_count __read_mostly;
static uint16_t *subscr_vm_destroyed __read_mostly;
static uint16_t subscr_vm_destroyed_count __read_mostly;

/*
 * Our rx/tx buffers shared with the SPMC. FFA_RXTX_PAGE_COUNT is the
 * number of pages used in each of these buffers.
 *
 * The RX buffer is protected from concurrent usage with ffa_rx_buffer_lock.
 * Note that the SPMC is also tracking the ownership of our RX buffer so
 * for calls which uses our RX buffer to deliver a result we must call
 * ffa_rx_release() to let the SPMC know that we're done with the buffer.
 */
void *ffa_rx __read_mostly;
void *ffa_tx __read_mostly;
DEFINE_SPINLOCK(ffa_rx_buffer_lock);
DEFINE_SPINLOCK(ffa_tx_buffer_lock);


/* Used to track domains that could not be torn down immediately. */
static struct timer ffa_teardown_timer;
static struct list_head ffa_teardown_head;
static DEFINE_SPINLOCK(ffa_teardown_lock);

static bool ffa_get_version(uint32_t *vers)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_VERSION,
        .a1 = FFA_MY_VERSION,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);
    if ( resp.a0 == FFA_RET_NOT_SUPPORTED )
    {
        gprintk(XENLOG_ERR, "ffa: FFA_VERSION returned not supported\n");
        return false;
    }

    *vers = resp.a0;

    return true;
}

static int32_t ffa_features(uint32_t id)
{
    return ffa_simple_call(FFA_FEATURES, id, 0, 0, 0);
}

static bool check_mandatory_feature(uint32_t id)
{
    int32_t ret = ffa_features(id);

    if ( ret )
        printk(XENLOG_ERR "ffa: mandatory feature id %#x missing: error %d\n",
               id, ret);

    return !ret;
}

static int32_t ffa_rxtx_map(paddr_t tx_addr, paddr_t rx_addr,
                            uint32_t page_count)
{
    return ffa_simple_call(FFA_RXTX_MAP_64, tx_addr, rx_addr, page_count, 0);
}

static int32_t ffa_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                      uint32_t w4, uint32_t w5,
                                      uint32_t *count, uint32_t *fpi_size)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_PARTITION_INFO_GET,
        .a1 = w1,
        .a2 = w2,
        .a3 = w3,
        .a4 = w4,
        .a5 = w5,
    };
    struct arm_smccc_1_2_regs resp;
    uint32_t ret;

    arm_smccc_1_2_smc(&arg, &resp);

    ret = ffa_get_ret_code(&resp);
    if ( !ret )
    {
        *count = resp.a2;
        *fpi_size = resp.a3;
    }

    return ret;
}

static int32_t ffa_rx_release(void)
{
    return ffa_simple_call(FFA_RX_RELEASE, 0, 0, 0, 0);
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

static void handle_version(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t vers = get_user_reg(regs, 1);

    if ( vers < FFA_VERSION_1_1 )
        vers = FFA_VERSION_1_0;
    else
        vers = FFA_VERSION_1_1;

    ctx->guest_vers = vers;
    ffa_set_regs(regs, vers, 0, 0, 0, 0, 0, 0, 0);
}

static uint32_t ffa_handle_rxtx_map(uint32_t fid, register_t tx_addr,
				    register_t rx_addr, uint32_t page_count)
{
    uint32_t ret = FFA_RET_INVALID_PARAMETERS;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct page_info *tx_pg;
    struct page_info *rx_pg;
    p2m_type_t t;
    void *rx;
    void *tx;

    if ( !smccc_is_conv_64(fid) )
    {
        /*
         * Calls using the 32-bit calling convention must ignore the upper
         * 32 bits in the argument registers.
         */
        tx_addr &= UINT32_MAX;
        rx_addr &= UINT32_MAX;
    }

    if ( page_count > FFA_MAX_RXTX_PAGE_COUNT )
    {
        printk(XENLOG_ERR "ffa: RXTX_MAP: error: %u pages requested (limit %u)\n",
               page_count, FFA_MAX_RXTX_PAGE_COUNT);
        return FFA_RET_INVALID_PARAMETERS;
    }

    /* Already mapped */
    if ( ctx->rx )
        return FFA_RET_DENIED;

    tx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(tx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        return FFA_RET_INVALID_PARAMETERS;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_tx_pg;

    rx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(rx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        goto err_put_tx_pg;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_rx_pg;

    tx = __map_domain_page_global(tx_pg);
    if ( !tx )
        goto err_put_rx_pg;

    rx = __map_domain_page_global(rx_pg);
    if ( !rx )
        goto err_unmap_tx;

    ctx->rx = rx;
    ctx->tx = tx;
    ctx->rx_pg = rx_pg;
    ctx->tx_pg = tx_pg;
    ctx->page_count = page_count;
    ctx->rx_is_free = true;
    return FFA_RET_OK;

err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);

    return ret;
}

static void rxtx_unmap(struct ffa_ctx *ctx)
{
    unmap_domain_page_global(ctx->rx);
    unmap_domain_page_global(ctx->tx);
    put_page(ctx->rx_pg);
    put_page(ctx->tx_pg);
    ctx->rx = NULL;
    ctx->tx = NULL;
    ctx->rx_pg = NULL;
    ctx->tx_pg = NULL;
    ctx->page_count = 0;
    ctx->rx_is_free = false;
}

static uint32_t ffa_handle_rxtx_unmap(void)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx->rx )
        return FFA_RET_INVALID_PARAMETERS;

    rxtx_unmap(ctx);

    return FFA_RET_OK;
}

static int32_t ffa_handle_partition_info_get(uint32_t w1, uint32_t w2,
                                             uint32_t w3, uint32_t w4,
                                             uint32_t w5, uint32_t *count,
                                             uint32_t *fpi_size)
{
    int32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    /*
     * FF-A v1.0 has w5 MBZ while v1.1 allows
     * FFA_PARTITION_INFO_GET_COUNT_FLAG to be non-zero.
     *
     * FFA_PARTITION_INFO_GET_COUNT is only using registers and not the
     * rxtx buffer so do the partition_info_get directly.
     */
    if ( w5 == FFA_PARTITION_INFO_GET_COUNT_FLAG &&
         ctx->guest_vers == FFA_VERSION_1_1 )
        return ffa_partition_info_get(w1, w2, w3, w4, w5, count, fpi_size);
    if ( w5 )
        return FFA_RET_INVALID_PARAMETERS;

    if ( !ffa_rx )
        return FFA_RET_DENIED;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count || !ctx->rx_is_free )
        goto out;
    spin_lock(&ffa_rx_buffer_lock);
    ret = ffa_partition_info_get(w1, w2, w3, w4, w5, count, fpi_size);
    if ( ret )
        goto out_rx_buf_unlock;
    /*
     * ffa_partition_info_get() succeeded so we now own the RX buffer we
     * share with the SPMC. We must give it back using ffa_rx_release()
     * once we've copied the content.
     */

    if ( ctx->guest_vers == FFA_VERSION_1_0 )
    {
        size_t n;
        struct ffa_partition_info_1_1 *src = ffa_rx;
        struct ffa_partition_info_1_0 *dst = ctx->rx;

        if ( ctx->page_count * FFA_PAGE_SIZE < *count * sizeof(*dst) )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }

        for ( n = 0; n < *count; n++ )
        {
            dst[n].id = src[n].id;
            dst[n].execution_context = src[n].execution_context;
            dst[n].partition_properties = src[n].partition_properties;
        }
    }
    else
    {
        size_t sz = *count * *fpi_size;

        if ( ctx->page_count * FFA_PAGE_SIZE < sz )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }

        memcpy(ctx->rx, ffa_rx, sz);
    }
    ctx->rx_is_free = false;
out_rx_release:
    ffa_rx_release();
out_rx_buf_unlock:
    spin_unlock(&ffa_rx_buffer_lock);
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static int32_t ffa_handle_rx_release(void)
{
    int32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count || ctx->rx_is_free )
        goto out;
    ret = FFA_RET_OK;
    ctx->rx_is_free = true;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static void handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
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

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != ffa_get_vm_id(d) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_INVALID_PARAMETERS;
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

static bool ffa_handle_call(struct cpu_user_regs *regs)
{
    uint32_t fid = get_user_reg(regs, 0);
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t fpi_size;
    uint32_t count;
    int e;

    if ( !ctx )
        return false;

    switch ( fid )
    {
    case FFA_VERSION:
        handle_version(regs);
        return true;
    case FFA_ID_GET:
        ffa_set_regs_success(regs, ffa_get_vm_id(d), 0);
        return true;
    case FFA_RXTX_MAP_32:
    case FFA_RXTX_MAP_64:
        e = ffa_handle_rxtx_map(fid, get_user_reg(regs, 1),
				get_user_reg(regs, 2), get_user_reg(regs, 3));
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;
    case FFA_RXTX_UNMAP:
        e = ffa_handle_rxtx_unmap();
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;
    case FFA_PARTITION_INFO_GET:
        e = ffa_handle_partition_info_get(get_user_reg(regs, 1),
                                          get_user_reg(regs, 2),
                                          get_user_reg(regs, 3),
                                          get_user_reg(regs, 4),
                                          get_user_reg(regs, 5), &count,
                                          &fpi_size);
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, count, fpi_size);
        return true;
    case FFA_RX_RELEASE:
        e = ffa_handle_rx_release();
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;
    case FFA_MSG_SEND_DIRECT_REQ_32:
    case FFA_MSG_SEND_DIRECT_REQ_64:
        handle_msg_send_direct_req(regs, fid);
        return true;
    case FFA_MEM_SHARE_32:
    case FFA_MEM_SHARE_64:
        ffa_handle_mem_share(regs);
        return true;
    case FFA_MEM_RECLAIM:
        e = ffa_handle_mem_reclaim(regpair_to_uint64(get_user_reg(regs, 2),
                                                     get_user_reg(regs, 1)),
                                   get_user_reg(regs, 3));
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;

    default:
        gprintk(XENLOG_ERR, "ffa: unhandled fid 0x%x\n", fid);
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return true;
    }
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

static int ffa_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx;
    unsigned int n;
    int32_t res;

    if ( !ffa_version )
        return -ENODEV;
     /*
      * We can't use that last possible domain ID or ffa_get_vm_id() would
      * cause an overflow.
      */
    if ( d->domain_id >= UINT16_MAX)
        return -ERANGE;

    ctx = xzalloc_flex_struct(struct ffa_ctx, vm_destroy_bitmap,
                              BITS_TO_LONGS(subscr_vm_destroyed_count));
    if ( !ctx )
        return -ENOMEM;

    d->arch.tee = ctx;
    ctx->teardown_d = d;
    INIT_LIST_HEAD(&ctx->shm_list);

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

static void send_vm_destroyed(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

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
}

static void ffa_domain_teardown_continue(struct ffa_ctx *ctx, bool first_time)
{
    struct ffa_ctx *next_ctx = NULL;
    bool retry = false;

    send_vm_destroyed(ctx->teardown_d);
    if ( !ffa_shm_domain_destroy(ctx->teardown_d) )
        retry = true;

    if ( retry ||
         !bitmap_empty(ctx->vm_destroy_bitmap, subscr_vm_destroyed_count) )
    {
        printk(XENLOG_G_INFO "%pd: ffa: Remaining cleanup, retrying\n", ctx->teardown_d);

        ctx->teardown_expire = NOW() + FFA_CTX_TEARDOWN_DELAY;

        spin_lock(&ffa_teardown_lock);
        list_add_tail(&ctx->teardown_list, &ffa_teardown_head);
        /* Need to set a new timer for the next ctx in line */
        next_ctx = list_first_entry(&ffa_teardown_head, struct ffa_ctx,
                                    teardown_list);
        spin_unlock(&ffa_teardown_lock);
    }
    else
    {
        /*
         * domain_destroy() might have been called (via put_domain() in
         * ffa_reclaim_shms()), so we can't touch the domain structure
         * anymore.
         */
        xfree(ctx);

        /* Only check if there has been a change to the teardown queue */
        if ( !first_time )
        {
            spin_lock(&ffa_teardown_lock);
            next_ctx = list_first_entry_or_null(&ffa_teardown_head,
                                                struct ffa_ctx, teardown_list);
            spin_unlock(&ffa_teardown_lock);
        }
    }

    if ( next_ctx )
        set_timer(&ffa_teardown_timer, next_ctx->teardown_expire);
}

static void ffa_teardown_timer_callback(void *arg)
{
    struct ffa_ctx *ctx;

    spin_lock(&ffa_teardown_lock);
    ctx = list_first_entry_or_null(&ffa_teardown_head, struct ffa_ctx,
                                   teardown_list);
    if ( ctx )
        list_del(&ctx->teardown_list);
    spin_unlock(&ffa_teardown_lock);

    if ( ctx )
        ffa_domain_teardown_continue(ctx, false /* !first_time */);
    else
        printk(XENLOG_G_ERR "%s: teardown list is empty\n", __func__);
}

/* This function is supposed to undo what ffa_domain_init() has done */
static int ffa_domain_teardown(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx )
        return 0;

    if ( ctx->rx )
        rxtx_unmap(ctx);

    ffa_domain_teardown_continue(ctx, true /* first_time */);

    return 0;
}

static int ffa_relinquish_resources(struct domain *d)
{
    return 0;
}

static void uninit_subscribers(void)
{
        subscr_vm_created_count = 0;
        subscr_vm_destroyed_count = 0;
        XFREE(subscr_vm_created);
        XFREE(subscr_vm_destroyed);
}

static bool init_subscribers(struct ffa_partition_info_1_1 *fpi, uint16_t count)
{
    uint16_t n;
    uint16_t c_pos;
    uint16_t d_pos;

    subscr_vm_created_count = 0;
    subscr_vm_destroyed_count = 0;
    for ( n = 0; n < count; n++ )
    {
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_CREATED )
            subscr_vm_created_count++;
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
            subscr_vm_destroyed_count++;
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
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_CREATED )
            subscr_vm_created[c_pos++] = fpi[n].id;
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
            subscr_vm_destroyed[d_pos++] = fpi[n].id;
    }

    return true;
}

static bool init_sps(void)
{
    bool ret = false;
    uint32_t fpi_size;
    uint32_t count;
    int e;

    e = ffa_partition_info_get(0, 0, 0, 0, 0, &count, &fpi_size);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to get list of SPs: %d\n", e);
        goto out;
    }

    if ( count >= UINT16_MAX )
    {
        printk(XENLOG_ERR "ffa: Impossible number of SPs: %u\n", count);
        goto out;
    }

    ret = init_subscribers(ffa_rx, count);

out:
    ffa_rx_release();

    return ret;
}

static bool ffa_probe(void)
{
    uint32_t vers;
    int e;
    unsigned int major_vers;
    unsigned int minor_vers;

    /*
     * FF-A often works in units of 4K pages and currently it's assumed
     * that we can map memory using that granularity. See also the comment
     * above the FFA_PAGE_SIZE define.
     *
     * It is possible to support a PAGE_SIZE larger than 4K in Xen, but
     * until that is fully handled in this code make sure that we only use
     * 4K page sizes.
     */
    BUILD_BUG_ON(PAGE_SIZE != FFA_PAGE_SIZE);

    /*
     * psci_init_smccc() updates this value with what's reported by EL-3
     * or secure world.
     */
    if ( smccc_ver < ARM_SMCCC_VERSION_1_2 )
    {
        printk(XENLOG_ERR
               "ffa: unsupported SMCCC version %#x (need at least %#x)\n",
               smccc_ver, ARM_SMCCC_VERSION_1_2);
        return false;
    }

    if ( !ffa_get_version(&vers) )
        return false;

    if ( vers < FFA_MIN_SPMC_VERSION || vers > FFA_MY_VERSION )
    {
        printk(XENLOG_ERR "ffa: Incompatible version %#x found\n", vers);
        return false;
    }

    major_vers = (vers >> FFA_VERSION_MAJOR_SHIFT) & FFA_VERSION_MAJOR_MASK;
    minor_vers = vers & FFA_VERSION_MINOR_MASK;
    printk(XENLOG_INFO "ARM FF-A Mediator version %u.%u\n",
           FFA_MY_VERSION_MAJOR, FFA_MY_VERSION_MINOR);
    printk(XENLOG_INFO "ARM FF-A Firmware version %u.%u\n",
           major_vers, minor_vers);

    /*
     * At the moment domains must support the same features used by Xen.
     * TODO: Rework the code to allow domain to use a subset of the
     * features supported.
     */
    if ( !check_mandatory_feature(FFA_PARTITION_INFO_GET) ||
         !check_mandatory_feature(FFA_RX_RELEASE) ||
         !check_mandatory_feature(FFA_RXTX_MAP_64) ||
         !check_mandatory_feature(FFA_MEM_SHARE_64) ||
         !check_mandatory_feature(FFA_RXTX_UNMAP) ||
         !check_mandatory_feature(FFA_MEM_SHARE_32) ||
         !check_mandatory_feature(FFA_MEM_RECLAIM) ||
         !check_mandatory_feature(FFA_MSG_SEND_DIRECT_REQ_32) )
        return false;

    ffa_rx = alloc_xenheap_pages(get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_rx )
        return false;

    ffa_tx = alloc_xenheap_pages(get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_tx )
        goto err_free_ffa_rx;

    e = ffa_rxtx_map(__pa(ffa_tx), __pa(ffa_rx), FFA_RXTX_PAGE_COUNT);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to map rxtx: error %d\n", e);
        goto err_free_ffa_tx;
    }
    ffa_version = vers;

    if ( !init_sps() )
        goto err_free_ffa_tx;

    INIT_LIST_HEAD(&ffa_teardown_head);
    init_timer(&ffa_teardown_timer, ffa_teardown_timer_callback, NULL, 0);

    return true;

err_free_ffa_tx:
    free_xenheap_pages(ffa_tx, 0);
    ffa_tx = NULL;
err_free_ffa_rx:
    free_xenheap_pages(ffa_rx, 0);
    ffa_rx = NULL;
    ffa_version = 0;

    return false;
}

static const struct tee_mediator_ops ffa_ops =
{
    .probe = ffa_probe,
    .domain_init = ffa_domain_init,
    .domain_teardown = ffa_domain_teardown,
    .relinquish_resources = ffa_relinquish_resources,
    .handle_call = ffa_handle_call,
};

REGISTER_TEE_MEDIATOR(ffa, "FF-A", XEN_DOMCTL_CONFIG_TEE_FFA, &ffa_ops);
