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

/* Negotiated FF-A version to use with the SPMC */
static uint32_t __ro_after_init ffa_version;


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

static void handle_features(struct cpu_user_regs *regs)
{
    uint32_t a1 = get_user_reg(regs, 1);
    unsigned int n;

    for ( n = 2; n <= 7; n++ )
    {
        if ( get_user_reg(regs, n) )
        {
            ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
            return;
        }
    }

    switch ( a1 )
    {
    case FFA_ERROR:
    case FFA_VERSION:
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
    case FFA_FEATURES:
    case FFA_ID_GET:
    case FFA_RX_RELEASE:
    case FFA_RXTX_UNMAP:
    case FFA_MEM_RECLAIM:
    case FFA_PARTITION_INFO_GET:
    case FFA_MSG_SEND_DIRECT_REQ_32:
    case FFA_MSG_SEND_DIRECT_REQ_64:
        ffa_set_regs_success(regs, 0, 0);
        break;
    case FFA_MEM_SHARE_64:
    case FFA_MEM_SHARE_32:
        /*
         * We currently don't support dynamically allocated buffers. Report
         * that with 0 in bit[0] of w2.
         */
        ffa_set_regs_success(regs, 0, 0);
        break;
    case FFA_RXTX_MAP_64:
    case FFA_RXTX_MAP_32:
        /*
         * We currently support 4k pages only, report that as 00 in
         * bit[0:1] in w0. This needs to be revised if Xen page size
         * differs from FFA_PAGE_SIZE (SZ_4K).
         */
        BUILD_BUG_ON(PAGE_SIZE != FFA_PAGE_SIZE);
        ffa_set_regs_success(regs, 0, 0);
        break;
    default:
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        break;
    }
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
    case FFA_FEATURES:
        handle_features(regs);
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

static int ffa_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx;

    if ( !ffa_version )
        return -ENODEV;
     /*
      * We can't use that last possible domain ID or ffa_get_vm_id() would
      * cause an overflow.
      */
    if ( d->domain_id >= UINT16_MAX)
        return -ERANGE;

    ctx = xzalloc(struct ffa_ctx);
    if ( !ctx )
        return -ENOMEM;

    d->arch.tee = ctx;
    ctx->teardown_d = d;
    INIT_LIST_HEAD(&ctx->shm_list);

    /*
     * ffa_domain_teardown() will be called if ffa_domain_init() returns an
     * error, so no need for cleanup in this function.
     */

    if ( !ffa_partinfo_domain_init(d) )
        return -EIO;

    return 0;
}

static void ffa_domain_teardown_continue(struct ffa_ctx *ctx, bool first_time)
{
    struct ffa_ctx *next_ctx = NULL;
    bool retry = false;

    if ( !ffa_partinfo_domain_destroy(ctx->teardown_d) )
        retry = true;
    if ( !ffa_shm_domain_destroy(ctx->teardown_d) )
        retry = true;

    if ( retry )
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

    ffa_rxtx_domain_destroy(d);

    ffa_domain_teardown_continue(ctx, true /* first_time */);

    return 0;
}

static int ffa_relinquish_resources(struct domain *d)
{
    return 0;
}

static bool ffa_probe(void)
{
    uint32_t vers;
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

    if ( !ffa_rxtx_init() )
        return false;

    ffa_version = vers;

    if ( !ffa_partinfo_init() )
        goto err_rxtx_destroy;

    INIT_LIST_HEAD(&ffa_teardown_head);
    init_timer(&ffa_teardown_timer, ffa_teardown_timer_callback, NULL, 0);

    return true;

err_rxtx_destroy:
    ffa_rxtx_destroy();
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
