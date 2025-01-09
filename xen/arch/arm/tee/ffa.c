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
 * o FFA_NOTIFICATION_*:
 *   - only supports global notifications, that is, per vCPU notifications
 *     are not supported
 *   - doesn't support signalling the secondary scheduler of pending
 *     notification for secure partitions
 *   - doesn't support notifications for Xen itself
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

/* Negotiated FF-A version to use with the SPMC, 0 if not there or supported */
static uint32_t __ro_after_init ffa_fw_version;

/* Features supported by the SPMC or secure world when present */
DECLARE_BITMAP(ffa_fw_abi_supported, FFA_ABI_BITMAP_SIZE);

struct ffa_fw_abi {
    uint32_t id;
    const char *name;
};

#define FW_ABI(abi) {abi,#abi}

/* List of ABI we use from the firmware */
static const struct ffa_fw_abi ffa_fw_abi_needed[] = {
    FW_ABI(FFA_VERSION),
    FW_ABI(FFA_FEATURES),
    FW_ABI(FFA_NOTIFICATION_BITMAP_CREATE),
    FW_ABI(FFA_NOTIFICATION_BITMAP_DESTROY),
    FW_ABI(FFA_PARTITION_INFO_GET),
    FW_ABI(FFA_NOTIFICATION_INFO_GET_64),
    FW_ABI(FFA_NOTIFICATION_GET),
    FW_ABI(FFA_RX_RELEASE),
    FW_ABI(FFA_RXTX_MAP_64),
    FW_ABI(FFA_RXTX_UNMAP),
    FW_ABI(FFA_MEM_SHARE_32),
    FW_ABI(FFA_MEM_SHARE_64),
    FW_ABI(FFA_MEM_RECLAIM),
    FW_ABI(FFA_MSG_SEND_DIRECT_REQ_32),
    FW_ABI(FFA_MSG_SEND_DIRECT_REQ_64),
    FW_ABI(FFA_MSG_SEND2),
};

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
        return false;

    *vers = resp.a0;

    return true;
}

static bool ffa_abi_supported(uint32_t id)
{
    return !ffa_simple_call(FFA_FEATURES, id, 0, 0, 0);
}

static void handle_version(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t vers = get_user_reg(regs, 1);

    /*
     * Guest will use the version it requested if it is our major and minor
     * lower or equals to ours. If the minor is greater, our version will be
     * used.
     * In any case return our version to the caller.
     */
    if ( FFA_VERSION_MAJOR(vers) == FFA_MY_VERSION_MAJOR )
    {
        if ( FFA_VERSION_MINOR(vers) > FFA_MY_VERSION_MINOR )
            ctx->guest_vers = FFA_MY_VERSION;
        else
            ctx->guest_vers = vers;
    }
    ffa_set_regs(regs, FFA_MY_VERSION, 0, 0, 0, 0, 0, 0, 0);
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
    case FFA_MSG_SEND2:
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
    case FFA_FEATURE_NOTIF_PEND_INTR:
        ffa_set_regs_success(regs, GUEST_FFA_NOTIF_PEND_INTR_ID, 0);
        break;
    case FFA_FEATURE_SCHEDULE_RECV_INTR:
        ffa_set_regs_success(regs, GUEST_FFA_SCHEDULE_RECV_INTR_ID, 0);
        break;

    case FFA_NOTIFICATION_BIND:
    case FFA_NOTIFICATION_UNBIND:
    case FFA_NOTIFICATION_GET:
    case FFA_NOTIFICATION_SET:
    case FFA_NOTIFICATION_INFO_GET_32:
    case FFA_NOTIFICATION_INFO_GET_64:
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
        break;
    case FFA_RXTX_UNMAP:
        e = ffa_handle_rxtx_unmap();
        break;
    case FFA_PARTITION_INFO_GET:
        ffa_handle_partition_info_get(regs);
        return true;
    case FFA_RX_RELEASE:
        e = ffa_rx_release(d);
        break;
    case FFA_MSG_SEND_DIRECT_REQ_32:
    case FFA_MSG_SEND_DIRECT_REQ_64:
        ffa_handle_msg_send_direct_req(regs, fid);
        return true;
    case FFA_MSG_SEND2:
        e = ffa_handle_msg_send2(regs);
        break;
    case FFA_MEM_SHARE_32:
    case FFA_MEM_SHARE_64:
        ffa_handle_mem_share(regs);
        return true;
    case FFA_MEM_RECLAIM:
        e = ffa_handle_mem_reclaim(regpair_to_uint64(get_user_reg(regs, 2),
                                                     get_user_reg(regs, 1)),
                                   get_user_reg(regs, 3));
        break;
    case FFA_NOTIFICATION_BIND:
        e = ffa_handle_notification_bind(regs);
        break;
    case FFA_NOTIFICATION_UNBIND:
        e = ffa_handle_notification_unbind(regs);
        break;
    case FFA_NOTIFICATION_INFO_GET_32:
    case FFA_NOTIFICATION_INFO_GET_64:
        ffa_handle_notification_info_get(regs);
        return true;
    case FFA_NOTIFICATION_GET:
        ffa_handle_notification_get(regs);
        return true;
    case FFA_NOTIFICATION_SET:
        e = ffa_handle_notification_set(regs);
        break;

    default:
        gprintk(XENLOG_ERR, "ffa: unhandled fid 0x%x\n", fid);
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return true;
    }

    if ( e )
        ffa_set_regs_error(regs, e);
    else
        ffa_set_regs_success(regs, 0, 0);
    return true;
}

static int ffa_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx;
    int ret;

    if ( !ffa_fw_version )
        return -ENODEV;
    /*
     * We are using the domain_id + 1 as the FF-A ID for VMs as FF-A ID 0 is
     * reserved for the hypervisor and we only support secure endpoints using
     * FF-A IDs with BIT 15 set to 1 so make sure those are not used by Xen.
     */
    BUILD_BUG_ON(DOMID_FIRST_RESERVED >= UINT16_MAX);
    BUILD_BUG_ON((DOMID_MASK & BIT(15, U)) != 0);

    if ( d->domain_id >= DOMID_FIRST_RESERVED )
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

    ret = ffa_partinfo_domain_init(d);
    if ( ret )
        return ret;

    return ffa_notif_domain_init(d);
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
    ffa_notif_domain_destroy(d);

    ffa_domain_teardown_continue(ctx, true /* first_time */);

    return 0;
}

static void ffa_free_domain_ctx(struct domain *d)
{
    XFREE(d->arch.tee);
}

static int ffa_relinquish_resources(struct domain *d)
{
    return 0;
}

static void ffa_init_secondary(void)
{
    ffa_notif_init_interrupt();
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

    printk(XENLOG_INFO "ARM FF-A Mediator version %u.%u\n",
           FFA_MY_VERSION_MAJOR, FFA_MY_VERSION_MINOR);

    /*
     * psci_init_smccc() updates this value with what's reported by EL-3
     * or secure world.
     */
    if ( smccc_ver < ARM_SMCCC_VERSION_1_2 )
    {
        printk(XENLOG_ERR
               "ffa: unsupported SMCCC version %#x (need at least %#x)\n",
               smccc_ver, ARM_SMCCC_VERSION_1_2);
        goto err_no_fw;
    }

    if ( !ffa_get_version(&vers) )
    {
        gprintk(XENLOG_ERR, "Cannot retrieve the FFA version\n");
        goto err_no_fw;
    }

    /* Some sanity check in case we update the version we support */
    BUILD_BUG_ON(FFA_MIN_SPMC_VERSION > FFA_MY_VERSION);
    BUILD_BUG_ON(FFA_VERSION_MAJOR(FFA_MIN_SPMC_VERSION) !=
                                   FFA_MY_VERSION_MAJOR);

    major_vers = FFA_VERSION_MAJOR(vers);
    minor_vers = FFA_VERSION_MINOR(vers);

    if ( major_vers != FFA_MY_VERSION_MAJOR ||
         minor_vers < FFA_VERSION_MINOR(FFA_MIN_SPMC_VERSION) )
    {
        printk(XENLOG_ERR "ffa: Incompatible firmware version %u.%u\n",
               major_vers, minor_vers);
        goto err_no_fw;
    }

    printk(XENLOG_INFO "ARM FF-A Firmware version %u.%u\n",
           major_vers, minor_vers);

    /*
     * If the call succeed and the version returned is higher or equal to
     * the one Xen requested, the version requested by Xen will be the one
     * used. If the version returned is lower but compatible with Xen, Xen
     * will use that version instead.
     * A version with a different major or lower than the minimum version
     * we support is rejected before.
     * See https://developer.arm.com/documentation/den0077/e/ chapter 13.2.1
     */
    if ( minor_vers > FFA_MY_VERSION_MINOR )
        ffa_fw_version = FFA_MY_VERSION;
    else
        ffa_fw_version = vers;

    for ( unsigned int i = 0; i < ARRAY_SIZE(ffa_fw_abi_needed); i++ )
    {
        ASSERT(FFA_ABI_BITNUM(ffa_fw_abi_needed[i].id) < FFA_ABI_BITMAP_SIZE);

        if ( ffa_abi_supported(ffa_fw_abi_needed[i].id) )
            set_bit(FFA_ABI_BITNUM(ffa_fw_abi_needed[i].id),
                    ffa_fw_abi_supported);
        else
            printk(XENLOG_INFO "ARM FF-A Firmware does not support %s\n",
                   ffa_fw_abi_needed[i].name);
    }

    if ( !ffa_rxtx_init() )
    {
        printk(XENLOG_ERR "ffa: Error during RXTX buffer init\n");
        goto err_no_fw;
    }

    if ( !ffa_partinfo_init() )
        goto err_rxtx_destroy;

    ffa_notif_init();
    INIT_LIST_HEAD(&ffa_teardown_head);
    init_timer(&ffa_teardown_timer, ffa_teardown_timer_callback, NULL, 0);

    return true;

err_rxtx_destroy:
    ffa_rxtx_destroy();
err_no_fw:
    ffa_fw_version = 0;
    bitmap_zero(ffa_fw_abi_supported, FFA_ABI_BITMAP_SIZE);
    printk(XENLOG_WARNING "ARM FF-A No firmware support\n");

    return false;
}

static const struct tee_mediator_ops ffa_ops =
{
    .probe = ffa_probe,
    .init_secondary = ffa_init_secondary,
    .domain_init = ffa_domain_init,
    .domain_teardown = ffa_domain_teardown,
    .free_domain_ctx = ffa_free_domain_ctx,
    .relinquish_resources = ffa_relinquish_resources,
    .handle_call = ffa_handle_call,
};

REGISTER_TEE_MEDIATOR(ffa, "FF-A", XEN_DOMCTL_CONFIG_TEE_FFA, &ffa_ops);
