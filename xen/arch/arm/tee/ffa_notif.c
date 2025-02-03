/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/cpu.h>
#include <xen/list.h>
#include <xen/notifier.h>
#include <xen/spinlock.h>
#include <xen/tasklet.h>
#include <xen/types.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

static bool __ro_after_init notif_enabled;
static unsigned int __ro_after_init notif_sri_irq;

int ffa_handle_notification_bind(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t src_dst = get_user_reg(regs, 1);
    uint32_t flags = get_user_reg(regs, 2);
    uint32_t bitmap_lo = get_user_reg(regs, 3);
    uint32_t bitmap_hi = get_user_reg(regs, 4);

    if ( !notif_enabled )
        return FFA_RET_NOT_SUPPORTED;

    if ( (src_dst & 0xFFFFU) != ffa_get_vm_id(d) )
        return FFA_RET_INVALID_PARAMETERS;

    if ( flags )    /* Only global notifications are supported */
        return FFA_RET_DENIED;

    /*
     * We only support notifications from SP so no need to check the sender
     * endpoint ID, the SPMC will take care of that for us.
     */
    return ffa_simple_call(FFA_NOTIFICATION_BIND, src_dst, flags, bitmap_lo,
                           bitmap_hi);
}

int ffa_handle_notification_unbind(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t src_dst = get_user_reg(regs, 1);
    uint32_t bitmap_lo = get_user_reg(regs, 3);
    uint32_t bitmap_hi = get_user_reg(regs, 4);

    if ( !notif_enabled )
        return FFA_RET_NOT_SUPPORTED;

    if ( (src_dst & 0xFFFFU) != ffa_get_vm_id(d) )
        return FFA_RET_INVALID_PARAMETERS;

    /*
     * We only support notifications from SP so no need to check the
     * destination endpoint ID, the SPMC will take care of that for us.
     */
    return  ffa_simple_call(FFA_NOTIFICATION_UNBIND, src_dst, 0, bitmap_lo,
                            bitmap_hi);
}

void ffa_handle_notification_info_get(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( test_and_clear_bool(ctx->notif.secure_pending) )
    {
        /* A pending global notification for the guest */
        ffa_set_regs(regs, FFA_SUCCESS_64, 0,
                     1U << FFA_NOTIF_INFO_GET_ID_COUNT_SHIFT, ffa_get_vm_id(d),
                     0, 0, 0, 0);
    }
    else
    {
        /* Report an error if there where no pending global notification */
        ffa_set_regs_error(regs, FFA_RET_NO_DATA);
    }
}

void ffa_handle_notification_get(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t recv = get_user_reg(regs, 1);
    uint32_t flags = get_user_reg(regs, 2);
    uint32_t w2 = 0;
    uint32_t w3 = 0;
    uint32_t w4 = 0;
    uint32_t w5 = 0;
    uint32_t w6 = 0;
    uint32_t w7 = 0;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( (recv & 0xFFFFU) != ffa_get_vm_id(d) )
    {
        ffa_set_regs_error(regs, FFA_RET_INVALID_PARAMETERS);
        return;
    }

    if ( flags & ( FFA_NOTIF_FLAG_BITMAP_SP | FFA_NOTIF_FLAG_BITMAP_SPM ) )
    {
        struct arm_smccc_1_2_regs arg = {
            .a0 = FFA_NOTIFICATION_GET,
            .a1 = recv,
            .a2 = flags & ( FFA_NOTIF_FLAG_BITMAP_SP |
                            FFA_NOTIF_FLAG_BITMAP_SPM ),
        };
        struct arm_smccc_1_2_regs resp;
        int32_t e;

        /*
         * Clear secure pending if both FFA_NOTIF_FLAG_BITMAP_SP and
         * FFA_NOTIF_FLAG_BITMAP_SPM are set since secure world can't have
         * any more pending notifications.
         */
        if ( ( flags  & FFA_NOTIF_FLAG_BITMAP_SP ) &&
             ( flags & FFA_NOTIF_FLAG_BITMAP_SPM ) )
        {
                struct ffa_ctx *ctx = d->arch.tee;

                ACCESS_ONCE(ctx->notif.secure_pending) = false;
        }

        arm_smccc_1_2_smc(&arg, &resp);
        e = ffa_get_ret_code(&resp);
        if ( e )
        {
            ffa_set_regs_error(regs, e);
            return;
        }

        if ( flags & FFA_NOTIF_FLAG_BITMAP_SP )
        {
            w2 = resp.a2;
            w3 = resp.a3;
        }

        if ( flags & FFA_NOTIF_FLAG_BITMAP_SPM )
            w6 = resp.a6;
    }

    ffa_set_regs(regs, FFA_SUCCESS_32, 0, w2, w3, w4, w5, w6, w7);
}

int ffa_handle_notification_set(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t src_dst = get_user_reg(regs, 1);
    uint32_t flags = get_user_reg(regs, 2);
    uint32_t bitmap_lo = get_user_reg(regs, 3);
    uint32_t bitmap_hi = get_user_reg(regs, 4);

    if ( !notif_enabled )
        return FFA_RET_NOT_SUPPORTED;

    if ( (src_dst >> 16) != ffa_get_vm_id(d) )
        return FFA_RET_INVALID_PARAMETERS;

    /* Let the SPMC check the destination of the notification */
    return ffa_simple_call(FFA_NOTIFICATION_SET, src_dst, flags, bitmap_lo,
                           bitmap_hi);
}

/*
 * Extract a 16-bit ID (index n) from the successful return value from
 * FFA_NOTIFICATION_INFO_GET_64 or FFA_NOTIFICATION_INFO_GET_32. IDs are
 * returned in registers 3 to 7 with four IDs per register for 64-bit
 * calling convention and two IDs per register for 32-bit calling
 * convention.
 */
static uint16_t get_id_from_resp(struct arm_smccc_1_2_regs *resp,
                                 unsigned int n)
{
    unsigned int ids_per_reg;
    unsigned int reg_idx;
    unsigned int reg_shift;

    if ( smccc_is_conv_64(resp->a0) )
        ids_per_reg = 4;
    else
        ids_per_reg = 2;

    reg_idx = n / ids_per_reg + 3;
    reg_shift = ( n % ids_per_reg ) * 16;

    switch ( reg_idx )
    {
    case 3:
        return resp->a3 >> reg_shift;
    case 4:
        return resp->a4 >> reg_shift;
    case 5:
        return resp->a5 >> reg_shift;
    case 6:
        return resp->a6 >> reg_shift;
    case 7:
        return resp->a7 >> reg_shift;
    default:
        ASSERT(0); /* "Can't happen" */
        return 0;
    }
}

static void notif_vm_pend_intr(uint16_t vm_id)
{
    struct ffa_ctx *ctx;
    struct domain *d;
    struct vcpu *v;

    /*
     * vm_id == 0 means a notifications pending for Xen itself, but
     * we don't support that yet.
     */
    if ( !vm_id )
        return;

    /*
     * This can fail if the domain has been destroyed after
     * FFA_NOTIFICATION_INFO_GET_64. Ignoring this is harmless since the
     * guest doesn't exist any more.
     */
    d = ffa_rcu_lock_domain_by_vm_id(vm_id);
    if ( !d )
        return;

    /*
     * Failing here is unlikely since the domain ID must have been reused
     * for a new domain between the FFA_NOTIFICATION_INFO_GET_64 and
     * ffa_rcu_lock_domain_by_vm_id() calls.
     *
     * Continuing on the scenario above if the domain has FF-A enabled. We
     * can't tell here if the domain ID has been reused for a new domain so
     * we inject an NPI. When the NPI handler in the domain calls
     * FFA_NOTIFICATION_GET it will have accurate information, the worst
     * case is a spurious NPI.
     */
    ctx = d->arch.tee;
    if ( !ctx )
        goto out_unlock;

    /*
     * arch.tee is freed from complete_domain_destroy() so the RCU lock
     * guarantees that the data structure isn't freed while we're accessing
     * it.
     */
    ACCESS_ONCE(ctx->notif.secure_pending) = true;

    /*
     * Since we're only delivering global notification, always
     * deliver to the first online vCPU. It doesn't matter
     * which we chose, as long as it's available.
     */
    for_each_vcpu(d, v)
    {
        if ( is_vcpu_online(v) )
        {
            vgic_inject_irq(d, v, GUEST_FFA_NOTIF_PEND_INTR_ID,
                            true);
            break;
        }
    }
    if ( !v )
        printk(XENLOG_ERR "ffa: can't inject NPI, all vCPUs offline\n");

out_unlock:
    rcu_unlock_domain(d);
}

static void notif_sri_action(void *unused)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_NOTIFICATION_INFO_GET_64,
    };
    struct arm_smccc_1_2_regs resp;
    unsigned int id_pos;
    unsigned int list_count;
    uint64_t ids_count;
    unsigned int n;
    int32_t res;

    do {
        arm_smccc_1_2_smc(&arg, &resp);
        res = ffa_get_ret_code(&resp);
        if ( res )
        {
            if ( res != FFA_RET_NO_DATA )
                printk(XENLOG_ERR "ffa: notification info get failed: error %d\n",
                       res);
            return;
        }

        ids_count = resp.a2 >> FFA_NOTIF_INFO_GET_ID_LIST_SHIFT;
        list_count = ( resp.a2 >> FFA_NOTIF_INFO_GET_ID_COUNT_SHIFT ) &
                     FFA_NOTIF_INFO_GET_ID_COUNT_MASK;

        id_pos = 0;
        for ( n = 0; n < list_count; n++ )
        {
            unsigned int count = ((ids_count >> 2 * n) & 0x3) + 1;
            uint16_t vm_id = get_id_from_resp(&resp, id_pos);

            notif_vm_pend_intr(vm_id);

            id_pos += count;
        }

    } while (resp.a2 & FFA_NOTIF_INFO_GET_MORE_FLAG);
}

static DECLARE_TASKLET(notif_sri_tasklet, notif_sri_action, NULL);

static void notif_irq_handler(int irq, void *data)
{
    tasklet_schedule(&notif_sri_tasklet);
}

static int32_t ffa_notification_bitmap_create(uint16_t vm_id,
                                              uint32_t vcpu_count)
{
    return ffa_simple_call(FFA_NOTIFICATION_BITMAP_CREATE, vm_id, vcpu_count,
                           0, 0);
}

static int32_t ffa_notification_bitmap_destroy(uint16_t vm_id)
{
    return ffa_simple_call(FFA_NOTIFICATION_BITMAP_DESTROY, vm_id, 0, 0, 0);
}

void ffa_notif_init_interrupt(void)
{
    int ret;

    if ( notif_enabled && notif_sri_irq < NR_GIC_SGI )
    {
        /*
         * An error here is unlikely since the primary CPU has already
         * succeeded in installing the interrupt handler. If this fails it
         * may lead to a problem with notifictaions.
         *
         * The CPUs without an notification handler installed will fail to
         * trigger on the SGI indicating that there are notifications
         * pending, while the SPMC in the secure world will not notice that
         * the interrupt was lost.
         */
        ret = request_irq(notif_sri_irq, 0, notif_irq_handler, "FF-A notif",
                          NULL);
        if ( ret )
            printk(XENLOG_ERR "ffa: request_irq irq %u failed: error %d\n",
                   notif_sri_irq, ret);
    }
}

void ffa_notif_init(void)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_FEATURES,
        .a1 = FFA_FEATURE_SCHEDULE_RECV_INTR,
    };
    struct arm_smccc_1_2_regs resp;
    unsigned int irq;
    int ret;

    /* Only enable fw notification if all ABIs we need are supported */
    if ( !(ffa_fw_supports_fid(FFA_NOTIFICATION_BITMAP_CREATE) &&
           ffa_fw_supports_fid(FFA_NOTIFICATION_BITMAP_DESTROY) &&
           ffa_fw_supports_fid(FFA_NOTIFICATION_GET) &&
           ffa_fw_supports_fid(FFA_NOTIFICATION_INFO_GET_64)) )
        return;

    arm_smccc_1_2_smc(&arg, &resp);
    if ( resp.a0 != FFA_SUCCESS_32 )
        return;

    irq = resp.a2;
    notif_sri_irq = irq;
    if ( irq >= NR_GIC_SGI )
        irq_set_type(irq, IRQ_TYPE_EDGE_RISING);
    ret = request_irq(irq, 0, notif_irq_handler, "FF-A notif", NULL);
    if ( ret )
    {
        printk(XENLOG_ERR "ffa: request_irq irq %u failed: error %d\n",
               irq, ret);
        return;
    }

    notif_enabled = true;
}

int ffa_notif_domain_init(struct domain *d)
{
    int32_t res;

    if ( !notif_enabled )
        return 0;

    res = ffa_notification_bitmap_create(ffa_get_vm_id(d), d->max_vcpus);
    if ( res )
        return -ENOMEM;

    return 0;
}

void ffa_notif_domain_destroy(struct domain *d)
{
    /*
     * Call bitmap_destroy even if bitmap create failed as the SPMC will
     * return a DENIED error that we will ignore.
     */
    if ( notif_enabled )
        ffa_notification_bitmap_destroy(ffa_get_vm_id(d));
}
