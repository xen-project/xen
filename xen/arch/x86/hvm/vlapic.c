/*
 * vlapic.c: virtualize LAPIC for HVM vcpus.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2006 Keir Fraser, XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/numa.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <public/hvm/ioreq.h>
#include <public/hvm/params.h>

#define VLAPIC_VERSION                  0x00050014
#define VLAPIC_LVT_NUM                  6

/* vlapic's frequence is 100 MHz */
#define APIC_BUS_CYCLE_NS               10

#define LVT_MASK \
    APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK

#define LINT_MASK   \
    LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY |\
    APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER

static unsigned int vlapic_lvt_mask[VLAPIC_LVT_NUM] =
{
     /* LVTT */
     LVT_MASK | APIC_TIMER_MODE_MASK,
     /* LVTTHMR */
     LVT_MASK | APIC_MODE_MASK,
     /* LVTPC */
     LVT_MASK | APIC_MODE_MASK,
     /* LVT0-1 */
     LINT_MASK, LINT_MASK,
     /* LVTERR */
     LVT_MASK
};

/* Following could belong in apicdef.h */
#define APIC_SHORT_MASK                  0xc0000
#define APIC_DEST_NOSHORT                0x0
#define APIC_DEST_MASK                   0x800

#define vlapic_lvt_vector(vlapic, lvt_type)                     \
    (vlapic_get_reg(vlapic, lvt_type) & APIC_VECTOR_MASK)

#define vlapic_lvt_dm(vlapic, lvt_type)                         \
    (vlapic_get_reg(vlapic, lvt_type) & APIC_MODE_MASK)

#define vlapic_lvtt_period(vlapic)                              \
    ((vlapic_get_reg(vlapic, APIC_LVTT) & APIC_TIMER_MODE_MASK) \
     == APIC_TIMER_MODE_PERIODIC)

#define vlapic_lvtt_oneshot(vlapic)                             \
    ((vlapic_get_reg(vlapic, APIC_LVTT) & APIC_TIMER_MODE_MASK) \
     == APIC_TIMER_MODE_ONESHOT)

#define vlapic_lvtt_tdt(vlapic)                                 \
    ((vlapic_get_reg(vlapic, APIC_LVTT) & APIC_TIMER_MODE_MASK) \
     == APIC_TIMER_MODE_TSC_DEADLINE)


/*
 * Generic APIC bitmap vector update & search routines.
 */

#define VEC_POS(v) ((v)%32)
#define REG_POS(v) (((v)/32) * 0x10)
#define vlapic_test_and_set_vector(vec, bitmap)                         \
    test_and_set_bit(VEC_POS(vec),                                      \
                     (unsigned long *)((bitmap) + REG_POS(vec)))
#define vlapic_test_and_clear_vector(vec, bitmap)                       \
    test_and_clear_bit(VEC_POS(vec),                                    \
                       (unsigned long *)((bitmap) + REG_POS(vec)))
#define vlapic_set_vector(vec, bitmap)                                  \
    set_bit(VEC_POS(vec), (unsigned long *)((bitmap) + REG_POS(vec)))
#define vlapic_clear_vector(vec, bitmap)                                \
    clear_bit(VEC_POS(vec), (unsigned long *)((bitmap) + REG_POS(vec)))

static int vlapic_find_highest_vector(void *bitmap)
{
    uint32_t *word = bitmap;
    int word_offset = MAX_VECTOR / 32;

    /* Work backwards through the bitmap (first 32-bit word in every four). */
    while ( (word_offset != 0) && (word[(--word_offset)*4] == 0) )
        continue;

    return (fls(word[word_offset*4]) - 1) + (word_offset * 32);
}


/*
 * IRR-specific bitmap update & search routines.
 */

static int vlapic_test_and_set_irr(int vector, struct vlapic *vlapic)
{
    return vlapic_test_and_set_vector(vector, &vlapic->regs->data[APIC_IRR]);
}

static void vlapic_clear_irr(int vector, struct vlapic *vlapic)
{
    vlapic_clear_vector(vector, &vlapic->regs->data[APIC_IRR]);
}

static int vlapic_find_highest_irr(struct vlapic *vlapic)
{
    return vlapic_find_highest_vector(&vlapic->regs->data[APIC_IRR]);
}

int vlapic_set_irq(struct vlapic *vlapic, uint8_t vec, uint8_t trig)
{
    if ( trig )
        vlapic_set_vector(vec, &vlapic->regs->data[APIC_TMR]);

    /* We may need to wake up target vcpu, besides set pending bit here */
    return !vlapic_test_and_set_irr(vec, vlapic);
}

static int vlapic_find_highest_isr(struct vlapic *vlapic)
{
    return vlapic_find_highest_vector(&vlapic->regs->data[APIC_ISR]);
}

static uint32_t vlapic_get_ppr(struct vlapic *vlapic)
{
    uint32_t tpr, isrv, ppr;
    int isr;

    tpr  = vlapic_get_reg(vlapic, APIC_TASKPRI);
    isr  = vlapic_find_highest_isr(vlapic);
    isrv = (isr != -1) ? isr : 0;

    if ( (tpr & 0xf0) >= (isrv & 0xf0) )
        ppr = tpr & 0xff;
    else
        ppr = isrv & 0xf0;

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_INTERRUPT,
                "vlapic %p, ppr 0x%x, isr 0x%x, isrv 0x%x",
                vlapic, ppr, isr, isrv);

    return ppr;
}

static int vlapic_match_logical_addr(struct vlapic *vlapic, uint8_t mda)
{
    int result = 0;
    uint32_t logical_id;

    if ( vlapic_x2apic_mode(vlapic) )
    {
        logical_id = vlapic_get_reg(vlapic, APIC_LDR);
        return !!(logical_id & mda);
    }

    logical_id = GET_xAPIC_LOGICAL_ID(vlapic_get_reg(vlapic, APIC_LDR));

    switch ( vlapic_get_reg(vlapic, APIC_DFR) )
    {
    case APIC_DFR_FLAT:
        if ( logical_id & mda )
            result = 1;
        break;
    case APIC_DFR_CLUSTER:
        if ( ((logical_id >> 4) == (mda >> 0x4)) && (logical_id & mda & 0xf) )
            result = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "Bad DFR value for lapic of vcpu %d: %08x\n",
                 vlapic_vcpu(vlapic)->vcpu_id,
                 vlapic_get_reg(vlapic, APIC_DFR));
        break;
    }

    return result;
}

bool_t vlapic_match_dest(
    struct vlapic *target, struct vlapic *source,
    int short_hand, uint8_t dest, uint8_t dest_mode)
{
    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "target %p, source %p, dest 0x%x, "
                "dest_mode 0x%x, short_hand 0x%x",
                target, source, dest, dest_mode, short_hand);

    switch ( short_hand )
    {
    case APIC_DEST_NOSHORT:
        if ( dest_mode )
            return vlapic_match_logical_addr(target, dest);
        return ((dest == 0xFF) || (dest == VLAPIC_ID(target)));

    case APIC_DEST_SELF:
        return (target == source);

    case APIC_DEST_ALLINC:
        return 1;

    case APIC_DEST_ALLBUT:
        return (target != source);

    default:
        gdprintk(XENLOG_WARNING, "Bad dest shorthand value %x\n", short_hand);
        break;
    }

    return 0;
}

static void vlapic_init_sipi_action(unsigned long _vcpu)
{
    struct vcpu *origin = (struct vcpu *)_vcpu;
    struct vcpu *target = vcpu_vlapic(origin)->init_sipi.target;
    uint32_t icr = vcpu_vlapic(origin)->init_sipi.icr;

    vcpu_pause(target);

    switch ( icr & APIC_MODE_MASK )
    {
    case APIC_DM_INIT: {
        bool_t fpu_initialised;
        int rc;

        domain_lock(target->domain);
        /* Reset necessary VCPU state. This does not include FPU state. */
        fpu_initialised = target->fpu_initialised;
        rc = vcpu_reset(target);
        ASSERT(!rc);
        target->fpu_initialised = fpu_initialised;
        vlapic_reset(vcpu_vlapic(target));
        domain_unlock(target->domain);
        break;
    }

    case APIC_DM_STARTUP: {
        uint16_t reset_cs = (icr & 0xffu) << 8;
        hvm_vcpu_reset_state(target, reset_cs, 0);
        break;
    }

    default:
        BUG();
    }

    vcpu_unpause(target);

    vcpu_vlapic(origin)->init_sipi.target = NULL;
    vcpu_unpause(origin);
}

static int vlapic_schedule_init_sipi_tasklet(struct vcpu *target, uint32_t icr)
{
    struct vcpu *origin = current;

    if ( vcpu_vlapic(origin)->init_sipi.target != NULL )
    {
        WARN(); /* should be impossible but don't BUG, just in case */
        return X86EMUL_UNHANDLEABLE;
    }

    vcpu_pause_nosync(origin);

    vcpu_vlapic(origin)->init_sipi.target = target;
    vcpu_vlapic(origin)->init_sipi.icr = icr;
    tasklet_schedule(&vcpu_vlapic(origin)->init_sipi.tasklet);

    return X86EMUL_RETRY;
}

/* Add a pending IRQ into lapic. */
static int vlapic_accept_irq(struct vcpu *v, uint32_t icr_low)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    uint8_t vector = (uint8_t)icr_low;
    int rc = X86EMUL_OKAY;

    switch ( icr_low & APIC_MODE_MASK )
    {
    case APIC_DM_FIXED:
    case APIC_DM_LOWEST:
        if ( vlapic_enabled(vlapic) &&
             !vlapic_test_and_set_irr(vector, vlapic) )
            vcpu_kick(v);
        break;

    case APIC_DM_REMRD:
        gdprintk(XENLOG_WARNING, "Ignoring delivery mode 3\n");
        break;

    case APIC_DM_SMI:
        gdprintk(XENLOG_WARNING, "Ignoring guest SMI\n");
        break;

    case APIC_DM_NMI:
        if ( !test_and_set_bool(v->nmi_pending) )
        {
            bool_t wake = 0;
            domain_lock(v->domain);
            if ( v->is_initialised )
                wake = test_and_clear_bit(_VPF_down, &v->pause_flags);
            domain_unlock(v->domain);
            if ( wake )
                vcpu_wake(v);
            vcpu_kick(v);
        }
        break;

    case APIC_DM_INIT:
        /* No work on INIT de-assert for P4-type APIC. */
        if ( (icr_low & (APIC_INT_LEVELTRIG | APIC_INT_ASSERT)) ==
             APIC_INT_LEVELTRIG )
            break;
        /* Nothing to do if the VCPU is already reset. */
        if ( !v->is_initialised )
            break;
        hvm_vcpu_down(v);
        rc = vlapic_schedule_init_sipi_tasklet(v, icr_low);
        break;

    case APIC_DM_STARTUP:
        /* Nothing to do if the VCPU is already initialised. */
        if ( v->is_initialised )
            break;
        rc = vlapic_schedule_init_sipi_tasklet(v, icr_low);
        break;

    default:
        gdprintk(XENLOG_ERR, "TODO: unsupported delivery mode in ICR %x\n",
                 icr_low);
        domain_crash(v->domain);
    }

    return rc;
}

struct vlapic *vlapic_lowest_prio(
    struct domain *d, struct vlapic *source,
    int short_hand, uint8_t dest, uint8_t dest_mode)
{
    int old = d->arch.hvm_domain.irq.round_robin_prev_vcpu;
    uint32_t ppr, target_ppr = UINT_MAX;
    struct vlapic *vlapic, *target = NULL;
    struct vcpu *v;

    if ( unlikely(!d->vcpu) || unlikely((v = d->vcpu[old]) == NULL) )
        return NULL;

    do {
        v = v->next_in_list ? : d->vcpu[0];
        vlapic = vcpu_vlapic(v);
        if ( vlapic_match_dest(vlapic, source, short_hand, dest, dest_mode) &&
             vlapic_enabled(vlapic) &&
             ((ppr = vlapic_get_ppr(vlapic)) < target_ppr) )
        {
            target = vlapic;
            target_ppr = ppr;
        }
    } while ( v->vcpu_id != old );

    if ( target != NULL )
        d->arch.hvm_domain.irq.round_robin_prev_vcpu =
            vlapic_vcpu(target)->vcpu_id;

    return target;
}

void vlapic_EOI_set(struct vlapic *vlapic)
{
    int vector = vlapic_find_highest_isr(vlapic);

    /* Some EOI writes may not have a matching to an in-service interrupt. */
    if ( vector == -1 )
        return;

    vlapic_clear_vector(vector, &vlapic->regs->data[APIC_ISR]);

    if ( vlapic_test_and_clear_vector(vector, &vlapic->regs->data[APIC_TMR]) )
        vioapic_update_EOI(vlapic_domain(vlapic), vector);

    hvm_dpci_msi_eoi(current->domain, vector);
}

int vlapic_ipi(
    struct vlapic *vlapic, uint32_t icr_low, uint32_t icr_high)
{
    unsigned int dest;
    unsigned int short_hand = icr_low & APIC_SHORT_MASK;
    unsigned int dest_mode  = !!(icr_low & APIC_DEST_MASK);
    struct vlapic *target;
    struct vcpu *v;
    int rc = X86EMUL_OKAY;

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "icr = 0x%08x:%08x", icr_high, icr_low);

    dest = (vlapic_x2apic_mode(vlapic)
            ? icr_high
            : GET_xAPIC_DEST_FIELD(icr_high));

    if ( (icr_low & APIC_MODE_MASK) == APIC_DM_LOWEST )
    {
        target = vlapic_lowest_prio(vlapic_domain(vlapic), vlapic,
                                    short_hand, dest, dest_mode);
        if ( target != NULL )
            rc = vlapic_accept_irq(vlapic_vcpu(target), icr_low);
        return rc;
    }

    for_each_vcpu ( vlapic_domain(vlapic), v )
    {
        if ( vlapic_match_dest(vcpu_vlapic(v), vlapic,
                               short_hand, dest, dest_mode) )
                rc = vlapic_accept_irq(v, icr_low);
        if ( rc != X86EMUL_OKAY )
            break;
    }

    return rc;
}

static uint32_t vlapic_get_tmcct(struct vlapic *vlapic)
{
    struct vcpu *v = current;
    uint32_t tmcct = 0, tmict = vlapic_get_reg(vlapic, APIC_TMICT);
    uint64_t counter_passed;

    counter_passed = ((hvm_get_guest_time(v) - vlapic->timer_last_update)
                      / (APIC_BUS_CYCLE_NS * vlapic->hw.timer_divisor));

    if ( tmict != 0 )
    {
        if ( vlapic_lvtt_period(vlapic) )
            counter_passed %= tmict;
        if ( counter_passed < tmict )
            tmcct = tmict - counter_passed;
    }

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER,
                "timer initial count %d, timer current count %d, "
                "offset %"PRId64,
                tmict, tmcct, counter_passed);

    return tmcct;
}

static void vlapic_set_tdcr(struct vlapic *vlapic, unsigned int val)
{
    /* Only bits 0, 1 and 3 are settable; others are MBZ. */
    val &= 0xb;
    vlapic_set_reg(vlapic, APIC_TDCR, val);

    /* Update the demangled hw.timer_divisor. */
    val = ((val & 3) | ((val & 8) >> 1)) + 1;
    vlapic->hw.timer_divisor = 1 << (val & 7);

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER,
                "timer_divisor: %d", vlapic->hw.timer_divisor);
}

static void vlapic_read_aligned(
    struct vlapic *vlapic, unsigned int offset, unsigned int *result)
{
    switch ( offset )
    {
    case APIC_PROCPRI:
        *result = vlapic_get_ppr(vlapic);
        break;

    case APIC_TMCCT: /* Timer CCR */
        if ( !vlapic_lvtt_oneshot(vlapic) && !vlapic_lvtt_period(vlapic) )
        {
            *result = 0;
            break;
        }
        *result = vlapic_get_tmcct(vlapic);
        break;

    case APIC_TMICT: /* Timer ICR */
        if ( !vlapic_lvtt_oneshot(vlapic) && !vlapic_lvtt_period(vlapic) )
        {
            *result = 0;
            break;
        }
    default:
        *result = vlapic_get_reg(vlapic, offset);
        break;
    }
}

static int vlapic_read(
    struct vcpu *v, unsigned long address,
    unsigned long len, unsigned long *pval)
{
    unsigned int alignment;
    unsigned int tmp;
    unsigned long result = 0;
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int offset = address - vlapic_base_address(vlapic);

    if ( offset > (APIC_TDCR + 0x3) )
        goto out;

    alignment = offset & 0x3;

    vlapic_read_aligned(vlapic, offset & ~0x3, &tmp);
    switch ( len )
    {
    case 1:
        result = *((unsigned char *)&tmp + alignment);
        break;

    case 2:
        if ( alignment == 3 )
            goto unaligned_exit_and_crash;
        result = *(unsigned short *)((unsigned char *)&tmp + alignment);
        break;

    case 4:
        if ( alignment != 0 )
            goto unaligned_exit_and_crash;
        result = *(unsigned int *)((unsigned char *)&tmp + alignment);
        break;

    default:
        gdprintk(XENLOG_ERR, "Local APIC read with len=0x%lx, "
                 "should be 4 instead.\n", len);
        goto exit_and_crash;
    }

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "offset 0x%x with length 0x%lx, "
                "and the result is 0x%lx", offset, len, result);

 out:
    *pval = result;
    return X86EMUL_OKAY;

 unaligned_exit_and_crash:
    gdprintk(XENLOG_ERR, "Unaligned LAPIC read len=0x%lx at offset=0x%x.\n",
             len, offset);
 exit_and_crash:
    domain_crash(v->domain);
    return X86EMUL_OKAY;
}

int hvm_x2apic_msr_read(struct vcpu *v, unsigned int msr, uint64_t *msr_content)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    uint32_t low, high = 0, offset = (msr - MSR_IA32_APICBASE_MSR) << 4;

    if ( !vlapic_x2apic_mode(vlapic) )
        return 1;

    vlapic_read_aligned(vlapic, offset, &low);
    switch ( offset )
    {
    case APIC_ID:
        low = GET_xAPIC_ID(low);
        break;

    case APIC_ICR:
        vlapic_read_aligned(vlapic, APIC_ICR2, &high);
        break;

    case APIC_ICR2:
        return 1;
    }

    *msr_content = (((uint64_t)high) << 32) | low;
    return 0;
}

static void vlapic_pt_cb(struct vcpu *v, void *data)
{
    *(s_time_t *)data = hvm_get_guest_time(v);
}

static void vlapic_tdt_pt_cb(struct vcpu *v, void *data)
{
    *(s_time_t *)data = hvm_get_guest_time(v);
    vcpu_vlapic(v)->hw.tdt_msr = 0;
}

static int vlapic_reg_write(struct vcpu *v,
                            unsigned int offset, unsigned long val)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    int rc = X86EMUL_OKAY;

    switch ( offset )
    {
    case APIC_ID:
        if ( !vlapic_x2apic_mode(vlapic) )
            vlapic_set_reg(vlapic, APIC_ID, val);
        else
            rc = X86EMUL_UNHANDLEABLE;
        break;

    case APIC_TASKPRI:
        vlapic_set_reg(vlapic, APIC_TASKPRI, val & 0xff);
        break;

    case APIC_EOI:
        vlapic_EOI_set(vlapic);
        break;

    case APIC_LDR:
        if ( !vlapic_x2apic_mode(vlapic) )
            vlapic_set_reg(vlapic, APIC_LDR, val & APIC_LDR_MASK);
        else
            rc = X86EMUL_UNHANDLEABLE;
        break;

    case APIC_DFR:
        if ( !vlapic_x2apic_mode(vlapic) )
            vlapic_set_reg(vlapic, APIC_DFR, val | 0x0FFFFFFF);
        else
            rc = X86EMUL_UNHANDLEABLE;
        break;

    case APIC_SPIV:
        vlapic_set_reg(vlapic, APIC_SPIV, val & 0x3ff);

        if ( !(val & APIC_SPIV_APIC_ENABLED) )
        {
            int i;
            uint32_t lvt_val;

            vlapic->hw.disabled |= VLAPIC_SW_DISABLED;

            for ( i = 0; i < VLAPIC_LVT_NUM; i++ )
            {
                lvt_val = vlapic_get_reg(vlapic, APIC_LVTT + 0x10 * i);
                vlapic_set_reg(vlapic, APIC_LVTT + 0x10 * i,
                               lvt_val | APIC_LVT_MASKED);
            }
        }
        else
        {
            vlapic->hw.disabled &= ~VLAPIC_SW_DISABLED;
            pt_may_unmask_irq(vlapic_domain(vlapic), &vlapic->pt);
        }
        break;

    case APIC_ESR:
        if ( vlapic_x2apic_mode(vlapic) && (val != 0) )
        {
            gdprintk(XENLOG_ERR, "Local APIC write ESR with non-zero %lx\n",
                    val);
            rc = X86EMUL_UNHANDLEABLE;
        }
        break;

    case APIC_SELF_IPI:
        rc = vlapic_x2apic_mode(vlapic)
            ? vlapic_reg_write(v, APIC_ICR, 0x40000 | (val & 0xff))
            : X86EMUL_UNHANDLEABLE;
        break;

    case APIC_ICR:
        val &= ~(1 << 12); /* always clear the pending bit */
        rc = vlapic_ipi(vlapic, val, vlapic_get_reg(vlapic, APIC_ICR2));
        if ( rc == X86EMUL_OKAY )
            vlapic_set_reg(vlapic, APIC_ICR, val);
        break;

    case APIC_ICR2:
        if ( !vlapic_x2apic_mode(vlapic) )
            val &= 0xff000000;
        vlapic_set_reg(vlapic, APIC_ICR2, val);
        break;

    case APIC_LVTT:         /* LVT Timer Reg */
        if ( (vlapic_get_reg(vlapic, offset) & APIC_TIMER_MODE_MASK) !=
             (val & APIC_TIMER_MODE_MASK) )
        {
            destroy_periodic_time(&vlapic->pt);
            vlapic_set_reg(vlapic, APIC_TMICT, 0);
            vlapic_set_reg(vlapic, APIC_TMCCT, 0);
            vlapic->hw.tdt_msr = 0;
        }
        vlapic->pt.irq = val & APIC_VECTOR_MASK;
    case APIC_LVTTHMR:      /* LVT Thermal Monitor */
    case APIC_LVTPC:        /* LVT Performance Counter */
    case APIC_LVT0:         /* LVT LINT0 Reg */
    case APIC_LVT1:         /* LVT Lint1 Reg */
    case APIC_LVTERR:       /* LVT Error Reg */
        if ( vlapic_sw_disabled(vlapic) )
            val |= APIC_LVT_MASKED;
        val &= vlapic_lvt_mask[(offset - APIC_LVTT) >> 4];
        vlapic_set_reg(vlapic, offset, val);
        if ( offset == APIC_LVT0 )
        {
            vlapic_adjust_i8259_target(v->domain);
            pt_may_unmask_irq(v->domain, NULL);
        }
        if ( (offset == APIC_LVTT) && !(val & APIC_LVT_MASKED) )
            pt_may_unmask_irq(NULL, &vlapic->pt);
        break;

    case APIC_TMICT:
    {
        uint64_t period;

        if ( !vlapic_lvtt_oneshot(vlapic) && !vlapic_lvtt_period(vlapic) )
            break;

        vlapic_set_reg(vlapic, APIC_TMICT, val);
        if ( val == 0 )
        {
            destroy_periodic_time(&vlapic->pt);
            break;
        }

        period = ((uint64_t)APIC_BUS_CYCLE_NS *
                  (uint32_t)val * vlapic->hw.timer_divisor);
        create_periodic_time(current, &vlapic->pt, period, 
                             vlapic_lvtt_period(vlapic) ? period : 0,
                             vlapic->pt.irq,
                             vlapic_lvtt_period(vlapic) ? vlapic_pt_cb : NULL,
                             &vlapic->timer_last_update);
        vlapic->timer_last_update = vlapic->pt.last_plt_gtime;

        HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                    "bus cycle is %uns, "
                    "initial count %lu, period %"PRIu64"ns",
                    APIC_BUS_CYCLE_NS, val, period);
    }
    break;

    case APIC_TDCR:
        vlapic_set_tdcr(vlapic, val & 0xb);
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER, "timer divisor is 0x%x",
                    vlapic->hw.timer_divisor);
        break;

    default:
        break;
    }
    if (rc == X86EMUL_UNHANDLEABLE)
        gdprintk(XENLOG_DEBUG,
                "Local APIC Write wrong to register 0x%x\n", offset);
    return rc;
}

static int vlapic_write(struct vcpu *v, unsigned long address,
                        unsigned long len, unsigned long val)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int offset = address - vlapic_base_address(vlapic);
    int rc = X86EMUL_OKAY;

    if ( offset != 0xb0 )
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                    "offset 0x%x with length 0x%lx, and value is 0x%lx",
                    offset, len, val);

    /*
     * According to the IA32 Manual, all accesses should be 32 bits.
     * Some OSes do 8- or 16-byte accesses, however.
     */
    val = (uint32_t)val;
    if ( len != 4 )
    {
        unsigned int tmp;
        unsigned char alignment;

        gdprintk(XENLOG_INFO, "Notice: Local APIC write with len = %lx\n",len);

        alignment = offset & 0x3;
        (void)vlapic_read_aligned(vlapic, offset & ~0x3, &tmp);

        switch ( len )
        {
        case 1:
            val = ((tmp & ~(0xff << (8*alignment))) |
                   ((val & 0xff) << (8*alignment)));
            break;

        case 2:
            if ( alignment & 1 )
                goto unaligned_exit_and_crash;
            val = ((tmp & ~(0xffff << (8*alignment))) |
                   ((val & 0xffff) << (8*alignment)));
            break;

        default:
            gdprintk(XENLOG_ERR, "Local APIC write with len = %lx, "
                     "should be 4 instead\n", len);
            goto exit_and_crash;
        }
    }
    else if ( (offset & 0x3) != 0 )
        goto unaligned_exit_and_crash;

    offset &= ~0x3;

    return vlapic_reg_write(v, offset, val);

 unaligned_exit_and_crash:
    gdprintk(XENLOG_ERR, "Unaligned LAPIC write len=0x%lx at offset=0x%x.\n",
             len, offset);
 exit_and_crash:
    domain_crash(v->domain);
    return rc;
}

int hvm_x2apic_msr_write(struct vcpu *v, unsigned int msr, uint64_t msr_content)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    uint32_t offset = (msr - MSR_IA32_APICBASE_MSR) << 4;

    if ( !vlapic_x2apic_mode(vlapic) )
        return X86EMUL_UNHANDLEABLE;

    switch ( offset )
    {
        int rc;

    case APIC_ICR:
        rc = vlapic_reg_write(v, APIC_ICR2, (uint32_t)(msr_content >> 32));
        if ( rc )
            return rc;
        break;

    case APIC_ICR2:
        return X86EMUL_UNHANDLEABLE;
    }

    return vlapic_reg_write(v, offset, (uint32_t)msr_content);
}

static int vlapic_range(struct vcpu *v, unsigned long addr)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned long offset  = addr - vlapic_base_address(vlapic);
    return (!vlapic_hw_disabled(vlapic) && (offset < PAGE_SIZE));
}

const struct hvm_mmio_handler vlapic_mmio_handler = {
    .check_handler = vlapic_range,
    .read_handler = vlapic_read,
    .write_handler = vlapic_write
};

void vlapic_msr_set(struct vlapic *vlapic, uint64_t value)
{
    if ( (vlapic->hw.apic_base_msr ^ value) & MSR_IA32_APICBASE_ENABLE )
    {
        if ( value & MSR_IA32_APICBASE_ENABLE )
        {
            vlapic_reset(vlapic);
            vlapic->hw.disabled &= ~VLAPIC_HW_DISABLED;
            pt_may_unmask_irq(vlapic_domain(vlapic), &vlapic->pt);
        }
        else
        {
            vlapic->hw.disabled |= VLAPIC_HW_DISABLED;
            pt_may_unmask_irq(vlapic_domain(vlapic), NULL);
        }
    }

    vlapic->hw.apic_base_msr = value;

    if ( vlapic_x2apic_mode(vlapic) )
    {
        u32 id = vlapic_get_reg(vlapic, APIC_ID);
        u32 ldr = ((id & ~0xf) << 16) | (1 << (id & 0xf));
        vlapic_set_reg(vlapic, APIC_LDR, ldr);
    }

    vmx_vlapic_msr_changed(vlapic_vcpu(vlapic));

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                "apic base msr is 0x%016"PRIx64, vlapic->hw.apic_base_msr);
}

uint64_t  vlapic_tdt_msr_get(struct vlapic *vlapic)
{
    if ( !vlapic_lvtt_tdt(vlapic) )
        return 0;

    return vlapic->hw.tdt_msr;
}

void vlapic_tdt_msr_set(struct vlapic *vlapic, uint64_t value)
{
    uint64_t guest_tsc;
    struct vcpu *v = vlapic_vcpu(vlapic);

    /* may need to exclude some other conditions like vlapic->hw.disabled */
    if ( !vlapic_lvtt_tdt(vlapic) )
    {
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER, "ignore tsc deadline msr write");
        return;
    }
    
    /* new_value = 0, >0 && <= now, > now */
    guest_tsc = hvm_get_guest_tsc(v);
    if ( value > guest_tsc )
    {
        uint64_t delta = gtsc_to_gtime(v->domain, value - guest_tsc);
        delta = max_t(s64, delta, 0);

        HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER, "delta[0x%016"PRIx64"]", delta);

        vlapic->hw.tdt_msr = value;
        /* .... reprogram tdt timer */
        create_periodic_time(v, &vlapic->pt, delta, 0,
                             vlapic->pt.irq, vlapic_tdt_pt_cb,
                             &vlapic->timer_last_update);
        vlapic->timer_last_update = vlapic->pt.last_plt_gtime;
    }
    else
    {
        vlapic->hw.tdt_msr = 0;

        /* trigger a timer event if needed */
        if ( value > 0 )
        {
            create_periodic_time(v, &vlapic->pt, 0, 0,
                                 vlapic->pt.irq, vlapic_tdt_pt_cb,
                                 &vlapic->timer_last_update);
            vlapic->timer_last_update = vlapic->pt.last_plt_gtime;
        }
        else
        {
            /* .... stop tdt timer */
            destroy_periodic_time(&vlapic->pt);
        }

        HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER, "value[0x%016"PRIx64"]", value);
    }

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER,
                "tdt_msr[0x%016"PRIx64"],"
                " gtsc[0x%016"PRIx64"]",
                vlapic->hw.tdt_msr, guest_tsc);
}

static int __vlapic_accept_pic_intr(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct vlapic *vlapic = vcpu_vlapic(v);
    uint32_t lvt0 = vlapic_get_reg(vlapic, APIC_LVT0);
    union vioapic_redir_entry redir0 = domain_vioapic(d)->redirtbl[0];

    /* We deliver 8259 interrupts to the appropriate CPU as follows. */
    return ((/* IOAPIC pin0 is unmasked and routing to this LAPIC? */
             ((redir0.fields.delivery_mode == dest_ExtINT) &&
              !redir0.fields.mask &&
              redir0.fields.dest_id == VLAPIC_ID(vlapic) &&
              !vlapic_disabled(vlapic)) ||
             /* LAPIC has LVT0 unmasked for ExtInts? */
             ((lvt0 & (APIC_MODE_MASK|APIC_LVT_MASKED)) == APIC_DM_EXTINT) ||
             /* LAPIC is fully disabled? */
             vlapic_hw_disabled(vlapic)));
}

int vlapic_accept_pic_intr(struct vcpu *v)
{
    return ((v == v->domain->arch.hvm_domain.i8259_target) &&
            __vlapic_accept_pic_intr(v));
}

void vlapic_adjust_i8259_target(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        if ( __vlapic_accept_pic_intr(v) )
            goto found;

    v = d->vcpu ? d->vcpu[0] : NULL;

 found:
    if ( d->arch.hvm_domain.i8259_target == v )
        return;
    d->arch.hvm_domain.i8259_target = v;
    pt_adjust_global_vcpu_target(v);
}

int vlapic_has_pending_irq(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    int irr, isr;

    if ( !vlapic_enabled(vlapic) )
        return -1;

    irr = vlapic_find_highest_irr(vlapic);
    if ( irr == -1 )
        return -1;

    isr = vlapic_find_highest_isr(vlapic);
    isr = (isr != -1) ? isr : 0;
    if ( (isr & 0xf0) >= (irr & 0xf0) )
        return -1;

    return irr;
}

int vlapic_ack_pending_irq(struct vcpu *v, int vector)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    vlapic_set_vector(vector, &vlapic->regs->data[APIC_ISR]);
    vlapic_clear_irr(vector, vlapic);

    return 1;
}

bool_t is_vlapic_lvtpc_enabled(struct vlapic *vlapic)
{
    return (vlapic_enabled(vlapic) &&
            !(vlapic_get_reg(vlapic, APIC_LVTPC) & APIC_LVT_MASKED));
}

/* Reset the VLPAIC back to its power-on/reset state. */
void vlapic_reset(struct vlapic *vlapic)
{
    struct vcpu *v = vlapic_vcpu(vlapic);
    int i;

    vlapic_set_reg(vlapic, APIC_ID,  (v->vcpu_id * 2) << 24);
    vlapic_set_reg(vlapic, APIC_LVR, VLAPIC_VERSION);

    for ( i = 0; i < 8; i++ )
    {
        vlapic_set_reg(vlapic, APIC_IRR + 0x10 * i, 0);
        vlapic_set_reg(vlapic, APIC_ISR + 0x10 * i, 0);
        vlapic_set_reg(vlapic, APIC_TMR + 0x10 * i, 0);
    }
    vlapic_set_reg(vlapic, APIC_ICR,     0);
    vlapic_set_reg(vlapic, APIC_ICR2,    0);
    vlapic_set_reg(vlapic, APIC_LDR,     0);
    vlapic_set_reg(vlapic, APIC_TASKPRI, 0);
    vlapic_set_reg(vlapic, APIC_TMICT,   0);
    vlapic_set_reg(vlapic, APIC_TMCCT,   0);
    vlapic_set_tdcr(vlapic, 0);

    vlapic_set_reg(vlapic, APIC_DFR, 0xffffffffU);

    for ( i = 0; i < VLAPIC_LVT_NUM; i++ )
        vlapic_set_reg(vlapic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);

    vlapic_set_reg(vlapic, APIC_SPIV, 0xff);
    vlapic->hw.disabled |= VLAPIC_SW_DISABLED;

    destroy_periodic_time(&vlapic->pt);
}

/* rearm the actimer if needed, after a HVM restore */
static void lapic_rearm(struct vlapic *s)
{
    unsigned long tmict;
    uint64_t period, tdt_msr;

    s->pt.irq = vlapic_get_reg(s, APIC_LVTT) & APIC_VECTOR_MASK;

    if ( vlapic_lvtt_tdt(s) )
    {
        if ( (tdt_msr = vlapic_tdt_msr_get(s)) != 0 )
            vlapic_tdt_msr_set(s, tdt_msr);
        return;
    }

    if ( (tmict = vlapic_get_reg(s, APIC_TMICT)) == 0 )
        return;

    period = ((uint64_t)APIC_BUS_CYCLE_NS *
              (uint32_t)tmict * s->hw.timer_divisor);
    create_periodic_time(vlapic_vcpu(s), &s->pt, period,
                         vlapic_lvtt_period(s) ? period : 0,
                         s->pt.irq,
                         vlapic_lvtt_period(s) ? vlapic_pt_cb : NULL,
                         &s->timer_last_update);
    s->timer_last_update = s->pt.last_plt_gtime;
}

static int lapic_save_hidden(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct vlapic *s;
    int rc = 0;

    for_each_vcpu ( d, v )
    {
        s = vcpu_vlapic(v);
        if ( (rc = hvm_save_entry(LAPIC, v->vcpu_id, h, &s->hw)) != 0 )
            break;
    }

    return rc;
}

static int lapic_save_regs(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct vlapic *s;
    int rc = 0;

    for_each_vcpu ( d, v )
    {
        s = vcpu_vlapic(v);
        if ( (rc = hvm_save_entry(LAPIC_REGS, v->vcpu_id, h, s->regs)) != 0 )
            break;
    }

    return rc;
}

static int lapic_load_hidden(struct domain *d, hvm_domain_context_t *h)
{
    uint16_t vcpuid;
    struct vcpu *v;
    struct vlapic *s;
    
    /* Which vlapic to load? */
    vcpuid = hvm_load_instance(h); 
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no apic%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }
    s = vcpu_vlapic(v);
    
    if ( hvm_load_entry_zeroextend(LAPIC, h, &s->hw) != 0 ) 
        return -EINVAL;

    vmx_vlapic_msr_changed(v);

    return 0;
}

static int lapic_load_regs(struct domain *d, hvm_domain_context_t *h)
{
    uint16_t vcpuid;
    struct vcpu *v;
    struct vlapic *s;
    
    /* Which vlapic to load? */
    vcpuid = hvm_load_instance(h); 
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no apic%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }
    s = vcpu_vlapic(v);
    
    if ( hvm_load_entry(LAPIC_REGS, h, s->regs) != 0 ) 
        return -EINVAL;

    vlapic_adjust_i8259_target(d);
    lapic_rearm(s);
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(LAPIC, lapic_save_hidden, lapic_load_hidden,
                          1, HVMSR_PER_VCPU);
HVM_REGISTER_SAVE_RESTORE(LAPIC_REGS, lapic_save_regs, lapic_load_regs,
                          1, HVMSR_PER_VCPU);

int vlapic_init(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int memflags = MEMF_node(vcpu_to_node(v));

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "%d", v->vcpu_id);

    vlapic->pt.source = PTSRC_lapic;

#ifdef __i386__
    /* 32-bit VMX may be limited to 32-bit physical addresses. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        memflags |= MEMF_bits(32);
#endif
    if (vlapic->regs_page == NULL)
    {
        vlapic->regs_page = alloc_domheap_page(NULL, memflags);
        if ( vlapic->regs_page == NULL )
        {
            dprintk(XENLOG_ERR, "alloc vlapic regs error: %d/%d\n",
                    v->domain->domain_id, v->vcpu_id);
            return -ENOMEM;
        }
    }
    if (vlapic->regs == NULL) 
    {
        vlapic->regs = __map_domain_page_global(vlapic->regs_page);
        if ( vlapic->regs == NULL )
        {
            dprintk(XENLOG_ERR, "map vlapic regs error: %d/%d\n",
                    v->domain->domain_id, v->vcpu_id);
            return -ENOMEM;
        }
    }
    clear_page(vlapic->regs);

    vlapic_reset(vlapic);

    vlapic->hw.apic_base_msr = (MSR_IA32_APICBASE_ENABLE |
                                APIC_DEFAULT_PHYS_BASE);
    if ( v->vcpu_id == 0 )
        vlapic->hw.apic_base_msr |= MSR_IA32_APICBASE_BSP;

    tasklet_init(&vlapic->init_sipi.tasklet,
                 vlapic_init_sipi_action,
                 (unsigned long)v);

    return 0;
}

void vlapic_destroy(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    tasklet_kill(&vlapic->init_sipi.tasklet);
    destroy_periodic_time(&vlapic->pt);
    unmap_domain_page_global(vlapic->regs);
    free_domheap_page(vlapic->regs_page);
}
