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
#include <xen/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>
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
     LVT_MASK | APIC_LVT_TIMER_PERIODIC,
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

#define vlapic_lvt_enabled(vlapic, lvt_type)                    \
    (!(vlapic_get_reg(vlapic, lvt_type) & APIC_LVT_MASKED))

#define vlapic_lvt_vector(vlapic, lvt_type)                     \
    (vlapic_get_reg(vlapic, lvt_type) & APIC_VECTOR_MASK)

#define vlapic_lvt_dm(vlapic, lvt_type)                         \
    (vlapic_get_reg(vlapic, lvt_type) & APIC_MODE_MASK)

#define vlapic_lvtt_period(vlapic)                              \
    (vlapic_get_reg(vlapic, APIC_LVTT) & APIC_LVT_TIMER_PERIODIC)

#define vlapic_base_address(vlapic)                             \
    (vlapic->hw.apic_base_msr & MSR_IA32_APICBASE_BASE)

/*
 * Generic APIC bitmap vector update & search routines.
 */

#define VEC_POS(v) ((v)%32)
#define REG_POS(v) (((v)/32)* 0x10)
#define vlapic_test_and_set_vector(vec, bitmap)                 \
    test_and_set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))
#define vlapic_test_and_clear_vector(vec, bitmap)               \
    test_and_clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))
#define vlapic_set_vector(vec, bitmap)                          \
    set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))
#define vlapic_clear_vector(vec, bitmap)                        \
    clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))

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

int vlapic_find_highest_irr(struct vlapic *vlapic)
{
    int result;

    result = vlapic_find_highest_vector(&vlapic->regs->data[APIC_IRR]);
    ASSERT((result == -1) || (result >= 16));

    return result;
}

int vlapic_set_irq(struct vlapic *vlapic, uint8_t vec, uint8_t trig)
{
    int ret;

    ret = !vlapic_test_and_set_irr(vec, vlapic);
    if ( trig )
        vlapic_set_vector(vec, &vlapic->regs->data[APIC_TMR]);

    /* We may need to wake up target vcpu, besides set pending bit here */
    return ret;
}

int vlapic_find_highest_isr(struct vlapic *vlapic)
{
    int result;

    result = vlapic_find_highest_vector(&vlapic->regs->data[APIC_ISR]);
    ASSERT((result == -1) || (result >= 16));

    return result;
}

uint32_t vlapic_get_ppr(struct vlapic *vlapic)
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
                "vlapic %p, ppr 0x%x, isr 0x%x, isrv 0x%x.",
                vlapic, ppr, isr, isrv);

    return ppr;
}

int vlapic_match_logical_addr(struct vlapic *vlapic, uint8_t mda)
{
    int result = 0;
    uint8_t logical_id;

    logical_id = GET_APIC_LOGICAL_ID(vlapic_get_reg(vlapic, APIC_LDR));

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

static int vlapic_match_dest(struct vcpu *v, struct vlapic *source,
                             int short_hand, int dest, int dest_mode)
{
    int result = 0;
    struct vlapic *target = vcpu_vlapic(v);

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "target %p, source %p, dest 0x%x, "
                "dest_mode 0x%x, short_hand 0x%x\n",
                target, source, dest, dest_mode, short_hand);

    switch ( short_hand )
    {
    case APIC_DEST_NOSHORT:
        if ( dest_mode == 0 )
        {
            /* Physical mode. */
            if ( (dest == 0xFF) || (dest == VLAPIC_ID(target)) )
                result = 1;
        }
        else
        {
            /* Logical mode. */
            result = vlapic_match_logical_addr(target, dest);
        }
        break;

    case APIC_DEST_SELF:
        if ( target == source )
            result = 1;
        break;

    case APIC_DEST_ALLINC:
        result = 1;
        break;

    case APIC_DEST_ALLBUT:
        if ( target != source )
            result = 1;
        break;

    default:
        gdprintk(XENLOG_WARNING, "Bad dest shorthand value %x\n", short_hand);
        break;
    }

    return result;
}

/* Add a pending IRQ into lapic. */
static int vlapic_accept_irq(struct vcpu *v, int delivery_mode,
                             int vector, int level, int trig_mode)
{
    int result = 0;
    struct vlapic *vlapic = vcpu_vlapic(v);

    switch ( delivery_mode )
    {
    case APIC_DM_FIXED:
    case APIC_DM_LOWEST:
        /* FIXME add logic for vcpu on reset */
        if ( unlikely(!vlapic_enabled(vlapic)) )
            break;

        if ( vlapic_test_and_set_irr(vector, vlapic) && trig_mode )
        {
            HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                        "level trig mode repeatedly for vector %d\n", vector);
            break;
        }

        if ( trig_mode )
        {
            HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                        "level trig mode for vector %d\n", vector);
            vlapic_set_vector(vector, &vlapic->regs->data[APIC_TMR]);
        }

        vcpu_kick(v);

        result = 1;
        break;

    case APIC_DM_REMRD:
        gdprintk(XENLOG_WARNING, "Ignoring delivery mode 3\n");
        break;

    case APIC_DM_SMI:
        gdprintk(XENLOG_WARNING, "Ignoring guest SMI\n");
        break;

    case APIC_DM_NMI:
        gdprintk(XENLOG_WARNING, "Ignoring guest NMI\n");
        break;

    case APIC_DM_INIT:
        /* No work on INIT de-assert for P4-type APIC. */
        if ( trig_mode && !(level & APIC_INT_ASSERT) )
            break;
        /* FIXME How to check the situation after vcpu reset? */
        if ( v->is_initialised )
            hvm_vcpu_reset(v);
        v->arch.hvm_vcpu.init_sipi_sipi_state =
            HVM_VCPU_INIT_SIPI_SIPI_STATE_WAIT_SIPI;
        result = 1;
        break;

    case APIC_DM_STARTUP:
        if ( v->arch.hvm_vcpu.init_sipi_sipi_state ==
             HVM_VCPU_INIT_SIPI_SIPI_STATE_NORM )
            break;

        v->arch.hvm_vcpu.init_sipi_sipi_state =
            HVM_VCPU_INIT_SIPI_SIPI_STATE_NORM;

        if ( v->is_initialised )
        {
            gdprintk(XENLOG_ERR, "SIPI for initialized vcpu %x\n", v->vcpu_id);
            goto exit_and_crash;
        }

        if ( hvm_bringup_ap(v->vcpu_id, vector) != 0 )
            result = 0;
        break;

    default:
        gdprintk(XENLOG_ERR, "TODO: unsupported delivery mode %x\n",
                 delivery_mode);
        goto exit_and_crash;
    }

    return result;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
}

/* This function is used by both ioapic and lapic.The bitmap is for vcpu_id. */
struct vlapic *apic_round_robin(
    struct domain *d, uint8_t vector, uint32_t bitmap)
{
    int next, old;
    struct vlapic *target = NULL;

    old = next = d->arch.hvm_domain.irq.round_robin_prev_vcpu;

    do {
        if ( ++next == MAX_VIRT_CPUS ) 
            next = 0;
        if ( (d->vcpu[next] == NULL) || !test_bit(next, &bitmap) )
            continue;
        target = vcpu_vlapic(d->vcpu[next]);
        if ( vlapic_enabled(target) )
            break;
        target = NULL;
    } while ( next != old );

    d->arch.hvm_domain.irq.round_robin_prev_vcpu = next;

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
}

static void vlapic_ipi(struct vlapic *vlapic)
{
    uint32_t icr_low = vlapic_get_reg(vlapic, APIC_ICR);
    uint32_t icr_high = vlapic_get_reg(vlapic, APIC_ICR2);

    unsigned int dest =         GET_APIC_DEST_FIELD(icr_high);
    unsigned int short_hand =   icr_low & APIC_SHORT_MASK;
    unsigned int trig_mode =    icr_low & APIC_INT_LEVELTRIG;
    unsigned int level =        icr_low & APIC_INT_ASSERT;
    unsigned int dest_mode =    icr_low & APIC_DEST_MASK;
    unsigned int delivery_mode =icr_low & APIC_MODE_MASK;
    unsigned int vector =       icr_low & APIC_VECTOR_MASK;

    struct vlapic *target;
    struct vcpu *v;
    uint32_t lpr_map = 0;

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "icr_high 0x%x, icr_low 0x%x, "
                "short_hand 0x%x, dest 0x%x, trig_mode 0x%x, level 0x%x, "
                "dest_mode 0x%x, delivery_mode 0x%x, vector 0x%x.",
                icr_high, icr_low, short_hand, dest,
                trig_mode, level, dest_mode, delivery_mode, vector);

    for_each_vcpu ( vlapic_domain(vlapic), v )
    {
        if ( vlapic_match_dest(v, vlapic, short_hand, dest, dest_mode) )
        {
            if ( delivery_mode == APIC_DM_LOWEST )
                set_bit(v->vcpu_id, &lpr_map);
            else
                vlapic_accept_irq(v, delivery_mode,
                                  vector, level, trig_mode);
        }
    }

    if ( delivery_mode == APIC_DM_LOWEST )
    {
        target = apic_round_robin(vlapic_domain(v), vector, lpr_map);
        if ( target != NULL )
            vlapic_accept_irq(vlapic_vcpu(target), delivery_mode,
                              vector, level, trig_mode);
    }
}

static uint32_t vlapic_get_tmcct(struct vlapic *vlapic)
{
    struct vcpu *v = current;
    uint32_t tmcct, tmict = vlapic_get_reg(vlapic, APIC_TMICT);
    uint64_t counter_passed;

    counter_passed = (hvm_get_guest_time(v) - vlapic->pt.last_plt_gtime) // TSC
                     * 1000000000ULL / ticks_per_sec(v) // NS
                     / APIC_BUS_CYCLE_NS / vlapic->hw.timer_divisor;
    tmcct = tmict - counter_passed;

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER,
                "timer initial count %d, timer current count %d, "
                "offset %"PRId64".",
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
                "vlapic_set_tdcr timer_divisor: %d.", vlapic->hw.timer_divisor);
}

static void vlapic_read_aligned(struct vlapic *vlapic, unsigned int offset,
                         unsigned int len, unsigned int *result)
{
    ASSERT((len == 4) && (offset >= 0) && (offset <= APIC_TDCR));

    switch ( offset )
    {
    case APIC_PROCPRI:
        *result = vlapic_get_ppr(vlapic);
        break;

    case APIC_TMCCT: /* Timer CCR */
        *result = vlapic_get_tmcct(vlapic);
        break;

    default:
        *result = vlapic_get_reg(vlapic, offset);
        break;
    }
}

static unsigned long vlapic_read(struct vcpu *v, unsigned long address,
                                 unsigned long len)
{
    unsigned int alignment;
    unsigned int tmp;
    unsigned long result;
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int offset = address - vlapic_base_address(vlapic);

    if ( offset > APIC_TDCR )
        return 0;

    /* some bugs on kernel cause read this with byte*/
    if ( len != 4 )
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                    "read with len=0x%lx, should be 4 instead.\n",
                    len);

    alignment = offset & 0x3;

    vlapic_read_aligned(vlapic, offset & ~0x3, 4, &tmp);
    switch ( len )
    {
    case 1:
        result = *((unsigned char *)&tmp + alignment);
        break;

    case 2:
        ASSERT( alignment != 3 );
        result = *(unsigned short *)((unsigned char *)&tmp + alignment);
        break;

    case 4:
        ASSERT( alignment == 0 );
        result = *(unsigned int *)((unsigned char *)&tmp + alignment);
        break;

    default:
        gdprintk(XENLOG_ERR, "Local APIC read with len=0x%lx, "
                 "should be 4 instead.\n", len);
        goto exit_and_crash;
    }

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "offset 0x%x with length 0x%lx, "
                "and the result is 0x%lx.", offset, len, result);

    return result;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
}

static void vlapic_write(struct vcpu *v, unsigned long address,
                         unsigned long len, unsigned long val)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int offset = address - vlapic_base_address(vlapic);

    if ( offset != 0xb0 )
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                    "offset 0x%x with length 0x%lx, and value is 0x%lx.",
                    offset, len, val);

    /*
     * According to the IA32 Manual, all accesses should be 32 bits.
     * Some OSes do 8- or 16-byte accesses, however.
     */
    val &= 0xffffffff;
    if ( len != 4 )
    {
        unsigned int tmp;
        unsigned char alignment;

        gdprintk(XENLOG_INFO, "Notice: Local APIC write with len = %lx\n",len);

        alignment = offset & 0x3;
        tmp = vlapic_read(v, offset & ~0x3, 4);

        switch ( len )
        {
        case 1:
            val = (tmp & ~(0xff << (8*alignment))) |
                  ((val & 0xff) << (8*alignment));
            break;

        case 2:
            if ( alignment & 1 )
            {
                gdprintk(XENLOG_ERR, "Uneven alignment error for "
                         "2-byte vlapic access\n");
                goto exit_and_crash;
            }

            val = (tmp & ~(0xffff << (8*alignment))) |
                  ((val & 0xffff) << (8*alignment));
            break;

        default:
            gdprintk(XENLOG_ERR, "Local APIC write with len = %lx, "
                     "should be 4 instead\n", len);
        exit_and_crash:
            domain_crash(v->domain);
            return;
        }
    }

    offset &= 0xff0;

    switch ( offset )
    {
    case APIC_TASKPRI:
        vlapic_set_reg(vlapic, APIC_TASKPRI, val & 0xff);
        hvm_update_vtpr(v, (val >> 4) & 0x0f);
        break;

    case APIC_EOI:
        vlapic_EOI_set(vlapic);
        break;

    case APIC_LDR:
        vlapic_set_reg(vlapic, APIC_LDR, val & APIC_LDR_MASK);
        break;

    case APIC_DFR:
        vlapic_set_reg(vlapic, APIC_DFR, val | 0x0FFFFFFF);
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
            vlapic->hw.disabled &= ~VLAPIC_SW_DISABLED;
        break;

    case APIC_ESR:
        /* Nothing to do. */
        break;

    case APIC_ICR:
        /* No delay here, so we always clear the pending bit*/
        vlapic_set_reg(vlapic, APIC_ICR, val & ~(1 << 12));
        vlapic_ipi(vlapic);
        break;

    case APIC_ICR2:
        vlapic_set_reg(vlapic, APIC_ICR2, val & 0xff000000);
        break;

    case APIC_LVTT:         /* LVT Timer Reg */
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
        break;

    case APIC_TMICT:
    {
        uint64_t period = APIC_BUS_CYCLE_NS * (uint32_t)val * vlapic->hw.timer_divisor;

        vlapic_set_reg(vlapic, APIC_TMICT, val);
        create_periodic_time(current, &vlapic->pt, period, vlapic->pt.irq,
                             vlapic_lvtt_period(vlapic), NULL, vlapic);

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
        gdprintk(XENLOG_DEBUG,
                 "Local APIC Write to read-only register 0x%x\n", offset);
        break;
    }
}

static int vlapic_range(struct vcpu *v, unsigned long addr)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned long offset  = addr - vlapic_base_address(vlapic);
    return (!vlapic_hw_disabled(vlapic) && (offset < PAGE_SIZE));
}

struct hvm_mmio_handler vlapic_mmio_handler = {
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
        }
        else
        {
            vlapic->hw.disabled |= VLAPIC_HW_DISABLED;
        }
    }

    vlapic->hw.apic_base_msr = value;

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                "apic base msr is 0x%016"PRIx64".", vlapic->hw.apic_base_msr);
}

int vlapic_accept_pic_intr(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    uint32_t lvt0 = vlapic_get_reg(vlapic, APIC_LVT0);

    /*
     * Only CPU0 is wired to the 8259A. INTA cycles occur if LINT0 is set up
     * accept ExtInts, or if the LAPIC is disabled (so LINT0 behaves as INTR).
     */
    return ((v->vcpu_id == 0) &&
            (((lvt0 & (APIC_MODE_MASK|APIC_LVT_MASKED)) == APIC_DM_EXTINT) ||
             vlapic_hw_disabled(vlapic)));
}

int vlapic_has_interrupt(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    int highest_irr;

    if ( !vlapic_enabled(vlapic) )
        return -1;

    highest_irr = vlapic_find_highest_irr(vlapic);
    if ( (highest_irr == -1) ||
         ((highest_irr & 0xF0) <= vlapic_get_ppr(vlapic)) )
        return -1;

    return highest_irr;
}

int cpu_get_apic_interrupt(struct vcpu *v, int *mode)
{
    int vector = vlapic_has_interrupt(v);
    struct vlapic *vlapic = vcpu_vlapic(v);

    if ( vector == -1 )
        return -1;
 
    vlapic_set_vector(vector, &vlapic->regs->data[APIC_ISR]);
    vlapic_clear_irr(vector, vlapic);

    *mode = APIC_DM_FIXED;
    return vector;
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
}

#ifdef HVM_DEBUG_SUSPEND
static void lapic_info(struct vlapic *s)
{
    printk("*****lapic state:*****\n");
    printk("lapic 0x%"PRIx64".\n", s->hw.apic_base_msr);
    printk("lapic 0x%x.\n", s->hw.disabled);
    printk("lapic 0x%x.\n", s->hw.timer_divisor);
}
#else
static void lapic_info(struct vlapic *s)
{
}
#endif

/* rearm the actimer if needed, after a HVM restore */
static void lapic_rearm(struct vlapic *s)
{
    unsigned long tmict;

    tmict = vlapic_get_reg(s, APIC_TMICT);
    if (tmict > 0) {
        uint64_t period = APIC_BUS_CYCLE_NS * (uint32_t)tmict * s->hw.timer_divisor;
        uint32_t lvtt = vlapic_get_reg(s, APIC_LVTT);

        s->pt.irq = lvtt & APIC_VECTOR_MASK;
        create_periodic_time(vlapic_vcpu(s), &s->pt, period, s->pt.irq,
                             vlapic_lvtt_period(s), NULL, s);

        printk("lapic_load to rearm the actimer:"
                    "bus cycle is %uns, "
                    "saved tmict count %lu, period %"PRIu64"ns, irq=%"PRIu8"\n",
                    APIC_BUS_CYCLE_NS, tmict, period, s->pt.irq);
    }

    lapic_info(s);
}

static int lapic_save_hidden(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct vlapic *s;

    for_each_vcpu(d, v)
    {
        s = vcpu_vlapic(v);
        lapic_info(s);

        if ( hvm_save_entry(LAPIC, v->vcpu_id, h, &s->hw) != 0 )
            return 1; 
    }
    return 0;
}

static int lapic_save_regs(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct vlapic *s;

    for_each_vcpu(d, v)
    {
        s = vcpu_vlapic(v);
        if ( hvm_save_entry(LAPIC_REGS, v->vcpu_id, h, s->regs) != 0 )
            return 1; 
    }
    return 0;
}

static int lapic_load_hidden(struct domain *d, hvm_domain_context_t *h)
{
    uint16_t vcpuid;
    struct vcpu *v;
    struct vlapic *s;
    
    /* Which vlapic to load? */
    vcpuid = hvm_load_instance(h); 
    if ( vcpuid > MAX_VIRT_CPUS || (v = d->vcpu[vcpuid]) == NULL ) 
    {
        gdprintk(XENLOG_ERR, "HVM restore: domain has no vlapic %u\n", vcpuid);
        return -EINVAL;
    }
    s = vcpu_vlapic(v);
    
    if ( hvm_load_entry(LAPIC, h, &s->hw) != 0 ) 
        return -EINVAL;

    lapic_info(s);
    return 0;
}

static int lapic_load_regs(struct domain *d, hvm_domain_context_t *h)
{
    uint16_t vcpuid;
    struct vcpu *v;
    struct vlapic *s;
    
    /* Which vlapic to load? */
    vcpuid = hvm_load_instance(h); 
    if ( vcpuid > MAX_VIRT_CPUS || (v = d->vcpu[vcpuid]) == NULL ) 
    {
        gdprintk(XENLOG_ERR, "HVM restore: domain has no vlapic %u\n", vcpuid);
        return -EINVAL;
    }
    s = vcpu_vlapic(v);
    
    if ( hvm_load_entry(LAPIC_REGS, h, s->regs) != 0 ) 
        return -EINVAL;

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

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "vlapic_init %d", v->vcpu_id);

    vlapic->regs_page = alloc_domheap_page(NULL);
    if ( vlapic->regs_page == NULL )
    {
        dprintk(XENLOG_ERR, "malloc vlapic regs error for vcpu %x\n",
                v->vcpu_id);
        return -ENOMEM;
    }

    vlapic->regs = map_domain_page_global(page_to_mfn(vlapic->regs_page));
    memset(vlapic->regs, 0, PAGE_SIZE);

    vlapic_reset(vlapic);

    vlapic->hw.apic_base_msr = MSR_IA32_APICBASE_ENABLE | APIC_DEFAULT_PHYS_BASE;
    if ( v->vcpu_id == 0 )
        vlapic->hw.apic_base_msr |= MSR_IA32_APICBASE_BSP;

    init_timer(&vlapic->pt.timer, pt_timer_fn, &vlapic->pt, v->processor);

    return 0;
}

void vlapic_destroy(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    kill_timer(&vlapic->pt.timer);
    unmap_domain_page_global(vlapic->regs);
    free_domheap_page(vlapic->regs_page);
}

int is_lvtt(struct vcpu *v, int vector)
{
    return vcpu_vlapic(v)->pt.enabled &&
           vector == vlapic_lvt_vector(vcpu_vlapic(v), APIC_LVTT);
}

int is_lvtt_enabled(struct vcpu *v)
{
    if ( unlikely(!vlapic_enabled(vcpu_vlapic(v))) ||
            !vlapic_lvt_enabled(vcpu_vlapic(v), APIC_LVTT)) 
        return 0;

    return 1;
}
