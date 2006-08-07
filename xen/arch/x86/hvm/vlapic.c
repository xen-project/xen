/*
 * vlapic.c: virtualize LAPIC for HVM vcpus.
 *
 * Copyright (c) 2004, Intel Corporation.
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
#include <asm/shadow.h>
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

/* XXX remove this definition after GFW enabled */
#define VLAPIC_NO_BIOS

extern u32 get_apic_bus_cycle(void);

#define APIC_BUS_CYCLE_NS (((s_time_t)get_apic_bus_cycle()) / 1000)

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

int hvm_apic_support(struct domain *d)
{
    return d->arch.hvm_domain.params[HVM_PARAM_APIC_ENABLED];
}

int vlapic_find_highest_irr(struct vlapic *vlapic)
{
    int result;

     result = find_highest_bit((unsigned long *)(vlapic->regs + APIC_IRR),
                               MAX_VECTOR);

     ASSERT( result == -1 || result > 16);

     return result;
}

s_time_t get_apictime_scheduled(struct vcpu *v)
{
    struct vlapic *vlapic = VLAPIC(v);

    if ( !hvm_apic_support(v->domain) ||
         !vlapic_lvt_enabled(vlapic, APIC_LVTT) )
        return -1;

    return vlapic->vlapic_timer.expires;
}

int vlapic_find_highest_isr(struct vlapic *vlapic)
{
    int result;

    result = find_highest_bit((unsigned long *)(vlapic->regs + APIC_ISR),
                               MAX_VECTOR);

    ASSERT( result == -1 || result > 16);

    return result;
}

uint32_t vlapic_update_ppr(struct vlapic *vlapic)
{
    uint32_t tpr, isrv, ppr;
    int isr;

    tpr = vlapic_get_reg(vlapic, APIC_TASKPRI);

    isr = vlapic_find_highest_isr(vlapic);

    if ( isr != -1 )
        isrv = (isr >> 4) & 0xf;   /* ditto */
    else
        isrv = 0;

    if ( (tpr >> 4) >= isrv )
        ppr = tpr & 0xff;
    else
        ppr = isrv << 4;  /* low 4 bits of PPR have to be cleared */

    vlapic_set_reg(vlapic, APIC_PROCPRI, ppr);

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_INTERRUPT,
                "vlapic %p, ppr 0x%x, isr 0x%x, isrv 0x%x.",
                vlapic, ppr, isr, isrv);

    return ppr;
}

/* This only for fixed delivery mode */
static int vlapic_match_dest(struct vcpu *v, struct vlapic *source,
                             int short_hand, int dest, int dest_mode,
                             int delivery_mode)
{
    int result = 0;
    struct vlapic *target = VLAPIC(v);

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "target %p, source %p, dest 0x%x, "
                "dest_mode 0x%x, short_hand 0x%x, delivery_mode 0x%x.",
                target, source, dest, dest_mode, short_hand, delivery_mode);

    if ( unlikely(target == NULL) &&
         ((delivery_mode != APIC_DM_INIT) &&
          (delivery_mode != APIC_DM_STARTUP) &&
          (delivery_mode != APIC_DM_NMI)) )
    {
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "uninitialized target vcpu %p, "
                    "delivery_mode 0x%x, dest 0x%x.\n", v, delivery_mode, dest);
        return result;
    }

    switch ( short_hand ) {
    case APIC_DEST_NOSHORT:             /* no shorthand */
        if ( !dest_mode )   /* Physical */
        {
            result = ( ((target != NULL) ?
                         GET_APIC_ID(vlapic_get_reg(target, APIC_ID)):
                         v->vcpu_id)) == dest;
        }
        else                /* Logical */
        {
            uint32_t ldr = vlapic_get_reg(target, APIC_LDR);

            if ( target == NULL )
                break;
            /* Flat mode */
            if ( vlapic_get_reg(target, APIC_DFR) == APIC_DFR_FLAT)
            {
                result = GET_APIC_LOGICAL_ID(ldr) & dest;
            }
            else
            {
                if ( (delivery_mode == APIC_DM_LOWEST) &&
                     (dest == 0xff) )
                {
                    /* What shall we do now? */
                    printk("Broadcast IPI with lowest priority "
                           "delivery mode\n");
                    domain_crash_synchronous();
                }
                result = (GET_APIC_LOGICAL_ID(ldr) == (dest & 0xf)) ?
                         (GET_APIC_LOGICAL_ID(ldr) >> 4) & (dest >> 4) : 0;
            }
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
        break;
    }

    return result;
}

/*
 * Add a pending IRQ into lapic.
 * Return 1 if successfully added and 0 if discarded.
 */
static int vlapic_accept_irq(struct vcpu *v, int delivery_mode,
                             int vector, int level, int trig_mode)
{
    int result = 0;
    struct vlapic *vlapic = VLAPIC(v);

    switch ( delivery_mode ) {
    case APIC_DM_FIXED:
    case APIC_DM_LOWEST:
        /* FIXME add logic for vcpu on reset */
        if ( unlikely(vlapic == NULL || !vlapic_enabled(vlapic)) )
            break;

        if ( test_and_set_bit(vector, vlapic->regs + APIC_IRR) )
        {
            HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
              "level trig mode repeatedly for vector %d\n", vector);
            break;
        }

        if ( level )
        {
            HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
              "level trig mode for vector %d\n", vector);
            set_bit(vector, vlapic->regs + APIC_TMR);
        }
        evtchn_set_pending(v, iopacket_port(v));

        result = 1;
        break;

    case APIC_DM_REMRD:
        printk("Ignore deliver mode 3 in vlapic_accept_irq\n");
        break;

    case APIC_DM_SMI:
    case APIC_DM_NMI:
        /* Fixme */
        printk("TODO: for guest SMI/NMI\n");
        break;

    case APIC_DM_INIT:
        if ( level && !(trig_mode & APIC_INT_ASSERT) )     //Deassert
            printk("This hvm_vlapic is for P4, no work for De-assert init\n");
        else
        {
            /* FIXME How to check the situation after vcpu reset? */
            if ( test_and_clear_bit(_VCPUF_initialised, &v->vcpu_flags) )
            {
                printk("Reset hvm vcpu not supported yet\n");
                domain_crash_synchronous();
            }
            v->arch.hvm_vcpu.init_sipi_sipi_state =
                HVM_VCPU_INIT_SIPI_SIPI_STATE_WAIT_SIPI;
            result = 1;
        }
        break;

    case APIC_DM_STARTUP:
        if ( v->arch.hvm_vcpu.init_sipi_sipi_state ==
                HVM_VCPU_INIT_SIPI_SIPI_STATE_NORM )
            break;

        v->arch.hvm_vcpu.init_sipi_sipi_state =
                HVM_VCPU_INIT_SIPI_SIPI_STATE_NORM;

        if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
        {
            printk("SIPI for initialized vcpu vcpuid %x\n", v->vcpu_id);
            domain_crash_synchronous();
        }

        if ( hvm_bringup_ap(v->vcpu_id, vector) != 0 )
            result = 0;
        break;

    default:
        printk("TODO: not support interrupt type %x\n", delivery_mode);
        domain_crash_synchronous();
        break;
    }

    return result;
}
/*
    This function is used by both ioapic and local APIC
    The bitmap is for vcpu_id
 */
struct vlapic* apic_round_robin(struct domain *d,
                                uint8_t dest_mode,
                                uint8_t vector,
                                uint32_t bitmap)
{
    int next, old;
    struct vlapic* target = NULL;

    if ( dest_mode == 0 )   //Physical mode
    {
        printk("<apic_round_robin> lowest priority for physical mode.\n");
        return NULL;
    }

    if ( !bitmap )
    {
        printk("<apic_round_robin> no bit set in bitmap.\n");
        return NULL;
    }

    spin_lock(&d->arch.hvm_domain.round_robin_lock);

    old = next = d->arch.hvm_domain.round_info[vector];

    /* the vcpu array is arranged according to vcpu_id */
    do
    {
        next++;
        if ( !d->vcpu[next] ||
             !test_bit(_VCPUF_initialised, &d->vcpu[next]->vcpu_flags) ||
             next == MAX_VIRT_CPUS )
            next = 0;

        if ( test_bit(next, &bitmap) )
        {
            target = d->vcpu[next]->arch.hvm_vcpu.vlapic;

            if ( target == NULL || !vlapic_enabled(target) )
            {
                printk("warning: targe round robin local apic disabled\n");
                /* XXX should we domain crash?? Or should we return NULL */
            }
            break;
        }
    } while ( next != old );

    d->arch.hvm_domain.round_info[vector] = next;
    spin_unlock(&d->arch.hvm_domain.round_robin_lock);

    return target;
}

void vlapic_EOI_set(struct vlapic *vlapic)
{
    int vector = vlapic_find_highest_isr(vlapic);

    /* Not every write EOI will has correpsoning ISR,
       one example is when Kernel check timer on setup_IO_APIC */
    if ( vector == -1 )
        return ;

    clear_bit(vector, vlapic->regs + APIC_ISR);
    vlapic_update_ppr(vlapic);

    if ( test_and_clear_bit(vector, vlapic->regs + APIC_TMR) )
        ioapic_update_EOI(vlapic->domain, vector);
}

static int vlapic_check_vector(struct vlapic *vlapic,
                        uint32_t dm, uint32_t vector)
{
    if ( (dm == APIC_DM_FIXED) && (vector < 16) )
    {
        vlapic->err_status |= 0x40;
        vlapic_accept_irq(vlapic->vcpu, APIC_DM_FIXED,
                          vlapic_lvt_vector(vlapic, APIC_LVTERR), 0, 0);
        printk("<vlapic_check_vector>: check failed "
               " dm %x vector %x\n", dm, vector);
        return 0;
    }
    return 1;
}

static void vlapic_ipi(struct vlapic *vlapic)
{
    uint32_t icr_low = vlapic_get_reg(vlapic, APIC_ICR);
    uint32_t icr_high = vlapic_get_reg(vlapic, APIC_ICR2);

    unsigned int dest =         GET_APIC_DEST_FIELD(icr_high);
    unsigned int short_hand =   icr_low & APIC_SHORT_MASK;
    unsigned int trig_mode =    icr_low & APIC_INT_ASSERT;
    unsigned int level =        icr_low & APIC_INT_LEVELTRIG;
    unsigned int dest_mode =    icr_low & APIC_DEST_MASK;
    unsigned int delivery_mode =    icr_low & APIC_MODE_MASK;
    unsigned int vector =       icr_low & APIC_VECTOR_MASK;

    struct vlapic *target;
    struct vcpu *v = NULL;
    uint32_t lpr_map;

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "icr_high 0x%x, icr_low 0x%x, "
                "short_hand 0x%x, dest 0x%x, trig_mode 0x%x, level 0x%x, "
                "dest_mode 0x%x, delivery_mode 0x%x, vector 0x%x.",
                icr_high, icr_low, short_hand, dest,
                trig_mode, level, dest_mode, delivery_mode, vector);

    for_each_vcpu ( vlapic->domain, v )
    {
        if ( vlapic_match_dest(v, vlapic, short_hand,
                               dest, dest_mode, delivery_mode) )
        {
            if ( delivery_mode == APIC_DM_LOWEST)
                set_bit(v->vcpu_id, &lpr_map);
            else
                vlapic_accept_irq(v, delivery_mode,
                                  vector, level, trig_mode);
        }
    }

    if ( delivery_mode == APIC_DM_LOWEST)
    {
        v = vlapic->vcpu;
        target = apic_round_robin(v->domain, dest_mode, vector, lpr_map);

        if ( target )
            vlapic_accept_irq(target->vcpu, delivery_mode,
                              vector, level, trig_mode);
    }
}

static uint32_t vlapic_get_tmcct(struct vlapic *vlapic)
{
    uint32_t counter_passed;
    s_time_t passed, now = NOW();
    uint32_t tmcct = vlapic_get_reg(vlapic, APIC_TMCCT);

    ASSERT(vlapic != NULL);

    if ( unlikely(now <= vlapic->timer_last_update) )
    {
        passed = ~0x0LL - vlapic->timer_last_update + now;
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "time elapsed.");
    }
    else
        passed = now - vlapic->timer_last_update;

    counter_passed = passed /
      (APIC_BUS_CYCLE_NS * vlapic->timer_divide_count);

    tmcct -= counter_passed;

    if ( tmcct <= 0 )
    {
        if ( unlikely(!vlapic_lvtt_period(vlapic)) )
        {
            tmcct =  0;
            // FIXME: should we add interrupt here?
        }
        else
        {
            do {
                tmcct += vlapic_get_reg(vlapic, APIC_TMICT);
            } while ( tmcct < 0 );
        }
    }

    vlapic->timer_last_update = now;
    vlapic_set_reg(vlapic, APIC_TMCCT, tmcct);

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER,
      "timer initial count 0x%x, timer current count 0x%x, "
      "update 0x%016"PRIx64", now 0x%016"PRIx64", offset 0x%x.",
      vlapic_get_reg(vlapic, APIC_TMICT),
      vlapic_get_reg(vlapic, APIC_TMCCT),
      vlapic->timer_last_update, now, counter_passed);

    return tmcct;
}

static void vlapic_read_aligned(struct vlapic *vlapic, unsigned int offset,
                         unsigned int len, unsigned int *result)
{
    ASSERT(len == 4 && offset > 0 && offset <= APIC_TDCR);

    *result = 0;

    switch ( offset ) {
    case APIC_ARBPRI:
        printk("access local APIC ARBPRI register which is for P6\n");
        break;

    case APIC_TMCCT:        //Timer CCR
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
    struct vlapic *vlapic = VLAPIC(v);
    unsigned int offset = address - vlapic->base_address;

    if ( offset > APIC_TDCR)
        return 0;

    /* some bugs on kernel cause read this with byte*/
    if ( len != 4 )
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                    "read with len=0x%lx, should be 4 instead.\n",
                    len);

    alignment = offset & 0x3;

    vlapic_read_aligned(vlapic, offset & ~0x3, 4, &tmp);
    switch ( len ) {
    case 1:
        result = *((unsigned char *)&tmp + alignment);
        break;

    case 2:
        result = *(unsigned short *)((unsigned char *)&tmp + alignment);
        break;

    case 4:
        result = *(unsigned int *)((unsigned char *)&tmp + alignment);
        break;

    default:
        printk("Local APIC read with len=0x%lx, should be 4 instead.\n", len);
        domain_crash_synchronous();
        break;
    }

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "offset 0x%x with length 0x%lx, "
                "and the result is 0x%lx.", offset, len, result);

    return result;
}

static void vlapic_write(struct vcpu *v, unsigned long address,
                         unsigned long len, unsigned long val)
{
    struct vlapic *vlapic = VLAPIC(v);
    unsigned int offset = address - vlapic->base_address;

    if ( offset != 0xb0 )
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                    "offset 0x%x with length 0x%lx, and value is 0x%lx.",
                    offset, len, val);

    /*
     * According to IA 32 Manual, all resgiters should be accessed with
     * 32 bits alignment.
     */
    if ( len != 4 )
    {
        unsigned int tmp;
        unsigned char alignment;

        /* Some kernel do will access with byte/word alignment*/
        printk("Notice: Local APIC write with len = %lx\n",len);
        alignment = offset & 0x3;
        tmp = vlapic_read(v, offset & ~0x3, 4);
        switch ( len ) {
        case 1:
            /* XXX the saddr is a tmp variable from caller, so should be ok
               But we should still change the following ref to val to
               local variable later */
            val = (tmp & ~(0xff << alignment)) |
                  ((val & 0xff) << alignment);
            break;

        case 2:
            if ( alignment != 0x0 && alignment != 0x2 )
            {
                printk("alignment error for vlapic with len == 2\n");
                domain_crash_synchronous();
            }

            val = (tmp & ~(0xffff << alignment)) |
                  ((val & 0xffff) << alignment);
            break;

        case 3:
            /* will it happen? */
            printk("vlapic_write with len = 3 !!!\n");
            domain_crash_synchronous();
            break;

        default:
            printk("Local APIC write with len = %lx, should be 4 instead\n", len);
            domain_crash_synchronous();
            break;
        }
    }

    offset &= 0xff0;

    switch ( offset ) {
    case APIC_ID:   /* Local APIC ID */
        vlapic_set_reg(vlapic, APIC_ID, val);
        break;

    case APIC_TASKPRI:
        vlapic_set_reg(vlapic, APIC_TASKPRI, val & 0xff);
        vlapic_update_ppr(vlapic);
        break;

    case APIC_EOI:
        vlapic_EOI_set(vlapic);
        break;

    case APIC_LDR:
        vlapic_set_reg(vlapic, APIC_LDR, val & APIC_LDR_MASK);
        break;

    case APIC_DFR:
        vlapic_set_reg(vlapic, APIC_DFR, val);
        break;

    case APIC_SPIV:
        vlapic_set_reg(vlapic, APIC_SPIV, val & 0x1ff);

        if ( !( val & APIC_SPIV_APIC_ENABLED) )
        {
            int i;
            uint32_t lvt_val;

            vlapic->status |= VLAPIC_SOFTWARE_DISABLE_MASK;

            for ( i = 0; i < VLAPIC_LVT_NUM; i++ )
            {
                lvt_val = vlapic_get_reg(vlapic, APIC_LVT1 + 0x10 * i);
                vlapic_set_reg(vlapic, APIC_LVTT + 0x10 * i,
                               lvt_val | APIC_LVT_MASKED);
            }

            if ( (vlapic_get_reg(vlapic, APIC_LVT0) & APIC_MODE_MASK)
                 == APIC_DM_EXTINT )
                clear_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status);
        }
        else
        {
            vlapic->status &= ~VLAPIC_SOFTWARE_DISABLE_MASK;
            if ( (vlapic_get_reg(vlapic, APIC_LVT0) & APIC_MODE_MASK)
                  == APIC_DM_EXTINT )
                set_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status);
        }
        break;

    case APIC_ESR:
        vlapic->err_write_count = !vlapic->err_write_count;
        if ( !vlapic->err_write_count )
            vlapic->err_status = 0;
        break;

    case APIC_ICR:
        /* No delay here, so we always clear the pending bit*/
        vlapic_set_reg(vlapic, APIC_ICR, val & ~(1 << 12));
        vlapic_ipi(vlapic);
        break;

    case APIC_ICR2:
        vlapic_set_reg(vlapic, APIC_ICR2, val & 0xff000000);
        break;

    case APIC_LVTT:         // LVT Timer Reg
    case APIC_LVTTHMR:      // LVT Thermal Monitor
    case APIC_LVTPC:        // LVT Performance Counter
    case APIC_LVT0:         // LVT LINT0 Reg
    case APIC_LVT1:         // LVT Lint1 Reg
    case APIC_LVTERR:       // LVT Error Reg
        {
            if ( vlapic->status & VLAPIC_SOFTWARE_DISABLE_MASK )
                val |= APIC_LVT_MASKED;

            val &= vlapic_lvt_mask[(offset - APIC_LVTT) >> 4];

            vlapic_set_reg(vlapic, offset, val);

            /* On hardware, when write vector less than 0x20 will error */
            if ( !(val & APIC_LVT_MASKED) )
                vlapic_check_vector(vlapic, vlapic_lvt_dm(vlapic, offset),
                                    vlapic_lvt_vector(vlapic, offset));

            if ( !vlapic->vcpu_id && (offset == APIC_LVT0) )
            {
                if ( (val & APIC_MODE_MASK) == APIC_DM_EXTINT )
                    if ( val & APIC_LVT_MASKED)
                        clear_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status);
                    else
                        set_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status);
                else
                    clear_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status);
            }

        }
        break;

    case APIC_TMICT:
        {
            s_time_t now = NOW(), offset;

            stop_timer(&vlapic->vlapic_timer);

            vlapic_set_reg(vlapic, APIC_TMICT, val);
            vlapic_set_reg(vlapic, APIC_TMCCT, val);
            vlapic->timer_last_update = now;

            offset = APIC_BUS_CYCLE_NS *
                     vlapic->timer_divide_count * val;

            set_timer(&vlapic->vlapic_timer, now + offset);

            HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                        "bus cycle is %"PRId64"ns, now 0x%016"PRIx64", "
                        "timer initial count 0x%x, offset 0x%016"PRIx64", "
                        "expire @ 0x%016"PRIx64".",
                        APIC_BUS_CYCLE_NS, now,
                        vlapic_get_reg(vlapic, APIC_TMICT),
                        offset, now + offset);
        }
        break;

    case APIC_TDCR:
        {
            unsigned int tmp1, tmp2;

            tmp1 = val & 0xf;
            tmp2 = ((tmp1 & 0x3) | ((tmp1 & 0x8) >> 1)) + 1;
            vlapic->timer_divide_count = 0x1 << (tmp2 & 0x7);

            vlapic_set_reg(vlapic, APIC_TDCR, val);

            HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER, "timer divide count is 0x%x",
                        vlapic->timer_divide_count);
        }
        break;

    default:
        printk("Local APIC Write to read-only register\n");
        break;
    }
}

static int vlapic_range(struct vcpu *v, unsigned long addr)
{
    struct vlapic *vlapic = VLAPIC(v);

    if ( vlapic_global_enabled(vlapic) &&
         (addr >= vlapic->base_address) &&
         (addr <= vlapic->base_address + VLOCAL_APIC_MEM_LENGTH) )
        return 1;

    return 0;
}

struct hvm_mmio_handler vlapic_mmio_handler = {
    .check_handler = vlapic_range,
    .read_handler = vlapic_read,
    .write_handler = vlapic_write
};

void vlapic_msr_set(struct vlapic *vlapic, uint64_t value)
{
    /* When apic disabled */
    if ( vlapic == NULL )
        return;

    if ( vlapic->vcpu_id )
        value &= ~MSR_IA32_APICBASE_BSP;

    vlapic->apic_base_msr = value;
    vlapic->base_address = vlapic->apic_base_msr &
                           MSR_IA32_APICBASE_BASE;

    /* with FSB delivery interrupt, we can restart APIC functionality */
    if ( !(value & MSR_IA32_APICBASE_ENABLE) )
        set_bit(_VLAPIC_GLOB_DISABLE, &vlapic->status );
    else
        clear_bit(_VLAPIC_GLOB_DISABLE, &vlapic->status);

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                "apic base msr is 0x%016"PRIx64", and base address is 0x%lx.",
                vlapic->apic_base_msr, vlapic->base_address);
}

void vlapic_timer_fn(void *data)
{
    struct vlapic *vlapic = data;
    struct vcpu *v;
    uint32_t timer_vector;
    s_time_t now;

    if ( unlikely(!vlapic_enabled(vlapic) ||
                  !vlapic_lvt_enabled(vlapic, APIC_LVTT)) )
        return;

    v = vlapic->vcpu;
    timer_vector = vlapic_lvt_vector(vlapic, APIC_LVTT);
    now = NOW();

    vlapic->timer_last_update = now;

    if ( test_and_set_bit(timer_vector, vlapic->regs + APIC_IRR ))
        vlapic->intr_pending_count[timer_vector]++;

    if ( vlapic_lvtt_period(vlapic) )
    {
        s_time_t offset;
        uint32_t tmict = vlapic_get_reg(vlapic, APIC_TMICT);

        vlapic_set_reg(vlapic, APIC_TMCCT, tmict);

        offset = APIC_BUS_CYCLE_NS *
                 vlapic->timer_divide_count * tmict;

        set_timer(&vlapic->vlapic_timer, now + offset);
    }
    else
        vlapic_set_reg(vlapic, APIC_TMCCT, 0);

#if 0
    if ( test_bit(_VCPUF_running, &v->vcpu_flags) )
    {
        /* TODO: add guest time handling here */
    }
#endif

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC_TIMER,
                "now 0x%016"PRIx64", expire @ 0x%016"PRIx64", "
                "timer initial count 0x%x, timer current count 0x%x.",
                now, vlapic->vlapic_timer.expires,
                vlapic_get_reg(vlapic, APIC_TMICT),
                vlapic_get_reg(vlapic, APIC_TMCCT));
}

#if 0
static int
vlapic_check_direct_intr(struct vcpu *v, int * mode)
{
    struct vlapic *vlapic = VLAPIC(v);
    int type;

    type = fls(vlapic->direct_intr.deliver_mode) - 1;
    if ( type == -1 )
        return -1;

    *mode = type;
    return 0;
}
#endif

int vlapic_accept_pic_intr(struct vcpu *v)
{
    struct vlapic *vlapic = VLAPIC(v);

    return vlapic ? test_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status) : 1;
}

int cpu_get_apic_interrupt(struct vcpu *v, int *mode)
{
    struct vlapic *vlapic = VLAPIC(v);

    if ( vlapic && vlapic_enabled(vlapic) )
    {
        int highest_irr = vlapic_find_highest_irr(vlapic);

        if ( highest_irr != -1 &&
             ( (highest_irr & 0xF0) > vlapic_get_reg(vlapic, APIC_PROCPRI) ) )
        {
            if ( highest_irr < 0x10 )
            {
                uint32_t err_vector;

                vlapic->err_status |= 0x20;
                err_vector = vlapic_lvt_vector(vlapic, APIC_LVTERR);

                HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                            "Sending an illegal vector 0x%x.", highest_irr);

                set_bit(err_vector, vlapic->regs + APIC_IRR);
                highest_irr = err_vector;
            }

            *mode = APIC_DM_FIXED;
            return highest_irr;
        }
    }
    return -1;
}

int cpu_has_apic_interrupt(struct vcpu* v)
{
    struct vlapic *vlapic = VLAPIC(v);

    if (vlapic && vlapic_enabled(vlapic)) {
        int highest_irr = vlapic_find_highest_irr(vlapic);

        if ( highest_irr != -1 &&
             ( (highest_irr & 0xF0) > vlapic_get_reg(vlapic, APIC_PROCPRI) ) ) {
            return 1;
        }
    }
    return 0;
}

void vlapic_post_injection(struct vcpu *v, int vector, int deliver_mode)
{
    struct vlapic *vlapic = VLAPIC(v);

    if ( unlikely(vlapic == NULL) )
        return;

    switch ( deliver_mode ) {
    case APIC_DM_FIXED:
    case APIC_DM_LOWEST:
        set_bit(vector, vlapic->regs + APIC_ISR);
        clear_bit(vector, vlapic->regs + APIC_IRR);
        vlapic_update_ppr(vlapic);

        if ( vector == vlapic_lvt_vector(vlapic, APIC_LVTT) )
        {
            vlapic->intr_pending_count[vector]--;
            if ( vlapic->intr_pending_count[vector] > 0 )
                test_and_set_bit(vector, vlapic->regs + APIC_IRR);
        }
        break;

    /*XXX deal with these later */
    case APIC_DM_REMRD:
        printk("Ignore deliver mode 3 in vlapic_post_injection\n");
        break;

    case APIC_DM_SMI:
    case APIC_DM_NMI:
    case APIC_DM_INIT:
    case APIC_DM_STARTUP:
        vlapic->direct_intr.deliver_mode &= deliver_mode;
        break;

    default:
        printk("<vlapic_post_injection> invalid deliver mode\n");
        break;
    }
}

static int vlapic_reset(struct vlapic *vlapic)
{
    struct vcpu *v;
    int i;

    ASSERT( vlapic != NULL );

    v = vlapic->vcpu;

    ASSERT( v != NULL );

    vlapic->domain = v->domain;

    vlapic->vcpu_id = v->vcpu_id;

    vlapic_set_reg(vlapic, APIC_ID, v->vcpu_id << 24);

    vlapic_set_reg(vlapic, APIC_LVR, VLAPIC_VERSION);

    for ( i = 0; i < VLAPIC_LVT_NUM; i++ )
        vlapic_set_reg(vlapic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);

    vlapic_set_reg(vlapic, APIC_DFR, 0xffffffffU);

    vlapic_set_reg(vlapic, APIC_SPIV, 0xff);

    vlapic->apic_base_msr = MSR_IA32_APICBASE_ENABLE | APIC_DEFAULT_PHYS_BASE;

    if ( v->vcpu_id == 0 )
        vlapic->apic_base_msr |= MSR_IA32_APICBASE_BSP;

    vlapic->base_address = vlapic->apic_base_msr &
                           MSR_IA32_APICBASE_BASE;

    hvm_vioapic_add_lapic(vlapic, v);

    init_timer(&vlapic->vlapic_timer,
                  vlapic_timer_fn, vlapic, v->processor);

#ifdef VLAPIC_NO_BIOS
    /*
     * XXX According to mp sepcific, BIOS will enable LVT0/1,
     * remove it after BIOS enabled
     */
    if ( !v->vcpu_id )
    {
        vlapic_set_reg(vlapic, APIC_LVT0, APIC_MODE_EXTINT << 8);
        vlapic_set_reg(vlapic, APIC_LVT1, APIC_MODE_NMI << 8);
        set_bit(_VLAPIC_BSP_ACCEPT_PIC, &vlapic->status);
    }
#endif

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC,
                "vcpu=%p, id=%d, vlapic_apic_base_msr=0x%016"PRIx64", "
                "base_address=0x%0lx.",
                v,  GET_APIC_ID(vlapic_get_reg(vlapic, APIC_ID)),
                vlapic->apic_base_msr, vlapic->base_address);

    return 1;
}

int vlapic_init(struct vcpu *v)
{
    struct vlapic *vlapic = NULL;

    ASSERT( v != NULL );

    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "vlapic_init %d", v->vcpu_id);

    vlapic = xmalloc_bytes(sizeof(struct vlapic));
    if ( vlapic == NULL )
    {
        printk("malloc vlapic error for vcpu %x\n", v->vcpu_id);
        return -ENOMEM;
    }

    memset(vlapic, 0, sizeof(struct vlapic));

    vlapic->regs_page = alloc_domheap_page(NULL);
    if ( vlapic->regs_page == NULL )
    {
        printk("malloc vlapic regs error for vcpu %x\n", v->vcpu_id);
        xfree(vlapic);
        return -ENOMEM;
    }

    vlapic->regs = map_domain_page_global(page_to_mfn(vlapic->regs_page));

    memset(vlapic->regs, 0, PAGE_SIZE);

    VLAPIC(v) = vlapic;

    vlapic->vcpu = v;

    vlapic_reset(vlapic);

    return 0;
}
