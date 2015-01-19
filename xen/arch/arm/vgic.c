/*
 * xen/arch/arm/vgic.c
 *
 * ARM Virtual Generic Interrupt Controller support
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/bitops.h>
#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/sched.h>

#include <asm/current.h>

#include "io.h"
#include <asm/gic.h>

#define REG(n) (n/4)

/* Number of ranks of interrupt registers for a domain */
#define DOMAIN_NR_RANKS(d) (((d)->arch.vgic.nr_lines+31)/32)

/*
 * Rank containing GICD_<FOO><n> for GICD_<FOO> with
 * <b>-bits-per-interrupt
 */
static inline int REG_RANK_NR(int b, uint32_t n)
{
    switch ( b )
    {
    case 8: return n >> 3;
    case 4: return n >> 2;
    case 2: return n >> 1;
    case 1: return n;
    default: BUG();
    }
}

/*
 * Offset of GICD_<FOO><n> with its rank, for GICD_<FOO> with
 * <b>-bits-per-interrupt.
 */
#define REG_RANK_INDEX(b, n) ((n) & ((b)-1))

/*
 * Returns rank corresponding to a GICD_<FOO><n> register for
 * GICD_<FOO> with <b>-bits-per-interrupt.
 */
static struct vgic_irq_rank *vgic_irq_rank(struct vcpu *v, int b, int n)
{
    int rank = REG_RANK_NR(b, n);

    if ( rank == 0 )
        return &v->arch.vgic.private_irqs;
    else if ( rank <= DOMAIN_NR_RANKS(v->domain) )
        return &v->domain->arch.vgic.shared_irqs[rank - 1];
    else
        return NULL;
}

int domain_vgic_init(struct domain *d)
{
    int i;

    d->arch.vgic.ctlr = 0;

    /* Currently nr_lines in vgic and gic doesn't have the same meanings
     * Here nr_lines = number of SPIs
     */
    if ( d->domain_id == 0 )
        d->arch.vgic.nr_lines = gic_number_lines() - 32;
    else
        d->arch.vgic.nr_lines = 0; /* We don't need SPIs for the guest */

    d->arch.vgic.shared_irqs =
        xzalloc_array(struct vgic_irq_rank, DOMAIN_NR_RANKS(d));
    if ( d->arch.vgic.shared_irqs == NULL )
        return -ENOMEM;

    d->arch.vgic.pending_irqs =
        xzalloc_array(struct pending_irq, d->arch.vgic.nr_lines);
    if ( d->arch.vgic.pending_irqs == NULL )
        return -ENOMEM;

    for (i=0; i<d->arch.vgic.nr_lines; i++)
    {
        INIT_LIST_HEAD(&d->arch.vgic.pending_irqs[i].inflight);
        INIT_LIST_HEAD(&d->arch.vgic.pending_irqs[i].lr_queue);
    }
    for (i=0; i<DOMAIN_NR_RANKS(d); i++)
        spin_lock_init(&d->arch.vgic.shared_irqs[i].lock);
    return 0;
}

void domain_vgic_free(struct domain *d)
{
    xfree(d->arch.vgic.shared_irqs);
    xfree(d->arch.vgic.pending_irqs);
}

int vcpu_vgic_init(struct vcpu *v)
{
    int i;
    memset(&v->arch.vgic.private_irqs, 0, sizeof(v->arch.vgic.private_irqs));

    spin_lock_init(&v->arch.vgic.private_irqs.lock);

    memset(&v->arch.vgic.pending_irqs, 0, sizeof(v->arch.vgic.pending_irqs));
    for (i = 0; i < 32; i++)
    {
        INIT_LIST_HEAD(&v->arch.vgic.pending_irqs[i].inflight);
        INIT_LIST_HEAD(&v->arch.vgic.pending_irqs[i].lr_queue);
    }

    /* For SGI and PPI the target is always this CPU */
    for ( i = 0 ; i < 8 ; i++ )
        v->arch.vgic.private_irqs.itargets[i] =
              (1<<(v->vcpu_id+0))
            | (1<<(v->vcpu_id+8))
            | (1<<(v->vcpu_id+16))
            | (1<<(v->vcpu_id+24));
    INIT_LIST_HEAD(&v->arch.vgic.inflight_irqs);
    INIT_LIST_HEAD(&v->arch.vgic.lr_pending);
    spin_lock_init(&v->arch.vgic.lock);

    return 0;
}

#define vgic_lock(v)   spin_lock_irq(&(v)->domain->arch.vgic.lock)
#define vgic_unlock(v) spin_unlock_irq(&(v)->domain->arch.vgic.lock)

#define vgic_lock_rank(v, r) spin_lock(&(r)->lock)
#define vgic_unlock_rank(v, r) spin_unlock(&(r)->lock)

static uint32_t byte_read(uint32_t val, int sign, int offset)
{
    int byte = offset & 0x3;

    val = val >> (8*byte);
    if ( sign && (val & 0x80) )
        val |= 0xffffff00;
    else
        val &= 0x000000ff;
    return val;
}

static void byte_write(uint32_t *reg, uint32_t var, int offset)
{
    int byte = offset & 0x3;

    var &= (0xff << (8*byte));

    *reg &= ~(0xff << (8*byte));
    *reg |= var;
}

static int vgic_distr_mmio_read(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t *r = select_user_reg(regs, dabt.reg);
    struct vgic_irq_rank *rank;
    int offset = (int)(info->gpa - v->domain->arch.vgic.dbase);
    int gicd_reg = REG(offset);

    switch ( gicd_reg )
    {
    case GICD_CTLR:
        if ( dabt.size != 2 ) goto bad_width;
        vgic_lock(v);
        *r = v->domain->arch.vgic.ctlr;
        vgic_unlock(v);
        return 1;
    case GICD_TYPER:
        if ( dabt.size != 2 ) goto bad_width;
        /* No secure world support for guests. */
        vgic_lock(v);
        *r = ( (v->domain->max_vcpus<<5) & GICD_TYPE_CPUS )
            |( ((v->domain->arch.vgic.nr_lines/32)) & GICD_TYPE_LINES );
        vgic_unlock(v);
        return 1;
    case GICD_IIDR:
        if ( dabt.size != 2 ) goto bad_width;
        /*
         * XXX Do we need a JEP106 manufacturer ID?
         * Just use the physical h/w value for now
         */
        *r = 0x0000043b;
        return 1;

    /* Implementation defined -- read as zero */
    case REG(0x020) ... REG(0x03c):
        goto read_as_zero;

    case GICD_IGROUPR ... GICD_IGROUPRN:
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero;

    case GICD_ISENABLER ... GICD_ISENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ISENABLER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->ienable;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ICENABLER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->ienable;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ISPENDR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->ipend, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ICPENDR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->ipend, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ISACTIVER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->iactive;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ICACTIVER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->iactive;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ITARGETSR ... GICD_ITARGETSRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ITARGETSR);
        if ( rank == NULL) goto read_as_zero;

        vgic_lock_rank(v, rank);
        *r = rank->itargets[REG_RANK_INDEX(8, gicd_reg - GICD_ITARGETSR)];
        if ( dabt.size == 0 )
            *r = byte_read(*r, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_IPRIORITYR ... GICD_IPRIORITYRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_IPRIORITYR);
        if ( rank == NULL) goto read_as_zero;

        vgic_lock_rank(v, rank);
        *r = rank->ipriority[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR)];
        if ( dabt.size == 0 )
            *r = byte_read(*r, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICFGR ... GICD_ICFGRN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 2, gicd_reg - GICD_ICFGR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR)];
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_NSACR ... GICD_NSACRN:
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero;

    case GICD_SGIR:
        if ( dabt.size != 2 ) goto bad_width;
        /* Write only -- read unknown */
        *r = 0xdeadbeef;
        return 1;

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_CPENDSGIR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->pendsgi, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_SPENDSGIR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->pendsgi, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    /* Implementation defined -- read as zero */
    case REG(0xfd0) ... REG(0xfe4):
        goto read_as_zero;

    case GICD_ICPIDR2:
        if ( dabt.size != 2 ) goto bad_width;
        printk(XENLOG_G_ERR "%pv: vGICD: unhandled read from ICPIDR2\n", v);
        return 0;

    /* Implementation defined -- read as zero */
    case REG(0xfec) ... REG(0xffc):
        goto read_as_zero;

    /* Reserved -- read as zero */
    case REG(0x00c) ... REG(0x01c):
    case REG(0x040) ... REG(0x07c):
    case REG(0x7fc):
    case REG(0xbfc):
    case REG(0xf04) ... REG(0xf0c):
    case REG(0xf30) ... REG(0xfcc):
        goto read_as_zero;

    default:
        printk(XENLOG_G_ERR "%pv: vGICD: unhandled read r%d offset %#08x\n",
               v, dabt.reg, offset);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR "%pv: vGICD: bad read width %d r%d offset %#08x\n",
           v, dabt.size, dabt.reg, offset);
    domain_crash_synchronous();
    return 0;

read_as_zero:
    if ( dabt.size != 2 ) goto bad_width;
    *r = 0;
    return 1;
}

static void vgic_disable_irqs(struct vcpu *v, uint32_t r, int n)
{
    const unsigned long mask = r;
    struct pending_irq *p;
    unsigned int irq;
    int i = 0;

    while ( (i = find_next_bit(&mask, 32, i)) < 32 ) {
        irq = i + (32 * n);
        p = irq_to_pending(v, irq);
        clear_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        gic_remove_from_queues(v, irq);
        if ( p->desc != NULL )
            p->desc->handler->disable(p->desc);
        i++;
    }
}

static void vgic_enable_irqs(struct vcpu *v, uint32_t r, int n)
{
    const unsigned long mask = r;
    struct pending_irq *p;
    unsigned int irq;
    int i = 0;

    while ( (i = find_next_bit(&mask, 32, i)) < 32 ) {
        irq = i + (32 * n);
        p = irq_to_pending(v, irq);
        set_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        if ( !list_empty(&p->inflight) && !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
            gic_set_guest_irq(v, irq, GICH_LR_PENDING, p->priority);
        if ( p->desc != NULL )
            p->desc->handler->enable(p->desc);
        i++;
    }
}

static inline int is_vcpu_running(struct domain *d, int vcpuid)
{
    struct vcpu *v;

    if ( vcpuid >= d->max_vcpus )
        return 0;

    v = d->vcpu[vcpuid];
    if ( v == NULL )
        return 0;
    if (test_bit(_VPF_down, &v->pause_flags) )
        return 0;

    return 1;
}

static int vgic_to_sgi(struct vcpu *v, register_t sgir)
{
    struct domain *d = v->domain;
    int virtual_irq;
    int filter;
    int vcpuid;
    int i;
    unsigned long vcpu_mask = 0;

    ASSERT(d->max_vcpus < 8*sizeof(vcpu_mask));

    filter = (sgir & GICD_SGI_TARGET_LIST_MASK);
    virtual_irq = (sgir & GICD_SGI_INTID_MASK);
    ASSERT( virtual_irq < 16 );

    switch ( filter )
    {
        case GICD_SGI_TARGET_LIST:
            vcpu_mask = (sgir & GICD_SGI_TARGET_MASK) >> GICD_SGI_TARGET_SHIFT;
            break;
        case GICD_SGI_TARGET_OTHERS:
            for ( i = 0; i < d->max_vcpus; i++ )
            {
                if ( i != current->vcpu_id && is_vcpu_running(d, i) )
                    set_bit(i, &vcpu_mask);
            }
            break;
        case GICD_SGI_TARGET_SELF:
            set_bit(current->vcpu_id, &vcpu_mask);
            break;
        default:
            gdprintk(XENLOG_WARNING, "vGICD: unhandled GICD_SGIR write %"PRIregister" with wrong TargetListFilter field\n",
                     sgir);
            return 0;
    }

    for_each_set_bit( vcpuid, &vcpu_mask, d->max_vcpus )
    {
        if ( !is_vcpu_running(d, vcpuid) )
        {
            gdprintk(XENLOG_WARNING, "vGICD: GICD_SGIR write r=%"PRIregister" vcpu_mask=%lx, wrong CPUTargetList\n",
                     sgir, vcpu_mask);
            continue;
        }
        vgic_vcpu_inject_irq(d->vcpu[vcpuid], virtual_irq, 1);
    }
    return 1;
}

static int vgic_distr_mmio_write(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t *r = select_user_reg(regs, dabt.reg);
    struct vgic_irq_rank *rank;
    int offset = (int)(info->gpa - v->domain->arch.vgic.dbase);
    int gicd_reg = REG(offset);
    uint32_t tr;

    switch ( gicd_reg )
    {
    case GICD_CTLR:
        if ( dabt.size != 2 ) goto bad_width;
        /* Ignore all but the enable bit */
        v->domain->arch.vgic.ctlr = (*r) & GICD_CTL_ENABLE;
        return 1;

    /* R/O -- write ignored */
    case GICD_TYPER:
    case GICD_IIDR:
        goto write_ignore;

    /* Implementation defined -- write ignored */
    case REG(0x020) ... REG(0x03c):
        goto write_ignore;

    case GICD_IGROUPR ... GICD_IGROUPRN:
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore;

    case GICD_ISENABLER ... GICD_ISENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ISENABLER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        tr = rank->ienable;
        rank->ienable |= *r;
        vgic_enable_irqs(v, (*r) & (~tr), gicd_reg - GICD_ISENABLER);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ICENABLER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        tr = rank->ienable;
        rank->ienable &= ~*r;
        vgic_disable_irqs(v, (*r) & tr, gicd_reg - GICD_ICENABLER);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ISPENDR%d\n",
               v, dabt.size ? "word" : "byte", *r, gicd_reg - GICD_ISPENDR);
        return 0;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ICPENDR%d\n",
               v, dabt.size ? "word" : "byte", *r, gicd_reg - GICD_ICPENDR);
        return 0;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ISACTIVER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        rank->iactive &= ~*r;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 1, gicd_reg - GICD_ICACTIVER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        rank->iactive &= ~*r;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ITARGETSR ... GICD_ITARGETSR + 7:
        /* SGI/PPI target is read only */
        goto write_ignore;

    case GICD_ITARGETSR + 8 ... GICD_ITARGETSRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ITARGETSR);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        if ( dabt.size == 2 )
            rank->itargets[REG_RANK_INDEX(8, gicd_reg - GICD_ITARGETSR)] = *r;
        else
            byte_write(&rank->itargets[REG_RANK_INDEX(8, gicd_reg - GICD_ITARGETSR)],
                       *r, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_IPRIORITYR ... GICD_IPRIORITYRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_IPRIORITYR);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        if ( dabt.size == 2 )
            rank->ipriority[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR)] = *r;
        else
            byte_write(&rank->ipriority[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR)],
                       *r, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICFGR: /* SGIs */
        goto write_ignore;
    case GICD_ICFGR + 1: /* PPIs */
        /* It is implementation defined if these are writeable. We chose not */
        goto write_ignore;
    case GICD_ICFGR + 2 ... GICD_ICFGRN: /* SPIs */
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 2, gicd_reg - GICD_ICFGR);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR)] = *r;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_NSACR ... GICD_NSACRN:
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore;

    case GICD_SGIR:
        if ( dabt.size != 2 )
            goto bad_width;
        return vgic_to_sgi(v, *r);

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ICPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", *r, gicd_reg - GICD_CPENDSGIR);
        return 0;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ISPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", *r, gicd_reg - GICD_SPENDSGIR);
        return 0;

    /* Implementation defined -- write ignored */
    case REG(0xfd0) ... REG(0xfe4):
        goto write_ignore;

    /* R/O -- write ignore */
    case GICD_ICPIDR2:
        goto write_ignore;

    /* Implementation defined -- write ignored */
    case REG(0xfec) ... REG(0xffc):
        goto write_ignore;

    /* Reserved -- write ignored */
    case REG(0x00c) ... REG(0x01c):
    case REG(0x040) ... REG(0x07c):
    case REG(0x7fc):
    case REG(0xbfc):
    case REG(0xf04) ... REG(0xf0c):
    case REG(0xf30) ... REG(0xfcc):
        goto write_ignore;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled write r%d=%"PRIregister" offset %#08x\n",
               v, dabt.reg, *r, offset);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR
           "%pv: vGICD: bad write width %d r%d=%"PRIregister" offset %#08x\n",
           v, dabt.size, dabt.reg, *r, offset);
    domain_crash_synchronous();
    return 0;

write_ignore:
    if ( dabt.size != 2 ) goto bad_width;
    return 1;
}

static int vgic_distr_mmio_check(struct vcpu *v, paddr_t addr)
{
    struct domain *d = v->domain;

    return (addr >= (d->arch.vgic.dbase)) && (addr < (d->arch.vgic.dbase + PAGE_SIZE));
}

const struct mmio_handler vgic_distr_mmio_handler = {
    .check_handler = vgic_distr_mmio_check,
    .read_handler  = vgic_distr_mmio_read,
    .write_handler = vgic_distr_mmio_write,
};

struct pending_irq *irq_to_pending(struct vcpu *v, unsigned int irq)
{
    struct pending_irq *n;
    /* Pending irqs allocation strategy: the first vgic.nr_lines irqs
     * are used for SPIs; the rests are used for per cpu irqs */
    if ( irq < 32 )
        n = &v->arch.vgic.pending_irqs[irq];
    else
        n = &v->domain->arch.vgic.pending_irqs[irq - 32];
    return n;
}

void vgic_clear_pending_irqs(struct vcpu *v)
{
    struct pending_irq *p, *t;
    unsigned long flags;

    spin_lock_irqsave(&v->arch.vgic.lock, flags);
    list_for_each_entry_safe ( p, t, &v->arch.vgic.inflight_irqs, inflight )
        list_del_init(&p->inflight);
    gic_clear_pending_irqs(v);
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
}

void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int irq, int virtual)
{
    int idx = irq >> 2, byte = irq & 0x3;
    uint8_t priority;
    struct vgic_irq_rank *rank = vgic_irq_rank(v, 8, idx);
    struct pending_irq *iter, *n = irq_to_pending(v, irq);
    unsigned long flags;
    bool_t running;

    spin_lock_irqsave(&v->arch.vgic.lock, flags);

    if ( !list_empty(&n->inflight) )
    {
        if ( (irq != current->domain->arch.evtchn_irq) ||
             (!test_bit(GIC_IRQ_GUEST_VISIBLE, &n->status)) )
            set_bit(GIC_IRQ_GUEST_PENDING, &n->status);
        spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
        return;
    }

    /* vcpu offline */
    if ( test_bit(_VPF_down, &v->pause_flags) )
    {
        spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
        return;
    }

    priority = byte_read(rank->ipriority[REG_RANK_INDEX(8, idx)], 0, byte);

    n->irq = irq;
    set_bit(GIC_IRQ_GUEST_PENDING, &n->status);
    n->priority = priority;

    /* the irq is enabled */
    if ( test_bit(GIC_IRQ_GUEST_ENABLED, &n->status) )
        gic_set_guest_irq(v, irq, GICH_LR_PENDING, priority);

    list_for_each_entry ( iter, &v->arch.vgic.inflight_irqs, inflight )
    {
        if ( iter->priority > priority )
        {
            list_add_tail(&n->inflight, &iter->inflight);
            goto out;
        }
    }
    list_add_tail(&n->inflight, &v->arch.vgic.inflight_irqs);
out:
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
    /* we have a new higher priority irq, inject it into the guest */
    running = v->is_running;
    vcpu_unblock(v);
    if ( running && v != current )
        smp_send_event_check_mask(cpumask_of(v->processor));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

