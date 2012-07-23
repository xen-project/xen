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

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/sched.h>

#include <asm/current.h>

#include "io.h"
#include "gic.h"

#define VGIC_DISTR_BASE_ADDRESS 0x000000002c001000

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
    d->arch.vgic.nr_lines = 32;
    d->arch.vgic.shared_irqs =
        xmalloc_array(struct vgic_irq_rank, DOMAIN_NR_RANKS(d));
    d->arch.vgic.pending_irqs =
        xzalloc_array(struct pending_irq, d->arch.vgic.nr_lines);
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
    uint32_t *r = &regs->r0 + dabt.reg;
    struct vgic_irq_rank *rank;
    int offset = (int)(info->gpa - VGIC_DISTR_BASE_ADDRESS);
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
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ISENABLER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->ienable;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ICENABLER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->ienable;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ISPENDR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->ipend, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ICPENDR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->ipend, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ISACTIVER);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = rank->iactive;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ICACTIVER);
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
        /* We do not implement securty extensions for guests, read zero */
        goto read_as_zero;

    case GICD_SGIR:
        if ( dabt.size != 2 ) goto bad_width;
        /* Write only -- read unknown */
        *r = 0xdeadbeef;
        return 1;

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_CPENDSGIR);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank);
        *r = byte_read(rank->pendsgi, dabt.sign, offset);
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_SPENDSGIR);
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
        printk("vGICD: unhandled read from ICPIDR2\n");
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
        printk("vGICD: unhandled read r%d offset %#08x\n",
               dabt.reg, offset);
        return 0;
    }

bad_width:
    printk("vGICD: bad read width %d r%d offset %#08x\n",
           dabt.size, dabt.reg, offset);
    domain_crash_synchronous();
    return 0;

read_as_zero:
    if ( dabt.size != 2 ) goto bad_width;
    *r = 0;
    return 1;
}

static void vgic_enable_irqs(struct vcpu *v, uint32_t r, int n)
{
    struct pending_irq *p;
    unsigned int irq;
    int i = 0;

    while ( (i = find_next_bit((const long unsigned int *) &r, 32, i)) < 32 ) {
        irq = i + (32 * n);
        p = irq_to_pending(v, irq);
        if ( !list_empty(&p->inflight) )
            gic_set_guest_irq(v, irq, GICH_LR_PENDING, p->priority);
        i++;
    }
}

static int vgic_distr_mmio_write(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    uint32_t *r = &regs->r0 + dabt.reg;
    struct vgic_irq_rank *rank;
    int offset = (int)(info->gpa - VGIC_DISTR_BASE_ADDRESS);
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
        /* We do not implement securty extensions for guests, write ignore */
        goto write_ignore;

    case GICD_ISENABLER ... GICD_ISENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ISENABLER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        tr = rank->ienable;
        rank->ienable |= *r;
        vgic_unlock_rank(v, rank);
        vgic_enable_irqs(v, (*r) & (~tr), gicd_reg - GICD_ISENABLER);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ICENABLER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        rank->ienable &= ~*r;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk("vGICD: unhandled %s write %#"PRIx32" to ISPENDR%d\n",
               dabt.size ? "word" : "byte", *r, gicd_reg - GICD_ISPENDR);
        return 0;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk("vGICD: unhandled %s write %#"PRIx32" to ICPENDR%d\n",
               dabt.size ? "word" : "byte", *r, gicd_reg - GICD_ICPENDR);
        return 0;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ISACTIVER);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank);
        rank->iactive &= ~*r;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != 2 ) goto bad_width;
        rank = vgic_irq_rank(v, 8, gicd_reg - GICD_ICACTIVER);
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
        vgic_lock_rank(v, rank);
        if ( rank == NULL) goto write_ignore;
        rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR)] = *r;
        vgic_unlock_rank(v, rank);
        return 1;

    case GICD_NSACR ... GICD_NSACRN:
        /* We do not implement securty extensions for guests, write ignore */
        goto write_ignore;

    case GICD_SGIR:
        if ( dabt.size != 2 ) goto bad_width;
        printk("vGICD: unhandled write %#"PRIx32" to ICFGR%d\n",
               *r, gicd_reg - GICD_ICFGR);
        return 0;

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk("vGICD: unhandled %s write %#"PRIx32" to ICPENDSGIR%d\n",
               dabt.size ? "word" : "byte", *r, gicd_reg - GICD_CPENDSGIR);
        return 0;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != 0 && dabt.size != 2 ) goto bad_width;
        printk("vGICD: unhandled %s write %#"PRIx32" to ISPENDSGIR%d\n",
               dabt.size ? "word" : "byte", *r, gicd_reg - GICD_SPENDSGIR);
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
        printk("vGICD: unhandled write r%d=%"PRIx32" offset %#08x\n",
               dabt.reg, *r, offset);
        return 0;
    }

bad_width:
    printk("vGICD: bad write width %d r%d=%"PRIx32" offset %#08x\n",
           dabt.size, dabt.reg, *r, offset);
    domain_crash_synchronous();
    return 0;

write_ignore:
    if ( dabt.size != 2 ) goto bad_width;
    return 0;
}

static int vgic_distr_mmio_check(struct vcpu *v, paddr_t addr)
{
    return addr >= VGIC_DISTR_BASE_ADDRESS && addr < (VGIC_DISTR_BASE_ADDRESS+PAGE_SIZE);
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

void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int irq, int virtual)
{
    int idx = irq >> 2, byte = irq & 0x3;
    uint8_t priority;
    struct vgic_irq_rank *rank = vgic_irq_rank(v, 8, idx);
    struct pending_irq *iter, *n = irq_to_pending(v, irq);
    unsigned long flags;

    /* irq still pending */
    if (!list_empty(&n->inflight))
        return;

    priority = byte_read(rank->ipriority[REG_RANK_INDEX(8, idx)], 0, byte);

    n->irq = irq;
    n->priority = priority;
    if (!virtual)
        n->desc = irq_to_desc(irq);
    else
        n->desc = NULL;

    /* the irq is enabled */
    if ( rank->ienable & (1 << (irq % 32)) )
        gic_set_guest_irq(v, irq, GICH_LR_PENDING, priority);

    spin_lock_irqsave(&v->arch.vgic.lock, flags);
    list_for_each_entry ( iter, &v->arch.vgic.inflight_irqs, inflight )
    {
        if ( iter->priority > priority )
        {
            list_add_tail(&n->inflight, &iter->inflight);
            spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
            return;
        }
    }
    list_add_tail(&n->inflight, &v->arch.vgic.inflight_irqs);
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
    /* we have a new higher priority irq, inject it into the guest */
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

