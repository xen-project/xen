/*
 * xen/arch/arm/vgic-v2.c
 *
 * ARM Virtual Generic Interrupt Controller support v2
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
#include <asm/device.h>

#include <asm/mmio.h>
#include <asm/gic.h>
#include <asm/vgic.h>

static int vgic_v2_distr_mmio_read(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t *r = select_user_reg(regs, dabt.reg);
    struct vgic_irq_rank *rank;
    int gicd_reg = (int)(info->gpa - v->domain->arch.vgic.dbase);
    unsigned long flags;

    switch ( gicd_reg )
    {
    case GICD_CTLR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        vgic_lock(v);
        *r = v->domain->arch.vgic.ctlr;
        vgic_unlock(v);
        return 1;
    case GICD_TYPER:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* No secure world support for guests. */
        vgic_lock(v);
        *r = ( ((v->domain->max_vcpus - 1) << GICD_TYPE_CPUS_SHIFT) )
            |( ((v->domain->arch.vgic.nr_spis / 32)) & GICD_TYPE_LINES );
        vgic_unlock(v);
        return 1;
    case GICD_IIDR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /*
         * XXX Do we need a JEP106 manufacturer ID?
         * Just use the physical h/w value for now
         */
        *r = 0x0000043b;
        return 1;

    /* Implementation defined -- read as zero */
    case 0x020 ... 0x03c:
        goto read_as_zero;

    case GICD_IGROUPR ... GICD_IGROUPRN:
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case GICD_ISENABLER ... GICD_ISENABLERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISENABLER, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->ienable;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->ienable;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISPENDR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_byte_read(rank->ipend, dabt.sign, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 0, gicd_reg - GICD_ICPENDR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_byte_read(rank->ipend, dabt.sign, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISACTIVER, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->iactive;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICACTIVER, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->iactive;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ITARGETSR ... GICD_ITARGETSRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_ITARGETSR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->v2.itargets[REG_RANK_INDEX(8, gicd_reg - GICD_ITARGETSR,
                                              DABT_WORD)];
        if ( dabt.size == DABT_BYTE )
            *r = vgic_byte_read(*r, dabt.sign, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_IPRIORITYR ... GICD_IPRIORITYRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;

        vgic_lock_rank(v, rank, flags);
        *r = rank->ipriority[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR,
                                            DABT_WORD)];
        if ( dabt.size == DABT_BYTE )
            *r = vgic_byte_read(*r, dabt.sign, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICFGR ... GICD_ICFGRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 2, gicd_reg - GICD_ICFGR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR, DABT_WORD)];
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_NSACR ... GICD_NSACRN:
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case GICD_SGIR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* Write only -- read unknown */
        *r = 0xdeadbeef;
        return 1;

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_CPENDSGIR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_byte_read(rank->pendsgi, dabt.sign, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_SPENDSGIR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_byte_read(rank->pendsgi, dabt.sign, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    /* Implementation defined -- read as zero */
    case 0xfd0 ... 0xfe4:
        goto read_as_zero;

    case GICD_ICPIDR2:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR "%pv: vGICD: unhandled read from ICPIDR2\n", v);
        return 0;

    /* Implementation defined -- read as zero */
    case 0xfec ... 0xffc:
        goto read_as_zero;

    /* Reserved -- read as zero */
    case 0x00c ... 0x01c:
    case 0x040 ... 0x07c:
    case 0x7fc:
    case 0xbfc:
    case 0xf04 ... 0xf0c:
    case 0xf30 ... 0xfcc:
        goto read_as_zero;

    default:
        printk(XENLOG_G_ERR "%pv: vGICD: unhandled read r%d offset %#08x\n",
               v, dabt.reg, gicd_reg);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR "%pv: vGICD: bad read width %d r%d offset %#08x\n",
           v, dabt.size, dabt.reg, gicd_reg);
    domain_crash_synchronous();
    return 0;

read_as_zero_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
read_as_zero:
    *r = 0;
    return 1;
}

static int vgic_v2_to_sgi(struct vcpu *v, register_t sgir)
{

    int virq;
    int irqmode;
    enum gic_sgi_mode sgi_mode;
    unsigned long vcpu_mask = 0;

    irqmode = (sgir & GICD_SGI_TARGET_LIST_MASK) >> GICD_SGI_TARGET_LIST_SHIFT;
    virq = (sgir & GICD_SGI_INTID_MASK);
    vcpu_mask = (sgir & GICD_SGI_TARGET_MASK) >> GICD_SGI_TARGET_SHIFT;

    /* Map GIC sgi value to enum value */
    switch ( irqmode )
    {
    case GICD_SGI_TARGET_LIST_VAL:
        sgi_mode = SGI_TARGET_LIST;
        break;
    case GICD_SGI_TARGET_OTHERS_VAL:
        sgi_mode = SGI_TARGET_OTHERS;
        break;
    case GICD_SGI_TARGET_SELF_VAL:
        sgi_mode = SGI_TARGET_SELF;
        break;
    default:
        printk(XENLOG_G_DEBUG
               "%pv: vGICD: unhandled GICD_SGIR write %"PRIregister" with wrong mode\n",
               v, sgir);
        return 0;
    }

    return vgic_to_sgi(v, sgir, sgi_mode, virq, vcpu_mask);
}

static int vgic_v2_distr_mmio_write(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t *r = select_user_reg(regs, dabt.reg);
    struct vgic_irq_rank *rank;
    int gicd_reg = (int)(info->gpa - v->domain->arch.vgic.dbase);
    uint32_t tr;
    unsigned long flags;

    switch ( gicd_reg )
    {
    case GICD_CTLR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* Ignore all but the enable bit */
        vgic_lock(v);
        v->domain->arch.vgic.ctlr = (*r) & GICD_CTL_ENABLE;
        vgic_unlock(v);

        return 1;

    /* R/O -- write ignored */
    case GICD_TYPER:
    case GICD_IIDR:
        goto write_ignore_32;

    /* Implementation defined -- write ignored */
    case 0x020 ... 0x03c:
        goto write_ignore;

    case GICD_IGROUPR ... GICD_IGROUPRN:
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case GICD_ISENABLER ... GICD_ISENABLERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISENABLER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        rank->ienable |= *r;
        /* The virtual irq is derived from register offset.
         * The register difference is word difference. So divide by 2(DABT_WORD)
         * to get Virtual irq number */
        vgic_enable_irqs(v, (*r) & (~tr),
                         (gicd_reg - GICD_ISENABLER) >> DABT_WORD);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        rank->ienable &= ~*r;
        /* The virtual irq is derived from register offset.
         * The register difference is word difference. So divide by 2(DABT_WORD)
         * to get  Virtual irq number */
        vgic_disable_irqs(v, (*r) & tr,
                         (gicd_reg - GICD_ICENABLER) >> DABT_WORD);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ISPENDR%d\n",
               v, *r, gicd_reg - GICD_ISPENDR);
        return 0;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ICPENDR%d\n",
               v, *r, gicd_reg - GICD_ICPENDR);
        return 0;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISACTIVER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        rank->iactive &= ~*r;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICACTIVER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        rank->iactive &= ~*r;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ITARGETSR ... GICD_ITARGETSR + 7:
        /* SGI/PPI target is read only */
        goto write_ignore_32;

    case GICD_ITARGETSR + 8 ... GICD_ITARGETSRN:
    {
        /* unsigned long needed for find_next_bit */
        unsigned long target;
        int i;
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_ITARGETSR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        /* 8-bit vcpu mask for this domain */
        BUG_ON(v->domain->max_vcpus > 8);
        target = (1 << v->domain->max_vcpus) - 1;
        if ( dabt.size == 2 )
            target = target | (target << 8) | (target << 16) | (target << 24);
        else
            target = (target << (8 * (gicd_reg & 0x3)));
        target &= *r;
        /* ignore zero writes */
        if ( !target )
            goto write_ignore;
        /* For word reads ignore writes where any single byte is zero */
        if ( dabt.size == 2 &&
            !((target & 0xff) && (target & (0xff << 8)) &&
             (target & (0xff << 16)) && (target & (0xff << 24))))
            goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        i = 0;
        while ( (i = find_next_bit(&target, 32, i)) < 32 )
        {
            unsigned int irq, new_target, old_target;
            unsigned long old_target_mask;
            struct vcpu *v_target, *v_old;

            new_target = i % 8;
            old_target_mask = vgic_byte_read(rank->v2.itargets[REG_RANK_INDEX(8,
                                             gicd_reg - GICD_ITARGETSR, DABT_WORD)], 0, i/8);
            old_target = find_first_bit(&old_target_mask, 8);

            if ( new_target != old_target )
            {
                irq = gicd_reg - GICD_ITARGETSR + (i / 8);
                v_target = v->domain->vcpu[new_target];
                v_old = v->domain->vcpu[old_target];
                vgic_migrate_irq(v_old, v_target, irq);
            }
            i += 8 - new_target;
        }
        if ( dabt.size == DABT_WORD )
            rank->v2.itargets[REG_RANK_INDEX(8, gicd_reg - GICD_ITARGETSR,
                                             DABT_WORD)] = target;
        else
            vgic_byte_write(&rank->v2.itargets[REG_RANK_INDEX(8,
                      gicd_reg - GICD_ITARGETSR, DABT_WORD)], target, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;
    }

    case GICD_IPRIORITYR ... GICD_IPRIORITYRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        if ( dabt.size == DABT_WORD )
            rank->ipriority[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR,
                                           DABT_WORD)] = *r;
        else
            vgic_byte_write(&rank->ipriority[REG_RANK_INDEX(8,
                        gicd_reg - GICD_IPRIORITYR, DABT_WORD)], *r, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICFGR: /* SGIs */
        goto write_ignore_32;
    case GICD_ICFGR + 1: /* PPIs */
        /* It is implementation defined if these are writeable. We chose not */
        goto write_ignore_32;
    case GICD_ICFGR + 2 ... GICD_ICFGRN: /* SPIs */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 2, gicd_reg - GICD_ICFGR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR, DABT_WORD)] = *r;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_NSACR ... GICD_NSACRN:
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case GICD_SGIR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        return vgic_v2_to_sgi(v, *r);

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ICPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", *r, gicd_reg - GICD_CPENDSGIR);
        return 0;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ISPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", *r, gicd_reg - GICD_SPENDSGIR);
        return 0;

    /* Implementation defined -- write ignored */
    case 0xfd0 ... 0xfe4:
        goto write_ignore;

    /* R/O -- write ignore */
    case GICD_ICPIDR2:
        goto write_ignore_32;

    /* Implementation defined -- write ignored */
    case 0xfec ... 0xffc:
        goto write_ignore;

    /* Reserved -- write ignored */
    case 0x00c ... 0x01c:
    case 0x040 ... 0x07c:
    case 0x7fc:
    case 0xbfc:
    case 0xf04 ... 0xf0c:
    case 0xf30 ... 0xfcc:
        goto write_ignore;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled write r%d=%"PRIregister" offset %#08x\n",
               v, dabt.reg, *r, gicd_reg);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR
           "%pv: vGICD: bad write width %d r%d=%"PRIregister" offset %#08x\n",
           v, dabt.size, dabt.reg, *r, gicd_reg);
    domain_crash_synchronous();
    return 0;

write_ignore_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
write_ignore:
    return 1;
}

static const struct mmio_handler_ops vgic_v2_distr_mmio_handler = {
    .read_handler  = vgic_v2_distr_mmio_read,
    .write_handler = vgic_v2_distr_mmio_write,
};

static struct vcpu *vgic_v2_get_target_vcpu(struct vcpu *v, unsigned int irq)
{
    unsigned long target;
    struct vcpu *v_target;
    struct vgic_irq_rank *rank = vgic_rank_irq(v, irq);
    ASSERT(spin_is_locked(&rank->lock));

    target = vgic_byte_read(rank->v2.itargets[REG_RANK_INDEX(8,
                                              irq, DABT_WORD)], 0, irq & 0x3);

    /* 1-N SPI should be delivered as pending to all the vcpus in the
     * mask, but here we just return the first vcpu for simplicity and
     * because it would be too slow to do otherwise. */
    target = find_first_bit(&target, 8);
    ASSERT(target >= 0 && target < v->domain->max_vcpus);
    v_target = v->domain->vcpu[target];
    return v_target;
}

static int vgic_v2_get_irq_priority(struct vcpu *v, unsigned int irq)
{
    int priority;
    struct vgic_irq_rank *rank = vgic_rank_irq(v, irq);

    ASSERT(spin_is_locked(&rank->lock));
    priority = vgic_byte_read(rank->ipriority[REG_RANK_INDEX(8,
                                              irq, DABT_WORD)], 0, irq & 0x3);

    return priority;
}

static int vgic_v2_vcpu_init(struct vcpu *v)
{
    int i;

    /* For SGI and PPI the target is always this CPU */
    for ( i = 0 ; i < 8 ; i++ )
        v->arch.vgic.private_irqs->v2.itargets[i] =
              (1<<(v->vcpu_id+0))
            | (1<<(v->vcpu_id+8))
            | (1<<(v->vcpu_id+16))
            | (1<<(v->vcpu_id+24));

    return 0;
}

static int vgic_v2_domain_init(struct domain *d)
{
    int i;

    /* By default deliver to CPU0 */
    for ( i = 0; i < DOMAIN_NR_RANKS(d); i++ )
        memset(d->arch.vgic.shared_irqs[i].v2.itargets, 0x1,
               sizeof(d->arch.vgic.shared_irqs[i].v2.itargets));

    /* We rely on gicv_setup() to initialize dbase(vGIC distributor base) */
    register_mmio_handler(d, &vgic_v2_distr_mmio_handler, d->arch.vgic.dbase,
                          PAGE_SIZE);

    return 0;
}

static const struct vgic_ops vgic_v2_ops = {
    .vcpu_init   = vgic_v2_vcpu_init,
    .domain_init = vgic_v2_domain_init,
    .get_irq_priority = vgic_v2_get_irq_priority,
    .get_target_vcpu = vgic_v2_get_target_vcpu,
};

int vgic_v2_init(struct domain *d)
{
    register_vgic_ops(d, &vgic_v2_ops);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
