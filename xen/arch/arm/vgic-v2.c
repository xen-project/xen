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
#include <xen/sizes.h>

#include <asm/current.h>

#include <asm/mmio.h>
#include <asm/platform.h>
#include <asm/vgic.h>
#include <asm/vgic-emul.h>

static struct {
    bool_t enabled;
    /* Distributor interface address */
    paddr_t dbase;
    /* CPU interface address & size */
    paddr_t cbase;
    paddr_t csize;
    /* Virtual CPU interface address */
    paddr_t vbase;

    /* Offset to add to get an 8kB contiguous region if GIC is aliased */
    uint32_t aliased_offset;
} vgic_v2_hw;

void vgic_v2_setup_hw(paddr_t dbase, paddr_t cbase, paddr_t csize,
                      paddr_t vbase, uint32_t aliased_offset)
{
    vgic_v2_hw.enabled = 1;
    vgic_v2_hw.dbase = dbase;
    vgic_v2_hw.cbase = cbase;
    vgic_v2_hw.csize = csize;
    vgic_v2_hw.vbase = vbase;
    vgic_v2_hw.aliased_offset = aliased_offset;
}

#define NR_TARGETS_PER_ITARGETSR    4U
#define NR_BITS_PER_TARGET  (32U / NR_TARGETS_PER_ITARGETSR)

/*
 * Fetch an ITARGETSR register based on the offset from ITARGETSR0. Only
 * one vCPU will be listed for a given vIRQ.
 *
 * Note the byte offset will be aligned to an ITARGETSR<n> boundary.
 */
static uint32_t vgic_fetch_itargetsr(struct vgic_irq_rank *rank,
                                     unsigned int offset)
{
    uint32_t reg = 0;
    unsigned int i;

    ASSERT(spin_is_locked(&rank->lock));

    offset &= INTERRUPT_RANK_MASK;
    offset &= ~(NR_TARGETS_PER_ITARGETSR - 1);

    for ( i = 0; i < NR_TARGETS_PER_ITARGETSR; i++, offset++ )
        reg |= (1 << read_atomic(&rank->vcpu[offset])) << (i * NR_BITS_PER_TARGET);

    return reg;
}

/*
 * Store an ITARGETSR register in a convenient way and migrate the vIRQ
 * if necessary. This function only deals with ITARGETSR8 and onwards.
 *
 * Note the byte offset will be aligned to an ITARGETSR<n> boundary.
 */
static void vgic_store_itargetsr(struct domain *d, struct vgic_irq_rank *rank,
                                 unsigned int offset, uint32_t itargetsr)
{
    unsigned int i;
    unsigned int virq;

    ASSERT(spin_is_locked(&rank->lock));

    /*
     * The ITARGETSR0-7, used for SGIs/PPIs, are implemented RO in the
     * emulation and should never call this function.
     *
     * They all live in the first rank.
     */
    BUILD_BUG_ON(NR_INTERRUPT_PER_RANK != 32);
    ASSERT(rank->index >= 1);

    offset &= INTERRUPT_RANK_MASK;
    offset &= ~(NR_TARGETS_PER_ITARGETSR - 1);

    virq = rank->index * NR_INTERRUPT_PER_RANK + offset;

    for ( i = 0; i < NR_TARGETS_PER_ITARGETSR; i++, offset++, virq++ )
    {
        unsigned int new_target, old_target;
        uint8_t new_mask;

        /*
         * Don't need to mask as we rely on new_mask to fit for only one
         * target.
         */
        BUILD_BUG_ON((sizeof (new_mask) * 8) != NR_BITS_PER_TARGET);

        new_mask = itargetsr >> (i * NR_BITS_PER_TARGET);

        /*
         * SPIs are using the 1-N model (see 1.4.3 in ARM IHI 0048B).
         * While the interrupt could be set pending to all the vCPUs in
         * target list, it's not guaranteed by the spec.
         * For simplicity, always route the vIRQ to the first interrupt
         * in the target list
         */
        new_target = ffs(new_mask);

        /*
         * Ignore the write request for this interrupt if the new target
         * is invalid.
         * XXX: From the spec, if the target list is not valid, the
         * interrupt should be ignored (i.e not forwarded to the
         * guest).
         */
        if ( !new_target || (new_target > d->max_vcpus) )
        {
            gprintk(XENLOG_WARNING,
                   "No valid vCPU found for vIRQ%u in the target list (%#x). Skip it\n",
                   virq, new_mask);
            continue;
        }

        /* The vCPU ID always starts from 0 */
        new_target--;

        old_target = read_atomic(&rank->vcpu[offset]);

        /* Only migrate the vIRQ if the target vCPU has changed */
        if ( new_target != old_target )
        {
            vgic_migrate_irq(d->vcpu[old_target],
                             d->vcpu[new_target],
                             virq);
        }

        write_atomic(&rank->vcpu[offset], new_target);
    }
}

static int vgic_v2_distr_mmio_read(struct vcpu *v, mmio_info_t *info,
                                   register_t *r, void *priv)
{
    struct hsr_dabt dabt = info->dabt;
    struct vgic_irq_rank *rank;
    int gicd_reg = (int)(info->gpa - v->domain->arch.vgic.dbase);
    unsigned long flags;

    perfc_incr(vgicd_reads);

    switch ( gicd_reg )
    {
    case VREG32(GICD_CTLR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        vgic_lock(v);
        *r = vgic_reg32_extract(v->domain->arch.vgic.ctlr, info);
        vgic_unlock(v);
        return 1;

    case VREG32(GICD_TYPER):
    {
        uint32_t typer;

        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* No secure world support for guests. */
        vgic_lock(v);
        typer = ((v->domain->max_vcpus - 1) << GICD_TYPE_CPUS_SHIFT)
            | DIV_ROUND_UP(v->domain->arch.vgic.nr_spis, 32);
        vgic_unlock(v);

        *r = vgic_reg32_extract(typer, info);

        return 1;
    }

    case VREG32(GICD_IIDR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /*
         * XXX Do we need a JEP106 manufacturer ID?
         * Just use the physical h/w value for now
         */
        *r = vgic_reg32_extract(0x0000043b, info);
        return 1;

    case VRANGE32(0x00C, 0x01C):
        goto read_reserved;

    case VRANGE32(0x020, 0x03C):
        goto read_impl_defined;

    case VRANGE32(0x040, 0x07C):
        goto read_reserved;

    case VRANGE32(GICD_IGROUPR, GICD_IGROUPRN):
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case VRANGE32(GICD_ISENABLER, GICD_ISENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISENABLER, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_reg32_extract(rank->ienable, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(GICD_ICENABLER, GICD_ICENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_reg32_extract(rank->ienable, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    /* Read the pending status of an IRQ via GICD is not supported */
    case VRANGE32(GICD_ISPENDR, GICD_ISPENDRN):
    case VRANGE32(GICD_ICPENDR, GICD_ICPENDRN):
        goto read_as_zero;

    /* Read the active status of an IRQ via GICD is not supported */
    case VRANGE32(GICD_ISACTIVER, GICD_ISACTIVERN):
    case VRANGE32(GICD_ICACTIVER, GICD_ICACTIVERN):
        goto read_as_zero;

    case VRANGE32(GICD_IPRIORITYR, GICD_IPRIORITYRN):
    {
        uint32_t ipriorityr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL ) goto read_as_zero;

        vgic_lock_rank(v, rank, flags);
        ipriorityr = rank->ipriorityr[REG_RANK_INDEX(8,
                                                     gicd_reg - GICD_IPRIORITYR,
                                                     DABT_WORD)];
        vgic_unlock_rank(v, rank, flags);
        *r = vgic_reg32_extract(ipriorityr, info);

        return 1;
    }

    case VREG32(0x7FC):
        goto read_reserved;

    case VRANGE32(GICD_ITARGETSR, GICD_ITARGETSRN):
    {
        uint32_t itargetsr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_ITARGETSR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        itargetsr = vgic_fetch_itargetsr(rank, gicd_reg - GICD_ITARGETSR);
        vgic_unlock_rank(v, rank, flags);
        *r = vgic_reg32_extract(itargetsr, info);

        return 1;
    }

    case VREG32(0xBFC):
        goto read_reserved;

    case VRANGE32(GICD_ICFGR, GICD_ICFGRN):
    {
        uint32_t icfgr;

        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 2, gicd_reg - GICD_ICFGR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        icfgr = rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR, DABT_WORD)];
        vgic_unlock_rank(v, rank, flags);

        *r = vgic_reg32_extract(icfgr, info);

        return 1;
    }

    case VRANGE32(0xD00, 0xDFC):
        goto read_impl_defined;

    case VRANGE32(GICD_NSACR, GICD_NSACRN):
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case VREG32(GICD_SGIR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* Write only -- read unknown */
        *r = 0xdeadbeef;
        return 1;

    case VRANGE32(0xF04, 0xF0C):
        goto read_reserved;

    /* Setting/Clearing the SGI pending bit via GICD is not supported */
    case VRANGE32(GICD_CPENDSGIR, GICD_CPENDSGIRN):
    case VRANGE32(GICD_SPENDSGIR, GICD_SPENDSGIRN):
        goto read_as_zero;

    case VRANGE32(0xF30, 0xFCC):
        goto read_reserved;

    case VRANGE32(0xFD0, 0xFE4):
        goto read_impl_defined;

    case VREG32(GICD_ICPIDR2):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR "%pv: vGICD: unhandled read from ICPIDR2\n", v);
        return 0;

    case VRANGE32(0xFEC, 0xFFC):
        goto read_impl_defined;

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

read_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: RAZ on implemention defined register offset %#08x\n",
           v, gicd_reg);
    *r = 0;
    return 1;

read_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: RAZ on reserved register offset %#08x\n",
           v, gicd_reg);
    *r = 0;
    return 1;
}

static int vgic_v2_to_sgi(struct vcpu *v, register_t sgir)
{

    int virq;
    int irqmode;
    enum gic_sgi_mode sgi_mode;
    struct sgi_target target;

    irqmode = (sgir & GICD_SGI_TARGET_LIST_MASK) >> GICD_SGI_TARGET_LIST_SHIFT;
    virq = (sgir & GICD_SGI_INTID_MASK);

    /* Map GIC sgi value to enum value */
    switch ( irqmode )
    {
    case GICD_SGI_TARGET_LIST_VAL:
        sgi_target_init(&target);
        target.list = (sgir & GICD_SGI_TARGET_MASK) >> GICD_SGI_TARGET_SHIFT;
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

    return vgic_to_sgi(v, sgir, sgi_mode, virq, &target);
}

static int vgic_v2_distr_mmio_write(struct vcpu *v, mmio_info_t *info,
                                    register_t r, void *priv)
{
    struct hsr_dabt dabt = info->dabt;
    struct vgic_irq_rank *rank;
    int gicd_reg = (int)(info->gpa - v->domain->arch.vgic.dbase);
    uint32_t tr;
    unsigned long flags;

    perfc_incr(vgicd_writes);

    switch ( gicd_reg )
    {
    case VREG32(GICD_CTLR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* Ignore all but the enable bit */
        vgic_lock(v);
        vgic_reg32_update(&v->domain->arch.vgic.ctlr, r, info);
        v->domain->arch.vgic.ctlr &= GICD_CTL_ENABLE;
        vgic_unlock(v);

        return 1;

    /* R/O -- write ignored */
    case VREG32(GICD_TYPER):
    case VREG32(GICD_IIDR):
        goto write_ignore_32;

    case VRANGE32(0x00C, 0x01C):
        goto write_reserved;

    case VRANGE32(0x020, 0x03C):
        goto write_impl_defined;

    case VRANGE32(0x040, 0x07C):
        goto write_reserved;

    case VRANGE32(GICD_IGROUPR, GICD_IGROUPRN):
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case VRANGE32(GICD_ISENABLER, GICD_ISENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ISENABLER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        vgic_reg32_setbits(&rank->ienable, r, info);
        vgic_enable_irqs(v, (rank->ienable) & (~tr), rank->index);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(GICD_ICENABLER, GICD_ICENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        vgic_reg32_clearbits(&rank->ienable, r, info);
        vgic_disable_irqs(v, (~rank->ienable) & tr, rank->index);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(GICD_ISPENDR, GICD_ISPENDRN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ISPENDR%d\n",
               v, r, gicd_reg - GICD_ISPENDR);
        return 0;

    case VRANGE32(GICD_ICPENDR, GICD_ICPENDRN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ICPENDR%d\n",
               v, r, gicd_reg - GICD_ICPENDR);
        return 0;

    case VRANGE32(GICD_ISACTIVER, GICD_ISACTIVERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ISACTIVER%d\n",
               v, r, gicd_reg - GICD_ISACTIVER);
        return 0;

    case VRANGE32(GICD_ICACTIVER, GICD_ICACTIVERN):
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ICACTIVER%d\n",
               v, r, gicd_reg - GICD_ICACTIVER);
        goto write_ignore_32;

    case VRANGE32(GICD_IPRIORITYR, GICD_IPRIORITYRN):
    {
        uint32_t *ipriorityr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        ipriorityr = &rank->ipriorityr[REG_RANK_INDEX(8,
                                                      gicd_reg - GICD_IPRIORITYR,
                                                      DABT_WORD)];
        vgic_reg32_update(ipriorityr, r, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;
    }

    case VREG32(0x7FC):
        goto write_reserved;

    case VRANGE32(GICD_ITARGETSR, GICD_ITARGETSR7):
        /* SGI/PPI target is read only */
        goto write_ignore_32;

    case VRANGE32(GICD_ITARGETSR8, GICD_ITARGETSRN):
    {
        uint32_t itargetsr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_ITARGETSR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        itargetsr = vgic_fetch_itargetsr(rank, gicd_reg - GICD_ITARGETSR);
        vgic_reg32_update(&itargetsr, r, info);
        vgic_store_itargetsr(v->domain, rank, gicd_reg - GICD_ITARGETSR,
                             itargetsr);
        vgic_unlock_rank(v, rank, flags);
        return 1;
    }

    case VREG32(0xBFC):
        goto write_reserved;

    case VREG32(GICD_ICFGR): /* SGIs */
        goto write_ignore_32;

    case VREG32(GICD_ICFGR1):
        /* It is implementation defined if these are writeable. We chose not */
        goto write_ignore_32;

    case VRANGE32(GICD_ICFGR2, GICD_ICFGRN): /* SPIs */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 2, gicd_reg - GICD_ICFGR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        vgic_reg32_update(&rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR,
                                                     DABT_WORD)],
                          r, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(0xD00, 0xDFC):
        goto write_impl_defined;

    case VRANGE32(GICD_NSACR, GICD_NSACRN):
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case VREG32(GICD_SGIR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        return vgic_v2_to_sgi(v, r);

    case VRANGE32(0xF04, 0xF0C):
        goto write_reserved;

    case VRANGE32(GICD_CPENDSGIR, GICD_CPENDSGIRN):
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ICPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", r, gicd_reg - GICD_CPENDSGIR);
        return 0;

    case VRANGE32(GICD_SPENDSGIR, GICD_SPENDSGIRN):
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ISPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", r, gicd_reg - GICD_SPENDSGIR);
        return 0;

    case VRANGE32(0xF30, 0xFCC):
        goto write_reserved;

    case VRANGE32(0xFD0, 0xFE4):
        /* Implementation defined identification registers */
        goto write_impl_defined;

    /* R/O -- write ignore */
    case VREG32(GICD_ICPIDR2):
        goto write_ignore_32;

    case VRANGE32(0xFEC, 0xFFC):
        /* Implementation defined identification registers */

    default:
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled write r%d=%"PRIregister" offset %#08x\n",
               v, dabt.reg, r, gicd_reg);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR
           "%pv: vGICD: bad write width %d r%d=%"PRIregister" offset %#08x\n",
           v, dabt.size, dabt.reg, r, gicd_reg);
    domain_crash_synchronous();
    return 0;

write_ignore_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
write_ignore:
    return 1;

write_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: WI on implementation defined register offset %#08x\n",
           v, gicd_reg);
    return 1;

write_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: WI on implementation defined register offset %#08x\n",
           v, gicd_reg);
    return 1;
}

static const struct mmio_handler_ops vgic_v2_distr_mmio_handler = {
    .read  = vgic_v2_distr_mmio_read,
    .write = vgic_v2_distr_mmio_write,
};

static int vgic_v2_vcpu_init(struct vcpu *v)
{
    /* Nothing specific to initialize for this driver */

    return 0;
}

static int vgic_v2_domain_init(struct domain *d)
{
    int ret;
    paddr_t cbase, csize;
    paddr_t vbase;

    /*
     * The hardware domain gets the hardware address.
     * Guests get the virtual platform layout.
     */
    if ( is_hardware_domain(d) )
    {
        d->arch.vgic.dbase = vgic_v2_hw.dbase;
        /*
         * For the hardware domain, we always map the whole HW CPU
         * interface region in order to match the device tree (the "reg"
         * properties is copied as it is).
         * Note that we assume the size of the CPU interface is always
         * aligned to PAGE_SIZE.
         */
        cbase = vgic_v2_hw.cbase;
        csize = vgic_v2_hw.csize;
        vbase = vgic_v2_hw.vbase;
    }
    else
    {
        d->arch.vgic.dbase = GUEST_GICD_BASE;
        /*
         * The CPU interface exposed to the guest is always 8kB. We may
         * need to add an offset to the virtual CPU interface base
         * address when in the GIC is aliased to get a 8kB contiguous
         * region.
         */
        BUILD_BUG_ON(GUEST_GICC_SIZE != SZ_8K);
        cbase = GUEST_GICC_BASE;
        csize = GUEST_GICC_SIZE;
        vbase = vgic_v2_hw.vbase + vgic_v2_hw.aliased_offset;
    }

    /*
     * Map the gic virtual cpu interface in the gic cpu interface
     * region of the guest.
     */
    ret = map_mmio_regions(d, _gfn(paddr_to_pfn(cbase)), csize / PAGE_SIZE,
                           _mfn(paddr_to_pfn(vbase)));
    if ( ret )
        return ret;

    register_mmio_handler(d, &vgic_v2_distr_mmio_handler, d->arch.vgic.dbase,
                          PAGE_SIZE, NULL);

    return 0;
}

static void vgic_v2_domain_free(struct domain *d)
{
    /* Nothing to be cleanup for this driver */
}

static const struct vgic_ops vgic_v2_ops = {
    .vcpu_init   = vgic_v2_vcpu_init,
    .domain_init = vgic_v2_domain_init,
    .domain_free = vgic_v2_domain_free,
    .max_vcpus = 8,
};

int vgic_v2_init(struct domain *d, int *mmio_count)
{
    if ( !vgic_v2_hw.enabled )
    {
        printk(XENLOG_G_ERR
               "d%d: vGICv2 is not supported on this platform.\n",
               d->domain_id);
        return -ENODEV;
    }

    *mmio_count = 1; /* Only GICD region */
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
