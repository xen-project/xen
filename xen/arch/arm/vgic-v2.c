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
 * Store an ITARGETSR register. This function only deals with ITARGETSR8
 * and onwards.
 *
 * Note the offset will be aligned to the appropriate boundary.
 */
static void vgic_store_itargetsr(struct domain *d, struct vgic_irq_rank *rank,
                                 unsigned int offset, uint32_t itargetsr)
{
    unsigned int i;
    unsigned int regidx = REG_RANK_INDEX(8, offset, DABT_WORD);
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
        uint8_t new_mask, old_mask;

        /*
         * Don't need to mask as we rely on new_mask to fit for only one
         * target.
         */
        BUILD_BUG_ON((sizeof (new_mask) * 8) != NR_BITS_PER_TARGET);

        new_mask = itargetsr >> (i * NR_BITS_PER_TARGET);
        old_mask = vgic_byte_read(rank->v2.itargets[regidx], i);

        /*
         * SPIs are using the 1-N model (see 1.4.3 in ARM IHI 0048B).
         * While the interrupt could be set pending to all the vCPUs in
         * target list, it's not guaranteed by the spec.
         * For simplicity, always route the vIRQ to the first interrupt
         * in the target list
         */
        new_target = ffs(new_mask);
        old_target = ffs(old_mask);

        /* The current target should always be valid */
        ASSERT(old_target && (old_target <= d->max_vcpus));

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
        old_target--;

        /* Only migrate the vIRQ if the target vCPU has changed */
        if ( new_target != old_target )
        {
            vgic_migrate_irq(d->vcpu[old_target],
                             d->vcpu[new_target],
                             virq);
        }

        /* Bit corresponding to unimplemented CPU is write-ignore. */
        new_mask &= (1 << d->max_vcpus) - 1;
        vgic_byte_write(&rank->v2.itargets[regidx], new_mask, i);
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
            | DIV_ROUND_UP(v->domain->arch.vgic.nr_spis, 32);
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

    /* Read the pending status of an IRQ via GICD is not supported */
    case GICD_ISPENDR ... GICD_ISPENDRN:
    case GICD_ICPENDR ... GICD_ICPENDRN:
        goto read_as_zero;

    /* Read the active status of an IRQ via GICD is not supported */
    case GICD_ISACTIVER ... GICD_ISACTIVERN:
    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        goto read_as_zero;

    case GICD_ITARGETSR ... GICD_ITARGETSRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_ITARGETSR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = rank->v2.itargets[REG_RANK_INDEX(8, gicd_reg - GICD_ITARGETSR,
                                              DABT_WORD)];
        if ( dabt.size == DABT_BYTE )
            *r = vgic_byte_read(*r, gicd_reg);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_IPRIORITYR ... GICD_IPRIORITYRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL) goto read_as_zero;

        vgic_lock_rank(v, rank, flags);
        *r = rank->ipriorityr[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR,
                                             DABT_WORD)];
        if ( dabt.size == DABT_BYTE )
            *r = vgic_byte_read(*r, gicd_reg);
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

    /* Setting/Clearing the SGI pending bit via GICD is not supported */
    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        goto read_as_zero;

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
    case GICD_CTLR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* Ignore all but the enable bit */
        vgic_lock(v);
        v->domain->arch.vgic.ctlr = r & GICD_CTL_ENABLE;
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
        rank->ienable |= r;
        vgic_enable_irqs(v, r & (~tr), rank->index);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ICENABLER ... GICD_ICENABLERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, gicd_reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        rank->ienable &= ~r;
        vgic_disable_irqs(v, r & tr, rank->index);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_ISPENDR ... GICD_ISPENDRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ISPENDR%d\n",
               v, r, gicd_reg - GICD_ISPENDR);
        return 0;

    case GICD_ICPENDR ... GICD_ICPENDRN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ICPENDR%d\n",
               v, r, gicd_reg - GICD_ICPENDR);
        return 0;

    case GICD_ISACTIVER ... GICD_ISACTIVERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ISACTIVER%d\n",
               v, r, gicd_reg - GICD_ISACTIVER);
        return 0;

    case GICD_ICACTIVER ... GICD_ICACTIVERN:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled word write %#"PRIregister" to ICACTIVER%d\n",
               v, r, gicd_reg - GICD_ICACTIVER);
        return 0;

    case GICD_ITARGETSR ... GICD_ITARGETSR7:
        /* SGI/PPI target is read only */
        goto write_ignore_32;

    case GICD_ITARGETSR8 ... GICD_ITARGETSRN:
    {
        uint32_t itargetsr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_ITARGETSR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        if ( dabt.size == DABT_WORD )
            itargetsr = r;
        else
        {
            itargetsr = rank->v2.itargets[REG_RANK_INDEX(8,
                                    gicd_reg - GICD_ITARGETSR,
                                    DABT_WORD)];
            vgic_byte_write(&itargetsr, r, gicd_reg);
        }
        vgic_store_itargetsr(v->domain, rank, gicd_reg - GICD_ITARGETSR,
                             itargetsr);
        vgic_unlock_rank(v, rank, flags);
        return 1;
    }

    case GICD_IPRIORITYR ... GICD_IPRIORITYRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, gicd_reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        if ( dabt.size == DABT_WORD )
            rank->ipriorityr[REG_RANK_INDEX(8, gicd_reg - GICD_IPRIORITYR,
                                            DABT_WORD)] = r;
        else
            vgic_byte_write(&rank->ipriorityr[REG_RANK_INDEX(8,
                        gicd_reg - GICD_IPRIORITYR, DABT_WORD)], r, gicd_reg);
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
        rank->icfg[REG_RANK_INDEX(2, gicd_reg - GICD_ICFGR, DABT_WORD)] = r;
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case GICD_NSACR ... GICD_NSACRN:
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case GICD_SGIR:
        if ( dabt.size != DABT_WORD ) goto bad_width;
        return vgic_v2_to_sgi(v, r);

    case GICD_CPENDSGIR ... GICD_CPENDSGIRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ICPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", r, gicd_reg - GICD_CPENDSGIR);
        return 0;

    case GICD_SPENDSGIR ... GICD_SPENDSGIRN:
        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICD: unhandled %s write %#"PRIregister" to ISPENDSGIR%d\n",
               v, dabt.size ? "word" : "byte", r, gicd_reg - GICD_SPENDSGIR);
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
}

static const struct mmio_handler_ops vgic_v2_distr_mmio_handler = {
    .read  = vgic_v2_distr_mmio_read,
    .write = vgic_v2_distr_mmio_write,
};

static struct vcpu *vgic_v2_get_target_vcpu(struct vcpu *v, unsigned int irq)
{
    unsigned long target;
    struct vcpu *v_target;
    struct vgic_irq_rank *rank = vgic_rank_irq(v, irq);
    ASSERT(spin_is_locked(&rank->lock));

    target = vgic_byte_read(rank->v2.itargets[REG_RANK_INDEX(8,
                                              irq, DABT_WORD)], irq & 0x3);

    /* 1-N SPI should be delivered as pending to all the vcpus in the
     * mask, but here we just return the first vcpu for simplicity and
     * because it would be too slow to do otherwise. */
    target = find_first_bit(&target, 8);
    ASSERT(target >= 0 && target < v->domain->max_vcpus);
    v_target = v->domain->vcpu[target];
    return v_target;
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
    int i, ret;
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
    ret = map_mmio_regions(d, paddr_to_pfn(cbase), csize / PAGE_SIZE,
                           paddr_to_pfn(vbase));
    if ( ret )
        return ret;

    /* By default deliver to CPU0 */
    for ( i = 0; i < DOMAIN_NR_RANKS(d); i++ )
        memset(d->arch.vgic.shared_irqs[i].v2.itargets, 0x1,
               sizeof(d->arch.vgic.shared_irqs[i].v2.itargets));

    register_mmio_handler(d, &vgic_v2_distr_mmio_handler, d->arch.vgic.dbase,
                          PAGE_SIZE, NULL);

    return 0;
}

static const struct vgic_ops vgic_v2_ops = {
    .vcpu_init   = vgic_v2_vcpu_init,
    .domain_init = vgic_v2_domain_init,
    .get_target_vcpu = vgic_v2_get_target_vcpu,
    .max_vcpus = 8,
};

int vgic_v2_init(struct domain *d)
{
    if ( !vgic_v2_hw.enabled )
    {
        printk(XENLOG_G_ERR
               "d%d: vGICv2 is not supported on this platform.\n",
               d->domain_id);
        return -ENODEV;
    }

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
