/*
 * xen/arch/arm/vgic-v3.c
 *
 * ARM Virtual Generic Interrupt Controller v3 support
 * based on xen/arch/arm/vgic.c
 *
 * Vijaya Kumar K <vijaya.kumar@caviumnetworks.com>
 * Copyright (c) 2014 Cavium Inc.
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
#include <asm/gic_v3_defs.h>
#include <asm/vgic.h>
#include <asm/vgic-emul.h>

/*
 * PIDR2: Only bits[7:4] are not implementation defined. We are
 * emulating a GICv3 ([7:4] = 0x3).
 *
 * We don't emulate a specific registers scheme so implement the others
 * bits as RES0 as recommended by the spec (see 8.1.13 in ARM IHI 0069A).
 */
#define GICV3_GICD_PIDR2  0x30
#define GICV3_GICR_PIDR2  GICV3_GICD_PIDR2

/*
 * GICD_CTLR default value:
 *      - No GICv2 compatibility => ARE = 1
 */
#define VGICD_CTLR_DEFAULT  (GICD_CTLR_ARE_NS)

static struct {
    bool_t enabled;
    /* Distributor interface address */
    paddr_t dbase;
    /* Re-distributor regions */
    unsigned int nr_rdist_regions;
    const struct rdist_region *regions;
    uint32_t rdist_stride; /* Re-distributor stride */
} vgic_v3_hw;

void vgic_v3_setup_hw(paddr_t dbase,
                      unsigned int nr_rdist_regions,
                      const struct rdist_region *regions,
                      uint32_t rdist_stride)
{
    vgic_v3_hw.enabled = 1;
    vgic_v3_hw.dbase = dbase;
    vgic_v3_hw.nr_rdist_regions = nr_rdist_regions;
    vgic_v3_hw.regions = regions;
    vgic_v3_hw.rdist_stride = rdist_stride;
}

static struct vcpu *vgic_v3_irouter_to_vcpu(struct domain *d, uint64_t irouter)
{
    unsigned int vcpu_id;

    /*
     * When the Interrupt Route Mode is set, the IRQ targets any vCPUs.
     * For simplicity, the IRQ is always routed to vCPU0.
     */
    if ( irouter & GICD_IROUTER_SPI_MODE_ANY )
        return d->vcpu[0];

    vcpu_id = vaffinity_to_vcpuid(irouter);
    if ( vcpu_id >= d->max_vcpus )
        return NULL;

    return d->vcpu[vcpu_id];
}

#define NR_BYTES_PER_IROUTER 8U

/*
 * Fetch an IROUTER register based on the offset from IROUTER0. Only one
 * vCPU will be listed for a given vIRQ.
 *
 * Note the byte offset will be aligned to an IROUTER<n> boundary.
 */
static uint64_t vgic_fetch_irouter(struct vgic_irq_rank *rank,
                                   unsigned int offset)
{
    ASSERT(spin_is_locked(&rank->lock));

    /* There is exactly 1 vIRQ per IROUTER */
    offset /= NR_BYTES_PER_IROUTER;

    /* Get the index in the rank */
    offset &= INTERRUPT_RANK_MASK;

    return vcpuid_to_vaffinity(read_atomic(&rank->vcpu[offset]));
}

/*
 * Store an IROUTER register in a convenient way and migrate the vIRQ
 * if necessary. This function only deals with IROUTER32 and onwards.
 *
 * Note the offset will be aligned to the appropriate boundary.
 */
static void vgic_store_irouter(struct domain *d, struct vgic_irq_rank *rank,
                               unsigned int offset, uint64_t irouter)
{
    struct vcpu *new_vcpu, *old_vcpu;
    unsigned int virq;

    /* There is 1 vIRQ per IROUTER */
    virq = offset / NR_BYTES_PER_IROUTER;

    /*
     * The IROUTER0-31, used for SGIs/PPIs, are reserved and should
     * never call this function.
     */
    ASSERT(virq >= 32);

    /* Get the index in the rank */
    offset &= virq & INTERRUPT_RANK_MASK;

    new_vcpu = vgic_v3_irouter_to_vcpu(d, irouter);
    old_vcpu = d->vcpu[read_atomic(&rank->vcpu[offset])];

    /*
     * From the spec (see 8.9.13 in IHI 0069A), any write with an
     * invalid vCPU will lead to the interrupt being ignored.
     *
     * But the current code to inject an IRQ is not able to cope with
     * invalid vCPU. So for now, just ignore the write.
     *
     * TODO: Respect the spec
     */
    if ( !new_vcpu )
        return;

    /* Only migrate the IRQ if the target vCPU has changed */
    if ( new_vcpu != old_vcpu )
    {
        if ( vgic_migrate_irq(old_vcpu, new_vcpu, virq) )
            write_atomic(&rank->vcpu[offset], new_vcpu->vcpu_id);
    }
}

static inline bool vgic_reg64_check_access(struct hsr_dabt dabt)
{
    /*
     * 64 bits registers can be accessible using 32-bit and 64-bit unless
     * stated otherwise (See 8.1.3 ARM IHI 0069A).
     */
    return ( dabt.size == DABT_DOUBLE_WORD || dabt.size == DABT_WORD );
}

static int __vgic_v3_rdistr_rd_mmio_read(struct vcpu *v, mmio_info_t *info,
                                         uint32_t gicr_reg,
                                         register_t *r)
{
    struct hsr_dabt dabt = info->dabt;

    switch ( gicr_reg )
    {
    case VREG32(GICR_CTLR):
        /* We have not implemented LPI's, read zero */
        goto read_as_zero_32;

    case VREG32(GICR_IIDR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GICV3_GICR_IIDR_VAL, info);
        return 1;

    case VREG64(GICR_TYPER):
    {
        uint64_t typer, aff;

        if ( !vgic_reg64_check_access(dabt) ) goto bad_width;
        /* TBD: Update processor id in [23:8] when ITS support is added */
        aff = (MPIDR_AFFINITY_LEVEL(v->arch.vmpidr, 3) << 56 |
               MPIDR_AFFINITY_LEVEL(v->arch.vmpidr, 2) << 48 |
               MPIDR_AFFINITY_LEVEL(v->arch.vmpidr, 1) << 40 |
               MPIDR_AFFINITY_LEVEL(v->arch.vmpidr, 0) << 32);
        typer = aff;

        if ( v->arch.vgic.flags & VGIC_V3_RDIST_LAST )
            typer |= GICR_TYPER_LAST;

        *r = vgic_reg64_extract(typer, info);

        return 1;
    }

    case VREG32(GICR_STATUSR):
        /* Not implemented */
        goto read_as_zero_32;

    case VREG32(GICR_WAKER):
        /* Power management is not implemented */
        goto read_as_zero_32;

    case 0x0018:
        goto read_reserved;

    case 0x0020:
        goto read_impl_defined;

    case VREG64(GICR_SETLPIR):
        /* WO. Read unknown */
        goto read_unknown;

    case VREG64(GICR_CLRLPIR):
        /* WO. Read unknown */
        goto read_unknown;

    case 0x0050:
        goto read_reserved;

    case VREG64(GICR_PROPBASER):
        /* LPI's not implemented */
        goto read_as_zero_64;

    case VREG64(GICR_PENDBASER):
        /* LPI's not implemented */
        goto read_as_zero_64;

    case 0x0080:
        goto read_reserved;

    case VREG64(GICR_INVLPIR):
        /* WO. Read unknown */
        goto read_unknown;

    case 0x00A8:
        goto read_reserved;

    case VREG64(GICR_INVALLR):
        /* WO. Read unknown */
        goto read_unknown;

    case 0x00B8:
        goto read_reserved;

    case VREG32(GICR_SYNCR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* RO . But when read it always returns busy bito bit[0] */
        *r = vgic_reg32_extract(GICR_SYNCR_NOT_BUSY, info);
        return 1;

    case 0x00C8:
        goto read_reserved;

    case VREG64(0x0100):
        goto read_impl_defined;

    case 0x0108:
        goto read_reserved;

    case VREG64(0x0110):
        goto read_impl_defined;

    case 0x0118 ... 0xBFFC:
        goto read_reserved;

    case 0xC000 ... 0xFFCC:
        goto read_impl_defined;

    case 0xFFD0 ... 0xFFE4:
        /* Implementation defined identification registers */
       goto read_impl_defined;

    case VREG32(GICR_PIDR2):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GICV3_GICR_PIDR2, info);
         return 1;

    case 0xFFEC ... 0xFFFC:
         /* Implementation defined identification registers */
         goto read_impl_defined;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGICR: unhandled read r%d offset %#08x\n",
               v, dabt.reg, gicr_reg);
        return 0;
    }
bad_width:
    printk(XENLOG_G_ERR "%pv vGICR: bad read width %d r%d offset %#08x\n",
           v, dabt.size, dabt.reg, gicr_reg);
    domain_crash_synchronous();
    return 0;

read_as_zero_64:
    if ( !vgic_reg64_check_access(dabt) ) goto bad_width;
    *r = 0;
    return 1;

read_as_zero_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
    *r = 0;
    return 1;

read_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICR: RAZ on implementation defined register offset %#08x\n",
           v, gicr_reg);
    *r = 0;
    return 1;

read_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGICR: RAZ on reserved register offset %#08x\n",
           v, gicr_reg);
    *r = 0;
    return 1;

read_unknown:
    *r = vgic_reg64_extract(0xdeadbeafdeadbeaf, info);
    return 1;
}

static int __vgic_v3_rdistr_rd_mmio_write(struct vcpu *v, mmio_info_t *info,
                                          uint32_t gicr_reg,
                                          register_t r)
{
    struct hsr_dabt dabt = info->dabt;

    switch ( gicr_reg )
    {
    case VREG32(GICR_CTLR):
        /* LPI's not implemented */
        goto write_ignore_32;

    case VREG32(GICR_IIDR):
        /* RO */
        goto write_ignore_32;

    case VREG64(GICR_TYPER):
        /* RO */
        goto write_ignore_64;

    case VREG32(GICR_STATUSR):
        /* Not implemented */
        goto write_ignore_32;

    case VREG32(GICR_WAKER):
        /* Power mgmt not implemented */
        goto write_ignore_32;

    case 0x0018:
        goto write_reserved;

    case 0x0020:
        goto write_impl_defined;

    case VREG64(GICR_SETLPIR):
        /* LPI is not implemented */
        goto write_ignore_64;

    case VREG64(GICR_CLRLPIR):
        /* LPI is not implemented */
        goto write_ignore_64;

    case 0x0050:
        goto write_reserved;

    case VREG64(GICR_PROPBASER):
        /* LPI is not implemented */
        goto write_ignore_64;

    case VREG64(GICR_PENDBASER):
        /* LPI is not implemented */
        goto write_ignore_64;

    case 0x0080:
        goto write_reserved;

    case VREG64(GICR_INVLPIR):
        /* LPI is not implemented */
        goto write_ignore_64;

    case 0x00A8:
        goto write_reserved;

    case VREG64(GICR_INVALLR):
        /* LPI is not implemented */
        goto write_ignore_64;

    case 0x00B8:
        goto write_reserved;

    case VREG32(GICR_SYNCR):
        /* RO */
        goto write_ignore_32;

    case 0x00C8:
        goto write_reserved;

    case VREG64(0x0100):
        goto write_impl_defined;

    case 0x0108:
        goto write_reserved;

    case VREG64(0x0110):
        goto write_impl_defined;

    case 0x0118 ... 0xBFFC:
        goto write_reserved;

    case 0xC000 ... 0xFFCC:
        goto write_impl_defined;

    case 0xFFD0 ... 0xFFE4:
        /* Implementation defined identification registers */
       goto write_impl_defined;

    case VREG32(GICR_PIDR2):
        /* RO */
        goto write_ignore_32;

    case 0xFFEC ... 0xFFFC:
         /* Implementation defined identification registers */
         goto write_impl_defined;

    default:
        printk(XENLOG_G_ERR "%pv: vGICR: unhandled write r%d offset %#08x\n",
               v, dabt.reg, gicr_reg);
        return 0;
    }
bad_width:
    printk(XENLOG_G_ERR
          "%pv: vGICR: bad write width %d r%d=%"PRIregister" offset %#08x\n",
          v, dabt.size, dabt.reg, r, gicr_reg);
    domain_crash_synchronous();
    return 0;

write_ignore_64:
    if ( vgic_reg64_check_access(dabt) ) goto bad_width;
    return 1;

write_ignore_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
    return 1;

write_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICR: WI on implementation defined register offset %#08x\n",
           v, gicr_reg);
    return 1;

write_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGICR: WI on reserved register offset %#08x\n",
           v, gicr_reg);
    return 1;
}

static int __vgic_v3_distr_common_mmio_read(const char *name, struct vcpu *v,
                                            mmio_info_t *info, uint32_t reg,
                                            register_t *r)
{
    struct hsr_dabt dabt = info->dabt;
    struct vgic_irq_rank *rank;
    unsigned long flags;

    switch ( reg )
    {
    case VRANGE32(GICD_IGROUPR, GICD_IGROUPRN):
        /* We do not implement security extensions for guests, read zero */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        goto read_as_zero;

    case VRANGE32(GICD_ISENABLER, GICD_ISENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, reg - GICD_ISENABLER, DABT_WORD);
        if ( rank == NULL ) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_reg32_extract(rank->ienable, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(GICD_ICENABLER, GICD_ICENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL ) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        *r = vgic_reg32_extract(rank->ienable, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    /* Read the pending status of an IRQ via GICD/GICR is not supported */
    case VRANGE32(GICD_ISPENDR, GICD_ISPENDRN):
    case VRANGE32(GICD_ICPENDR, GICD_ICPENDR):
        goto read_as_zero;

    /* Read the active status of an IRQ via GICD/GICR is not supported */
    case VRANGE32(GICD_ISACTIVER, GICD_ISACTIVER):
    case VRANGE32(GICD_ICACTIVER, GICD_ICACTIVERN):
        goto read_as_zero;

    case VRANGE32(GICD_IPRIORITYR, GICD_IPRIORITYRN):
    {
        uint32_t ipriorityr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL ) goto read_as_zero;

        vgic_lock_rank(v, rank, flags);
        ipriorityr = rank->ipriorityr[REG_RANK_INDEX(8, reg - GICD_IPRIORITYR,
                                                     DABT_WORD)];
        vgic_unlock_rank(v, rank, flags);

        *r = vgic_reg32_extract(ipriorityr, info);

        return 1;
    }

    case VRANGE32(GICD_ICFGR, GICD_ICFGRN):
    {
        uint32_t icfgr;

        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 2, reg - GICD_ICFGR, DABT_WORD);
        if ( rank == NULL ) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        icfgr = rank->icfg[REG_RANK_INDEX(2, reg - GICD_ICFGR, DABT_WORD)];
        vgic_unlock_rank(v, rank, flags);

        *r = vgic_reg32_extract(icfgr, info);

        return 1;
    }

    default:
        printk(XENLOG_G_ERR
               "%pv: %s: unhandled read r%d offset %#08x\n",
               v, name, dabt.reg, reg);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR "%pv: %s: bad read width %d r%d offset %#08x\n",
           v, name, dabt.size, dabt.reg, reg);
    domain_crash_synchronous();
    return 0;

read_as_zero:
    *r = 0;
    return 1;
}

static int __vgic_v3_distr_common_mmio_write(const char *name, struct vcpu *v,
                                             mmio_info_t *info, uint32_t reg,
                                             register_t r)
{
    struct hsr_dabt dabt = info->dabt;
    struct vgic_irq_rank *rank;
    uint32_t tr;
    unsigned long flags;

    switch ( reg )
    {
    case VRANGE32(GICD_IGROUPR, GICD_IGROUPRN):
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case VRANGE32(GICD_ISENABLER, GICD_ISENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, reg - GICD_ISENABLER, DABT_WORD);
        if ( rank == NULL ) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        vgic_reg32_setbits(&rank->ienable, r, info);
        vgic_enable_irqs(v, (rank->ienable) & (~tr), rank->index);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(GICD_ICENABLER, GICD_ICENABLERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 1, reg - GICD_ICENABLER, DABT_WORD);
        if ( rank == NULL ) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        tr = rank->ienable;
        vgic_reg32_clearbits(&rank->ienable, r, info);
        vgic_disable_irqs(v, (~rank->ienable) & tr, rank->index);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    case VRANGE32(GICD_ISPENDR, GICD_ISPENDRN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: %s: unhandled word write %#"PRIregister" to ISPENDR%d\n",
               v, name, r, reg - GICD_ISPENDR);
        return 0;

    case VRANGE32(GICD_ICPENDR, GICD_ICPENDRN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: %s: unhandled word write %#"PRIregister" to ICPENDR%d\n",
               v, name, r, reg - GICD_ICPENDR);
        return 0;

    case VRANGE32(GICD_ISACTIVER, GICD_ISACTIVERN):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: %s: unhandled word write %#"PRIregister" to ISACTIVER%d\n",
               v, name, r, reg - GICD_ISACTIVER);
        return 0;

    case VRANGE32(GICD_ICACTIVER, GICD_ICACTIVERN):
        printk(XENLOG_G_ERR
               "%pv: %s: unhandled word write %#"PRIregister" to ICACTIVER%d\n",
               v, name, r, reg - GICD_ICACTIVER);
        goto write_ignore_32;

    case VRANGE32(GICD_IPRIORITYR, GICD_IPRIORITYRN):
    {
        uint32_t *ipriorityr;

        if ( dabt.size != DABT_BYTE && dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 8, reg - GICD_IPRIORITYR, DABT_WORD);
        if ( rank == NULL ) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        ipriorityr = &rank->ipriorityr[REG_RANK_INDEX(8, reg - GICD_IPRIORITYR,
                                                      DABT_WORD)];
        vgic_reg32_update(ipriorityr, r, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;
    }

    case VREG32(GICD_ICFGR): /* Restricted to configure SGIs */
        goto write_ignore_32;

    case VRANGE32(GICD_ICFGR + 4, GICD_ICFGRN): /* PPI + SPIs */
        /* ICFGR1 for PPI's, which is implementation defined
           if ICFGR1 is programmable or not. We chose to program */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        rank = vgic_rank_offset(v, 2, reg - GICD_ICFGR, DABT_WORD);
        if ( rank == NULL ) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        vgic_reg32_update(&rank->icfg[REG_RANK_INDEX(2, reg - GICD_ICFGR,
                                                     DABT_WORD)],
                          r, info);
        vgic_unlock_rank(v, rank, flags);
        return 1;

    default:
        printk(XENLOG_G_ERR
               "%pv: %s: unhandled write r%d=%"PRIregister" offset %#08x\n",
               v, name, dabt.reg, r, reg);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR
           "%pv: %s: bad write width %d r%d=%"PRIregister" offset %#08x\n",
           v, name, dabt.size, dabt.reg, r, reg);
    domain_crash_synchronous();
    return 0;

write_ignore_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
write_ignore:
    return 1;
}

static int vgic_v3_rdistr_sgi_mmio_read(struct vcpu *v, mmio_info_t *info,
                                        uint32_t gicr_reg, register_t *r)
{
    struct hsr_dabt dabt = info->dabt;

    switch ( gicr_reg )
    {
    case VREG32(GICR_IGROUPR0):
    case VREG32(GICR_ISENABLER0):
    case VREG32(GICR_ICENABLER0):
    case VREG32(GICR_ISACTIVER0):
    case VREG32(GICR_ICACTIVER0):
    case VRANGE32(GICR_IPRIORITYR0, GICR_IPRIORITYR7):
    case VRANGE32(GICR_ICFGR0, GICR_ICFGR1):
         /*
          * Above registers offset are common with GICD.
          * So handle in common with GICD handling
          */
        return __vgic_v3_distr_common_mmio_read("vGICR: SGI", v, info,
                                                gicr_reg, r);

    /* Read the pending status of an SGI is via GICR is not supported */
    case VREG32(GICR_ISPENDR0):
    case VREG32(GICR_ICPENDR0):
        goto read_as_zero;

    case VREG32(GICR_IGRPMODR0):
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case VREG32(GICR_NSACR):
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case 0x0E04 ... 0xBFFC:
        goto read_reserved;

    case 0xC000 ... 0xFFCC:
        goto read_impl_defined;

    case 0xFFD0 ... 0xFFFC:
        goto read_reserved;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGICR: SGI: unhandled read r%d offset %#08x\n",
               v, dabt.reg, gicr_reg);
        return 0;
    }
bad_width:
    printk(XENLOG_G_ERR "%pv: vGICR: SGI: bad read width %d r%d offset %#08x\n",
           v, dabt.size, dabt.reg, gicr_reg);
    domain_crash_synchronous();
    return 0;

read_as_zero_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
read_as_zero:
    *r = 0;
    return 1;

read_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICR: SGI: RAZ on implementation defined register offset %#08x\n",
           v, gicr_reg);
    *r = 0;
    return 1;

read_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGICR: SGI: RAZ on reserved register offset %#08x\n",
           v, gicr_reg);
    *r = 0;
    return 1;

}

static int vgic_v3_rdistr_sgi_mmio_write(struct vcpu *v, mmio_info_t *info,
                                         uint32_t gicr_reg, register_t r)
{
    struct hsr_dabt dabt = info->dabt;

    switch ( gicr_reg )
    {
    case VREG32(GICR_IGROUPR0):
    case VREG32(GICR_ISENABLER0):
    case VREG32(GICR_ICENABLER0):
    case VREG32(GICR_ISACTIVER0):
    case VREG32(GICR_ICACTIVER0):
    case VREG32(GICR_ICFGR1):
    case VRANGE32(GICR_IPRIORITYR0, GICR_IPRIORITYR7):
         /*
          * Above registers offset are common with GICD.
          * So handle common with GICD handling
          */
        return __vgic_v3_distr_common_mmio_write("vGICR: SGI", v,
                                                 info, gicr_reg, r);

    case VREG32(GICR_ISPENDR0):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICR: SGI: unhandled word write %#"PRIregister" to ISPENDR0\n",
               v, r);
        return 0;

    case VREG32(GICR_ICPENDR0):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        printk(XENLOG_G_ERR
               "%pv: vGICR: SGI: unhandled word write %#"PRIregister" to ICPENDR0\n",
               v, r);
        return 0;

    case VREG32(GICR_IGRPMODR0):
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;


    case VREG32(GICR_NSACR):
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGICR: SGI: unhandled write r%d offset %#08x\n",
               v, dabt.reg, gicr_reg);
        return 0;
    }

bad_width:
    printk(XENLOG_G_ERR
           "%pv: vGICR: SGI: bad write width %d r%d=%"PRIregister" offset %#08x\n",
           v, dabt.size, dabt.reg, r, gicr_reg);
    domain_crash_synchronous();
    return 0;

write_ignore_32:
    if ( dabt.size != DABT_WORD ) goto bad_width;
    return 1;
}

static struct vcpu *get_vcpu_from_rdist(struct domain *d,
    const struct vgic_rdist_region *region,
    paddr_t gpa, uint32_t *offset)
{
    struct vcpu *v;
    uint32_t stride = d->arch.vgic.rdist_stride;
    unsigned int vcpu_id;

    vcpu_id = region->first_cpu + ((gpa - region->base) / stride);
    if ( unlikely(vcpu_id >= d->max_vcpus) )
        return NULL;

    v = d->vcpu[vcpu_id];

    *offset = gpa - v->arch.vgic.rdist_base;

    return v;
}

static int vgic_v3_rdistr_mmio_read(struct vcpu *v, mmio_info_t *info,
                                    register_t *r, void *priv)
{
    uint32_t offset;
    const struct vgic_rdist_region *region = priv;

    perfc_incr(vgicr_reads);

    v = get_vcpu_from_rdist(v->domain, region, info->gpa, &offset);
    if ( unlikely(!v) )
        return 0;

    if ( offset < SZ_64K )
        return __vgic_v3_rdistr_rd_mmio_read(v, info, offset, r);
    else  if ( (offset >= SZ_64K) && (offset < 2 * SZ_64K) )
        return vgic_v3_rdistr_sgi_mmio_read(v, info, (offset - SZ_64K), r);
    else
        printk(XENLOG_G_WARNING
               "%pv: vGICR: unknown gpa read address %"PRIpaddr"\n",
                v, info->gpa);

    return 0;
}

static int vgic_v3_rdistr_mmio_write(struct vcpu *v, mmio_info_t *info,
                                     register_t r, void *priv)
{
    uint32_t offset;
    const struct vgic_rdist_region *region = priv;

    perfc_incr(vgicr_writes);

    v = get_vcpu_from_rdist(v->domain, region, info->gpa, &offset);
    if ( unlikely(!v) )
        return 0;

    if ( offset < SZ_64K )
        return __vgic_v3_rdistr_rd_mmio_write(v, info, offset, r);
    else  if ( (offset >= SZ_64K) && (offset < 2 * SZ_64K) )
        return vgic_v3_rdistr_sgi_mmio_write(v, info, (offset - SZ_64K), r);
    else
        printk(XENLOG_G_WARNING
               "%pv: vGICR: unknown gpa write address %"PRIpaddr"\n",
               v, info->gpa);

    return 0;
}

static int vgic_v3_distr_mmio_read(struct vcpu *v, mmio_info_t *info,
                                   register_t *r, void *priv)
{
    struct hsr_dabt dabt = info->dabt;
    struct vgic_irq_rank *rank;
    unsigned long flags;
    int gicd_reg = (int)(info->gpa - v->domain->arch.vgic.dbase);

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
        /*
         * Number of interrupt identifier bits supported by the GIC
         * Stream Protocol Interface
         */
        unsigned int irq_bits = get_count_order(vgic_num_irqs(v->domain));
        /*
         * Number of processors that may be used as interrupt targets when ARE
         * bit is zero. The maximum is 8.
         */
        unsigned int ncpus = min_t(unsigned int, v->domain->max_vcpus, 8);
        uint32_t typer;

        if ( dabt.size != DABT_WORD ) goto bad_width;
        /* No secure world support for guests. */
        typer = ((ncpus - 1) << GICD_TYPE_CPUS_SHIFT |
                 DIV_ROUND_UP(v->domain->arch.vgic.nr_spis, 32));

        typer |= (irq_bits - 1) << GICD_TYPE_ID_BITS_SHIFT;

        *r = vgic_reg32_extract(typer, info);

        return 1;
    }

    case VREG32(GICD_IIDR):
        if ( dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GICV3_GICD_IIDR_VAL, info);
        return 1;

    case VREG32(0x000C):
        goto read_reserved;

    case VREG32(GICD_STATUSR):
        /*
         *  Optional, Not implemented for now.
         *  Update to support guest debugging.
         */
        goto read_as_zero_32;

    case VRANGE32(0x0014, 0x001C):
        goto read_reserved;

    case VRANGE32(0x0020, 0x003C):
        goto read_impl_defined;

    case VREG32(GICD_SETSPI_NSR):
        /* Message based SPI is not implemented */
        goto read_reserved;

    case VREG32(0x0044):
        goto read_reserved;

    case VREG32(GICD_CLRSPI_NSR):
        /* Message based SPI is not implemented */
        goto read_reserved;

    case VREG32(0x004C):
        goto read_reserved;

    case VREG32(GICD_SETSPI_SR):
        /* Message based SPI is not implemented */
        goto read_reserved;

    case VREG32(0x0054):
        goto read_reserved;

    case VREG32(GICD_CLRSPI_SR):
        /* Message based SPI is not implemented */
        goto read_reserved;

    case VRANGE32(0x005C, 0x007C):
        goto read_reserved;

    case VRANGE32(GICD_IGROUPR, GICD_IGROUPRN):
    case VRANGE32(GICD_ISENABLER, GICD_ISENABLERN):
    case VRANGE32(GICD_ICENABLER, GICD_ICENABLERN):
    case VRANGE32(GICD_ISPENDR, GICD_ISPENDRN):
    case VRANGE32(GICD_ICPENDR, GICD_ICPENDRN):
    case VRANGE32(GICD_ISACTIVER, GICD_ISACTIVERN):
    case VRANGE32(GICD_ICACTIVER, GICD_ICACTIVERN):
    case VRANGE32(GICD_IPRIORITYR, GICD_IPRIORITYRN):
    case VRANGE32(GICD_ICFGR, GICD_ICFGRN):
        /*
         * Above all register are common with GICR and GICD
         * Manage in common
         */
        return __vgic_v3_distr_common_mmio_read("vGICD", v, info, gicd_reg, r);

    case VRANGE32(GICD_NSACR, GICD_NSACRN):
        /* We do not implement security extensions for guests, read zero */
        goto read_as_zero_32;

    case VREG32(GICD_SGIR):
        /* Read as ICH_SGIR system register with SRE set. So ignore */
        goto read_as_zero_32;

    case VRANGE32(GICD_CPENDSGIR, GICD_CPENDSGIRN):
        /* Replaced with GICR_ICPENDR0. So ignore write */
        goto read_as_zero_32;

    case VRANGE32(GICD_SPENDSGIR, GICD_SPENDSGIRN):
        /* Replaced with GICR_ISPENDR0. So ignore write */
        goto read_as_zero_32;

    case VRANGE32(0x0F30, 0x60FC):
        goto read_reserved;

    case VRANGE64(GICD_IROUTER32, GICD_IROUTER1019):
    {
        uint64_t irouter;

        if ( !vgic_reg64_check_access(dabt) ) goto bad_width;
        rank = vgic_rank_offset(v, 64, gicd_reg - GICD_IROUTER,
                                DABT_DOUBLE_WORD);
        if ( rank == NULL ) goto read_as_zero;
        vgic_lock_rank(v, rank, flags);
        irouter = vgic_fetch_irouter(rank, gicd_reg - GICD_IROUTER);
        vgic_unlock_rank(v, rank, flags);

        *r = vgic_reg64_extract(irouter, info);

        return 1;
    }

    case VRANGE32(0x7FE0, 0xBFFC):
        goto read_reserved;

    case VRANGE32(0xC000, 0xFFCC):
        goto read_impl_defined;

    case VRANGE32(0xFFD0, 0xFFE4):
        /* Implementation defined identification registers */
       goto read_impl_defined;

    case VREG32(GICD_PIDR2):
        /* GICv3 identification value */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GICV3_GICD_PIDR2, info);
        return 1;

    case VRANGE32(0xFFEC, 0xFFFC):
         /* Implementation defined identification registers */
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
    *r = 0;
    return 1;

read_as_zero:
    *r = 0;
    return 1;

read_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: RAZ on implementation defined register offset %#08x\n",
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

static int vgic_v3_distr_mmio_write(struct vcpu *v, mmio_info_t *info,
                                    register_t r, void *priv)
{
    struct hsr_dabt dabt = info->dabt;
    struct vgic_irq_rank *rank;
    unsigned long flags;
    int gicd_reg = (int)(info->gpa - v->domain->arch.vgic.dbase);

    perfc_incr(vgicd_writes);

    switch ( gicd_reg )
    {
    case VREG32(GICD_CTLR):
    {
        uint32_t ctlr = 0;

        if ( dabt.size != DABT_WORD ) goto bad_width;

        vgic_lock(v);

        vgic_reg32_update(&ctlr, r, info);

        /* Only EnableGrp1A can be changed */
        if ( ctlr & GICD_CTLR_ENABLE_G1A )
            v->domain->arch.vgic.ctlr |= GICD_CTLR_ENABLE_G1A;
        else
            v->domain->arch.vgic.ctlr &= ~GICD_CTLR_ENABLE_G1A;
        vgic_unlock(v);

        return 1;
    }

    case VREG32(GICD_TYPER):
        /* RO -- write ignored */
        goto write_ignore_32;

    case VREG32(GICD_IIDR):
        /* RO -- write ignored */
        goto write_ignore_32;

    case VREG32(0x000C):
        goto write_reserved;

    case VREG32(GICD_STATUSR):
        /* RO -- write ignored */
        goto write_ignore_32;

    case VRANGE32(0x0014, 0x001C):
        goto write_reserved;

    case VRANGE32(0x0020, 0x003C):
        goto write_impl_defined;

    case VREG32(GICD_SETSPI_NSR):
        /* Message based SPI is not implemented */
        goto write_reserved;

    case VREG32(0x0044):
        goto write_reserved;

    case VREG32(GICD_CLRSPI_NSR):
        /* Message based SPI is not implemented */
        goto write_reserved;

    case VREG32(0x004C):
        goto write_reserved;

    case VREG32(GICD_SETSPI_SR):
        /* Message based SPI is not implemented */
        goto write_reserved;

    case VREG32(0x0054):
        goto write_reserved;

    case VREG32(GICD_CLRSPI_SR):
        /* Message based SPI is not implemented */
        goto write_reserved;

    case VRANGE32(0x005C, 0x007C):
        goto write_reserved;

    case VRANGE32(GICD_IGROUPR, GICD_IGROUPRN):
    case VRANGE32(GICD_ISENABLER, GICD_ISENABLERN):
    case VRANGE32(GICD_ICENABLER, GICD_ICENABLERN):
    case VRANGE32(GICD_ISPENDR, GICD_ISPENDRN):
    case VRANGE32(GICD_ICPENDR, GICD_ICPENDRN):
    case VRANGE32(GICD_ISACTIVER, GICD_ISACTIVERN):
    case VRANGE32(GICD_ICACTIVER, GICD_ICACTIVERN):
    case VRANGE32(GICD_IPRIORITYR, GICD_IPRIORITYRN):
    case VRANGE32(GICD_ICFGR, GICD_ICFGRN):
        /* Above registers are common with GICR and GICD
         * Manage in common */
        return __vgic_v3_distr_common_mmio_write("vGICD", v, info,
                                                 gicd_reg, r);

    case VRANGE32(GICD_NSACR, GICD_NSACRN):
        /* We do not implement security extensions for guests, write ignore */
        goto write_ignore_32;

    case VREG32(GICD_SGIR):
        /* it is accessed as system register in GICv3 */
        goto write_ignore_32;

    case VRANGE32(GICD_CPENDSGIR, GICD_CPENDSGIRN):
        /* Replaced with GICR_ICPENDR0. So ignore write */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        return 0;

    case VRANGE32(GICD_SPENDSGIR, GICD_SPENDSGIRN):
        /* Replaced with GICR_ISPENDR0. So ignore write */
        if ( dabt.size != DABT_WORD ) goto bad_width;
        return 0;

    case VRANGE32(0x0F30, 0x60FC):
        goto write_reserved;

    case VRANGE64(GICD_IROUTER32, GICD_IROUTER1019):
    {
        uint64_t irouter;

        if ( !vgic_reg64_check_access(dabt) ) goto bad_width;
        rank = vgic_rank_offset(v, 64, gicd_reg - GICD_IROUTER,
                                DABT_DOUBLE_WORD);
        if ( rank == NULL ) goto write_ignore;
        vgic_lock_rank(v, rank, flags);
        irouter = vgic_fetch_irouter(rank, gicd_reg - GICD_IROUTER);
        vgic_reg64_update(&irouter, r, info);
        vgic_store_irouter(v->domain, rank, gicd_reg - GICD_IROUTER, irouter);
        vgic_unlock_rank(v, rank, flags);
        return 1;
    }

    case VRANGE32(0x7FE0, 0xBFFC):
        goto write_reserved;

    case VRANGE32(0xC000, 0xFFCC):
        goto write_impl_defined;

    case VRANGE32(0xFFD0, 0xFFE4):
        /* Implementation defined identification registers */
       goto write_impl_defined;

    case VREG32(GICD_PIDR2):
        /* RO -- write ignore */
        goto write_ignore_32;

    case VRANGE32(0xFFEC, 0xFFFC):
         /* Implementation defined identification registers */
         goto write_impl_defined;

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
    return 1;

write_ignore:
    return 1;

write_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: WI on implementation defined register offset %#08x\n",
           v, gicd_reg);
    return 1;

write_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGICD: WI on reserved register offset %#08x\n",
           v, gicd_reg);
    return 1;
}

static int vgic_v3_to_sgi(struct vcpu *v, register_t sgir)
{
    int virq;
    int irqmode;
    enum gic_sgi_mode sgi_mode;
    struct sgi_target target;

    irqmode = (sgir >> ICH_SGI_IRQMODE_SHIFT) & ICH_SGI_IRQMODE_MASK;
    virq = (sgir >> ICH_SGI_IRQ_SHIFT ) & ICH_SGI_IRQ_MASK;

    /* Map GIC sgi value to enum value */
    switch ( irqmode )
    {
    case ICH_SGI_TARGET_LIST:
        sgi_target_init(&target);
        /* We assume that only AFF1 is used in ICC_SGI1R_EL1. */
        target.aff1 = (sgir >> ICH_SGI_AFFINITY_LEVEL(1)) & ICH_SGI_AFFx_MASK;
        target.list = sgir & ICH_SGI_TARGETLIST_MASK;
        sgi_mode = SGI_TARGET_LIST;
        break;
    case ICH_SGI_TARGET_OTHERS:
        sgi_mode = SGI_TARGET_OTHERS;
        break;
    default:
        gprintk(XENLOG_WARNING, "Wrong irq mode in SGI1R_EL1 register\n");
        return 0;
    }

    return vgic_to_sgi(v, sgir, sgi_mode, virq, &target);
}

static int vgic_v3_emulate_sysreg(struct cpu_user_regs *regs, union hsr hsr)
{
    struct vcpu *v = current;
    struct hsr_sysreg sysreg = hsr.sysreg;

    ASSERT (hsr.ec == HSR_EC_SYSREG);

    if ( sysreg.read )
        perfc_incr(vgic_sysreg_reads);
    else
        perfc_incr(vgic_sysreg_writes);

    switch ( hsr.bits & HSR_SYSREG_REGS_MASK )
    {
    case HSR_SYSREG_ICC_SGI1R_EL1:
        /* WO */
        if ( !sysreg.read )
            return vgic_v3_to_sgi(v, get_user_reg(regs, sysreg.reg));
        else
        {
            gprintk(XENLOG_WARNING, "Reading SGI1R_EL1 - WO register\n");
            return 0;
        }
    default:
        return 0;
    }
}

static const struct mmio_handler_ops vgic_rdistr_mmio_handler = {
    .read  = vgic_v3_rdistr_mmio_read,
    .write = vgic_v3_rdistr_mmio_write,
};

static const struct mmio_handler_ops vgic_distr_mmio_handler = {
    .read  = vgic_v3_distr_mmio_read,
    .write = vgic_v3_distr_mmio_write,
};

static int vgic_v3_vcpu_init(struct vcpu *v)
{
    int i;
    paddr_t rdist_base;
    struct vgic_rdist_region *region;
    unsigned int last_cpu;

    /* Convenient alias */
    struct domain *d = v->domain;
    uint32_t rdist_stride = d->arch.vgic.rdist_stride;

    /*
     * Find the region where the re-distributor lives. For this purpose,
     * we look one region ahead as we have only the first CPU in hand.
     */
    for ( i = 1; i < d->arch.vgic.nr_regions; i++ )
    {
        if ( v->vcpu_id < d->arch.vgic.rdist_regions[i].first_cpu )
            break;
    }

    region = &d->arch.vgic.rdist_regions[i - 1];

    /* Get the base address of the redistributor */
    rdist_base = region->base;
    rdist_base += (v->vcpu_id - region->first_cpu) * rdist_stride;

    /* Check if a valid region was found for the re-distributor */
    if ( (rdist_base < region->base) ||
         ((rdist_base + rdist_stride) > (region->base + region->size)) )
    {
        dprintk(XENLOG_ERR,
                "d%u: Unable to find a re-distributor for VCPU %u\n",
                d->domain_id, v->vcpu_id);
        return -EINVAL;
    }

    v->arch.vgic.rdist_base = rdist_base;

    /*
     * If the redistributor is the last one of the
     * contiguous region of the vCPU is the last of the domain, set
     * VGIC_V3_RDIST_LAST flags.
     * Note that we are assuming max_vcpus will never change.
     */
    last_cpu = (region->size / rdist_stride) + region->first_cpu - 1;

    if ( v->vcpu_id == last_cpu || (v->vcpu_id == (d->max_vcpus - 1)) )
        v->arch.vgic.flags |= VGIC_V3_RDIST_LAST;

    return 0;
}

static inline unsigned int vgic_v3_rdist_count(struct domain *d)
{
    return is_hardware_domain(d) ? vgic_v3_hw.nr_rdist_regions :
               GUEST_GICV3_RDIST_REGIONS;
}

static int vgic_v3_domain_init(struct domain *d)
{
    struct vgic_rdist_region *rdist_regions;
    int rdist_count, i;

    /* Allocate memory for Re-distributor regions */
    rdist_count = vgic_v3_rdist_count(d);

    rdist_regions = xzalloc_array(struct vgic_rdist_region, rdist_count);
    if ( !rdist_regions )
        return -ENOMEM;

    d->arch.vgic.nr_regions = rdist_count;
    d->arch.vgic.rdist_regions = rdist_regions;

    /*
     * Domain 0 gets the hardware address.
     * Guests get the virtual platform layout.
     */
    if ( is_hardware_domain(d) )
    {
        unsigned int first_cpu = 0;

        d->arch.vgic.dbase = vgic_v3_hw.dbase;

        d->arch.vgic.rdist_stride = vgic_v3_hw.rdist_stride;
        /*
         * If the stride is not set, the default stride for GICv3 is 2 * 64K:
         *     - first 64k page for Control and Physical LPIs
         *     - second 64k page for Control and Generation of SGIs
         */
        if ( !d->arch.vgic.rdist_stride )
            d->arch.vgic.rdist_stride = 2 * SZ_64K;

        for ( i = 0; i < vgic_v3_hw.nr_rdist_regions; i++ )
        {
            paddr_t size = vgic_v3_hw.regions[i].size;

            d->arch.vgic.rdist_regions[i].base = vgic_v3_hw.regions[i].base;
            d->arch.vgic.rdist_regions[i].size = size;

            /* Set the first CPU handled by this region */
            d->arch.vgic.rdist_regions[i].first_cpu = first_cpu;

            first_cpu += size / d->arch.vgic.rdist_stride;
        }
    }
    else
    {
        d->arch.vgic.dbase = GUEST_GICV3_GICD_BASE;

        /* XXX: Only one Re-distributor region mapped for the guest */
        BUILD_BUG_ON(GUEST_GICV3_RDIST_REGIONS != 1);

        d->arch.vgic.rdist_stride = GUEST_GICV3_RDIST_STRIDE;

        /* The first redistributor should contain enough space for all CPUs */
        BUILD_BUG_ON((GUEST_GICV3_GICR0_SIZE / GUEST_GICV3_RDIST_STRIDE) < MAX_VIRT_CPUS);
        d->arch.vgic.rdist_regions[0].base = GUEST_GICV3_GICR0_BASE;
        d->arch.vgic.rdist_regions[0].size = GUEST_GICV3_GICR0_SIZE;
        d->arch.vgic.rdist_regions[0].first_cpu = 0;
    }

    /* Register mmio handle for the Distributor */
    register_mmio_handler(d, &vgic_distr_mmio_handler, d->arch.vgic.dbase,
                          SZ_64K, NULL);

    /*
     * Register mmio handler per contiguous region occupied by the
     * redistributors. The handler will take care to choose which
     * redistributor is targeted.
     */
    for ( i = 0; i < d->arch.vgic.nr_regions; i++ )
    {
        struct vgic_rdist_region *region = &d->arch.vgic.rdist_regions[i];

        register_mmio_handler(d, &vgic_rdistr_mmio_handler,
                              region->base, region->size, region);
    }

    d->arch.vgic.ctlr = VGICD_CTLR_DEFAULT;

    return 0;
}

static void vgic_v3_domain_free(struct domain *d)
{
    xfree(d->arch.vgic.rdist_regions);
}

static const struct vgic_ops v3_ops = {
    .vcpu_init   = vgic_v3_vcpu_init,
    .domain_init = vgic_v3_domain_init,
    .domain_free = vgic_v3_domain_free,
    .emulate_sysreg  = vgic_v3_emulate_sysreg,
    /*
     * We use both AFF1 and AFF0 in (v)MPIDR. Thus, the max number of CPU
     * that can be supported is up to 4096(==256*16) in theory.
     */
    .max_vcpus = 4096,
};

int vgic_v3_init(struct domain *d, int *mmio_count)
{
    if ( !vgic_v3_hw.enabled )
    {
        printk(XENLOG_G_ERR
               "d%d: vGICv3 is not supported on this platform.\n",
               d->domain_id);
        return -ENODEV;
    }

    /* GICD region + number of Redistributors */
    *mmio_count = vgic_v3_rdist_count(d) + 1;

    register_vgic_ops(d, &v3_ops);

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
