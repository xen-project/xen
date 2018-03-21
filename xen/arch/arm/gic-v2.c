/*
 * xen/arch/arm/gic-v2.c
 *
 * ARM Generic Interrupt Controller support v2
 *
 * Tim Deegan <tim@xen.org>
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

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/irq.h>
#include <xen/iocap.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <xen/list.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/sizes.h>
#include <xen/acpi.h>
#include <acpi/actables.h>
#include <asm/p2m.h>
#include <asm/domain.h>
#include <asm/platform.h>
#include <asm/device.h>

#include <asm/io.h>
#include <asm/gic.h>
#include <asm/acpi.h>

/*
 * LR register definitions are GIC v2 specific.
 * Moved these definitions from header file to here
 */
#define GICH_V2_LR_VIRTUAL_MASK    0x3ff
#define GICH_V2_LR_VIRTUAL_SHIFT   0
#define GICH_V2_LR_PHYSICAL_MASK   0x3ff
#define GICH_V2_LR_PHYSICAL_SHIFT  10
#define GICH_V2_LR_STATE_MASK      0x3
#define GICH_V2_LR_STATE_SHIFT     28
#define GICH_V2_LR_PENDING         (1U << 28)
#define GICH_V2_LR_ACTIVE          (1U << 29)
#define GICH_V2_LR_PRIORITY_SHIFT  23
#define GICH_V2_LR_PRIORITY_MASK   0x1f
#define GICH_V2_LR_HW_SHIFT        31
#define GICH_V2_LR_HW_MASK         0x1
#define GICH_V2_LR_GRP_SHIFT       30
#define GICH_V2_LR_GRP_MASK        0x1
#define GICH_V2_LR_MAINTENANCE_IRQ (1U << 19)
#define GICH_V2_LR_GRP1            (1U << 30)
#define GICH_V2_LR_HW              (1U << GICH_V2_LR_HW_SHIFT)
#define GICH_V2_LR_CPUID_SHIFT     10
#define GICH_V2_LR_CPUID_MASK      0x7
#define GICH_V2_VTR_NRLRGS         0x3f

#define GICH_V2_VMCR_PRIORITY_MASK   0x1f
#define GICH_V2_VMCR_PRIORITY_SHIFT  27

/* GICv2m extension register definitions. */
/*
* MSI_TYPER:
*     [31:26] Reserved
*     [25:16] lowest SPI assigned to MSI
*     [15:10] Reserved
*     [9:0]   Number of SPIs assigned to MSI
*/
#define V2M_MSI_TYPER               0x008
#define V2M_MSI_TYPER_BASE_SHIFT    16
#define V2M_MSI_TYPER_BASE_MASK     0x3FF
#define V2M_MSI_TYPER_NUM_MASK      0x3FF
#define V2M_MSI_SETSPI_NS           0x040
#define V2M_MIN_SPI                 32
#define V2M_MAX_SPI                 1019
#define V2M_MSI_IIDR                0xFCC

#define V2M_MSI_TYPER_BASE_SPI(x)   \
                (((x) >> V2M_MSI_TYPER_BASE_SHIFT) & V2M_MSI_TYPER_BASE_MASK)

#define V2M_MSI_TYPER_NUM_SPI(x)    ((x) & V2M_MSI_TYPER_NUM_MASK)

struct v2m_data {
    struct list_head entry;
    /* Pointer to the DT node representing the v2m frame */
    const struct dt_device_node *dt_node;
    paddr_t addr; /* Register frame base */
    paddr_t size; /* Register frame size */
    u32 spi_start; /* The SPI number that MSIs start */
    u32 nr_spis; /* The number of SPIs for MSIs */
};

/* v2m extension register frame information list */
static LIST_HEAD(gicv2m_info);

/* Global state */
static struct {
    void __iomem * map_dbase; /* IO mapped Address of distributor registers */
    void __iomem * map_cbase; /* IO mapped Address of CPU interface registers */
    void __iomem * map_hbase; /* IO Address of virtual interface registers */
    spinlock_t lock;
} gicv2;

static struct gic_info gicv2_info;

/* The GIC mapping of CPU interfaces does not necessarily match the
 * logical CPU numbering. Let's use mapping as returned by the GIC
 * itself
 */
static DEFINE_PER_CPU(u8, gic_cpu_id);

/* Maximum cpu interface per GIC */
#define NR_GIC_CPU_IF 8

static inline void writeb_gicd(uint8_t val, unsigned int offset)
{
    writeb_relaxed(val, gicv2.map_dbase + offset);
}

static inline void writel_gicd(uint32_t val, unsigned int offset)
{
    writel_relaxed(val, gicv2.map_dbase + offset);
}

static inline uint32_t readl_gicd(unsigned int offset)
{
    return readl_relaxed(gicv2.map_dbase + offset);
}

static inline void writel_gicc(uint32_t val, unsigned int offset)
{
    writel_relaxed(val, gicv2.map_cbase + offset);
}

static inline uint32_t readl_gicc(unsigned int offset)
{
    return readl_relaxed(gicv2.map_cbase + offset);
}

static inline void writel_gich(uint32_t val, unsigned int offset)
{
    writel_relaxed(val, gicv2.map_hbase + offset);
}

static inline uint32_t readl_gich(int unsigned offset)
{
    return readl_relaxed(gicv2.map_hbase + offset);
}

static unsigned int gicv2_cpu_mask(const cpumask_t *cpumask)
{
    unsigned int cpu;
    unsigned int mask = 0;
    cpumask_t possible_mask;

    cpumask_and(&possible_mask, cpumask, &cpu_possible_map);
    for_each_cpu( cpu, &possible_mask )
    {
        ASSERT(cpu < NR_GIC_CPU_IF);
        mask |= per_cpu(gic_cpu_id, cpu);
    }

    return mask;
}

static void gicv2_save_state(struct vcpu *v)
{
    int i;

    /* No need for spinlocks here because interrupts are disabled around
     * this call and it only accesses struct vcpu fields that cannot be
     * accessed simultaneously by another pCPU.
     */
    for ( i = 0; i < gicv2_info.nr_lrs; i++ )
        v->arch.gic.v2.lr[i] = readl_gich(GICH_LR + i * 4);

    v->arch.gic.v2.apr = readl_gich(GICH_APR);
    v->arch.gic.v2.vmcr = readl_gich(GICH_VMCR);
    /* Disable until next VCPU scheduled */
    writel_gich(0, GICH_HCR);
}

static void gicv2_restore_state(const struct vcpu *v)
{
    int i;

    for ( i = 0; i < gicv2_info.nr_lrs; i++ )
        writel_gich(v->arch.gic.v2.lr[i], GICH_LR + i * 4);

    writel_gich(v->arch.gic.v2.apr, GICH_APR);
    writel_gich(v->arch.gic.v2.vmcr, GICH_VMCR);
    writel_gich(GICH_HCR_EN, GICH_HCR);
}

static void gicv2_dump_state(const struct vcpu *v)
{
    int i;

    if ( v == current )
    {
        for ( i = 0; i < gicv2_info.nr_lrs; i++ )
            printk("   HW_LR[%d]=%x\n", i,
                   readl_gich(GICH_LR + i * 4));
    }
    else
    {
        for ( i = 0; i < gicv2_info.nr_lrs; i++ )
            printk("   VCPU_LR[%d]=%x\n", i, v->arch.gic.v2.lr[i]);
    }
}

static void gicv2_eoi_irq(struct irq_desc *irqd)
{
    int irq = irqd->irq;
    /* Lower the priority */
    writel_gicc(irq, GICC_EOIR);
}

static void gicv2_dir_irq(struct irq_desc *irqd)
{
    /* Deactivate */
    writel_gicc(irqd->irq, GICC_DIR);
}

static unsigned int gicv2_read_irq(void)
{
    return (readl_gicc(GICC_IAR) & GICC_IA_IRQ);
}

static void gicv2_poke_irq(struct irq_desc *irqd, uint32_t offset)
{
    writel_gicd(1U << (irqd->irq % 32), offset + (irqd->irq / 32) * 4);
}

static void gicv2_set_irq_type(struct irq_desc *desc, unsigned int type)
{
    uint32_t cfg, actual, edgebit;
    unsigned int irq = desc->irq;

    spin_lock(&gicv2.lock);
    /* Set edge / level */
    cfg = readl_gicd(GICD_ICFGR + (irq / 16) * 4);
    edgebit = 2u << (2 * (irq % 16));
    if ( type & IRQ_TYPE_LEVEL_MASK )
        cfg &= ~edgebit;
    else if ( type & IRQ_TYPE_EDGE_BOTH )
        cfg |= edgebit;
    writel_gicd(cfg, GICD_ICFGR + (irq / 16) * 4);

    actual = readl_gicd(GICD_ICFGR + (irq / 16) * 4);
    if ( ( cfg & edgebit ) ^ ( actual & edgebit ) )
    {
        printk(XENLOG_WARNING "GICv2: WARNING: "
               "CPU%d: Failed to configure IRQ%u as %s-triggered. "
               "H/w forces to %s-triggered.\n",
               smp_processor_id(), desc->irq,
               cfg & edgebit ? "Edge" : "Level",
               actual & edgebit ? "Edge" : "Level");
        desc->arch.type = actual & edgebit ?
            IRQ_TYPE_EDGE_RISING :
            IRQ_TYPE_LEVEL_HIGH;
    }

    spin_unlock(&gicv2.lock);
}

static void gicv2_set_irq_priority(struct irq_desc *desc,
                                   unsigned int priority)
{
    unsigned int irq = desc->irq;

    spin_lock(&gicv2.lock);

    /* Set priority */
    writeb_gicd(priority, GICD_IPRIORITYR + irq);

    spin_unlock(&gicv2.lock);
}

static void __init gicv2_dist_init(void)
{
    uint32_t type;
    uint32_t cpumask;
    uint32_t gic_cpus;
    unsigned int nr_lines;
    int i;

    cpumask = readl_gicd(GICD_ITARGETSR) & 0xff;
    cpumask |= cpumask << 8;
    cpumask |= cpumask << 16;

    /* Disable the distributor */
    writel_gicd(0, GICD_CTLR);

    type = readl_gicd(GICD_TYPER);
    nr_lines = 32 * ((type & GICD_TYPE_LINES) + 1);
    gic_cpus = 1 + ((type & GICD_TYPE_CPUS) >> 5);
    printk("GICv2: %d lines, %d cpu%s%s (IID %8.8x).\n",
           nr_lines, gic_cpus, (gic_cpus == 1) ? "" : "s",
           (type & GICD_TYPE_SEC) ? ", secure" : "",
           readl_gicd(GICD_IIDR));

    /* Default all global IRQs to level, active low */
    for ( i = 32; i < nr_lines; i += 16 )
        writel_gicd(0x0, GICD_ICFGR + (i / 16) * 4);

    /* Route all global IRQs to this CPU */
    for ( i = 32; i < nr_lines; i += 4 )
        writel_gicd(cpumask, GICD_ITARGETSR + (i / 4) * 4);

    /* Default priority for global interrupts */
    for ( i = 32; i < nr_lines; i += 4 )
        writel_gicd(GIC_PRI_IRQ << 24 | GIC_PRI_IRQ << 16 |
                    GIC_PRI_IRQ << 8 | GIC_PRI_IRQ,
                    GICD_IPRIORITYR + (i / 4) * 4);

    /* Disable all global interrupts */
    for ( i = 32; i < nr_lines; i += 32 )
        writel_gicd(~0x0, GICD_ICENABLER + (i / 32) * 4);

    /* Only 1020 interrupts are supported */
    gicv2_info.nr_lines = min(1020U, nr_lines);

    /* Turn on the distributor */
    writel_gicd(GICD_CTL_ENABLE, GICD_CTLR);
}

static void gicv2_cpu_init(void)
{
    int i;

    this_cpu(gic_cpu_id) = readl_gicd(GICD_ITARGETSR) & 0xff;

    /* The first 32 interrupts (PPI and SGI) are banked per-cpu, so
     * even though they are controlled with GICD registers, they must
     * be set up here with the other per-cpu state. */
    writel_gicd(0xffff0000, GICD_ICENABLER); /* Disable all PPI */
    writel_gicd(0x0000ffff, GICD_ISENABLER); /* Enable all SGI */

    /* Set SGI priorities */
    for ( i = 0; i < 16; i += 4 )
        writel_gicd(GIC_PRI_IPI << 24 | GIC_PRI_IPI << 16 |
                    GIC_PRI_IPI << 8 | GIC_PRI_IPI,
                    GICD_IPRIORITYR + (i / 4) * 4);

    /* Set PPI priorities */
    for ( i = 16; i < 32; i += 4 )
        writel_gicd(GIC_PRI_IRQ << 24 | GIC_PRI_IRQ << 16 |
                    GIC_PRI_IRQ << 8 | GIC_PRI_IRQ,
                    GICD_IPRIORITYR + (i / 4) * 4);

    /* Local settings: interface controller */
    /* Don't mask by priority */
    writel_gicc(0xff, GICC_PMR);
    /* Finest granularity of priority */
    writel_gicc(0x0, GICC_BPR);
    /* Turn on delivery */
    writel_gicc(GICC_CTL_ENABLE|GICC_CTL_EOI, GICC_CTLR);
}

static void gicv2_cpu_disable(void)
{
    writel_gicc(0x0, GICC_CTLR);
}

static void gicv2_hyp_init(void)
{
    uint32_t vtr;
    uint8_t nr_lrs;

    vtr = readl_gich(GICH_VTR);
    nr_lrs  = (vtr & GICH_V2_VTR_NRLRGS) + 1;
    gicv2_info.nr_lrs = nr_lrs;
}

static void gicv2_hyp_disable(void)
{
    writel_gich(0, GICH_HCR);
}

static int gicv2_secondary_cpu_init(void)
{
    spin_lock(&gicv2.lock);

    gicv2_cpu_init();
    gicv2_hyp_init();

    spin_unlock(&gicv2.lock);

    return 0;
}

static void gicv2_send_SGI(enum gic_sgi sgi, enum gic_sgi_mode irqmode,
                           const cpumask_t *cpu_mask)
{
    unsigned int mask = 0;
    cpumask_t online_mask;

    switch ( irqmode )
    {
    case SGI_TARGET_OTHERS:
        writel_gicd(GICD_SGI_TARGET_OTHERS | sgi, GICD_SGIR);
        break;
    case SGI_TARGET_SELF:
        writel_gicd(GICD_SGI_TARGET_SELF | sgi, GICD_SGIR);
        break;
    case SGI_TARGET_LIST:
        cpumask_and(&online_mask, cpu_mask, &cpu_online_map);
        mask = gicv2_cpu_mask(&online_mask);
        writel_gicd(GICD_SGI_TARGET_LIST |
                    (mask << GICD_SGI_TARGET_SHIFT) | sgi,
                    GICD_SGIR);
        break;
    default:
        BUG();
    }
}

/* Shut down the per-CPU GIC interface */
static void gicv2_disable_interface(void)
{
    spin_lock(&gicv2.lock);
    gicv2_cpu_disable();
    gicv2_hyp_disable();
    spin_unlock(&gicv2.lock);
}

static void gicv2_update_lr(int lr, unsigned int virq, uint8_t priority,
                            unsigned int hw_irq, unsigned int state)
{
    uint32_t lr_reg;

    BUG_ON(lr >= gicv2_info.nr_lrs);
    BUG_ON(lr < 0);

    lr_reg = (((state & GICH_V2_LR_STATE_MASK) << GICH_V2_LR_STATE_SHIFT)  |
              ((GIC_PRI_TO_GUEST(priority) & GICH_V2_LR_PRIORITY_MASK)
                                          << GICH_V2_LR_PRIORITY_SHIFT) |
              ((virq & GICH_V2_LR_VIRTUAL_MASK) << GICH_V2_LR_VIRTUAL_SHIFT));

    if ( hw_irq != INVALID_IRQ )
        lr_reg |= GICH_V2_LR_HW | ((hw_irq & GICH_V2_LR_PHYSICAL_MASK )
                                   << GICH_V2_LR_PHYSICAL_SHIFT);

    writel_gich(lr_reg, GICH_LR + lr * 4);
}

static void gicv2_clear_lr(int lr)
{
    writel_gich(0, GICH_LR + lr * 4);
}

static void gicv2_read_lr(int lr, struct gic_lr *lr_reg)
{
    uint32_t lrv;

    lrv          = readl_gich(GICH_LR + lr * 4);
    lr_reg->virq = (lrv >> GICH_V2_LR_VIRTUAL_SHIFT) & GICH_V2_LR_VIRTUAL_MASK;
    lr_reg->priority = (lrv >> GICH_V2_LR_PRIORITY_SHIFT) & GICH_V2_LR_PRIORITY_MASK;
    lr_reg->pending = lrv & GICH_V2_LR_PENDING;
    lr_reg->active = lrv & GICH_V2_LR_ACTIVE;
    lr_reg->hw_status = lrv & GICH_V2_LR_HW;

    if ( lr_reg->hw_status )
    {
        lr_reg->hw.pirq = lrv >> GICH_V2_LR_PHYSICAL_SHIFT;
        lr_reg->hw.pirq &= GICH_V2_LR_PHYSICAL_MASK;
    }
    else
    {
        lr_reg->virt.eoi = (lrv & GICH_V2_LR_MAINTENANCE_IRQ);
        /*
         * This is only valid for SGI, but it does not matter to always
         * read it as it should be 0 by default.
         */
        lr_reg->virt.source = (lrv >> GICH_V2_LR_CPUID_SHIFT)
            & GICH_V2_LR_CPUID_MASK;
    }
}

static void gicv2_write_lr(int lr, const struct gic_lr *lr_reg)
{
    uint32_t lrv = 0;

    lrv = (((lr_reg->virq & GICH_V2_LR_VIRTUAL_MASK) << GICH_V2_LR_VIRTUAL_SHIFT)   |
          ((uint32_t)(lr_reg->priority & GICH_V2_LR_PRIORITY_MASK)
                                      << GICH_V2_LR_PRIORITY_SHIFT) );

    if ( lr_reg->active )
        lrv |= GICH_V2_LR_ACTIVE;

    if ( lr_reg->pending )
        lrv |= GICH_V2_LR_PENDING;

    if ( lr_reg->hw_status )
    {
        lrv |= GICH_V2_LR_HW;
        lrv |= lr_reg->hw.pirq << GICH_V2_LR_PHYSICAL_SHIFT;
    }
    else
    {
        if ( lr_reg->virt.eoi )
            lrv |= GICH_V2_LR_MAINTENANCE_IRQ;
        /*
         * Source is only valid for SGIs, the caller should make sure
         * the field virt.source is always 0 for non-SGI.
         */
        ASSERT(!lr_reg->virt.source || lr_reg->virq < NR_GIC_SGI);
        lrv |= (uint32_t)lr_reg->virt.source << GICH_V2_LR_CPUID_SHIFT;
    }

    writel_gich(lrv, GICH_LR + lr * 4);
}

static void gicv2_hcr_status(uint32_t flag, bool status)
{
    uint32_t hcr = readl_gich(GICH_HCR);

    if ( status )
        hcr |= flag;
    else
        hcr &= (~flag);

    writel_gich(hcr, GICH_HCR);
}

static unsigned int gicv2_read_vmcr_priority(void)
{
   return ((readl_gich(GICH_VMCR) >> GICH_V2_VMCR_PRIORITY_SHIFT)
           & GICH_V2_VMCR_PRIORITY_MASK);
}

static unsigned int gicv2_read_apr(int apr_reg)
{
   return readl_gich(GICH_APR);
}

static void gicv2_irq_enable(struct irq_desc *desc)
{
    unsigned long flags;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&gicv2.lock, flags);
    clear_bit(_IRQ_DISABLED, &desc->status);
    dsb(sy);
    /* Enable routing */
    gicv2_poke_irq(desc, GICD_ISENABLER);
    spin_unlock_irqrestore(&gicv2.lock, flags);
}

static void gicv2_irq_disable(struct irq_desc *desc)
{
    unsigned long flags;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&gicv2.lock, flags);
    /* Disable routing */
    gicv2_poke_irq(desc, GICD_ICENABLER);
    set_bit(_IRQ_DISABLED, &desc->status);
    spin_unlock_irqrestore(&gicv2.lock, flags);
}

static unsigned int gicv2_irq_startup(struct irq_desc *desc)
{
    gicv2_irq_enable(desc);

    return 0;
}

static void gicv2_irq_shutdown(struct irq_desc *desc)
{
    gicv2_irq_disable(desc);
}

static void gicv2_irq_ack(struct irq_desc *desc)
{
    /* No ACK -- reading IAR has done this for us */
}

static void gicv2_host_irq_end(struct irq_desc *desc)
{
    /* Lower the priority */
    gicv2_eoi_irq(desc);
    /* Deactivate */
    gicv2_dir_irq(desc);
}

static void gicv2_guest_irq_end(struct irq_desc *desc)
{
    /* Lower the priority of the IRQ */
    gicv2_eoi_irq(desc);
    /* Deactivation happens in maintenance interrupt / via GICV */
}

static void gicv2_irq_set_affinity(struct irq_desc *desc, const cpumask_t *cpu_mask)
{
    unsigned int mask;

    ASSERT(!cpumask_empty(cpu_mask));

    spin_lock(&gicv2.lock);

    mask = gicv2_cpu_mask(cpu_mask);

    /* Set target CPU mask (RAZ/WI on uniprocessor) */
    writeb_gicd(mask, GICD_ITARGETSR + desc->irq);

    spin_unlock(&gicv2.lock);
}

static int gicv2_map_hwdown_extra_mappings(struct domain *d)
{
    const struct v2m_data *v2m_data;

    /* For the moment, we'll assign all v2m frames to the hardware domain. */
    list_for_each_entry( v2m_data, &gicv2m_info, entry )
    {
        int ret;
        u32 spi;

        printk("GICv2: Mapping v2m frame to d%d: addr=0x%"PRIpaddr" size=0x%"PRIpaddr" spi_base=%u num_spis=%u\n",
               d->domain_id, v2m_data->addr, v2m_data->size,
               v2m_data->spi_start, v2m_data->nr_spis);

        ret = map_mmio_regions(d, gaddr_to_gfn(v2m_data->addr),
                               PFN_UP(v2m_data->size),
                               maddr_to_mfn(v2m_data->addr));
        if ( ret )
        {
            printk(XENLOG_ERR "GICv2: Map v2m frame to d%d failed.\n",
                   d->domain_id);
            return ret;
        }

        /*
         * Map all SPIs that are allocated to MSIs for the frame to the
         * domain.
         */
        for ( spi = v2m_data->spi_start;
              spi < (v2m_data->spi_start + v2m_data->nr_spis); spi++ )
        {
            /*
             * MSIs are always edge-triggered. Configure the associated SPIs
             * to be edge-rising as default type.
             */
            ret = irq_set_spi_type(spi, IRQ_TYPE_EDGE_RISING);
            if ( ret )
            {
                printk(XENLOG_ERR
                       "GICv2: Failed to set v2m MSI SPI[%d] type.\n", spi);
                return ret;
            }

            /* Route a SPI that is allocated to MSI to the domain. */
            ret = route_irq_to_guest(d, spi, spi, "v2m");
            if ( ret )
            {
                printk(XENLOG_ERR
                       "GICv2: Failed to route v2m MSI SPI[%d] to Dom%d.\n",
                       spi, d->domain_id);
                return ret;
            }

            /* Reserve a SPI that is allocated to MSI for the domain. */
            if ( !vgic_reserve_virq(d, spi) )
            {
                printk(XENLOG_ERR
                       "GICv2: Failed to reserve v2m MSI SPI[%d] for Dom%d.\n",
                       spi, d->domain_id);
                return -EINVAL;
            }
        }
    }

    return 0;
}

/*
 * Set up gic v2m DT sub-node.
 * Please refer to the binding document:
 * https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm,gic.txt
 */
static int gicv2m_make_dt_node(const struct domain *d,
                               const struct dt_device_node *gic,
                               void *fdt)
{
    u32 len;
    int res;
    const void *prop = NULL;
    const struct dt_device_node *v2m = NULL;
    const struct v2m_data *v2m_data;

    /* It is not necessary to create the node if there are not GICv2m frames */
    if ( list_empty(&gicv2m_info) )
        return 0;

    /* The sub-nodes require the ranges property */
    prop = dt_get_property(gic, "ranges", &len);
    if ( !prop )
    {
        printk(XENLOG_ERR "Can't find ranges property for the gic node\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "ranges", prop, len);
    if ( res )
        return res;

    list_for_each_entry( v2m_data, &gicv2m_info, entry )
    {
        v2m = v2m_data->dt_node;

        printk("GICv2: Creating v2m DT node for d%d: addr=0x%"PRIpaddr" size=0x%"PRIpaddr" spi_base=%u num_spis=%u\n",
               d->domain_id, v2m_data->addr, v2m_data->size,
               v2m_data->spi_start, v2m_data->nr_spis);

        res = fdt_begin_node(fdt, v2m->name);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "compatible", "arm,gic-v2m-frame");
        if ( res )
            return res;

        res = fdt_property(fdt, "msi-controller", NULL, 0);
        if ( res )
            return res;

        if ( v2m->phandle )
        {
            res = fdt_property_cell(fdt, "phandle", v2m->phandle);
            if ( res )
                return res;
        }

        /* Use the same reg regions as v2m node in host DTB. */
        prop = dt_get_property(v2m, "reg", &len);
        if ( !prop )
        {
            printk(XENLOG_ERR "GICv2: Can't find v2m reg property.\n");
            res = -FDT_ERR_XEN(ENOENT);
            return res;
        }

        res = fdt_property(fdt, "reg", prop, len);
        if ( res )
            return res;

        /*
         * The properties msi-base-spi and msi-num-spis are used to override
         * the hardware settings. Therefore it is fine to always write them
         * in the guest DT.
         */
        res = fdt_property_u32(fdt, "arm,msi-base-spi", v2m_data->spi_start);
        if ( res )
        {
            printk(XENLOG_ERR
                   "GICv2: Failed to create v2m msi-base-spi in Guest DT.\n");
            return res;
        }

        res = fdt_property_u32(fdt, "arm,msi-num-spis", v2m_data->nr_spis);
        if ( res )
        {
            printk(XENLOG_ERR
                   "GICv2: Failed to create v2m msi-num-spis in Guest DT.\n");
            return res;
        }

        fdt_end_node(fdt);
    }

    return res;
}

static int gicv2_make_hwdom_dt_node(const struct domain *d,
                                    const struct dt_device_node *gic,
                                    void *fdt)
{
    const void *compatible = NULL;
    u32 len;
    const __be32 *regs;
    int res = 0;

    compatible = dt_get_property(gic, "compatible", &len);
    if ( !compatible )
    {
        dprintk(XENLOG_ERR, "Can't find compatible property for the gic node\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "compatible", compatible, len);
    if ( res )
        return res;

    /*
     * DTB provides up to 4 regions to handle virtualization
     * (in order GICD, GICC, GICH and GICV interfaces)
     * however dom0 just needs GICD and GICC provided by Xen.
     */
    regs = dt_get_property(gic, "reg", &len);
    if ( !regs )
    {
        dprintk(XENLOG_ERR, "Can't find reg property for the gic node\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    len = dt_cells_to_size(dt_n_addr_cells(gic) + dt_n_size_cells(gic));
    len *= 2;

    res = fdt_property(fdt, "reg", regs, len);
    if ( res )
        return res;

    res = gicv2m_make_dt_node(d, gic, fdt);

    return res;
}

/* XXX different for level vs edge */
static hw_irq_controller gicv2_host_irq_type = {
    .typename     = "gic-v2",
    .startup      = gicv2_irq_startup,
    .shutdown     = gicv2_irq_shutdown,
    .enable       = gicv2_irq_enable,
    .disable      = gicv2_irq_disable,
    .ack          = gicv2_irq_ack,
    .end          = gicv2_host_irq_end,
    .set_affinity = gicv2_irq_set_affinity,
};

static hw_irq_controller gicv2_guest_irq_type = {
    .typename     = "gic-v2",
    .startup      = gicv2_irq_startup,
    .shutdown     = gicv2_irq_shutdown,
    .enable       = gicv2_irq_enable,
    .disable      = gicv2_irq_disable,
    .ack          = gicv2_irq_ack,
    .end          = gicv2_guest_irq_end,
    .set_affinity = gicv2_irq_set_affinity,
};

static bool gicv2_is_aliased(paddr_t cbase, paddr_t csize)
{
    uint32_t val_low, val_high;

    if ( csize != SZ_128K )
        return false;

    /*
     * Verify that we have the first 4kB of a GIC400
     * aliased over the first 64kB by checking the
     * GICC_IIDR register on both ends.
     */
    val_low = readl_gicc(GICC_IIDR);
    val_high = readl_gicc(GICC_IIDR + 0xf000);

    return ((val_low & 0xfff0fff) == 0x0202043B && val_low == val_high);
}

static void gicv2_add_v2m_frame_to_list(paddr_t addr, paddr_t size,
                                        u32 spi_start, u32 nr_spis,
                                        const struct dt_device_node *v2m)
{
    struct v2m_data *v2m_data;

    /*
     * If the hardware setting hasn't been overridden by DT or ACPI, we have
     * to read base_spi and num_spis from hardware registers to reserve irqs.
     */
    if ( !spi_start || !nr_spis )
    {
        u32 msi_typer;
        void __iomem *base;

        base = ioremap_nocache(addr, size);
        if ( !base )
            panic("GICv2: Cannot remap v2m register frame");

        msi_typer = readl_relaxed(base + V2M_MSI_TYPER);
        spi_start = V2M_MSI_TYPER_BASE_SPI(msi_typer);
        nr_spis = V2M_MSI_TYPER_NUM_SPI(msi_typer);

        iounmap(base);
    }

    if ( spi_start < V2M_MIN_SPI )
        panic("GICv2: Invalid v2m base SPI:%u\n", spi_start);

    if ( ( nr_spis == 0 ) || ( spi_start + nr_spis > V2M_MAX_SPI ) )
        panic("GICv2: Number of v2m SPIs (%u) exceed maximum (%u)\n",
              nr_spis, V2M_MAX_SPI - V2M_MIN_SPI + 1);

    /* Allocate an entry to record new v2m frame information. */
    v2m_data = xzalloc_bytes(sizeof(struct v2m_data));
    if ( !v2m_data )
        panic("GICv2: Cannot allocate memory for v2m frame");

    INIT_LIST_HEAD(&v2m_data->entry);
    v2m_data->addr = addr;
    v2m_data->size = size;
    v2m_data->spi_start = spi_start;
    v2m_data->nr_spis = nr_spis;
    v2m_data->dt_node = v2m;

    printk("GICv2m extension register frame:\n"
           "        gic_v2m_addr=%"PRIpaddr"\n"
           "        gic_v2m_size=%"PRIpaddr"\n"
           "        gic_v2m_spi_base=%u\n"
           "        gic_v2m_num_spis=%u\n",
           v2m_data->addr, v2m_data->size,
           v2m_data->spi_start, v2m_data->nr_spis);

    list_add_tail(&v2m_data->entry, &gicv2m_info);
}

static void gicv2_extension_dt_init(const struct dt_device_node *node)
{
    const struct dt_device_node *v2m = NULL;

    /*
     * Check whether this GIC implements the v2m extension. If so,
     * add v2m register frames to gicv2m_info.
     */
    dt_for_each_child_node(node, v2m)
    {
        u32 spi_start = 0, nr_spis = 0;
        paddr_t addr, size;

        if ( !dt_device_is_compatible(v2m, "arm,gic-v2m-frame") )
            continue;

        /* Get register frame resource from DT. */
        if ( dt_device_get_address(v2m, 0, &addr, &size) )
            panic("GICv2: Cannot find a valid v2m frame address");

        /*
         * Check whether DT uses msi-base-spi and msi-num-spis properties to
         * override the hardware setting.
         */
        if ( dt_property_read_u32(v2m, "arm,msi-base-spi", &spi_start) &&
             dt_property_read_u32(v2m, "arm,msi-num-spis", &nr_spis) )
            printk("GICv2: DT overriding v2m hardware setting (base:%u, num:%u)\n",
                   spi_start, nr_spis);

        /* Add this v2m frame information to list. */
        gicv2_add_v2m_frame_to_list(addr, size, spi_start, nr_spis, v2m);
    }
}

static paddr_t __initdata hbase, dbase, cbase, csize, vbase;

static void __init gicv2_dt_init(void)
{
    int res;
    paddr_t vsize;
    const struct dt_device_node *node = gicv2_info.node;

    res = dt_device_get_address(node, 0, &dbase, NULL);
    if ( res )
        panic("GICv2: Cannot find a valid address for the distributor");

    res = dt_device_get_address(node, 1, &cbase, &csize);
    if ( res )
        panic("GICv2: Cannot find a valid address for the CPU");

    res = dt_device_get_address(node, 2, &hbase, NULL);
    if ( res )
        panic("GICv2: Cannot find a valid address for the hypervisor");

    res = dt_device_get_address(node, 3, &vbase, &vsize);
    if ( res )
        panic("GICv2: Cannot find a valid address for the virtual CPU");

    res = platform_get_irq(node, 0);
    if ( res < 0 )
        panic("GICv2: Cannot find the maintenance IRQ");
    gicv2_info.maintenance_irq = res;

    /* TODO: Add check on distributor */

    /*
     * The GICv2 CPU interface should at least be 8KB. Although, most of the DT
     * don't correctly set it and use the GICv1 CPU interface size (i.e 4KB).
     * Warn and then fixup.
     */
    if ( csize < SZ_8K )
    {
        printk(XENLOG_WARNING "GICv2: WARNING: "
               "The GICC size is too small: %#"PRIx64" expected %#x\n",
               csize, SZ_8K);
        if ( platform_has_quirk(PLATFORM_QUIRK_GIC_64K_STRIDE) )
        {
            printk(XENLOG_WARNING "GICv2: enable platform quirk: 64K stride\n");
            vsize = csize = SZ_128K;
        } else
            csize = SZ_8K;
    }

    /*
     * Check if the CPU interface and virtual CPU interface have the
     * same size.
     */
    if ( csize != vsize )
        panic("GICv2: Sizes of GICC (%#"PRIpaddr") and GICV (%#"PRIpaddr") don't match\n",
               csize, vsize);

    /*
     * Check whether this GIC implements the v2m extension. If so,
     * add v2m register frames to gicv2_extension_info.
     */
    gicv2_extension_dt_init(node);
}

static int gicv2_iomem_deny_access(const struct domain *d)
{
    int rc;
    unsigned long mfn, nr;

    mfn = dbase >> PAGE_SHIFT;
    rc = iomem_deny_access(d, mfn, mfn + 1);
    if ( rc )
        return rc;

    mfn = hbase >> PAGE_SHIFT;
    rc = iomem_deny_access(d, mfn, mfn + 1);
    if ( rc )
        return rc;

    mfn = cbase >> PAGE_SHIFT;
    nr = DIV_ROUND_UP(csize, PAGE_SIZE);
    rc = iomem_deny_access(d, mfn, mfn + nr);
    if ( rc )
        return rc;

    mfn = vbase >> PAGE_SHIFT;
    return iomem_deny_access(d, mfn, mfn + nr);
}

static unsigned long gicv2_get_hwdom_extra_madt_size(const struct domain *d)
{
    return 0;
}

#ifdef CONFIG_ACPI
static int gicv2_make_hwdom_madt(const struct domain *d, u32 offset)
{
    struct acpi_subtable_header *header;
    struct acpi_madt_generic_interrupt *host_gicc, *gicc;
    u32 i, size, table_len = 0;
    u8 *base_ptr = d->arch.efi_acpi_table + offset;

    header = acpi_table_get_entry_madt(ACPI_MADT_TYPE_GENERIC_INTERRUPT, 0);
    if ( !header )
    {
        printk("Can't get GICC entry");
        return -EINVAL;
    }

    host_gicc = container_of(header, struct acpi_madt_generic_interrupt,
                             header);
    size = sizeof(struct acpi_madt_generic_interrupt);
    /* Add Generic Interrupt */
    for ( i = 0; i < d->max_vcpus; i++ )
    {
        gicc = (struct acpi_madt_generic_interrupt *)(base_ptr + table_len);
        memcpy(gicc, host_gicc, size);
        gicc->cpu_interface_number = i;
        gicc->uid = i;
        gicc->flags = ACPI_MADT_ENABLED;
        gicc->arm_mpidr = vcpuid_to_vaffinity(i);
        gicc->parking_version = 0;
        gicc->performance_interrupt = 0;
        gicc->gicv_base_address = 0;
        gicc->gich_base_address = 0;
        gicc->vgic_interrupt = 0;
        table_len += size;
    }

    return table_len;
}

static int __init
gic_acpi_parse_madt_cpu(struct acpi_subtable_header *header,
                        const unsigned long end)
{
    static int cpu_base_assigned = 0;
    struct acpi_madt_generic_interrupt *processor =
               container_of(header, struct acpi_madt_generic_interrupt, header);

    if ( BAD_MADT_ENTRY(processor, end) )
        return -EINVAL;

    /* Read from APIC table and fill up the GIC variables */
    if ( cpu_base_assigned == 0 )
    {
        cbase = processor->base_address;
        csize = SZ_8K;
        hbase = processor->gich_base_address;
        vbase = processor->gicv_base_address;
        gicv2_info.maintenance_irq = processor->vgic_interrupt;

        if ( processor->flags & ACPI_MADT_VGIC_IRQ_MODE )
            irq_set_type(gicv2_info.maintenance_irq, IRQ_TYPE_EDGE_BOTH);
        else
            irq_set_type(gicv2_info.maintenance_irq, IRQ_TYPE_LEVEL_MASK);

        cpu_base_assigned = 1;
    }
    else
    {
        if ( cbase != processor->base_address
             || hbase != processor->gich_base_address
             || vbase != processor->gicv_base_address
             || gicv2_info.maintenance_irq != processor->vgic_interrupt )
        {
            printk("GICv2: GICC entries are not same in MADT table\n");
            return -EINVAL;
        }
    }

    return 0;
}

static int __init
gic_acpi_parse_madt_distributor(struct acpi_subtable_header *header,
                                const unsigned long end)
{
    struct acpi_madt_generic_distributor *dist =
             container_of(header, struct acpi_madt_generic_distributor, header);

    if ( BAD_MADT_ENTRY(dist, end) )
        return -EINVAL;

    dbase = dist->base_address;

    return 0;
}

static void __init gicv2_acpi_init(void)
{
    acpi_status status;
    struct acpi_table_header *table;
    int count;

    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        panic("GICv2: Failed to get MADT table, %s", msg);
    }

    /* Collect CPU base addresses */
    count = acpi_parse_entries(ACPI_SIG_MADT, sizeof(struct acpi_table_madt),
                               gic_acpi_parse_madt_cpu, table,
                               ACPI_MADT_TYPE_GENERIC_INTERRUPT, 0);
    if ( count <= 0 )
        panic("GICv2: No valid GICC entries exists");

    /*
     * Find distributor base address. We expect one distributor entry since
     * ACPI 5.0 spec neither support multi-GIC instances nor GIC cascade.
     */
    count = acpi_parse_entries(ACPI_SIG_MADT, sizeof(struct acpi_table_madt),
                               gic_acpi_parse_madt_distributor, table,
                               ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR, 0);
    if ( count <= 0 )
        panic("GICv2: No valid GICD entries exists");
}
#else
static void __init gicv2_acpi_init(void) { }
static int gicv2_make_hwdom_madt(const struct domain *d, u32 offset)
{
    return 0;
}
#endif

static int __init gicv2_init(void)
{
    uint32_t aliased_offset = 0;

    if ( acpi_disabled )
        gicv2_dt_init();
    else
        gicv2_acpi_init();

    printk("GICv2 initialization:\n"
              "        gic_dist_addr=%"PRIpaddr"\n"
              "        gic_cpu_addr=%"PRIpaddr"\n"
              "        gic_hyp_addr=%"PRIpaddr"\n"
              "        gic_vcpu_addr=%"PRIpaddr"\n"
              "        gic_maintenance_irq=%u\n",
              dbase, cbase, hbase, vbase,
              gicv2_info.maintenance_irq);

    if ( (dbase & ~PAGE_MASK) || (cbase & ~PAGE_MASK) ||
         (hbase & ~PAGE_MASK) || (vbase & ~PAGE_MASK) )
        panic("GICv2 interfaces not page aligned");

    gicv2.map_dbase = ioremap_nocache(dbase, PAGE_SIZE);
    if ( !gicv2.map_dbase )
        panic("GICv2: Failed to ioremap for GIC distributor\n");

    gicv2.map_cbase = ioremap_nocache(cbase, csize);
    if ( !gicv2.map_cbase )
        panic("GICv2: Failed to ioremap for GIC CPU interface\n");

    if ( gicv2_is_aliased(cbase, csize) )
    {
        /*
         * Move the base up by 60kB, so that we have a 8kB contiguous
         * region, which allows us to use GICC_DIR at its
         * normal offset.
         * Note the variable cbase is not updated as we need the original
         * value for the vGICv2 emulation.
         */
        aliased_offset = 0xf000;

        gicv2.map_cbase += aliased_offset;

        printk(XENLOG_WARNING
               "GICv2: Adjusting CPU interface base to %#"PRIx64"\n",
               cbase + aliased_offset);
    } else if ( csize == SZ_128K )
        printk(XENLOG_WARNING
               "GICv2: GICC size=%#"PRIx64" but not aliased\n",
               csize);

    gicv2.map_hbase = ioremap_nocache(hbase, PAGE_SIZE);
    if ( !gicv2.map_hbase )
        panic("GICv2: Failed to ioremap for GIC Virtual interface\n");

    vgic_v2_setup_hw(dbase, cbase, csize, vbase, aliased_offset);

    /* Global settings: interrupt distributor */
    spin_lock_init(&gicv2.lock);
    spin_lock(&gicv2.lock);

    gicv2_dist_init();
    gicv2_cpu_init();
    gicv2_hyp_init();

    spin_unlock(&gicv2.lock);

    return 0;
}

static void gicv2_do_LPI(unsigned int lpi)
{
    /* No LPIs in a GICv2 */
    BUG();
}

const static struct gic_hw_operations gicv2_ops = {
    .info                = &gicv2_info,
    .init                = gicv2_init,
    .secondary_init      = gicv2_secondary_cpu_init,
    .save_state          = gicv2_save_state,
    .restore_state       = gicv2_restore_state,
    .dump_state          = gicv2_dump_state,
    .gic_host_irq_type   = &gicv2_host_irq_type,
    .gic_guest_irq_type  = &gicv2_guest_irq_type,
    .eoi_irq             = gicv2_eoi_irq,
    .deactivate_irq      = gicv2_dir_irq,
    .read_irq            = gicv2_read_irq,
    .set_irq_type        = gicv2_set_irq_type,
    .set_irq_priority    = gicv2_set_irq_priority,
    .send_SGI            = gicv2_send_SGI,
    .disable_interface   = gicv2_disable_interface,
    .update_lr           = gicv2_update_lr,
    .update_hcr_status   = gicv2_hcr_status,
    .clear_lr            = gicv2_clear_lr,
    .read_lr             = gicv2_read_lr,
    .write_lr            = gicv2_write_lr,
    .read_vmcr_priority  = gicv2_read_vmcr_priority,
    .read_apr            = gicv2_read_apr,
    .make_hwdom_dt_node  = gicv2_make_hwdom_dt_node,
    .make_hwdom_madt     = gicv2_make_hwdom_madt,
    .get_hwdom_extra_madt_size = gicv2_get_hwdom_extra_madt_size,
    .map_hwdom_extra_mappings = gicv2_map_hwdown_extra_mappings,
    .iomem_deny_access   = gicv2_iomem_deny_access,
    .do_LPI              = gicv2_do_LPI,
};

/* Set up the GIC */
static int __init gicv2_dt_preinit(struct dt_device_node *node,
                                   const void *data)
{
    gicv2_info.hw_version = GIC_V2;
    gicv2_info.node = node;
    register_gic_ops(&gicv2_ops);
    dt_irq_xlate = gic_irq_xlate;

    return 0;
}

static const struct dt_device_match gicv2_dt_match[] __initconst =
{
    DT_MATCH_GIC_V2,
    { /* sentinel */ },
};

DT_DEVICE_START(gicv2, "GICv2", DEVICE_GIC)
        .dt_match = gicv2_dt_match,
        .init = gicv2_dt_preinit,
DT_DEVICE_END

#ifdef CONFIG_ACPI
/* Set up the GIC */
static int __init gicv2_acpi_preinit(const void *data)
{
    gicv2_info.hw_version = GIC_V2;
    register_gic_ops(&gicv2_ops);

    return 0;
}

ACPI_DEVICE_START(agicv2, "GICv2", DEVICE_GIC)
        .class_type = ACPI_MADT_GIC_VERSION_V2,
        .init = gicv2_acpi_preinit,
ACPI_DEVICE_END
#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
