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

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <xen/list.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/sizes.h>
#include <asm/p2m.h>
#include <asm/domain.h>
#include <asm/platform.h>
#include <asm/device.h>

#include <asm/io.h>
#include <asm/gic.h>

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
#define GICH_V2_LR_PRIORITY_SHIFT  23
#define GICH_V2_LR_PRIORITY_MASK   0x1f
#define GICH_V2_LR_HW_SHIFT        31
#define GICH_V2_LR_HW_MASK         0x1
#define GICH_V2_LR_GRP_SHIFT       30
#define GICH_V2_LR_GRP_MASK        0x1
#define GICH_V2_LR_MAINTENANCE_IRQ (1<<19)
#define GICH_V2_LR_GRP1            (1<<30)
#define GICH_V2_LR_HW              (1<<31)
#define GICH_V2_LR_CPUID_SHIFT     9
#define GICH_V2_VTR_NRLRGS         0x3f

#define GICH_V2_VMCR_PRIORITY_MASK   0x1f
#define GICH_V2_VMCR_PRIORITY_SHIFT  27

/* Global state */
static struct {
    void __iomem * map_dbase; /* IO mapped Address of distributor registers */
    void __iomem * map_cbase[2]; /* IO mapped Address of CPU interface registers */
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
    unsigned int page = offset >> PAGE_SHIFT;
    offset &= ~PAGE_MASK;
    writel_relaxed(val, gicv2.map_cbase[page] + offset);
}

static inline uint32_t readl_gicc(unsigned int offset)
{
    unsigned int page = offset >> PAGE_SHIFT;
    offset &= ~PAGE_MASK;
    return readl_relaxed(gicv2.map_cbase[page] + offset);
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

/*
 * needs to be called with a valid cpu_mask, ie each cpu in the mask has
 * already called gic_cpu_init
 */
static void gicv2_set_irq_properties(struct irq_desc *desc,
                                   const cpumask_t *cpu_mask,
                                   unsigned int priority)
{
    uint32_t cfg, actual, edgebit;
    unsigned int mask = gicv2_cpu_mask(cpu_mask);
    unsigned int irq = desc->irq;
    unsigned int type = desc->arch.type;

    ASSERT(type != DT_IRQ_TYPE_INVALID);
    ASSERT(spin_is_locked(&desc->lock));

    spin_lock(&gicv2.lock);
    /* Set edge / level */
    cfg = readl_gicd(GICD_ICFGR + (irq / 16) * 4);
    edgebit = 2u << (2 * (irq % 16));
    if ( type & DT_IRQ_TYPE_LEVEL_MASK )
        cfg &= ~edgebit;
    else if ( type & DT_IRQ_TYPE_EDGE_BOTH )
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
            DT_IRQ_TYPE_EDGE_RISING :
            DT_IRQ_TYPE_LEVEL_HIGH;
    }

    /* Set target CPU mask (RAZ/WI on uniprocessor) */
    writeb_gicd(mask, GICD_ITARGETSR + irq);
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

static void __cpuinit gicv2_cpu_init(void)
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

static void __cpuinit gicv2_hyp_init(void)
{
    uint32_t vtr;
    uint8_t nr_lrs;

    vtr = readl_gich(GICH_VTR);
    nr_lrs  = (vtr & GICH_V2_VTR_NRLRGS) + 1;
    gicv2_info.nr_lrs = nr_lrs;
}

static void __cpuinit gicv2_hyp_disable(void)
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

static void gicv2_update_lr(int lr, const struct pending_irq *p,
                            unsigned int state)
{
    uint32_t lr_reg;

    BUG_ON(lr >= gicv2_info.nr_lrs);
    BUG_ON(lr < 0);

    lr_reg = (((state & GICH_V2_LR_STATE_MASK) << GICH_V2_LR_STATE_SHIFT)  |
              ((GIC_PRI_TO_GUEST(p->priority) & GICH_V2_LR_PRIORITY_MASK)
                                             << GICH_V2_LR_PRIORITY_SHIFT) |
              ((p->irq & GICH_V2_LR_VIRTUAL_MASK) << GICH_V2_LR_VIRTUAL_SHIFT));

    if ( p->desc != NULL )
        lr_reg |= GICH_V2_LR_HW | ((p->desc->irq & GICH_V2_LR_PHYSICAL_MASK )
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
    lr_reg->pirq = (lrv >> GICH_V2_LR_PHYSICAL_SHIFT) & GICH_V2_LR_PHYSICAL_MASK;
    lr_reg->virq = (lrv >> GICH_V2_LR_VIRTUAL_SHIFT) & GICH_V2_LR_VIRTUAL_MASK;
    lr_reg->priority = (lrv >> GICH_V2_LR_PRIORITY_SHIFT) & GICH_V2_LR_PRIORITY_MASK;
    lr_reg->state     = (lrv >> GICH_V2_LR_STATE_SHIFT) & GICH_V2_LR_STATE_MASK;
    lr_reg->hw_status = (lrv >> GICH_V2_LR_HW_SHIFT) & GICH_V2_LR_HW_MASK;
    lr_reg->grp       = (lrv >> GICH_V2_LR_GRP_SHIFT) & GICH_V2_LR_GRP_MASK;
}

static void gicv2_write_lr(int lr, const struct gic_lr *lr_reg)
{
    uint32_t lrv = 0;

    lrv = ( ((lr_reg->pirq & GICH_V2_LR_PHYSICAL_MASK) << GICH_V2_LR_PHYSICAL_SHIFT) |
          ((lr_reg->virq & GICH_V2_LR_VIRTUAL_MASK) << GICH_V2_LR_VIRTUAL_SHIFT)   |
          ((uint32_t)(lr_reg->priority & GICH_V2_LR_PRIORITY_MASK)
                                      << GICH_V2_LR_PRIORITY_SHIFT) |
          ((uint32_t)(lr_reg->state & GICH_V2_LR_STATE_MASK)
                                   << GICH_V2_LR_STATE_SHIFT) |
          ((uint32_t)(lr_reg->hw_status & GICH_V2_LR_HW_MASK)
                                       << GICH_V2_LR_HW_SHIFT)  |
          ((uint32_t)(lr_reg->grp & GICH_V2_LR_GRP_MASK) << GICH_V2_LR_GRP_SHIFT) );

    writel_gich(lrv, GICH_LR + lr * 4);
}

static void gicv2_hcr_status(uint32_t flag, bool_t status)
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
    int irq = desc->irq;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&gicv2.lock, flags);
    clear_bit(_IRQ_DISABLED, &desc->status);
    dsb(sy);
    /* Enable routing */
    writel_gicd((1u << (irq % 32)), GICD_ISENABLER + (irq / 32) * 4);
    spin_unlock_irqrestore(&gicv2.lock, flags);
}

static void gicv2_irq_disable(struct irq_desc *desc)
{
    unsigned long flags;
    int irq = desc->irq;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&gicv2.lock, flags);
    /* Disable routing */
    writel_gicd(1u << (irq % 32), GICD_ICENABLER + (irq / 32) * 4);
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

static int gicv2_make_hwdom_dt_node(const struct domain *d,
                                    const struct dt_device_node *node,
                                    void *fdt)
{
    const struct dt_device_node *gic = dt_interrupt_controller;
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

    len = dt_cells_to_size(dt_n_addr_cells(node) + dt_n_size_cells(node));
    len *= 2;

    res = fdt_property(fdt, "reg", regs, len);

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

static int __init gicv2_init(void)
{
    int res;
    paddr_t hbase, dbase, cbase, vbase;
    const struct dt_device_node *node = gicv2_info.node;

    res = dt_device_get_address(node, 0, &dbase, NULL);
    if ( res )
        panic("GICv2: Cannot find a valid address for the distributor");

    res = dt_device_get_address(node, 1, &cbase, NULL);
    if ( res )
        panic("GICv2: Cannot find a valid address for the CPU");

    res = dt_device_get_address(node, 2, &hbase, NULL);
    if ( res )
        panic("GICv2: Cannot find a valid address for the hypervisor");

    res = dt_device_get_address(node, 3, &vbase, NULL);
    if ( res )
        panic("GICv2: Cannot find a valid address for the virtual CPU");

    res = platform_get_irq(node, 0);
    if ( res < 0 )
        panic("GICv2: Cannot find the maintenance IRQ");
    gicv2_info.maintenance_irq = res;

    /* TODO: Add check on distributor, cpu size */

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

    gicv2.map_cbase[0] = ioremap_nocache(cbase, PAGE_SIZE);

    if ( platform_has_quirk(PLATFORM_QUIRK_GIC_64K_STRIDE) )
        gicv2.map_cbase[1] = ioremap_nocache(cbase + SZ_64K, PAGE_SIZE);
    else
        gicv2.map_cbase[1] = ioremap_nocache(cbase + PAGE_SIZE, PAGE_SIZE);

    if ( !gicv2.map_cbase[0] || !gicv2.map_cbase[1] )
        panic("GICv2: Failed to ioremap for GIC CPU interface\n");

    gicv2.map_hbase = ioremap_nocache(hbase, PAGE_SIZE);
    if ( !gicv2.map_hbase )
        panic("GICv2: Failed to ioremap for GIC Virtual interface\n");

    vgic_v2_setup_hw(dbase, cbase, vbase);

    /* Global settings: interrupt distributor */
    spin_lock_init(&gicv2.lock);
    spin_lock(&gicv2.lock);

    gicv2_dist_init();
    gicv2_cpu_init();
    gicv2_hyp_init();

    spin_unlock(&gicv2.lock);

    return 0;
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
    .set_irq_properties  = gicv2_set_irq_properties,
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
};

/* Set up the GIC */
static int __init gicv2_preinit(struct dt_device_node *node, const void *data)
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
        .init = gicv2_preinit,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
