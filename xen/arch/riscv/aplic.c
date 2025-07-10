/* SPDX-License-Identifier: MIT */

/*
 * xen/arch/riscv/aplic.c
 *
 * RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) 2023-2024 Microchip.
 * Copyright (c) 2024-2025 Vates
 */

#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/sections.h>
#include <xen/spinlock.h>
#include <xen/types.h>
#include <xen/vmap.h>

#include "aplic-priv.h"

#include <asm/device.h>
#include <asm/imsic.h>
#include <asm/intc.h>
#include <asm/io.h>
#include <asm/riscv_encoding.h>

#define APLIC_DEFAULT_PRIORITY  1

static struct aplic_priv aplic = {
    .lock = SPIN_LOCK_UNLOCKED,
};

static struct intc_info __ro_after_init aplic_info = {
    .hw_version = INTC_APLIC,
};

static void __init aplic_init_hw_interrupts(void)
{
    unsigned int i;

    /* Disable all interrupts */
    for ( i = 0; i < ARRAY_SIZE(aplic.regs->clrie); i++)
        writel(~0U, &aplic.regs->clrie[i]);

    /* Set interrupt type and default priority for all interrupts */
    for ( i = 0; i < aplic_info.num_irqs; i++ )
    {
        writel(0, &aplic.regs->sourcecfg[i]);
        /*
         * Low bits of target register contains Interrupt Priority bits which
         * can't be zero according to AIA spec.
         * Thereby they are initialized to APLIC_DEFAULT_PRIORITY.
         */
        writel(APLIC_DEFAULT_PRIORITY, &aplic.regs->target[i]);
    }

    writel(APLIC_DOMAINCFG_IE | APLIC_DOMAINCFG_DM, &aplic.regs->domaincfg);
}

static int __init cf_check aplic_init(void)
{
    dt_phandle imsic_phandle;
    const __be32 *prop;
    uint64_t size, paddr;
    const struct dt_device_node *imsic_node;
    const struct dt_device_node *node = aplic_info.node;
    int rc;

    /* Check for associated imsic node */
    if ( !dt_property_read_u32(node, "msi-parent", &imsic_phandle) )
        panic("%s: IDC mode not supported\n", node->full_name);

    imsic_node = dt_find_node_by_phandle(imsic_phandle);
    if ( !imsic_node )
        panic("%s: unable to find IMSIC node\n", node->full_name);

    rc = imsic_init(imsic_node);
    if ( rc == IRQ_M_EXT )
        /* Machine mode imsic node, ignore this aplic node */
        return 0;

    if ( rc )
        panic("%s: Failed to initialize IMSIC\n", node->full_name);

    /* Find out number of interrupt sources */
    if ( !dt_property_read_u32(node, "riscv,num-sources",
                               &aplic_info.num_irqs) )
        panic("%s: failed to get number of interrupt sources\n",
              node->full_name);

    if ( aplic_info.num_irqs > ARRAY_SIZE(aplic.regs->sourcecfg) )
        aplic_info.num_irqs = ARRAY_SIZE(aplic.regs->sourcecfg);

    prop = dt_get_property(node, "reg", NULL);
    dt_get_range(&prop, node, &paddr, &size);
    if ( !paddr )
        panic("%s: first MMIO resource not found\n", node->full_name);

    if ( !IS_ALIGNED(paddr, KB(4)) )
        panic("%s: paddr of memory-mapped control region should be 4Kb aligned:%#lx\n",
              __func__, paddr);

    if ( !IS_ALIGNED(size, KB(4)) || (size < KB(16)) )
        panic("%s: control region size must be >= 16KB and 4KB-aligned:%#lx\n",
              __func__, size);

    aplic.paddr_start = paddr;
    aplic.size = size;

    aplic.regs = ioremap(paddr, size);
    if ( !aplic.regs )
        panic("%s: unable to map\n", node->full_name);

    /* Setup initial state APLIC interrupts */
    aplic_init_hw_interrupts();

    return 0;
}

static void cf_check aplic_irq_enable(struct irq_desc *desc)
{
    /*
     * TODO: Currently, APLIC is supported only with MSI interrupts.
     *       If APLIC without MSI interrupts is required in the future,
     *       this function will need to be updated accordingly.
     */
    ASSERT(readl(&aplic.regs->domaincfg) & APLIC_DOMAINCFG_DM);

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock(&aplic.lock);

    /* Enable interrupt in IMSIC */
    imsic_irq_enable(desc->irq);

    /* Enable interrupt in APLIC */
    writel(desc->irq, &aplic.regs->setienum);

    spin_unlock(&aplic.lock);
}

static void cf_check aplic_irq_disable(struct irq_desc *desc)
{
    /*
     * TODO: Currently, APLIC is supported only with MSI interrupts.
     *       If APLIC without MSI interrupts is required in the future,
     *       this function will need to be updated accordingly.
     */
    ASSERT(readl(&aplic.regs->domaincfg) & APLIC_DOMAINCFG_DM);

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock(&aplic.lock);

    /* Disable interrupt in APLIC */
    writel(desc->irq, &aplic.regs->clrienum);

    /* Disable interrupt in IMSIC */
    imsic_irq_disable(desc->irq);

    spin_unlock(&aplic.lock);
}

static unsigned int cf_check aplic_irq_startup(struct irq_desc *desc)
{
    aplic_irq_enable(desc);

    return 0;
}

static unsigned int aplic_get_cpu_from_mask(const cpumask_t *cpumask)
{
    cpumask_t mask;

    cpumask_and(&mask, cpumask, &cpu_online_map);

    return cpumask_any(&mask);
}

static void cf_check aplic_set_irq_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    unsigned int cpu;
    uint64_t group_index, base_ppn;
    uint32_t hhxw, lhxw, hhxs, value;
    const struct imsic_config *imsic = aplic.imsic_cfg;

    /*
     * TODO: Currently, APLIC is supported only with MSI interrupts.
     *       If APLIC without MSI interrupts is required in the future,
     *       this function will need to be updated accordingly.
     */
    ASSERT(readl(&aplic.regs->domaincfg) & APLIC_DOMAINCFG_DM);

    ASSERT(!cpumask_empty(mask));

    ASSERT(spin_is_locked(&desc->lock));

    cpu = cpuid_to_hartid(aplic_get_cpu_from_mask(mask));
    hhxw = imsic->group_index_bits;
    lhxw = imsic->hart_index_bits;
    /*
     * Although this variable is used only once in the calculation of
     * group_index, and it might seem that hhxs could be defined as:
     *   hhxs = imsic->group_index_shift - IMSIC_MMIO_PAGE_SHIFT;
     * and then the addition of IMSIC_MMIO_PAGE_SHIFT could be omitted
     * when calculating the group index.
     * It was done intentionally this way to follow the formula from
     * the AIA specification for calculating the MSI address.
     */
    hhxs = imsic->group_index_shift - IMSIC_MMIO_PAGE_SHIFT * 2;
    base_ppn = imsic->msi[cpu].base_addr >> IMSIC_MMIO_PAGE_SHIFT;

    /* Update hart and EEID in the target register */
    group_index = (base_ppn >> (hhxs + IMSIC_MMIO_PAGE_SHIFT)) &
                  (BIT(hhxw, UL) - 1);
    value = desc->irq;
    value |= cpu << APLIC_TARGET_HART_IDX_SHIFT;
    value |= group_index << (lhxw + APLIC_TARGET_HART_IDX_SHIFT);

    spin_lock(&aplic.lock);

    writel(value, &aplic.regs->target[desc->irq - 1]);

    spin_unlock(&aplic.lock);
}

static const hw_irq_controller aplic_xen_irq_type = {
    .typename     = "aplic",
    .startup      = aplic_irq_startup,
    .shutdown     = aplic_irq_disable,
    .enable       = aplic_irq_enable,
    .disable      = aplic_irq_disable,
    .set_affinity = aplic_set_irq_affinity,
};

static const struct intc_hw_operations aplic_ops = {
    .info                = &aplic_info,
    .init                = aplic_init,
    .host_irq_type       = &aplic_xen_irq_type,
};

static int cf_check aplic_irq_xlate(const uint32_t *intspec,
                                    unsigned int intsize,
                                    unsigned int *out_hwirq,
                                    unsigned int *out_type)
{
    if ( intsize < 2 )
        return -EINVAL;

    /* Mapping 1:1 */
    *out_hwirq = intspec[0];

    if ( out_type )
        *out_type = intspec[1] & IRQ_TYPE_SENSE_MASK;

    return 0;
}

static int __init aplic_preinit(struct dt_device_node *node, const void *dat)
{
    if ( aplic_info.node )
    {
        printk("XEN doesn't support more than one S mode APLIC\n");
        return -ENODEV;
    }

    /* don't process if APLIC node is not for S mode */
    if ( dt_get_property(node, "riscv,children", NULL) )
        return -ENODEV;

    aplic_info.node = node;

    aplic.imsic_cfg = imsic_get_config();

    dt_irq_xlate = aplic_irq_xlate;

    register_intc_ops(&aplic_ops);

    return 0;
}

static const struct dt_device_match __initconstrel aplic_dt_match[] =
{
    DT_MATCH_COMPATIBLE("riscv,aplic"),
    { /* sentinel */ },
};

DT_DEVICE_START(aplic, "APLIC", DEVICE_INTERRUPT_CONTROLLER)
    .dt_match = aplic_dt_match,
    .init = aplic_preinit,
DT_DEVICE_END
