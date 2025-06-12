/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Based on Linux drivers/pci/controller/dwc/pcie-designware.c
 * Based on xen/arch/arm/pci/pci-host-generic.c
 *
 */

#include <xen/delay.h>
#include <asm/io.h>

#include "pci-designware.h"
/**
 * upper_32_bits - return bits 32-63 of a number
 * @n: the number we're accessing
 *
 * A basic shift-right of a 64- or 32-bit quantity.  Use this to suppress
 * the "right shift count >= width of type" warning when that quantity is
 * 32-bits.
 */
#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((uint32_t)((n) & 0xffffffffU))

static int dw_pcie_read(void __iomem *addr, unsigned int len, uint32_t *val)
{
    if ( !IS_ALIGNED((uintptr_t)addr, len) )
    {
        *val = 0;
        return -EFAULT;
    }

    switch ( len )
    {
    case 1:
        *val = readb(addr);
        break;
    case 2:
        *val = readw(addr);
        break;
    case 4:
        *val = readl(addr);
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return 0;
}

static int dw_pcie_write(void __iomem *addr, unsigned int len, uint32_t val)
{
    if ( !IS_ALIGNED((uintptr_t)addr, len) )
        return -EFAULT;

    switch ( len )
    {
    case 1:
        writeb(val, addr);
        break;
    case 2:
        writew(val, addr);
        break;
    case 4:
        writel(val, addr);
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return 0;
}

static uint32_t dw_pcie_read_dbi(struct pci_host_bridge *bridge, uint32_t reg,
                                 size_t size)
{
    void __iomem *addr = bridge->cfg->win + reg;
    uint32_t val;
    int ret;

    ret = dw_pcie_read(addr, size, &val);
    if ( ret )
        printk(XENLOG_G_ERR "Read DBI address failed\n");

    return val;
}

static void dw_pcie_write_dbi(struct pci_host_bridge *bridge, uint32_t reg,
                              size_t size, uint32_t val)
{
    void __iomem *addr = bridge->cfg->win + reg;
    int ret;

    ret = dw_pcie_write(addr, size, val);
    if ( ret )
        printk(XENLOG_G_ERR "Write DBI address failed\n");
}

static uint32_t dw_pcie_readl_dbi(struct pci_host_bridge *bridge, uint32_t reg)
{
    return dw_pcie_read_dbi(bridge, reg, sizeof(uint32_t));
}

static void dw_pcie_writel_dbi(struct pci_host_bridge *pci, uint32_t reg,
                               uint32_t val)
{
    dw_pcie_write_dbi(pci, reg, sizeof(uint32_t), val);
}

static void dw_pcie_read_iatu_unroll_enabled(struct pci_host_bridge *bridge)
{
    struct dw_pcie_priv *priv = bridge->priv;
    uint32_t val;

    val = dw_pcie_readl_dbi(bridge, PCIE_ATU_VIEWPORT);
    if ( val == 0xffffffffU )
        priv->iatu_unroll_enabled = true;

    printk(XENLOG_G_DEBUG "%s iATU unroll: %sabled\n",
           dt_node_full_name(bridge->dt_node),
           priv->iatu_unroll_enabled ? "en" : "dis");
}

static uint32_t dw_pcie_readl_atu(struct pci_host_bridge *pci, uint32_t reg)
{
    struct dw_pcie_priv *priv = pci->priv;
    int ret;
    uint32_t val;

    ret = dw_pcie_read(priv->atu_base + reg, 4, &val);
    if ( ret )
        printk(XENLOG_G_ERR "Read ATU address %x failed\n", reg);

    return val;
}

static void dw_pcie_writel_atu(struct pci_host_bridge *pci, uint32_t reg,
                               uint32_t val)
{
    struct dw_pcie_priv *priv = pci->priv;
    int ret;

    ret = dw_pcie_write(priv->atu_base + reg, 4, val);
    if ( ret )
        printk(XENLOG_G_ERR "Write ATU address %x failed\n", reg);
}

static uint32_t dw_pcie_readl_ob_unroll(struct pci_host_bridge *pci,
                                        uint32_t index, uint32_t reg)
{
    uint32_t offset = PCIE_GET_ATU_OUTB_UNR_REG_OFFSET(index);

    return dw_pcie_readl_atu(pci, offset + reg);
}

static void dw_pcie_writel_ob_unroll(struct pci_host_bridge *pci,
                                     uint32_t index, uint32_t reg, uint32_t val)
{
    uint32_t offset = PCIE_GET_ATU_OUTB_UNR_REG_OFFSET(index);

    dw_pcie_writel_atu(pci, offset + reg, val);
}

static int dw_pcie_prog_outbound_atu_unroll(struct pci_host_bridge *pci,
                                            uint8_t func_no, int index,
                                            int type, uint64_t cpu_addr,
                                            uint64_t pci_addr, uint64_t size)
{
    uint32_t retries, val;
    uint64_t limit_addr = cpu_addr + size - 1;

    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_LOWER_BASE,
                             lower_32_bits(cpu_addr));
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_UPPER_BASE,
                             upper_32_bits(cpu_addr));
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_LOWER_LIMIT,
                             lower_32_bits(limit_addr));
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_UPPER_LIMIT,
                             upper_32_bits(limit_addr));
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_LOWER_TARGET,
                             lower_32_bits(pci_addr));
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_UPPER_TARGET,
                             upper_32_bits(pci_addr));
    val = type | PCIE_ATU_FUNC_NUM(func_no);
    val = upper_32_bits(size - 1) ? val | PCIE_ATU_INCREASE_REGION_SIZE : val;
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_REGION_CTRL1, val);
    dw_pcie_writel_ob_unroll(pci, index, PCIE_ATU_UNR_REGION_CTRL2,
                             PCIE_ATU_ENABLE);

    /*
     * Make sure ATU enable takes effect before any subsequent config
     * and I/O accesses.
     */
    for ( retries = 0; retries < LINK_WAIT_MAX_IATU_RETRIES; retries++ )
    {
        val = dw_pcie_readl_ob_unroll(pci, index, PCIE_ATU_UNR_REGION_CTRL2);
        if ( val & PCIE_ATU_ENABLE )
            return 0;

        mdelay(LINK_WAIT_IATU_DELAY_MS);
    }
    printk(XENLOG_G_ERR "Outbound iATU is not being enabled\n");

    return -ENXIO;
}

static int __dw_pcie_prog_outbound_atu(struct pci_host_bridge *pci,
                                       uint8_t func_no, int index, int type,
                                       uint64_t cpu_addr, uint64_t pci_addr,
                                       uint64_t size)
{
    struct dw_pcie_priv *priv = pci->priv;
    uint32_t retries, val;

    if ( priv->iatu_unroll_enabled )
        return dw_pcie_prog_outbound_atu_unroll(pci, func_no, index, type,
                                                cpu_addr, pci_addr, size);

    dw_pcie_writel_dbi(pci, PCIE_ATU_VIEWPORT,
                       PCIE_ATU_REGION_OUTBOUND | index);
    dw_pcie_writel_dbi(pci, PCIE_ATU_LOWER_BASE, lower_32_bits(cpu_addr));
    dw_pcie_writel_dbi(pci, PCIE_ATU_UPPER_BASE, upper_32_bits(cpu_addr));
    dw_pcie_writel_dbi(pci, PCIE_ATU_LIMIT, lower_32_bits(cpu_addr + size - 1));
    if ( priv->version >= 0x460A )
        dw_pcie_writel_dbi(pci, PCIE_ATU_UPPER_LIMIT,
                           upper_32_bits(cpu_addr + size - 1));
    dw_pcie_writel_dbi(pci, PCIE_ATU_LOWER_TARGET, lower_32_bits(pci_addr));
    dw_pcie_writel_dbi(pci, PCIE_ATU_UPPER_TARGET, upper_32_bits(pci_addr));
    val = type | PCIE_ATU_FUNC_NUM(func_no);
    val = ((upper_32_bits(size - 1)) && (priv->version >= 0x460A))
              ? val | PCIE_ATU_INCREASE_REGION_SIZE
              : val;
    dw_pcie_writel_dbi(pci, PCIE_ATU_CR1, val);
    dw_pcie_writel_dbi(pci, PCIE_ATU_CR2, PCIE_ATU_ENABLE);

    /*
     * Make sure ATU enable takes effect before any subsequent config
     * and I/O accesses.
     */
    for ( retries = 0; retries < LINK_WAIT_MAX_IATU_RETRIES; retries++ )
    {
        val = dw_pcie_readl_dbi(pci, PCIE_ATU_CR2);
        if ( val & PCIE_ATU_ENABLE )
            return 0;

        mdelay(LINK_WAIT_IATU_DELAY_MS);
    }
    printk(XENLOG_G_ERR "Outbound iATU is not being enabled\n");

    return -ENXIO;
}

static int dw_pcie_prog_outbound_atu(struct pci_host_bridge *pci, int index,
                                     int type, uint64_t cpu_addr,
                                     uint64_t pci_addr, uint64_t size)
{
    return __dw_pcie_prog_outbound_atu(pci, 0, index, type, cpu_addr, pci_addr,
                                       size);
}

void dw_pcie_set_version(struct pci_host_bridge *bridge, unsigned int version)
{
    struct dw_pcie_priv *priv = bridge->priv;

    priv->version = version;
}

void __iomem *dw_pcie_child_map_bus(struct pci_host_bridge *bridge,
                                    pci_sbdf_t sbdf, uint32_t where)
{
    uint32_t busdev;
    int ret;

    busdev = PCIE_ATU_BUS(sbdf.bus) | PCIE_ATU_DEV(PCI_SLOT(sbdf.devfn)) |
             PCIE_ATU_FUNC(PCI_FUNC(sbdf.devfn));

    /* FIXME: Parent is the root bus, so use PCIE_ATU_TYPE_CFG0. */
    ret = dw_pcie_prog_outbound_atu(bridge, PCIE_ATU_REGION_INDEX1,
                                    PCIE_ATU_TYPE_CFG0,
                                    bridge->child_cfg->phys_addr, busdev,
                                    bridge->child_cfg->size);
    if ( ret )
        return 0;

    return bridge->child_cfg->win + where;
}

int dw_pcie_child_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                              uint32_t reg, uint32_t len, uint32_t *value)
{
    struct dw_pcie_priv *priv = bridge->priv;
    int ret;

    /*
     * FIXME: we cannot read iATU settings at the early initialization
     * (probe) as the host's HW is not yet initialized at that phase.
     * This read operation is the very first thing Domain-0 will do
     * during its initialization, so take this opportunity and read
     * iATU setting now.
     */
    if ( unlikely(!priv->iatu_unroll_initilized) )
    {
        dw_pcie_read_iatu_unroll_enabled(bridge);
        priv->iatu_unroll_initilized = true;
    }

    ret = pci_generic_config_read(bridge, sbdf, reg, len, value);
    if ( !ret && (priv->num_viewport <= 2) )
        ret = dw_pcie_prog_outbound_atu(bridge, PCIE_ATU_REGION_INDEX1,
                                        PCIE_ATU_TYPE_IO,
                                        bridge->child_cfg->phys_addr, 0,
                                        bridge->child_cfg->size);

    return ret;
}

int dw_pcie_child_config_write(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                               uint32_t reg, uint32_t len, uint32_t value)
{
    struct dw_pcie_priv *priv = bridge->priv;
    int ret;

    ret = pci_generic_config_write(bridge, sbdf, reg, len, value);
    if ( !ret && (priv->num_viewport <= 2) )
        ret = dw_pcie_prog_outbound_atu(bridge, PCIE_ATU_REGION_INDEX1,
                                        PCIE_ATU_TYPE_IO,
                                        bridge->child_cfg->phys_addr, 0,
                                        bridge->child_cfg->size);
    return ret;
}

bool __init dw_pcie_child_need_p2m_hwdom_mapping(struct domain *d,
                                                 struct pci_host_bridge *bridge,
                                                 uint64_t addr)
{
    struct pci_config_window *cfg = bridge->child_cfg;

    /*
     * We do not want ECAM address space to be mapped in Domain-0's p2m,
     * so we can trap access to it.
     */
    return cfg->phys_addr != addr;
}

struct pci_host_bridge *__init
dw_pcie_host_probe(struct dt_device_node *dev, const void *data,
                   const struct pci_ecam_ops *ops,
                   const struct pci_ecam_ops *child_ops)
{
    struct pci_host_bridge *bridge;
    struct dw_pcie_priv *priv;

    paddr_t atu_phys_addr;
    paddr_t atu_size;
    int atu_idx, ret;

    bridge = pci_host_common_probe(dev, ops, child_ops);
    if ( IS_ERR(bridge) )
        return bridge;

    priv = xzalloc(struct dw_pcie_priv);
    if ( !priv )
        return ERR_PTR(-ENOMEM);

    bridge->priv = priv;

    atu_idx = dt_property_match_string(dev, "reg-names", "atu");
    if ( atu_idx < 0 )
    {
        printk(XENLOG_ERR "Cannot find \"atu\" range index in device tree\n");
        return ERR_PTR(atu_idx);
    }
    ret = dt_device_get_address(dev, atu_idx, &atu_phys_addr, &atu_size);
    if ( ret )
    {
        printk(XENLOG_ERR "Cannot find \"atu\" range in device tree\n");
        return ERR_PTR(ret);
    }
    printk("iATU at [mem 0x%" PRIpaddr "-0x%" PRIpaddr "]\n", atu_phys_addr,
           atu_phys_addr + atu_size - 1);
    priv->atu_base = ioremap_nocache(atu_phys_addr, atu_size);
    if ( !priv->atu_base )
    {
        printk(XENLOG_ERR "iATU ioremap failed\n");
        return ERR_PTR(ENXIO);
    }

    if ( !dt_property_read_u32(dev, "num-viewport", &priv->num_viewport) )
        priv->num_viewport = 2;

    /*
     * FIXME: we cannot read iATU unroll enable now as the host bridge's
     * HW is not yet initialized by Domain-0: leave it for later.
     */

    printk(XENLOG_INFO "%s number of view ports: %d\n", dt_node_full_name(dev),
           priv->num_viewport);

    return bridge;
}
