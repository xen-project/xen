/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Based on xen/arch/arm/pci/pci-host-generic.c
 */

#include <xen/init.h>
#include <xen/pci.h>

#include <asm/device.h>
#include <asm/io.h>
#include <asm/pci.h>

#include "pci-designware.h"

#define RCAR4_DWC_VERSION       0x520A

/* PCIE BDF-OSID assignment */
#define CNVID(n)             (0x700 + ((n) * 4))
#define CNVID_CNV_EN         (1U << 31)
#define CNVID_OSID_MASK      (0x0F << 16)
#define CNVID_OSID_SHIFT     16
#define CNVID_BDF_MASK       (0xFFFF << 0)
#define CNVID_BDF_SHIFT      0

#define CNVIDMSK(n)                (0x780 + ((n) * 4))
#define CNVIDMSK_BDF_MSK_MASK      (0xFFFF << 0)
#define CNVIDMSK_BDF_MSK_SHIFT     0

#define CNVOSIDCTRL                0x800
#define CNVOSIDCTRL_OSID_MASK      (0x0F << 16)
#define CNVOSIDCTRL_OSID_SHIFT     16

#define DEFAULT_OSID    0

#define NUM_OSID_REGS    16

struct rcar4_pcie_priv {
    bool init_done;
    void __iomem *app_base;
    DECLARE_BITMAP(osid_regs, NUM_OSID_REGS);
};

/*
 * PCI host bridges often have different ways to access the root and child
 * bus config spaces:
 *   "dbi"   : the aperture where root port's own configuration registers
 *             are available.
 *   "config": child's configuration space
 *   "atu"   : iATU registers for DWC version 4.80 or later
 */
static int __init rcar4_cfg_reg_index(struct dt_device_node *np)
{
    return dt_property_match_string(np, "reg-names", "dbi");
}

static int __init rcar4_child_cfg_reg_index(struct dt_device_node *np)
{
    return dt_property_match_string(np, "reg-names", "config");
}

/* ECAM ops */
const struct pci_ecam_ops rcar4_pcie_ops = {
    .bus_shift  = 20,
    .cfg_reg_index = rcar4_cfg_reg_index,
    .pci_ops    = {
        .map_bus                = pci_ecam_map_bus,
        .read                   = pci_generic_config_read,
        .write                  = pci_generic_config_write,
        .need_p2m_hwdom_mapping = pci_ecam_need_p2m_hwdom_mapping,
        .init_bus_range         = pci_generic_init_bus_range,
    }
};

const struct pci_ecam_ops rcar4_pcie_child_ops = {
    .bus_shift  = 20,
    .cfg_reg_index = rcar4_child_cfg_reg_index,
    .pci_ops    = {
        .map_bus                = dw_pcie_child_map_bus,
        .read                   = dw_pcie_child_config_read,
        .write                  = dw_pcie_child_config_write,
        .need_p2m_hwdom_mapping = dw_pcie_child_need_p2m_hwdom_mapping,
        .init_bus_range         = pci_generic_init_bus_range_child,
    }
};

static const struct dt_device_match __initconstrel rcar4_pcie_dt_match[] = {
    { .compatible = "renesas,r8a779f0-pcie" },
    { .compatible = "renesas,r8a779g0-pcie" },
    {},
};

static void rcar4_pcie_writel_app(struct rcar4_pcie_priv *pci, uint32_t reg,
                                  uint32_t val)
{
    writel(val, pci->app_base + reg);
}

static uint32_t rcar4_pcie_readl_app(struct rcar4_pcie_priv *pci, uint32_t reg)
{
    return readl(pci->app_base + reg);
}

int rcar4_pcie_osid_regs_init(struct pci_host_bridge *bridge)
{
    struct rcar4_pcie_priv *priv = dw_pcie_get_priv(bridge);
    uint32_t val = rcar4_pcie_readl_app(priv, CNVOSIDCTRL);

    if ( priv->init_done )
        return 0;
    priv->init_done = true;

    val = (val & ~CNVOSIDCTRL_OSID_MASK) |
          (DEFAULT_OSID << CNVOSIDCTRL_OSID_SHIFT);
    rcar4_pcie_writel_app(priv, CNVOSIDCTRL, val);
    bitmap_zero(priv->osid_regs, NUM_OSID_REGS);

    printk("%s: Initialized OSID regs (default OSID %u)\n",
           bridge->dt_node->full_name, DEFAULT_OSID);

    return 0;
}

int rcar4_pcie_osid_reg_alloc(struct pci_host_bridge *bridge)
{
    struct rcar4_pcie_priv *priv = dw_pcie_get_priv(bridge);
    int ret;

    ret = find_first_zero_bit(priv->osid_regs, NUM_OSID_REGS);
    if ( ret != NUM_OSID_REGS )
        set_bit(ret, priv->osid_regs);
    else
        ret = -EBUSY;

    return ret;
}

void rcar4_pcie_osid_reg_free(struct pci_host_bridge *bridge,
                              unsigned int reg_id)
{
    struct rcar4_pcie_priv *priv = dw_pcie_get_priv(bridge);

    clear_bit(reg_id, priv->osid_regs);
}

void rcar4_pcie_osid_bdf_set(struct pci_host_bridge *bridge,
                             unsigned int reg_id, uint32_t osid, uint32_t bdf)
{
    struct rcar4_pcie_priv *priv = dw_pcie_get_priv(bridge);
    uint32_t data = rcar4_pcie_readl_app(priv, CNVID(reg_id));

    data &= ~(CNVID_OSID_MASK | CNVID_BDF_MASK);
    data |= CNVID_CNV_EN | (osid << CNVID_OSID_SHIFT) |
            (bdf << CNVID_BDF_SHIFT);
    rcar4_pcie_writel_app(priv, CNVID(reg_id), data);
}

void rcar4_pcie_osid_bdf_clear(struct pci_host_bridge *bridge,
                               unsigned int reg_id)
{
    struct rcar4_pcie_priv *priv = dw_pcie_get_priv(bridge);
    uint32_t data = rcar4_pcie_readl_app(priv, CNVID(reg_id));

    data &= ~CNVID_CNV_EN;
    rcar4_pcie_writel_app(priv, CNVID(reg_id), data);
}

void rcar4_pcie_bdf_msk_set(struct pci_host_bridge *bridge, unsigned int reg_id,
                            uint32_t data)
{
    struct rcar4_pcie_priv *priv = dw_pcie_get_priv(bridge);

    uint32_t val = rcar4_pcie_readl_app(priv, CNVIDMSK(reg_id));

    val = (val & ~CNVIDMSK_BDF_MSK_MASK) | (data << CNVIDMSK_BDF_MSK_SHIFT);

    rcar4_pcie_writel_app(priv, CNVIDMSK(reg_id), val);
}

static int __init pci_host_rcar4_probe(struct dt_device_node *dev,
                                       const void *data)
{
    struct pci_host_bridge *bridge;
    paddr_t app_phys_addr;
    paddr_t app_size;
    int app_idx, ret;

    struct rcar4_pcie_priv *priv = xzalloc(struct rcar4_pcie_priv);
    if ( !priv )
        return -ENOMEM;

    bridge = dw_pcie_host_probe(dev, data, &rcar4_pcie_ops,
                                &rcar4_pcie_child_ops);

    app_idx = dt_property_match_string(dev, "reg-names", "app");
    if ( app_idx < 0 )
    {
        printk(XENLOG_ERR "Cannot find \"app\" range index in device tree\n");
        ret = app_idx;
        goto err;
    }
    ret = dt_device_get_address(dev, app_idx, &app_phys_addr, &app_size);
    if ( ret )
    {
        printk(XENLOG_ERR "Cannot find \"app\" range in device tree\n");
        goto err;
    }

    priv->app_base = ioremap_nocache(app_phys_addr, app_size);
    if ( !priv->app_base )
    {
        printk(XENLOG_ERR "APP ioremap failed\n");
        ret = -ENXIO;
        goto err;
    }
    printk("APP at [mem 0x%" PRIpaddr "-0x%" PRIpaddr "]\n", app_phys_addr,
           app_phys_addr + app_size - 1);

    dw_pcie_set_priv(bridge, priv);
    dw_pcie_set_version(bridge, RCAR4_DWC_VERSION);

    return 0;
err:
    xfree(priv);
    return ret;
}

DT_DEVICE_START(pci_gen, "PCI HOST R-CAR GEN4", DEVICE_PCI_HOSTBRIDGE)
.dt_match = rcar4_pcie_dt_match,
.init = pci_host_rcar4_probe,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
