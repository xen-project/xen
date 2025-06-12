/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Based on Linux drivers/pci/controller/dwc/pcie-designware.c
 * Based on xen/arch/arm/pci/pci-host-generic.c
 */

#include <xen/pci.h>
#include <xen/init.h>

#ifndef __PCI_DESIGNWARE_H__
#define __PCI_DESIGNWARE_H__


#define PCIE_ATU_VIEWPORT               0x900
#define PCIE_ATU_REGION_OUTBOUND        0
#define PCIE_ATU_CR1                    0x904
#define PCIE_ATU_INCREASE_REGION_SIZE   BIT(13, UL)
#define PCIE_ATU_CR2                    0x908
#define PCIE_ATU_ENABLE                 BIT(31, UL)
#define PCIE_ATU_LOWER_BASE             0x90C
#define PCIE_ATU_UPPER_BASE             0x910
#define PCIE_ATU_LIMIT                  0x914
#define PCIE_ATU_LOWER_TARGET           0x918
#define PCIE_ATU_UPPER_TARGET           0x91C
#define PCIE_ATU_UPPER_LIMIT            0x924

#define PCIE_ATU_REGION_INDEX1  0x1
#define PCIE_ATU_TYPE_IO        0x2
#define PCIE_ATU_TYPE_CFG0      0x4

#define FIELD_PREP(_mask, _val) \
    (((typeof(_mask))(_val) << (ffs64(_mask) - 1)) & (_mask))

#define PCIE_ATU_BUS(x)         FIELD_PREP(GENMASK(31, 24), (x))
#define PCIE_ATU_DEV(x)         FIELD_PREP(GENMASK(23, 19), (x))
#define PCIE_ATU_FUNC(x)        FIELD_PREP(GENMASK(18, 16), (x))

/* Register address builder */
#define PCIE_GET_ATU_OUTB_UNR_REG_OFFSET(region) \
    ((region) << 9)

/*
 * iATU Unroll-specific register definitions
 * From 4.80 core version the address translation will be made by unroll
 */
#define PCIE_ATU_UNR_REGION_CTRL1       0x00
#define PCIE_ATU_UNR_REGION_CTRL2       0x04
#define PCIE_ATU_UNR_LOWER_BASE         0x08
#define PCIE_ATU_UNR_UPPER_BASE         0x0C
#define PCIE_ATU_UNR_LOWER_LIMIT        0x10
#define PCIE_ATU_UNR_LOWER_TARGET       0x14
#define PCIE_ATU_UNR_UPPER_TARGET       0x18
#define PCIE_ATU_UNR_UPPER_LIMIT        0x20

#define PCIE_ATU_FUNC_NUM(pf)           ((pf) << 20)

/* Parameters for the waiting for iATU enabled routine */
#define LINK_WAIT_MAX_IATU_RETRIES      5
#define LINK_WAIT_IATU_DELAY_MS         10

struct dw_pcie_priv {
    uint32_t num_viewport;
    bool iatu_unroll_initilized;
    bool iatu_unroll_enabled;
    void __iomem *atu_base;
    unsigned int version;
};

void dw_pcie_set_version(struct pci_host_bridge *bridge, unsigned int version);

void __iomem *dw_pcie_child_map_bus(struct pci_host_bridge *bridge,
                                    pci_sbdf_t sbdf, uint32_t where);

int dw_pcie_child_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                              uint32_t reg, uint32_t len, uint32_t *value);

int dw_pcie_child_config_write(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                               uint32_t reg, uint32_t len, uint32_t value);

bool __init dw_pcie_child_need_p2m_hwdom_mapping(struct domain *d,
                                                 struct pci_host_bridge *bridge,
                                                 uint64_t addr);

struct pci_host_bridge *__init
dw_pcie_host_probe(struct dt_device_node *dev, const void *data,
                   const struct pci_ecam_ops *ops,
                   const struct pci_ecam_ops *child_ops);
#endif /* __PCI_DESIGNWARE_H__ */
