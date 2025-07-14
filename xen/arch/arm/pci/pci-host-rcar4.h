/* SPDX-License-Identifier: GPL-2.0-only */
#include <asm/pci.h>

#ifndef __PCI_HOST_RCAR4_H__
#define __PCI_HOST_RCAR4_H__

void rcar4_pcie_osid_bdf_set(struct pci_host_bridge *bridge,
                             unsigned int reg_id, uint32_t osid, uint32_t bdf);
void rcar4_pcie_osid_bdf_clear(struct pci_host_bridge *bridge,
                               unsigned int reg_id);
void rcar4_pcie_bdf_msk_set(struct pci_host_bridge *bridge, unsigned int reg_id,
                            uint32_t data);
int rcar4_pcie_osid_reg_alloc(struct pci_host_bridge *bridge);
void rcar4_pcie_osid_reg_free(struct pci_host_bridge *bridge,
                              unsigned int reg_id);
int rcar4_pcie_osid_regs_init(struct pci_host_bridge *bridge);

#endif /* __PCI_HOST_RCAR4_H__ */
