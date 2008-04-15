/******************************************************************************
 * pci.h
 * 
 * PCI access functions.
 */

#ifndef __XEN_PCI_H__
#define __XEN_PCI_H__

#include <xen/config.h>
#include <xen/types.h>

uint8_t pci_conf_read8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg);
uint16_t pci_conf_read16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg);
uint32_t pci_conf_read32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg);
void pci_conf_write8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint8_t data);
void pci_conf_write16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint16_t data);
void pci_conf_write32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint32_t data);

#endif /* __XEN_PCI_H__ */
