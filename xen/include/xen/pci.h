/******************************************************************************
 * pci.h
 * 
 * PCI access functions.
 */

#ifndef __XEN_PCI_H__
#define __XEN_PCI_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/list.h>

/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 * 15:8 = bus
 *  7:3 = slot
 *  2:0 = function
 */
#define PCI_DEVFN(slot,func)  (((slot & 0x1f) << 3) | (func & 0x07))
#define PCI_SLOT(devfn)       (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)       ((devfn) & 0x07)

struct pci_dev {
    struct list_head list;
    struct list_head msi_dev_list;
    u8 bus;
    u8 devfn;
    struct list_head msi_list;
};

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
int pci_find_cap_offset(u8 bus, u8 dev, u8 func, u8 cap);
int pci_find_next_cap(u8 bus, unsigned int devfn, u8 pos, int cap);

#endif /* __XEN_PCI_H__ */
