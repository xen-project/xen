/******************************************************************************
 * pci.c
 * 
 * Architecture-dependent PCI access functions.
 */

#include <xen/spinlock.h>
#include <xen/pci.h>
#include <xen/init.h>
#include <asm/io.h>

#define PCI_CONF_ADDRESS(bus, dev, func, reg) \
    (0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (reg & ~3))

uint8_t pci_conf_read8(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg)
{
    if ( seg || (reg > 255) )
        return ~0;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7));
    return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 3, 1);
}

uint16_t pci_conf_read16(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg)
{
    if ( seg || (reg > 255) )
        return ~0;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7));
    return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 2, 2);
}

uint32_t pci_conf_read32(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg)
{
    if ( seg || (reg > 255) )
        return ~0;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7));
    return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), 0, 4);
}

void pci_conf_write8(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg, uint8_t data)
{
    if ( seg )
        return;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 3, 1, data);
}

void pci_conf_write16(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg, uint16_t data)
{
    if ( seg )
        return;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 2, 2, data);
}

void pci_conf_write32(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg, uint32_t data)
{
    if ( seg )
        return;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), 0, 4, data);
}

void __init arch_pci_ro_device(int seg, int bdf)
{
}
