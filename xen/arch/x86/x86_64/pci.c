/******************************************************************************
 * pci.c
 * 
 * Architecture-dependent PCI access functions.
 */

#include <xen/spinlock.h>
#include <xen/pci.h>
#include <asm/io.h>

#define PCI_CONF_ADDRESS(bus, dev, func, reg) \
    (0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (reg & ~3))

int pci_mmcfg_read(unsigned int seg, unsigned int bus,
                   unsigned int devfn, int reg, int len, u32 *value);
int pci_mmcfg_write(unsigned int seg, unsigned int bus,
                    unsigned int devfn, int reg, int len, u32 value);
uint32_t pci_conf_read(uint32_t cf8, uint8_t offset, uint8_t bytes);
void pci_conf_write(uint32_t cf8, uint8_t offset, uint8_t bytes, uint32_t data);

uint8_t pci_conf_read8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    u32 value;

    if ( reg > 255 )
    {
        pci_mmcfg_read(0, bus, PCI_DEVFN(dev, func), reg, 1, &value);
        return value;
    }
    else
    {
        BUG_ON((bus > 255) || (dev > 31) || (func > 7));
        return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 3, 1);
    }
}

uint16_t pci_conf_read16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    u32 value;

    if ( reg > 255 )
    {
        pci_mmcfg_read(0, bus, PCI_DEVFN(dev, func), reg, 2, &value);
        return value;
    }
    else
    {
        BUG_ON((bus > 255) || (dev > 31) || (func > 7));
        return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 2, 2);
    }
}

uint32_t pci_conf_read32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    u32 value;

    if ( reg > 255 )
    {
        pci_mmcfg_read(0, bus, PCI_DEVFN(dev, func), reg, 4, &value);
        return value;
    }
    else
    {
        BUG_ON((bus > 255) || (dev > 31) || (func > 7));
        return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), 0, 4);
    }
}

void pci_conf_write8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint8_t data)
{
    if ( reg > 255 )
        pci_mmcfg_write(0, bus, PCI_DEVFN(dev, func), reg, 1, data);
    else
    {
        BUG_ON((bus > 255) || (dev > 31) || (func > 7));
        pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 3, 1, data);
    }
}

void pci_conf_write16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint16_t data)
{
    if ( reg > 255 )
        pci_mmcfg_write(0, bus, PCI_DEVFN(dev, func), reg, 2, data);
    else
    {
        BUG_ON((bus > 255) || (dev > 31) || (func > 7));
        pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 2, 2, data);
    }
}

void pci_conf_write32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint32_t data)
{
    if ( reg > 255 )
        pci_mmcfg_write(0, bus, PCI_DEVFN(dev, func), reg, 4, data);
    else
    {
        BUG_ON((bus > 255) || (dev > 31) || (func > 7));
        pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), 0, 4, data);
    }
}
