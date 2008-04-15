/******************************************************************************
 * pci.c
 * 
 * PCI access functions.
 */

#include <xen/config.h>
#include <xen/pci.h>
#include <xen/spinlock.h>
#include <asm/io.h>

#define PCI_CONF_ADDRESS(bus, dev, func, reg) \
    (0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (reg & ~3))

static DEFINE_SPINLOCK(pci_config_lock);

uint32_t pci_conf_read(uint32_t cf8, uint8_t offset, uint8_t bytes)
{
    unsigned long flags;
    uint32_t value;

    BUG_ON((offset + bytes) > 4);

    spin_lock_irqsave(&pci_config_lock, flags);

    outl(cf8, 0xcf8);

    switch ( bytes )
    {
    case 1:
        value = inb(0xcfc + offset);
        break;
    case 2:
        value = inw(0xcfc + offset);
        break;
    case 4:
        value = inl(0xcfc + offset);
        break;
    default:
        value = 0;
        BUG();
    }

    spin_unlock_irqrestore(&pci_config_lock, flags);

    return value;
}

void pci_conf_write(uint32_t cf8, uint8_t offset, uint8_t bytes, uint32_t data)
{
    unsigned long flags;

    BUG_ON((offset + bytes) > 4);

    spin_lock_irqsave(&pci_config_lock, flags);

    outl(cf8, 0xcf8);

    switch ( bytes )
    {
    case 1:
        outb((uint8_t)data, 0xcfc + offset);
        break;
    case 2:
        outw((uint16_t)data, 0xcfc + offset);
        break;
    case 4:
        outl(data, 0xcfc + offset);
        break;
    }

    spin_unlock_irqrestore(&pci_config_lock, flags);
}

uint8_t pci_conf_read8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 3, 1);
}

uint16_t pci_conf_read16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 2, 2);
}

uint32_t pci_conf_read32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    return pci_conf_read(PCI_CONF_ADDRESS(bus, dev, func, reg), 0, 4);
}

void pci_conf_write8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint8_t data)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 3, 1, data);
}

void pci_conf_write16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint16_t data)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), reg & 2, 2, data);
}

void pci_conf_write32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint32_t data)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_conf_write(PCI_CONF_ADDRESS(bus, dev, func, reg), 0, 4, data);
}
