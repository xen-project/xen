/******************************************************************************
 * pci.c
 * 
 * Architecture-dependent PCI access functions.
 */

#include <xen/spinlock.h>
#include <xen/pci.h>
#include <asm/io.h>

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

int pci_conf_write_intercept(unsigned int seg, unsigned int bdf,
                             unsigned int reg, unsigned int size,
                             uint32_t *data)
{
    struct pci_dev *pdev;
    int rc = 0;

    /*
     * Avoid expensive operations when no hook is going to do anything
     * for the access anyway.
     */
    if ( reg < 64 || reg >= 256 )
        return 0;

    spin_lock(&pcidevs_lock);

    pdev = pci_get_pdev(seg, PCI_BUS(bdf), PCI_DEVFN2(bdf));
    if ( pdev )
        rc = pci_msi_conf_write_intercept(pdev, reg, size, data);

    spin_unlock(&pcidevs_lock);

    return rc;
}
