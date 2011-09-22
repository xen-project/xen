/******************************************************************************
 * pci.c
 *
 * Architecture-independent PCI access functions.
 */

#include <xen/pci.h>
#include <xen/pci_regs.h>

int pci_find_cap_offset(u16 seg, u8 bus, u8 dev, u8 func, u8 cap)
{
    u8 id;
    int max_cap = 48;
    u8 pos = PCI_CAPABILITY_LIST;
    u16 status;

    status = pci_conf_read16(seg, bus, dev, func, PCI_STATUS);
    if ( (status & PCI_STATUS_CAP_LIST) == 0 )
        return 0;

    while ( max_cap-- )
    {
        pos = pci_conf_read8(seg, bus, dev, func, pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_conf_read8(seg, bus, dev, func, pos + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        else if ( id == cap )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }

    return 0;
}

int pci_find_next_cap(u16 seg, u8 bus, unsigned int devfn, u8 pos, int cap)
{
    u8 id;
    int ttl = 48;

    while ( ttl-- )
    {
        pos = pci_conf_read8(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_conf_read8(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                            pos + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        if ( id == cap )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}
