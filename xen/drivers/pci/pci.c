/******************************************************************************
 * pci.c
 *
 * Architecture-independent PCI access functions.
 */

#include <xen/init.h>
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
        pos = pci_conf_read8(PCI_SBDF(seg, bus, dev, func), pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_conf_read8(PCI_SBDF(seg, bus, dev, func), pos + PCI_CAP_LIST_ID);

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
        pos = pci_conf_read8(PCI_SBDF3(seg, bus, devfn), pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_conf_read8(PCI_SBDF3(seg, bus, devfn), pos + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        if ( id == cap )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

/**
 * pci_find_ext_capability - Find an extended capability
 * @seg/@bus/@devfn: PCI device to query
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.
 */
int pci_find_ext_capability(int seg, int bus, int devfn, int cap)
{
    return pci_find_next_ext_capability(seg, bus, devfn, 0, cap);
}

/**
 * pci_find_next_ext_capability - Find another extended capability
 * @seg/@bus/@devfn: PCI device to query
 * @pos: starting position
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.
 */
int pci_find_next_ext_capability(int seg, int bus, int devfn, int start, int cap)
{
    u32 header;
    int ttl = 480; /* 3840 bytes, minimum 8 bytes per capability */
    int pos = max(start, 0x100);

    header = pci_conf_read32(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), pos);

    /*
     * If we have no capabilities, this is indicated by cap ID,
     * cap version and next pointer all being 0.
     */
    if ( (header == 0) || (header == -1) )
        return 0;
    ASSERT(start != pos || PCI_EXT_CAP_ID(header) == cap);

    while ( ttl-- > 0 ) {
        if ( PCI_EXT_CAP_ID(header) == cap && pos != start )
            return pos;
        pos = PCI_EXT_CAP_NEXT(header);
        if ( pos < 0x100 )
            break;
        header = pci_conf_read32(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), pos);
    }
    return 0;
}

void pci_intx(const struct pci_dev *pdev, bool enable)
{
    uint16_t seg = pdev->seg;
    uint8_t bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn);
    uint8_t func = PCI_FUNC(pdev->devfn);
    uint16_t cmd = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);

    if ( enable )
        cmd &= ~PCI_COMMAND_INTX_DISABLE;
    else
        cmd |= PCI_COMMAND_INTX_DISABLE;
    pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
}

const char *__init parse_pci(const char *s, unsigned int *seg_p,
                             unsigned int *bus_p, unsigned int *dev_p,
                             unsigned int *func_p)
{
    bool def_seg;

    return parse_pci_seg(s, seg_p, bus_p, dev_p, func_p, &def_seg);
}

const char *__init parse_pci_seg(const char *s, unsigned int *seg_p,
                                 unsigned int *bus_p, unsigned int *dev_p,
                                 unsigned int *func_p, bool *def_seg)
{
    unsigned long seg = simple_strtoul(s, &s, 16), bus, dev, func;

    if ( *s != ':' )
        return NULL;
    bus = simple_strtoul(s + 1, &s, 16);
    *def_seg = false;
    if ( *s == ':' )
        dev = simple_strtoul(s + 1, &s, 16);
    else
    {
        dev = bus;
        bus = seg;
        seg = 0;
        *def_seg = true;
    }
    if ( func_p )
    {
        if ( *s != '.' )
            return NULL;
        func = simple_strtoul(s + 1, &s, 0);
    }
    else
        func = 0;
    if ( seg != (seg_p ? (u16)seg : 0) ||
         bus != PCI_BUS(PCI_BDF2(bus, 0)) ||
         dev != PCI_SLOT(PCI_DEVFN(dev, 0)) ||
         func != PCI_FUNC(PCI_DEVFN(0, func)) )
        return NULL;

    if ( seg_p )
        *seg_p = seg;
    *bus_p = bus;
    *dev_p = dev;
    if ( func_p )
        *func_p = func;

    return s;
}
