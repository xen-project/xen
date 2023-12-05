/******************************************************************************
 * pci.c
 *
 * Architecture-independent PCI access functions.
 */

#include <xen/init.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>

unsigned int pci_find_cap_offset(pci_sbdf_t sbdf, unsigned int cap)
{
    u8 id;
    int max_cap = 48;
    u8 pos = PCI_CAPABILITY_LIST;
    u16 status;

    status = pci_conf_read16(sbdf, PCI_STATUS);
    if ( (status & PCI_STATUS_CAP_LIST) == 0 )
        return 0;

    while ( max_cap-- )
    {
        pos = pci_conf_read8(sbdf, pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_conf_read8(sbdf, pos + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        else if ( id == cap )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }

    return 0;
}

unsigned int pci_find_next_cap_ttl(pci_sbdf_t sbdf, unsigned int pos,
                                   const unsigned int caps[], unsigned int n,
                                   unsigned int *ttl)
{
    while ( (*ttl)-- )
    {
        unsigned int id, i;

        pos = pci_conf_read8(sbdf, pos);
        if ( pos < 0x40 )
            break;

        id = pci_conf_read8(sbdf, (pos & ~3) + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        for ( i = 0; i < n; i++ )
        {
            if ( id == caps[i] )
                return pos;
        }

        pos = (pos & ~3) + PCI_CAP_LIST_NEXT;
    }

    return 0;
}

unsigned int pci_find_next_cap(pci_sbdf_t sbdf, unsigned int pos,
                               unsigned int cap)
{
    unsigned int ttl = 48;

    return pci_find_next_cap_ttl(sbdf, pos, &cap, 1, &ttl) & ~3;
}

/**
 * pci_find_ext_capability - Find an extended capability
 * @sbdf: PCI device to query
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.
 */
unsigned int pci_find_ext_capability(pci_sbdf_t sbdf, unsigned int cap)
{
    return pci_find_next_ext_capability(sbdf, 0, cap);
}

/**
 * pci_find_next_ext_capability - Find another extended capability
 * @sbdf: PCI device to query
 * @start: starting position
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.
 */
unsigned int pci_find_next_ext_capability(pci_sbdf_t sbdf, unsigned int start,
                                          unsigned int cap)
{
    u32 header;
    int ttl = 480; /* 3840 bytes, minimum 8 bytes per capability */
    unsigned int pos = max(start, 0x100U);

    header = pci_conf_read32(sbdf, pos);

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
        header = pci_conf_read32(sbdf, pos);
    }
    return 0;
}

void pci_intx(const struct pci_dev *pdev, bool enable)
{
    uint16_t cmd = pci_conf_read16(pdev->sbdf, PCI_COMMAND);

    if ( enable )
        cmd &= ~PCI_COMMAND_INTX_DISABLE;
    else
        cmd |= PCI_COMMAND_INTX_DISABLE;
    pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
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
         bus != PCI_BUS(PCI_BDF(bus, 0)) ||
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
