/******************************************************************************
 * pci.c
 * 
 * Architecture-dependent PCI access functions.
 */

#include <xen/spinlock.h>
#include <xen/pci.h>
#include <asm/io.h>
#include <xsm/xsm.h>

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
    int rc = xsm_pci_config_permission(XSM_HOOK, current->domain, bdf,
                                       reg, reg + size - 1, 1);

    if ( rc < 0 )
        return rc;
    ASSERT(!rc);

    /*
     * Avoid expensive operations when no hook is going to do anything
     * for the access anyway.
     */
    if ( reg < 64 || reg >= 256 )
        return 0;

    pcidevs_lock();

    pdev = pci_get_pdev(NULL, PCI_SBDF(seg, bdf));
    if ( pdev )
        rc = pci_msi_conf_write_intercept(pdev, reg, size, data);

    pcidevs_unlock();

    return rc;
}

bool pci_check_bar(const struct pci_dev *pdev, mfn_t start, mfn_t end)
{
    /*
     * Check if BAR is not overlapping with any memory region defined
     * in the memory map.
     */
    if ( !is_memory_hole(start, end) )
        gdprintk(XENLOG_WARNING,
                 "%pp: BAR at [%"PRI_mfn", %"PRI_mfn"] not in memory map hole\n",
                 &pdev->sbdf, mfn_x(start), mfn_x(end));

    /*
     * Unconditionally return true, pci_sanitize_bar_memory() will remove any
     * non-hole regions.
     */
    return true;
}

/* Remove overlaps with any ranges defined in the host memory map. */
int pci_sanitize_bar_memory(struct rangeset *r)
{
    unsigned int i;

    for ( i = 0; i < e820.nr_map; i++ )
    {
        const struct e820entry *entry = &e820.map[i];
        int rc;

        if ( !entry->size )
            continue;

        rc = rangeset_remove_range(r, PFN_DOWN(entry->addr),
                                   PFN_DOWN(entry->addr + entry->size - 1));
        if ( rc )
            return rc;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
