#include <xen/init.h>
#include <xen/pci.h>
#include <xen/msi.h>
#include <asm/hvm/io.h>

int pdev_msix_assign(struct domain *d, struct pci_dev *pdev)
{
    int rc;

    if ( pdev->msix )
    {
        rc = pci_reset_msix_state(pdev);
        if ( rc )
            return rc;
        msixtbl_init(d);
    }

    return 0;
}

int pdev_msi_init(struct pci_dev *pdev)
{
    unsigned int pos;

    INIT_LIST_HEAD(&pdev->msi_list);

    pos = pci_find_cap_offset(pdev->sbdf, PCI_CAP_ID_MSI);
    if ( pos )
    {
        uint16_t ctrl = pci_conf_read16(pdev->sbdf, msi_control_reg(pos));

        pdev->msi_pos = pos;
        pdev->msi_maxvec = multi_msi_capable(ctrl);
    }

    pos = pci_find_cap_offset(pdev->sbdf, PCI_CAP_ID_MSIX);
    if ( pos )
    {
        struct arch_msix *msix = xzalloc(struct arch_msix);
        uint16_t ctrl;

        if ( !msix )
            return -ENOMEM;

        pdev->msix_pos = pos;

        spin_lock_init(&msix->table_lock);

        ctrl = pci_conf_read16(pdev->sbdf, msix_control_reg(pos));

        if ( ctrl & (PCI_MSIX_FLAGS_MASKALL | PCI_MSIX_FLAGS_ENABLE) )
        {
            /*
             * pci_reset_msix_state() relies on MASKALL not being set
             * initially, clear it (and ENABLE too - for safety), to meet that
             * expectation.
             */
            printk(XENLOG_WARNING
                   "%pp: unexpected initial MSI-X state (MASKALL=%d, ENABLE=%d), fixing\n",
                   &pdev->sbdf,
                   !!(ctrl & PCI_MSIX_FLAGS_MASKALL),
                   !!(ctrl & PCI_MSIX_FLAGS_ENABLE));
            ctrl &= ~(PCI_MSIX_FLAGS_ENABLE | PCI_MSIX_FLAGS_MASKALL);
            pci_conf_write16(pdev->sbdf, msix_control_reg(pos), ctrl);
        }

        msix->nr_entries = msix_table_size(ctrl);

        pdev->msix = msix;
    }

    return 0;
}

void pdev_msi_deinit(struct pci_dev *pdev)
{
    XFREE(pdev->msix);
}

void pdev_dump_msi(const struct pci_dev *pdev)
{
    const struct msi_desc *msi;

    if ( list_empty(&pdev->msi_list) )
        return;

    printk(" - MSIs < ");
    list_for_each_entry ( msi, &pdev->msi_list, list )
        printk("%d ", msi->irq);
    printk(">");
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
