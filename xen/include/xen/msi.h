#ifndef __XEN_MSI_H_
#define __XEN_MSI_H_

#include <xen/pci.h>

#ifdef CONFIG_HAS_PCI_MSI

#include <asm/msi.h>

int pdev_msix_assign(struct domain *d, struct pci_dev *pdev);
int pdev_msi_init(struct pci_dev *pdev);
void pdev_msi_deinit(struct pci_dev *pdev);
void pdev_dump_msi(const struct pci_dev *pdev);

#else /* !CONFIG_HAS_PCI_MSI */

static inline int pdev_msix_assign(struct domain *d, struct pci_dev *pdev)
{
    return 0;
}

static inline int pdev_msi_init(struct pci_dev *pdev)
{
    return 0;
}

static inline void pdev_msi_deinit(struct pci_dev *pdev) {}
static inline void pci_cleanup_msi(struct pci_dev *pdev) {}
static inline void pdev_dump_msi(const struct pci_dev *pdev) {}

#endif /* CONFIG_HAS_PCI_MSI */

#endif /* __XEN_MSI_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
