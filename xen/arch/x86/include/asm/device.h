#ifndef __ASM_X86_DEVICE_H
#define __ASM_X86_DEVICE_H

#include <xen/pci.h>

/*
 * x86 only supports PCI. Therefore it's possible to directly use
 * pci_dev to avoid adding new field.
 */

typedef struct pci_dev device_t;

#define dev_is_pci(dev) ((void)(dev), 1)
#define pci_to_dev(pci) (pci)

#endif /* __ASM_X86_DEVICE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
