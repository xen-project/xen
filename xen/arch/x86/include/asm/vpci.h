/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef X86_VPCI_H
#define X86_VPCI_H

#include <xen/stdbool.h>

/* Arch-specific MSI data for vPCI. */
struct vpci_arch_msi {
    int pirq;
    bool bound;
};

/* Arch-specific MSI-X entry data for vPCI. */
struct vpci_arch_msix_entry {
    int pirq;
};

#endif /* X86_VPCI_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
