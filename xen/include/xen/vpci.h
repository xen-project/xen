#ifndef _XEN_VPCI_H_
#define _XEN_VPCI_H_

#include <xen/pci.h>
#include <xen/types.h>
#include <xen/list.h>

typedef uint32_t vpci_read_t(const struct pci_dev *pdev, unsigned int reg,
                             void *data);

typedef void vpci_write_t(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data);

typedef int vpci_register_init_t(struct pci_dev *dev);

#define REGISTER_VPCI_INIT(x)                   \
  static vpci_register_init_t *const x##_entry  \
               __used_section(".data.vpci") = x

/* Add vPCI handlers to device. */
int __must_check vpci_add_handlers(struct pci_dev *dev);

/* Add/remove a register handler. */
int __must_check vpci_add_register(struct vpci *vpci,
                                   vpci_read_t *read_handler,
                                   vpci_write_t *write_handler,
                                   unsigned int offset, unsigned int size,
                                   void *data);
int __must_check vpci_remove_register(struct vpci *vpci, unsigned int offset,
                                      unsigned int size);

/* Generic read/write handlers for the PCI config space. */
uint32_t vpci_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int size);
void vpci_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int size,
                uint32_t data);

struct vpci {
    /* List of vPCI handlers for a device. */
    struct list_head handlers;
    spinlock_t lock;
};

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
