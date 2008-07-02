#include <types.h>
#include <xen/io/pciif.h>
struct pcifront_dev;
struct pcifront_dev *init_pcifront(char *nodename);
void pcifront_scan(struct pcifront_dev *dev, void (*fun)(unsigned int domain, unsigned int bus, unsigned slot, unsigned int fun));
void pcifront_op(struct pcifront_dev *dev, struct xen_pci_op *op);
void shutdown_pcifront(struct pcifront_dev *dev);
int pcifront_conf_read(struct pcifront_dev *dev,
                       unsigned int dom,
                       unsigned int bus, unsigned int slot, unsigned long fun,
                       unsigned int off, unsigned int size, unsigned int *val);
int pcifront_conf_write(struct pcifront_dev *dev,
                        unsigned int dom,
                        unsigned int bus, unsigned int slot, unsigned long fun,
                        unsigned int off, unsigned int size, unsigned int val);
