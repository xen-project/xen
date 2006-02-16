/*
 * PCI Frontend - arch-dependendent declarations
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#ifndef __XEN_ASM_PCIFRONT_H__
#define __XEN_ASM_PCIFRONT_H__

#include <linux/config.h>
#include <linux/spinlock.h>

#ifdef __KERNEL__

struct pcifront_device;

struct pcifront_sd {
	int domain;
	struct pcifront_device *pdev;
};

struct pci_bus;

#ifdef CONFIG_PCI_DOMAINS
static inline int pci_domain_nr(struct pci_bus *bus)
{
	struct pcifront_sd *sd = bus->sysdata;
	return sd->domain;
}
static inline int pci_proc_domain(struct pci_bus *bus)
{
	return pci_domain_nr(bus);
}
#endif /* CONFIG_PCI_DOMAINS */

extern spinlock_t pci_bus_lock;

#endif /* __KERNEL__ */

#endif /* __XEN_ASM_PCIFRONT_H__ */
