/*
 * PCI Frontend - Common data structures & function declarations
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#ifndef __XEN_PCIFRONT_H__
#define __XEN_PCIFRONT_H__

#include <linux/spinlock.h>
#include <linux/pci.h>
#include <xen/xenbus.h>
#include <xen/interface/io/pciif.h>
#include <xen/pcifront.h>

struct pci_bus_entry {
	struct list_head list;
	struct pci_bus *bus;
};

struct pcifront_device {
	struct xenbus_device *xdev;
	struct list_head root_buses;
	spinlock_t dev_lock;

	int evtchn;
	int gnt_ref;

	/* Lock this when doing any operations in sh_info */
	spinlock_t sh_info_lock;
	struct xen_pci_sharedinfo *sh_info;
};

int pcifront_connect(struct pcifront_device *pdev);
void pcifront_disconnect(struct pcifront_device *pdev);

int pcifront_scan_root(struct pcifront_device *pdev,
		       unsigned int domain, unsigned int bus);
void pcifront_free_roots(struct pcifront_device *pdev);

#endif	/* __XEN_PCIFRONT_H__ */
