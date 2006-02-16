/*
 * PCI Backend - Provides restricted access to the real PCI bus topology
 *               to the frontend
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */

#include <linux/list.h>
#include <linux/pci.h>
#include "pciback.h"

struct passthrough_dev_data {
	struct list_head dev_list;
};

struct pci_dev *pciback_get_pci_dev(struct pciback_device *pdev,
				    unsigned int domain, unsigned int bus,
				    unsigned int devfn)
{
	struct passthrough_dev_data *dev_data = pdev->pci_dev_data;
	struct pci_dev_entry *dev_entry;

	list_for_each_entry(dev_entry, &dev_data->dev_list, list) {
		if (domain == (unsigned int)pci_domain_nr(dev_entry->dev->bus)
		    && bus == (unsigned int)dev_entry->dev->bus->number
		    && devfn == dev_entry->dev->devfn)
			return dev_entry->dev;
	}

	return NULL;
}

/* Must hold pciback_device->dev_lock when calling this */
int pciback_add_pci_dev(struct pciback_device *pdev, struct pci_dev *dev)
{
	struct passthrough_dev_data *dev_data = pdev->pci_dev_data;
	struct pci_dev_entry *dev_entry;

	dev_entry = kmalloc(sizeof(*dev_entry), GFP_KERNEL);
	if (!dev_entry)
		return -ENOMEM;
	dev_entry->dev = dev;

	list_add_tail(&dev_entry->list, &dev_data->dev_list);

	return 0;
}

int pciback_init_devices(struct pciback_device *pdev)
{
	struct passthrough_dev_data *dev_data;

	dev_data = kmalloc(sizeof(*dev_data), GFP_KERNEL);
	if (!dev_data)
		return -ENOMEM;

	INIT_LIST_HEAD(&dev_data->dev_list);

	pdev->pci_dev_data = dev_data;

	return 0;
}

int pciback_publish_pci_roots(struct pciback_device *pdev,
			      publish_pci_root_cb publish_root_cb)
{
	int err = 0;
	struct passthrough_dev_data *dev_data = pdev->pci_dev_data;
	struct pci_dev_entry *dev_entry, *e;
	struct pci_dev *dev;
	int found;
	unsigned int domain, bus;

	list_for_each_entry(dev_entry, &dev_data->dev_list, list) {
		/* Only publish this device as a root if none of its
		 * parent bridges are exported
		 */
		found = 0;
		dev = dev_entry->dev->bus->self;
		for (; !found && dev != NULL; dev = dev->bus->self) {
			list_for_each_entry(e, &dev_data->dev_list, list) {
				if (dev == e->dev) {
					found = 1;
					break;
				}
			}
		}

		domain = (unsigned int)pci_domain_nr(dev_entry->dev->bus);
		bus = (unsigned int)dev_entry->dev->bus->number;

		if (!found) {
			err = publish_root_cb(pdev, domain, bus);
			if (err)
				break;
		}
	}

	return err;
}

/* Must hold pciback_device->dev_lock when calling this */
void pciback_release_devices(struct pciback_device *pdev)
{
	struct passthrough_dev_data *dev_data = pdev->pci_dev_data;
	struct pci_dev_entry *dev_entry, *t;

	list_for_each_entry_safe(dev_entry, t, &dev_data->dev_list, list) {
		list_del(&dev_entry->list);
		pcistub_put_pci_dev(dev_entry->dev);
		kfree(dev_entry);
	}

	kfree(dev_data);
	pdev->pci_dev_data = NULL;
}
