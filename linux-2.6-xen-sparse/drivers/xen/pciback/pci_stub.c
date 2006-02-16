/*
 * PCI Stub Driver - Grabs devices in backend to be exported later
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>
#include "pciback.h"

static char *pci_devs_to_hide = NULL;
module_param_named(hide, pci_devs_to_hide, charp, 0444);

struct pci_stub_device_id {
	struct list_head slot_list;
	int domain;
	unsigned char bus;
	unsigned int devfn;
};
LIST_HEAD(pci_stub_device_ids);

struct pci_stub_device {
	struct list_head dev_list;
	struct pci_dev *dev;
	atomic_t in_use;
};
/* Access to pci_stub_devices & seized_devices lists and the initialize_devices
 * flag must be locked with pci_stub_devices_lock
 */
DEFINE_SPINLOCK(pci_stub_devices_lock);
LIST_HEAD(pci_stub_devices);

/* wait for device_initcall before initializing our devices
 * (see pcistub_init_devices_late)
 */
static int initialize_devices = 0;
LIST_HEAD(seized_devices);

static inline struct pci_dev *get_pci_dev(struct pci_stub_device *psdev)
{
	if (atomic_dec_and_test(&psdev->in_use))
		return psdev->dev;
	else {
		atomic_inc(&psdev->in_use);
		return NULL;
	}
}

struct pci_dev *pcistub_get_pci_dev_by_slot(int domain, int bus,
					    int slot, int func)
{
	struct pci_stub_device *psdev;
	struct pci_dev *found_dev = NULL;

	spin_lock(&pci_stub_devices_lock);

	list_for_each_entry(psdev, &pci_stub_devices, dev_list) {
		if (psdev->dev != NULL
		    && domain == pci_domain_nr(psdev->dev->bus)
		    && bus == psdev->dev->bus->number
		    && PCI_DEVFN(slot, func) == psdev->dev->devfn) {
			found_dev = get_pci_dev(psdev);
			break;
		}
	}

	spin_unlock(&pci_stub_devices_lock);
	return found_dev;
}

struct pci_dev *pcistub_get_pci_dev(struct pci_dev *dev)
{
	struct pci_stub_device *psdev;
	struct pci_dev *found_dev = NULL;

	spin_lock(&pci_stub_devices_lock);

	list_for_each_entry(psdev, &pci_stub_devices, dev_list) {
		if (psdev->dev == dev) {
			found_dev = get_pci_dev(psdev);
			break;
		}
	}

	spin_unlock(&pci_stub_devices_lock);
	return found_dev;
}

void pcistub_put_pci_dev(struct pci_dev *dev)
{
	struct pci_stub_device *psdev;

	spin_lock(&pci_stub_devices_lock);

	list_for_each_entry(psdev, &pci_stub_devices, dev_list) {
		if (psdev->dev == dev) {
			/* Cleanup our device
			 * (so it's ready for the next domain)
			 */
			pciback_reset_device(psdev->dev);

			atomic_inc(&psdev->in_use);
			break;
		}
	}

	spin_unlock(&pci_stub_devices_lock);
}

static int __devinit pcistub_match(struct pci_dev *dev,
				   struct pci_stub_device_id *pdev_id)
{
	/* Match the specified device by domain, bus, slot, func and also if
	 * any of the device's parent bridges match.
	 */
	for (; dev != NULL; dev = dev->bus->self) {
		if (pci_domain_nr(dev->bus) == pdev_id->domain
		    && dev->bus->number == pdev_id->bus
		    && dev->devfn == pdev_id->devfn)
			return 1;
	}

	return 0;
}

static int __devinit pcistub_init_device(struct pci_dev *dev)
{
	struct pciback_dev_data *dev_data;
	int err = 0;

	/* The PCI backend is not intended to be a module (or to work with
	 * removable PCI devices (yet). If it were, pciback_config_free()
	 * would need to be called somewhere to free the memory allocated
	 * here and then to call kfree(pci_get_drvdata(psdev->dev)).
	 */
	dev_data = kmalloc(sizeof(*dev_data), GFP_KERNEL);
	if (!dev_data) {
		err = -ENOMEM;
		goto out;
	}
	pci_set_drvdata(dev, dev_data);

	err = pciback_config_init(dev);
	if (err)
		goto out;

	/* HACK: Force device (& ACPI) to determine what IRQ it's on - we
	 * must do this here because pcibios_enable_device may specify
	 * the pci device's true irq (and possibly its other resources)
	 * if they differ from what's in the configuration space.
	 * This makes the assumption that the device's resources won't
	 * change after this point (otherwise this code may break!)
	 */
	err = pci_enable_device(dev);
	if (err)
		goto config_release;

	/* Now disable the device (this also ensures some private device
	 * data is setup before we export)
	 * This calls pciback_config_reset(dev)
	 */
	pciback_reset_device(dev);

	return 0;

      config_release:
	pciback_config_free(dev);

      out:
	pci_set_drvdata(dev, NULL);
	kfree(dev_data);
	return err;
}

/*
 * Because some initialization still happens on
 * devices during fs_initcall, we need to defer
 * full initialization of our devices until
 * device_initcall.
 */
static int __init pcistub_init_devices_late(void)
{
	struct pci_stub_device *psdev, *t;
	int err = 0;

	spin_lock(&pci_stub_devices_lock);

	list_for_each_entry_safe(psdev, t, &seized_devices, dev_list) {
		list_del(&psdev->dev_list);
		err = pcistub_init_device(psdev->dev);
		if (err) {
			printk(KERN_ERR
			       "pciback: %s error %d initializing device\n",
			       pci_name(psdev->dev), err);
			kfree(psdev);
			continue;
		}

		list_add_tail(&psdev->dev_list, &pci_stub_devices);
	}

	initialize_devices = 1;

	spin_unlock(&pci_stub_devices_lock);

	return 0;
}

device_initcall(pcistub_init_devices_late);

static int __devinit pcistub_seize(struct pci_dev *dev)
{
	struct pci_stub_device *psdev;
	int err = 0;

	psdev = kmalloc(sizeof(*psdev), GFP_KERNEL);
	if (!psdev)
		return -ENOMEM;

	psdev->dev = dev;
	atomic_set(&psdev->in_use, 1);

	spin_lock(&pci_stub_devices_lock);

	if (initialize_devices) {
		err = pcistub_init_device(psdev->dev);
		if (err)
			goto out;

		list_add(&psdev->dev_list, &pci_stub_devices);
	} else
		list_add(&psdev->dev_list, &seized_devices);

      out:
	spin_unlock(&pci_stub_devices_lock);

	if (err)
		kfree(psdev);

	return err;
}

static int __devinit pcistub_probe(struct pci_dev *dev,
				   const struct pci_device_id *id)
{
	struct pci_stub_device_id *pdev_id;
	struct pci_dev *seized_dev;
	int err = 0;

	list_for_each_entry(pdev_id, &pci_stub_device_ids, slot_list) {

		if (!pcistub_match(dev, pdev_id))
			continue;

		if (dev->hdr_type != PCI_HEADER_TYPE_NORMAL
		    && dev->hdr_type != PCI_HEADER_TYPE_BRIDGE) {
			printk(KERN_ERR
			       "pciback: %s: can't export pci devices that "
			       "don't have a normal (0) or bridge (1) "
			       "header type!\n", pci_name(dev));
			break;
		}

		pr_info("pciback: seizing PCI device %s\n", pci_name(dev));
		seized_dev = pci_dev_get(dev);

		if (seized_dev) {
			err = pcistub_seize(seized_dev);
			if (err) {
				pci_dev_put(dev);
				goto out;
			}

			/* Success! */
			goto out;
		}
	}

	/* Didn't find the device */
	err = -ENODEV;

      out:
	return err;
}

struct pci_device_id pcistub_ids[] = {
	{
	 .vendor = PCI_ANY_ID,
	 .device = PCI_ANY_ID,
	 .subvendor = PCI_ANY_ID,
	 .subdevice = PCI_ANY_ID,
	 },
	{0,},
};

/*
 * Note: There is no MODULE_DEVICE_TABLE entry here because this isn't
 * for a normal device. I don't want it to be loaded automatically.
 */

struct pci_driver pciback_pci_driver = {
	.name = "pciback",
	.id_table = pcistub_ids,
	.probe = pcistub_probe,
};

static int __init pcistub_init(void)
{
	int pos = 0;
	struct pci_stub_device_id *pci_dev_id;
	int err = 0;
	int domain, bus, slot, func;
	int parsed;

	if (pci_devs_to_hide && *pci_devs_to_hide) {
		do {
			parsed = 0;

			err = sscanf(pci_devs_to_hide + pos,
				     " (%x:%x:%x.%x) %n",
				     &domain, &bus, &slot, &func, &parsed);
			if (err != 4) {
				domain = 0;
				err = sscanf(pci_devs_to_hide + pos,
					     " (%x:%x.%x) %n",
					     &bus, &slot, &func, &parsed);
				if (err != 3)
					goto parse_error;
			}

			pci_dev_id = kmalloc(sizeof(*pci_dev_id), GFP_KERNEL);
			if (!pci_dev_id) {
				err = -ENOMEM;
				goto out;
			}

			pci_dev_id->domain = domain;
			pci_dev_id->bus = bus;
			pci_dev_id->devfn = PCI_DEVFN(slot, func);

			pr_debug
			    ("pciback: wants to seize %04x:%02x:%02x.%01x\n",
			     domain, bus, slot, func);

			list_add_tail(&pci_dev_id->slot_list,
				      &pci_stub_device_ids);

			/* if parsed<=0, we've reached the end of the string */
			pos += parsed;
		} while (parsed > 0 && pci_devs_to_hide[pos]);

		/* If we're the first PCI Device Driver to register, we're the
		 * first one to get offered PCI devices as they become
		 * available (and thus we can be the first to grab them)
		 */
		pci_register_driver(&pciback_pci_driver);
	}

      out:
	return err;

      parse_error:
	printk(KERN_ERR "pciback: Error parsing pci_devs_to_hide at \"%s\"\n",
	       pci_devs_to_hide + pos);
	return -EINVAL;
}

/*
 * fs_initcall happens before device_initcall
 * so pciback *should* get called first (b/c we 
 * want to suck up any device before other drivers
 * get a chance by being the first pci device
 * driver to register)
 */
fs_initcall(pcistub_init);
