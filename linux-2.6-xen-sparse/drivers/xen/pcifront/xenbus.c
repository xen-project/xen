/*
 * PCI Frontend Xenbus Setup - handles setup with backend (imports page/evtchn)
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <xen/xenbus.h>
#include <xen/gnttab.h>
#include "pcifront.h"

#define INVALID_GRANT_REF (0)
#define INVALID_EVTCHN    (-1)

static struct pcifront_device *alloc_pdev(struct xenbus_device *xdev)
{
	struct pcifront_device *pdev;

	pdev = kmalloc(sizeof(struct pcifront_device), GFP_KERNEL);
	if (pdev == NULL)
		goto out;

	pdev->sh_info =
	    (struct xen_pci_sharedinfo *)__get_free_page(GFP_KERNEL);
	if (pdev->sh_info == NULL) {
		kfree(pdev);
		pdev = NULL;
		goto out;
	}
	pdev->sh_info->flags = 0;

	xdev->dev.driver_data = pdev;
	pdev->xdev = xdev;

	INIT_LIST_HEAD(&pdev->root_buses);

	spin_lock_init(&pdev->dev_lock);
	spin_lock_init(&pdev->sh_info_lock);

	pdev->evtchn = INVALID_EVTCHN;
	pdev->gnt_ref = INVALID_GRANT_REF;

	dev_dbg(&xdev->dev, "Allocated pdev @ 0x%p pdev->sh_info @ 0x%p\n",
		pdev, pdev->sh_info);
      out:
	return pdev;
}

static void free_pdev(struct pcifront_device *pdev)
{
	dev_dbg(&pdev->xdev->dev, "freeing pdev @ 0x%p\n", pdev);

	pcifront_free_roots(pdev);

	if (pdev->evtchn != INVALID_EVTCHN)
		xenbus_free_evtchn(pdev->xdev, pdev->evtchn);

	if (pdev->gnt_ref != INVALID_GRANT_REF)
		gnttab_end_foreign_access(pdev->gnt_ref, 0,
					  (unsigned long)pdev->sh_info);

	pdev->xdev->dev.driver_data = NULL;

	kfree(pdev);
}

static int pcifront_publish_info(struct pcifront_device *pdev)
{
	int err = 0;
	struct xenbus_transaction trans;

	err = xenbus_grant_ring(pdev->xdev, virt_to_mfn(pdev->sh_info));
	if (err < 0)
		goto out;

	pdev->gnt_ref = err;

	err = xenbus_alloc_evtchn(pdev->xdev, &pdev->evtchn);
	if (err)
		goto out;

      do_publish:
	err = xenbus_transaction_start(&trans);
	if (err) {
		xenbus_dev_fatal(pdev->xdev, err,
				 "Error writing configuration for backend "
				 "(start transaction)");
		goto out;
	}

	err = xenbus_printf(trans, pdev->xdev->nodename,
			    "pci-op-ref", "%u", pdev->gnt_ref);
	if (!err)
		err = xenbus_printf(trans, pdev->xdev->nodename,
				    "event-channel", "%u", pdev->evtchn);
	if (!err)
		err = xenbus_printf(trans, pdev->xdev->nodename,
				    "magic", XEN_PCI_MAGIC);

	if (err) {
		xenbus_transaction_end(trans, 1);
		xenbus_dev_fatal(pdev->xdev, err,
				 "Error writing configuration for backend");
		goto out;
	} else {
		err = xenbus_transaction_end(trans, 0);
		if (err == -EAGAIN)
			goto do_publish;
		else if (err) {
			xenbus_dev_fatal(pdev->xdev, err,
					 "Error completing transaction "
					 "for backend");
			goto out;
		}
	}

	xenbus_switch_state(pdev->xdev, XenbusStateInitialised);

	dev_dbg(&pdev->xdev->dev, "publishing successful!\n");

      out:
	return err;
}

static int pcifront_try_connect(struct pcifront_device *pdev)
{
	int err = -EFAULT;
	int i, num_roots, len;
	char str[64];
	unsigned int domain, bus;

	spin_lock(&pdev->dev_lock);

	/* Only connect once */
	if (xenbus_read_driver_state(pdev->xdev->nodename) !=
	    XenbusStateInitialised)
		goto out;

	err = pcifront_connect(pdev);
	if (err) {
		xenbus_dev_fatal(pdev->xdev, err,
				 "Error connecting PCI Frontend");
		goto out;
	}

	err = xenbus_scanf(XBT_NIL, pdev->xdev->otherend,
			   "root_num", "%d", &num_roots);
	if (err == -ENOENT) {
		xenbus_dev_error(pdev->xdev, err,
				 "No PCI Roots found, trying 0000:00");
		err = pcifront_scan_root(pdev, 0, 0);
		num_roots = 0;
	} else if (err != 1) {
		if (err == 0)
			err = -EINVAL;
		xenbus_dev_fatal(pdev->xdev, err,
				 "Error reading number of PCI roots");
		goto out;
	}

	for (i = 0; i < num_roots; i++) {
		len = snprintf(str, sizeof(str), "root-%d", i);
		if (unlikely(len >= (sizeof(str) - 1))) {
			err = -ENOMEM;
			goto out;
		}

		err = xenbus_scanf(XBT_NIL, pdev->xdev->otherend, str,
				   "%x:%x", &domain, &bus);
		if (err != 2) {
			if (err >= 0)
				err = -EINVAL;
			xenbus_dev_fatal(pdev->xdev, err,
					 "Error reading PCI root %d", i);
			goto out;
		}

		err = pcifront_scan_root(pdev, domain, bus);
		if (err) {
			xenbus_dev_fatal(pdev->xdev, err,
					 "Error scanning PCI root %04x:%02x",
					 domain, bus);
			goto out;
		}
	}

	err = xenbus_switch_state(pdev->xdev, XenbusStateConnected);
	if (err)
		goto out;

      out:
	spin_unlock(&pdev->dev_lock);
	return err;
}

static int pcifront_try_disconnect(struct pcifront_device *pdev)
{
	int err = 0;
	enum xenbus_state prev_state;

	spin_lock(&pdev->dev_lock);

	prev_state = xenbus_read_driver_state(pdev->xdev->nodename);

	if (prev_state < XenbusStateClosing)
		err = xenbus_switch_state(pdev->xdev, XenbusStateClosing);

	if (!err && prev_state == XenbusStateConnected)
		pcifront_disconnect(pdev);

	spin_unlock(&pdev->dev_lock);

	return err;
}

static void pcifront_backend_changed(struct xenbus_device *xdev,
				     enum xenbus_state be_state)
{
	struct pcifront_device *pdev = xdev->dev.driver_data;

	switch (be_state) {
	case XenbusStateClosing:
		dev_warn(&xdev->dev, "backend going away!\n");
		pcifront_try_disconnect(pdev);
		break;

	case XenbusStateUnknown:
	case XenbusStateClosed:
		dev_warn(&xdev->dev, "backend went away!\n");
		pcifront_try_disconnect(pdev);

		device_unregister(&pdev->xdev->dev);
		break;

	case XenbusStateConnected:
		pcifront_try_connect(pdev);
		break;

	default:
		break;
	}
}

static int pcifront_xenbus_probe(struct xenbus_device *xdev,
				 const struct xenbus_device_id *id)
{
	int err = 0;
	struct pcifront_device *pdev = alloc_pdev(xdev);

	if (pdev == NULL) {
		err = -ENOMEM;
		xenbus_dev_fatal(xdev, err,
				 "Error allocating pcifront_device struct");
		goto out;
	}

	err = pcifront_publish_info(pdev);

      out:
	return err;
}

static int pcifront_xenbus_remove(struct xenbus_device *xdev)
{
	if (xdev->dev.driver_data)
		free_pdev(xdev->dev.driver_data);

	return 0;
}

static struct xenbus_device_id xenpci_ids[] = {
	{"pci"},
	{{0}},
};

static struct xenbus_driver xenbus_pcifront_driver = {
	.name 			= "pcifront",
	.owner 			= THIS_MODULE,
	.ids 			= xenpci_ids,
	.probe 			= pcifront_xenbus_probe,
	.remove 		= pcifront_xenbus_remove,
	.otherend_changed 	= pcifront_backend_changed,
};

static int __init pcifront_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	return xenbus_register_frontend(&xenbus_pcifront_driver);
}

/* Initialize after the Xen PCI Frontend Stub is initialized */
subsys_initcall(pcifront_init);
