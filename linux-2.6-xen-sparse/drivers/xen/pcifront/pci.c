/*
 * PCI Frontend Operations - ensure only one PCI frontend runs at a time
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include "pcifront.h"

DEFINE_SPINLOCK(pcifront_dev_lock);
static struct pcifront_device *pcifront_dev = NULL;

int pcifront_connect(struct pcifront_device *pdev)
{
	int err = 0;

	spin_lock(&pcifront_dev_lock);

	if (!pcifront_dev) {
		dev_info(&pdev->xdev->dev, "Installing PCI frontend\n");
		pcifront_dev = pdev;
	}
	else {
		dev_err(&pdev->xdev->dev, "PCI frontend already installed!\n");
		err = -EEXIST;
	}

	spin_unlock(&pcifront_dev_lock);

	return err;
}

void pcifront_disconnect(struct pcifront_device *pdev)
{
	spin_lock(&pcifront_dev_lock);

	if (pdev == pcifront_dev) {
		dev_info(&pdev->xdev->dev,
			 "Disconnecting PCI Frontend Buses\n");
		pcifront_dev = NULL;
	}

	spin_unlock(&pcifront_dev_lock);
}
