/*
 *	Adaptec AAC series RAID controller driver
 *	(c) Copyright 2001 Red Hat Inc.	<alan@redhat.com>
 *
 * based on the old aacraid driver that is..
 * Adaptec aacraid device driver for Linux.
 *
 * Copyright (c) 2000 Adaptec, Inc. (aacraid@adaptec.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Module Name:
 *  commctrl.c
 *
 * Abstract: Contains all routines for control of the AFA comm layer
 *
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
/*#include <linux/completion.h>*/
#include <linux/blk.h>
/*#include <asm/semaphore.h>*/
#include <asm/uaccess.h>
#include "scsi.h"
#include "hosts.h"

#include "aacraid.h"

/**
 *	ioctl_send_fib	-	send a FIB from userspace
 *	@dev:	adapter is being processed
 *	@arg:	arguments to the ioctl call
 *	
 *	This routine sends a fib to the adapter on behalf of a user level
 *	program.
 */
 
static int ioctl_send_fib(struct aac_dev * dev, void *arg)
{
	struct hw_fib * kfib;
	struct fib *fibptr;

	fibptr = fib_alloc(dev);
	if(fibptr == NULL)
		return -ENOMEM;
		
	kfib = fibptr->hw_fib;
	/*
	 *	First copy in the header so that we can check the size field.
	 */
	if (copy_from_user((void *)kfib, arg, sizeof(struct aac_fibhdr))) {
		fib_free(fibptr);
		return -EFAULT;
	}
	/*
	 *	Since we copy based on the fib header size, make sure that we
	 *	will not overrun the buffer when we copy the memory. Return
	 *	an error if we would.
	 */
	if(le32_to_cpu(kfib->header.Size) > sizeof(struct hw_fib) - sizeof(struct aac_fibhdr)) {
		fib_free(fibptr);
		return -EINVAL;
	}

	if (copy_from_user((void *) kfib, arg, le32_to_cpu(kfib->header.Size) + sizeof(struct aac_fibhdr))) {
		fib_free(fibptr);
		return -EFAULT;
	}

	if (kfib->header.Command == cpu_to_le32(TakeABreakPt)) {
		aac_adapter_interrupt(dev);
		/*
		 * Since we didn't really send a fib, zero out the state to allow 
		 * cleanup code not to assert.
		 */
		kfib->header.XferState = 0;
	} else {
		if (fib_send(kfib->header.Command, fibptr, le32_to_cpu(kfib->header.Size) , FsaNormal,
			1, 1, NULL, NULL) != 0) 
		{
			fib_free(fibptr);
			return -EINVAL;
		}
		if (fib_complete(fibptr) != 0) {
			fib_free(fibptr);
			return -EINVAL;
		}
	}
	/*
	 *	Make sure that the size returned by the adapter (which includes
	 *	the header) is less than or equal to the size of a fib, so we
	 *	don't corrupt application data. Then copy that size to the user
	 *	buffer. (Don't try to add the header information again, since it
	 *	was already included by the adapter.)
	 */

	if (copy_to_user(arg, (void *)kfib, kfib->header.Size)) {
		fib_free(fibptr);
		return -EFAULT;
	}
	fib_free(fibptr);
	return 0;
}

/**
 *	open_getadapter_fib	-	Get the next fib
 *
 *	This routine will get the next Fib, if available, from the AdapterFibContext
 *	passed in from the user.
 */

static int open_getadapter_fib(struct aac_dev * dev, void *arg)
{
	struct aac_fib_context * fibctx;
	int status;
	unsigned long flags;

	fibctx = kmalloc(sizeof(struct aac_fib_context), GFP_KERNEL);
	if (fibctx == NULL) {
		status = -ENOMEM;
	} else {
		fibctx->type = FSAFS_NTC_GET_ADAPTER_FIB_CONTEXT;
		fibctx->size = sizeof(struct aac_fib_context);
#if 0
		/*
		 *	Initialize the mutex used to wait for the next AIF.
		 */
		init_MUTEX_LOCKED(&fibctx->wait_sem);
#endif
		fibctx->wait = 0;
		/*
		 *	Initialize the fibs and set the count of fibs on
		 *	the list to 0.
		 */
		fibctx->count = 0;
		INIT_LIST_HEAD(&fibctx->fib_list);
		fibctx->jiffies = jiffies/HZ;
		/*
		 *	Now add this context onto the adapter's 
		 *	AdapterFibContext list.
		 */
		spin_lock_irqsave(&dev->fib_lock, flags);
		list_add_tail(&fibctx->next, &dev->fib_list);
		spin_unlock_irqrestore(&dev->fib_lock, flags);
		if (copy_to_user(arg,  &fibctx, sizeof(struct aac_fib_context *))) {
			status = -EFAULT;
		} else {
			status = 0;
		}	
	}
	return status;
}

/**
 *	next_getadapter_fib	-	get the next fib
 *	@dev: adapter to use
 *	@arg: ioctl argument
 *	
 * 	This routine will get the next Fib, if available, from the AdapterFibContext
 *	passed in from the user.
 */

static int next_getadapter_fib(struct aac_dev * dev, void *arg)
{
	struct fib_ioctl f;
	struct aac_fib_context *fibctx, *aifcp;
	struct fib * fib;
	int status;
	struct list_head * entry;
	int found;
	unsigned long flags;
	
	if(copy_from_user((void *)&f, arg, sizeof(struct fib_ioctl)))
		return -EFAULT;
	/*
	 *	Extract the AdapterFibContext from the Input parameters.
	 */
	fibctx = (struct aac_fib_context *) f.fibctx;

	/*
	 *	Verify that the HANDLE passed in was a valid AdapterFibContext
	 *
	 *	Search the list of AdapterFibContext addresses on the adapter
	 *	to be sure this is a valid address
	 */
	found = 0;
	entry = dev->fib_list.next;

	while(entry != &dev->fib_list) {
		aifcp = list_entry(entry, struct aac_fib_context, next);
		if(fibctx == aifcp) {   /* We found a winner */
			found = 1;
			break;
		}
		entry = entry->next;
	}
	if (found == 0) {
		dprintk ((KERN_INFO "Fib not found\n"));
		return -EINVAL;
	}

	if((fibctx->type != FSAFS_NTC_GET_ADAPTER_FIB_CONTEXT) ||
		 (fibctx->size != sizeof(struct aac_fib_context))) {
		dprintk ((KERN_INFO "Fib Context corrupt?\n"));
		return -EINVAL;
	}
	status = 0;
	spin_lock_irqsave(&dev->fib_lock, flags);
	/*
	 *	If there are no fibs to send back, then either wait or return
	 *	-EAGAIN
	 */
return_fib:
	if (!list_empty(&fibctx->fib_list)) {
		struct list_head * entry;
		/*
		 *	Pull the next fib from the fibs
		 */
		entry = fibctx->fib_list.next;
		list_del(entry);
		
		fib = list_entry(entry, struct fib, fiblink);
		fibctx->count--;
		spin_unlock_irqrestore(&dev->fib_lock, flags);
		if (copy_to_user(f.fib, fib->hw_fib, sizeof(struct hw_fib))) {
			kfree(fib->hw_fib);
			kfree(fib);
			return -EFAULT;
		}	
		/*
		 *	Free the space occupied by this copy of the fib.
		 */
		kfree(fib->hw_fib);
		kfree(fib);
		status = 0;
	} else {
		spin_unlock_irqrestore(&dev->fib_lock, flags);
		if (f.wait) {
#if 0
			if(down_interruptible(&fibctx->wait_sem) < 0) {
				status = -EINTR;
			} else {
#else
			{
#endif
				/* Lock again and retry */
				spin_lock_irqsave(&dev->fib_lock, flags);
				goto return_fib;
			}
		} else {
			status = -EAGAIN;
		}	
	}
	fibctx->jiffies = jiffies/HZ;
	return status;
}

int aac_close_fib_context(struct aac_dev * dev, struct aac_fib_context * fibctx)
{
	struct fib *fib;

	/*
	 *	First free any FIBs that have not been consumed.
	 */
	while (!list_empty(&fibctx->fib_list)) {
		struct list_head * entry;
		/*
		 *	Pull the next fib from the fibs
		 */
		entry = fibctx->fib_list.next;
		list_del(entry);
		fib = list_entry(entry, struct fib, fiblink);
		fibctx->count--;
		/*
		 *	Free the space occupied by this copy of the fib.
		 */
		kfree(fib->hw_fib);
		kfree(fib);
	}
	/*
	 *	Remove the Context from the AdapterFibContext List
	 */
	list_del(&fibctx->next);
	/*
	 *	Invalidate context
	 */
	fibctx->type = 0;
	/*
	 *	Free the space occupied by the Context
	 */
	kfree(fibctx);
	return 0;
}

/**
 *	close_getadapter_fib	-	close down user fib context
 *	@dev: adapter
 *	@arg: ioctl arguments
 *
 *	This routine will close down the fibctx passed in from the user.
 */
 
static int close_getadapter_fib(struct aac_dev * dev, void *arg)
{
	struct aac_fib_context *fibctx, *aifcp;
	int status;
	unsigned long flags;
	struct list_head * entry;
	int found;

	/*
	 *	Extract the fibctx from the input parameters
	 */
	fibctx = arg;

	/*
	 *	Verify that the HANDLE passed in was a valid AdapterFibContext
	 *
	 *	Search the list of AdapterFibContext addresses on the adapter
	 *	to be sure this is a valid address
	 */

	found = 0;
	entry = dev->fib_list.next;

	while(entry != &dev->fib_list) {
		aifcp = list_entry(entry, struct aac_fib_context, next);
		if(fibctx == aifcp) {   /* We found a winner */
			found = 1;
			break;
		}
		entry = entry->next;
	}

	if(found == 0)
		return 0; /* Already gone */

	if((fibctx->type != FSAFS_NTC_GET_ADAPTER_FIB_CONTEXT) ||
		 (fibctx->size != sizeof(struct aac_fib_context)))
		return -EINVAL;
	spin_lock_irqsave(&dev->fib_lock, flags);
	status = aac_close_fib_context(dev, fibctx);
	spin_unlock_irqrestore(&dev->fib_lock, flags);
	return status;
}

/**
 *	check_revision	-	close down user fib context
 *	@dev: adapter
 *	@arg: ioctl arguments
 *
 *	This routine returns the firmware version.
 *      Under Linux, there have been no version incompatibilities, so this is simple!
 */

static int check_revision(struct aac_dev *dev, void *arg)
{
	struct revision response;

	response.compat = 1;
	response.version = dev->adapter_info.kernelrev;
	response.build = dev->adapter_info.kernelbuild;

	if (copy_to_user(arg, &response, sizeof(response)))
		return -EFAULT;
	return 0;
}


struct aac_pci_info {
        u32 bus;
        u32 slot;
};


int aac_get_pci_info(struct aac_dev* dev, void* arg)
{
        struct aac_pci_info pci_info;

	pci_info.bus = dev->pdev->bus->number;
	pci_info.slot = PCI_SLOT(dev->pdev->devfn);

       if(copy_to_user( arg, (void*)&pci_info, sizeof(struct aac_pci_info)))
               return -EFAULT;
        return 0;
 }
 

int aac_do_ioctl(struct aac_dev * dev, int cmd, void *arg)
{
	int status;
	
	/*
	 *	HBA gets first crack
	 */
	 
	status = aac_dev_ioctl(dev, cmd, arg);
	if(status != -ENOTTY)
		return status;

	switch (cmd) {
	case FSACTL_MINIPORT_REV_CHECK:
		status = check_revision(dev, arg);
		break;
	case FSACTL_SENDFIB:
		status = ioctl_send_fib(dev, arg);
		break;
	case FSACTL_OPEN_GET_ADAPTER_FIB:
		status = open_getadapter_fib(dev, arg);
		break;
	case FSACTL_GET_NEXT_ADAPTER_FIB:
		status = next_getadapter_fib(dev, arg);
		break;
	case FSACTL_CLOSE_GET_ADAPTER_FIB:
		status = close_getadapter_fib(dev, arg);
		break;
	case FSACTL_GET_PCI_INFO:
		status = aac_get_pci_info(dev,arg);
		break;
	default:
		status = -ENOTTY;
	  	break;	
	}
	return status;
}

