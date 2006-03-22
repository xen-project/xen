/*
 * Copyright (c) 2005, IBM Corporation
 *
 * Author: Stefan Berger, stefanb@us.ibm.com
 * Grant table support: Mahadevan Gomathisankaran
 *
 * This code has been derived from drivers/xen/netfront/netfront.c
 *
 * Copyright (c) 2002-2004, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <xen/tpmfe.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <asm/io.h>
#include <xen/evtchn.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/io/tpmif.h>
#include <asm/uaccess.h>
#include <xen/xenbus.h>
#include <xen/interface/grant_table.h>

#include "tpmfront.h"

#undef DEBUG

/* locally visible variables */
static grant_ref_t gref_head;
static struct tpm_private *my_priv;

/* local function prototypes */
static irqreturn_t tpmif_int(int irq,
                             void *tpm_priv,
                             struct pt_regs *ptregs);
static void tpmif_rx_action(unsigned long unused);
static void tpmif_connect(struct tpm_private *tp, domid_t domid);
static DECLARE_TASKLET(tpmif_rx_tasklet, tpmif_rx_action, 0);
static int tpm_allocate_buffers(struct tpm_private *tp);
static void tpmif_set_connected_state(struct tpm_private *tp,
                                      u8 newstate);
static int tpm_xmit(struct tpm_private *tp,
                    const u8 * buf, size_t count, int userbuffer,
                    void *remember);

#define DPRINTK(fmt, args...) \
    pr_debug("xen_tpm_fr (%s:%d) " fmt, __FUNCTION__, __LINE__, ##args)
#define IPRINTK(fmt, args...) \
    printk(KERN_INFO "xen_tpm_fr: " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_tpm_fr: " fmt, ##args)


static inline int
tx_buffer_copy(struct tx_buffer *txb, const u8 * src, int len,
               int isuserbuffer)
{
	int copied = len;

	if (len > txb->size) {
		copied = txb->size;
	}
	if (isuserbuffer) {
		if (copy_from_user(txb->data, src, copied))
			return -EFAULT;
	} else {
		memcpy(txb->data, src, copied);
	}
	txb->len = len;
	return copied;
}

static inline struct tx_buffer *tx_buffer_alloc(void)
{
	struct tx_buffer *txb = kzalloc(sizeof (struct tx_buffer),
					GFP_KERNEL);

	if (txb) {
		txb->len = 0;
		txb->size = PAGE_SIZE;
		txb->data = (unsigned char *)__get_free_page(GFP_KERNEL);
		if (txb->data == NULL) {
			kfree(txb);
			txb = NULL;
		}
	}
	return txb;
}


/**************************************************************
 Utility function for the tpm_private structure
**************************************************************/
static inline void tpm_private_init(struct tpm_private *tp)
{
	spin_lock_init(&tp->tx_lock);
	init_waitqueue_head(&tp->wait_q);
}

static struct tpm_private *tpm_private_get(void)
{
	if (!my_priv) {
		my_priv = kzalloc(sizeof(struct tpm_private), GFP_KERNEL);
		if (my_priv) {
			tpm_private_init(my_priv);
		}
	}
	return my_priv;
}

static inline void tpm_private_free(void)
{
	kfree(my_priv);
	my_priv = NULL;
}

/**************************************************************

 The interface to let the tpm plugin register its callback
 function and send data to another partition using this module

**************************************************************/

static DEFINE_MUTEX(upperlayer_lock);
static DEFINE_MUTEX(suspend_lock);
static struct tpmfe_device *upperlayer_tpmfe;

/*
 * Send data via this module by calling this function
 */
int tpm_fe_send(struct tpm_private *tp, const u8 * buf, size_t count, void *ptr)
{
	int sent;

	mutex_lock(&suspend_lock);
	sent = tpm_xmit(tp, buf, count, 0, ptr);
	mutex_unlock(&suspend_lock);

	return sent;
}
EXPORT_SYMBOL(tpm_fe_send);

/*
 * Register a callback for receiving data from this module
 */
int tpm_fe_register_receiver(struct tpmfe_device *tpmfe_dev)
{
	int rc = 0;

	mutex_lock(&upperlayer_lock);
	if (NULL == upperlayer_tpmfe) {
		upperlayer_tpmfe = tpmfe_dev;
		tpmfe_dev->max_tx_size = TPMIF_TX_RING_SIZE * PAGE_SIZE;
		tpmfe_dev->tpm_private = tpm_private_get();
		if (!tpmfe_dev->tpm_private) {
			rc = -ENOMEM;
		}
	} else {
		rc = -EBUSY;
	}
	mutex_unlock(&upperlayer_lock);
	return rc;
}
EXPORT_SYMBOL(tpm_fe_register_receiver);

/*
 * Unregister the callback for receiving data from this module
 */
void tpm_fe_unregister_receiver(void)
{
	mutex_lock(&upperlayer_lock);
	upperlayer_tpmfe = NULL;
	mutex_unlock(&upperlayer_lock);
}
EXPORT_SYMBOL(tpm_fe_unregister_receiver);

/*
 * Call this function to send data to the upper layer's
 * registered receiver function.
 */
static int tpm_fe_send_upperlayer(const u8 * buf, size_t count,
                                  const void *ptr)
{
	int rc = 0;

	mutex_lock(&upperlayer_lock);

	if (upperlayer_tpmfe && upperlayer_tpmfe->receive)
		rc = upperlayer_tpmfe->receive(buf, count, ptr);

	mutex_unlock(&upperlayer_lock);
	return rc;
}

/**************************************************************
 XENBUS support code
**************************************************************/

static int setup_tpmring(struct xenbus_device *dev,
                         struct tpm_private *tp)
{
	tpmif_tx_interface_t *sring;
	int err;

	sring = (void *)__get_free_page(GFP_KERNEL);
	if (!sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	tp->tx = sring;

	tpm_allocate_buffers(tp);

	err = xenbus_grant_ring(dev, virt_to_mfn(tp->tx));
	if (err < 0) {
		free_page((unsigned long)sring);
		tp->tx = NULL;
		xenbus_dev_fatal(dev, err, "allocating grant reference");
		goto fail;
	}
	tp->ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &tp->evtchn);
	if (err)
		goto fail;

	tpmif_connect(tp, dev->otherend_id);

	return 0;
fail:
	return err;
}


static void destroy_tpmring(struct tpm_private *tp)
{
	tpmif_set_connected_state(tp, 0);
	if (tp->tx != NULL) {
		gnttab_end_foreign_access(tp->ring_ref, 0,
					  (unsigned long)tp->tx);
		tp->tx = NULL;
	}

	if (tp->irq)
		unbind_from_irqhandler(tp->irq, NULL);
	tp->evtchn = tp->irq = 0;
}


static int talk_to_backend(struct xenbus_device *dev,
                           struct tpm_private *tp)
{
	const char *message = NULL;
	int err;
	xenbus_transaction_t xbt;

	err = setup_tpmring(dev, tp);
	if (err) {
		xenbus_dev_fatal(dev, err, "setting up ring");
		goto out;
	}

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_tpmring;
	}

	err = xenbus_printf(xbt, dev->nodename,
	                    "ring-ref","%u", tp->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel", "%u", tp->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename,
	                    "state", "%d", XenbusStateInitialised);
	if (err) {
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err) {
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_tpmring;
	}
	return 0;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	if (message)
		xenbus_dev_error(dev, err, "%s", message);
destroy_tpmring:
	destroy_tpmring(tp);
out:
	return err;
}

/**
 * Callback received when the backend's state changes.
 */
static void backend_changed(struct xenbus_device *dev,
			    XenbusState backend_state)
{
	struct tpm_private *tp = dev->data;
	DPRINTK("\n");

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitWait:
	case XenbusStateInitialised:
	case XenbusStateUnknown:
		break;

	case XenbusStateConnected:
		tpmif_set_connected_state(tp, 1);
		break;

	case XenbusStateClosing:
		tpmif_set_connected_state(tp, 0);
		break;

	case XenbusStateClosed:
		if (tp->is_suspended == 0) {
			device_unregister(&dev->dev);
		}
		break;
	}
}


static int tpmfront_probe(struct xenbus_device *dev,
                          const struct xenbus_device_id *id)
{
	int err;
	int handle;
	struct tpm_private *tp = tpm_private_get();

	err = xenbus_scanf(XBT_NULL, dev->nodename,
	                   "handle", "%i", &handle);
	if (XENBUS_EXIST_ERR(err))
		return err;

	if (err < 0) {
		xenbus_dev_fatal(dev,err,"reading virtual-device");
		return err;
	}

	tp->dev = dev;
	dev->data = tp;

	err = talk_to_backend(dev, tp);
	if (err) {
		tpm_private_free();
		dev->data = NULL;
		return err;
	}
	return 0;
}


static int tpmfront_remove(struct xenbus_device *dev)
{
	struct tpm_private *tp = dev->data;
	destroy_tpmring(tp);
	return 0;
}

static int
tpmfront_suspend(struct xenbus_device *dev)
{
	struct tpm_private *tp = dev->data;
	u32 ctr;

	/* lock, so no app can send */
	mutex_lock(&suspend_lock);
	tp->is_suspended = 1;

	for (ctr = 0; atomic_read(&tp->tx_busy) && ctr <= 25; ctr++) {
		if ((ctr % 10) == 0)
			printk("TPM-FE [INFO]: Waiting for outstanding request.\n");
		/*
		 * Wait for a request to be responded to.
		 */
		interruptible_sleep_on_timeout(&tp->wait_q, 100);
	}

	if (atomic_read(&tp->tx_busy)) {
		/*
		 * A temporary work-around.
		 */
		printk("TPM-FE [WARNING]: Resetting busy flag.");
		atomic_set(&tp->tx_busy, 0);
	}

	return 0;
}

static int
tpmfront_resume(struct xenbus_device *dev)
{
	struct tpm_private *tp = dev->data;
	return talk_to_backend(dev, tp);
}

static void
tpmif_connect(struct tpm_private *tp, domid_t domid)
{
	int err;

	tp->backend_id = domid;

	err = bind_evtchn_to_irqhandler(tp->evtchn,
					tpmif_int, SA_SAMPLE_RANDOM, "tpmif",
					tp);
	if (err <= 0) {
		WPRINTK("bind_evtchn_to_irqhandler failed (err=%d)\n", err);
		return;
	}

	tp->irq = err;
}

static struct xenbus_device_id tpmfront_ids[] = {
	{ "vtpm" },
	{ "" }
};

static struct xenbus_driver tpmfront = {
	.name = "vtpm",
	.owner = THIS_MODULE,
	.ids = tpmfront_ids,
	.probe = tpmfront_probe,
	.remove =  tpmfront_remove,
	.resume = tpmfront_resume,
	.otherend_changed = backend_changed,
	.suspend = tpmfront_suspend,
};

static void __init init_tpm_xenbus(void)
{
	xenbus_register_frontend(&tpmfront);
}

static void __exit exit_tpm_xenbus(void)
{
	xenbus_unregister_driver(&tpmfront);
}


static int
tpm_allocate_buffers(struct tpm_private *tp)
{
	unsigned int i;

	for (i = 0; i < TPMIF_TX_RING_SIZE; i++)
		tp->tx_buffers[i] = tx_buffer_alloc();
	return 1;
}

static void
tpmif_rx_action(unsigned long priv)
{
	struct tpm_private *tp = (struct tpm_private *)priv;

	int i = 0;
	unsigned int received;
	unsigned int offset = 0;
	u8 *buffer;
	tpmif_tx_request_t *tx;
	tx = &tp->tx->ring[i].req;

	received = tx->size;

	buffer = kmalloc(received, GFP_KERNEL);
	if (NULL == buffer) {
		goto exit;
	}

	for (i = 0; i < TPMIF_TX_RING_SIZE && offset < received; i++) {
		struct tx_buffer *txb = tp->tx_buffers[i];
		tpmif_tx_request_t *tx;
		unsigned int tocopy;

		tx = &tp->tx->ring[i].req;
		tocopy = tx->size;
		if (tocopy > PAGE_SIZE) {
			tocopy = PAGE_SIZE;
		}

		memcpy(&buffer[offset], txb->data, tocopy);

		gnttab_release_grant_reference(&gref_head, tx->ref);

		offset += tocopy;
	}

	tpm_fe_send_upperlayer(buffer, received, tp->tx_remember);
	kfree(buffer);

exit:
	atomic_set(&tp->tx_busy, 0);
	wake_up_interruptible(&tp->wait_q);
}


static irqreturn_t
tpmif_int(int irq, void *tpm_priv, struct pt_regs *ptregs)
{
	struct tpm_private *tp = tpm_priv;
	unsigned long flags;

	spin_lock_irqsave(&tp->tx_lock, flags);
	tpmif_rx_tasklet.data = (unsigned long)tp;
	tasklet_schedule(&tpmif_rx_tasklet);
	spin_unlock_irqrestore(&tp->tx_lock, flags);

	return IRQ_HANDLED;
}


static int
tpm_xmit(struct tpm_private *tp,
         const u8 * buf, size_t count, int isuserbuffer,
         void *remember)
{
	tpmif_tx_request_t *tx;
	TPMIF_RING_IDX i;
	unsigned int offset = 0;

	spin_lock_irq(&tp->tx_lock);

	if (unlikely(atomic_read(&tp->tx_busy))) {
		printk("tpm_xmit: There's an outstanding request/response "
		       "on the way!\n");
		spin_unlock_irq(&tp->tx_lock);
		return -EBUSY;
	}

	if (tp->is_connected != 1) {
		spin_unlock_irq(&tp->tx_lock);
		return -EIO;
	}

	for (i = 0; count > 0 && i < TPMIF_TX_RING_SIZE; i++) {
		struct tx_buffer *txb = tp->tx_buffers[i];
		int copied;

		if (NULL == txb) {
			DPRINTK("txb (i=%d) is NULL. buffers initilized?\n"
				"Not transmitting anything!\n", i);
			spin_unlock_irq(&tp->tx_lock);
			return -EFAULT;
		}
		copied = tx_buffer_copy(txb, &buf[offset], count,
		                        isuserbuffer);
		if (copied < 0) {
			/* An error occurred */
			spin_unlock_irq(&tp->tx_lock);
			return copied;
		}
		count -= copied;
		offset += copied;

		tx = &tp->tx->ring[i].req;

		tx->addr = virt_to_machine(txb->data);
		tx->size = txb->len;

		DPRINTK("First 4 characters sent by TPM-FE are 0x%02x 0x%02x 0x%02x 0x%02x\n",
		        txb->data[0],txb->data[1],txb->data[2],txb->data[3]);

		/* get the granttable reference for this page */
		tx->ref = gnttab_claim_grant_reference(&gref_head);

		if (-ENOSPC == tx->ref) {
			spin_unlock_irq(&tp->tx_lock);
			DPRINTK(" Grant table claim reference failed in func:%s line:%d file:%s\n", __FUNCTION__, __LINE__, __FILE__);
			return -ENOSPC;
		}
		gnttab_grant_foreign_access_ref( tx->ref,
		                                 tp->backend_id,
		                                 (tx->addr >> PAGE_SHIFT),
		                                 0 /*RW*/);
		wmb();
	}

	atomic_set(&tp->tx_busy, 1);
	tp->tx_remember = remember;
	mb();

	DPRINTK("Notifying backend via event channel %d\n",
	        tp->evtchn);

	notify_remote_via_irq(tp->irq);

	spin_unlock_irq(&tp->tx_lock);
	return offset;
}


static void tpmif_notify_upperlayer(struct tpm_private *tp)
{
	/*
	 * Notify upper layer about the state of the connection
	 * to the BE.
	 */
	mutex_lock(&upperlayer_lock);

	if (upperlayer_tpmfe != NULL) {
		if (tp->is_connected) {
			upperlayer_tpmfe->status(TPMFE_STATUS_CONNECTED);
		} else {
			upperlayer_tpmfe->status(0);
		}
	}
	mutex_unlock(&upperlayer_lock);
}


static void tpmif_set_connected_state(struct tpm_private *tp, u8 is_connected)
{
	/*
	 * Don't notify upper layer if we are in suspend mode and
	 * should disconnect - assumption is that we will resume
	 * The mutex keeps apps from sending.
	 */
	if (is_connected == 0 && tp->is_suspended == 1) {
		return;
	}

	/*
	 * Unlock the mutex if we are connected again
	 * after being suspended - now resuming.
	 * This also removes the suspend state.
	 */
	if (is_connected == 1 && tp->is_suspended == 1) {
		tp->is_suspended = 0;
		/* unlock, so apps can resume sending */
		mutex_unlock(&suspend_lock);
	}

	if (is_connected != tp->is_connected) {
		tp->is_connected = is_connected;
		tpmif_notify_upperlayer(tp);
	}
}


/* =================================================================
 * Initialization function.
 * =================================================================
 */

static int __init
tpmif_init(void)
{
	IPRINTK("Initialising the vTPM driver.\n");
	if ( gnttab_alloc_grant_references ( TPMIF_TX_RING_SIZE,
	                                     &gref_head ) < 0) {
		return -EFAULT;
	}

	init_tpm_xenbus();

	return 0;
}

module_init(tpmif_init);

static void __exit
tpmif_exit(void)
{
	exit_tpm_xenbus();
	gnttab_free_grant_references(gref_head);
}

module_exit(tpmif_exit);

MODULE_LICENSE("Dual BSD/GPL");

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
