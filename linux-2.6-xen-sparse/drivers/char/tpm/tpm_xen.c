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

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include <xen/evtchn.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/io/tpmif.h>
#include <xen/gnttab.h>
#include <xen/xenbus.h>
#include "tpm.h"
#include "tpm_vtpm.h"

#undef DEBUG

/* local structures */
struct tpm_private {
	struct tpm_chip *chip;

	tpmif_tx_interface_t *tx;
	atomic_t refcnt;
	unsigned int irq;
	u8 is_connected;
	u8 is_suspended;

	spinlock_t tx_lock;

	struct tx_buffer *tx_buffers[TPMIF_TX_RING_SIZE];

	atomic_t tx_busy;
	void *tx_remember;

	domid_t backend_id;
	wait_queue_head_t wait_q;

	struct xenbus_device *dev;
	int ring_ref;
};

struct tx_buffer {
	unsigned int size;	// available space in data
	unsigned int len;	// used space in data
	unsigned char *data;	// pointer to a page
};


/* locally visible variables */
static grant_ref_t gref_head;
static struct tpm_private *my_priv;

/* local function prototypes */
static irqreturn_t tpmif_int(int irq,
                             void *tpm_priv,
                             struct pt_regs *ptregs);
static void tpmif_rx_action(unsigned long unused);
static int tpmif_connect(struct xenbus_device *dev,
                         struct tpm_private *tp,
                         domid_t domid);
static DECLARE_TASKLET(tpmif_rx_tasklet, tpmif_rx_action, 0);
static int tpmif_allocate_tx_buffers(struct tpm_private *tp);
static void tpmif_free_tx_buffers(struct tpm_private *tp);
static void tpmif_set_connected_state(struct tpm_private *tp,
                                      u8 newstate);
static int tpm_xmit(struct tpm_private *tp,
                    const u8 * buf, size_t count, int userbuffer,
                    void *remember);
static void destroy_tpmring(struct tpm_private *tp);
void __exit tpmif_exit(void);

#define DPRINTK(fmt, args...) \
    pr_debug("xen_tpm_fr (%s:%d) " fmt, __FUNCTION__, __LINE__, ##args)
#define IPRINTK(fmt, args...) \
    printk(KERN_INFO "xen_tpm_fr: " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_tpm_fr: " fmt, ##args)

#define GRANT_INVALID_REF	0


static inline int
tx_buffer_copy(struct tx_buffer *txb, const u8 *src, int len,
               int isuserbuffer)
{
	int copied = len;

	if (len > txb->size)
		copied = txb->size;
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
	struct tx_buffer *txb;

	txb = kzalloc(sizeof(struct tx_buffer), GFP_KERNEL);
	if (!txb)
		return NULL;

	txb->len = 0;
	txb->size = PAGE_SIZE;
	txb->data = (unsigned char *)__get_free_page(GFP_KERNEL);
	if (txb->data == NULL) {
		kfree(txb);
		txb = NULL;
	}

	return txb;
}


static inline void tx_buffer_free(struct tx_buffer *txb)
{
	if (txb) {
		free_page((long)txb->data);
		kfree(txb);
	}
}

/**************************************************************
 Utility function for the tpm_private structure
**************************************************************/
static void tpm_private_init(struct tpm_private *tp)
{
	spin_lock_init(&tp->tx_lock);
	init_waitqueue_head(&tp->wait_q);
	atomic_set(&tp->refcnt, 1);
}

static void tpm_private_put(void)
{
	if (!atomic_dec_and_test(&my_priv->refcnt))
		return;

	tpmif_free_tx_buffers(my_priv);
	kfree(my_priv);
	my_priv = NULL;
}

static struct tpm_private *tpm_private_get(void)
{
	int err;

	if (my_priv) {
		atomic_inc(&my_priv->refcnt);
		return my_priv;
	}

	my_priv = kzalloc(sizeof(struct tpm_private), GFP_KERNEL);
	if (!my_priv)
		return NULL;

	tpm_private_init(my_priv);
	err = tpmif_allocate_tx_buffers(my_priv);
	if (err < 0)
		tpm_private_put();

	return my_priv;
}

/**************************************************************

 The interface to let the tpm plugin register its callback
 function and send data to another partition using this module

**************************************************************/

static DEFINE_MUTEX(suspend_lock);
/*
 * Send data via this module by calling this function
 */
int vtpm_vd_send(struct tpm_private *tp,
                 const u8 * buf, size_t count, void *ptr)
{
	int sent;

	mutex_lock(&suspend_lock);
	sent = tpm_xmit(tp, buf, count, 0, ptr);
	mutex_unlock(&suspend_lock);

	return sent;
}

/**************************************************************
 XENBUS support code
**************************************************************/

static int setup_tpmring(struct xenbus_device *dev,
                         struct tpm_private *tp)
{
	tpmif_tx_interface_t *sring;
	int err;

	tp->ring_ref = GRANT_INVALID_REF;

	sring = (void *)__get_free_page(GFP_KERNEL);
	if (!sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	tp->tx = sring;

	err = xenbus_grant_ring(dev, virt_to_mfn(tp->tx));
	if (err < 0) {
		free_page((unsigned long)sring);
		tp->tx = NULL;
		xenbus_dev_fatal(dev, err, "allocating grant reference");
		goto fail;
	}
	tp->ring_ref = err;

	err = tpmif_connect(dev, tp, dev->otherend_id);
	if (err)
		goto fail;

	return 0;
fail:
	destroy_tpmring(tp);
	return err;
}


static void destroy_tpmring(struct tpm_private *tp)
{
	tpmif_set_connected_state(tp, 0);

	if (tp->ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(tp->ring_ref, 0,
					  (unsigned long)tp->tx);
		tp->ring_ref = GRANT_INVALID_REF;
		tp->tx = NULL;
	}

	if (tp->irq)
		unbind_from_irqhandler(tp->irq, tp);

	tp->irq = 0;
}


static int talk_to_backend(struct xenbus_device *dev,
                           struct tpm_private *tp)
{
	const char *message = NULL;
	int err;
	struct xenbus_transaction xbt;

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

	err = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
			    irq_to_evtchn_port(tp->irq));
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err) {
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_tpmring;
	}

	xenbus_switch_state(dev, XenbusStateConnected);

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
			    enum xenbus_state backend_state)
{
	struct tpm_private *tp = tpm_private_from_dev(&dev->dev);
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
		xenbus_frontend_closed(dev);
		break;

	case XenbusStateClosed:
		tpmif_set_connected_state(tp, 0);
		if (tp->is_suspended == 0)
			device_unregister(&dev->dev);
		xenbus_frontend_closed(dev);
		break;
	}
}

static int tpmfront_probe(struct xenbus_device *dev,
                          const struct xenbus_device_id *id)
{
	int err;
	int handle;
	struct tpm_private *tp = tpm_private_get();

	if (!tp)
		return -ENOMEM;

	tp->chip = init_vtpm(&dev->dev, tp);
	if (IS_ERR(tp->chip))
		return PTR_ERR(tp->chip);

	err = xenbus_scanf(XBT_NIL, dev->nodename,
	                   "handle", "%i", &handle);
	if (XENBUS_EXIST_ERR(err))
		return err;

	if (err < 0) {
		xenbus_dev_fatal(dev,err,"reading virtual-device");
		return err;
	}

	tp->dev = dev;

	err = talk_to_backend(dev, tp);
	if (err) {
		tpm_private_put();
		return err;
	}

	return 0;
}


static int tpmfront_remove(struct xenbus_device *dev)
{
	struct tpm_private *tp = tpm_private_from_dev(&dev->dev);
	destroy_tpmring(tp);
	cleanup_vtpm(&dev->dev);
	return 0;
}

static int tpmfront_suspend(struct xenbus_device *dev)
{
	struct tpm_private *tp = tpm_private_from_dev(&dev->dev);
	u32 ctr;

	/* Take the lock, preventing any application from sending. */
	mutex_lock(&suspend_lock);
	tp->is_suspended = 1;

	for (ctr = 0; atomic_read(&tp->tx_busy); ctr++) {
		if ((ctr % 10) == 0)
			printk("TPM-FE [INFO]: Waiting for outstanding "
			       "request.\n");
		/* Wait for a request to be responded to. */
		interruptible_sleep_on_timeout(&tp->wait_q, 100);
	}

	return 0;
}

static int tpmfront_suspend_finish(struct tpm_private *tp)
{
	tp->is_suspended = 0;
	/* Allow applications to send again. */
	mutex_unlock(&suspend_lock);
	return 0;
}

static int tpmfront_suspend_cancel(struct xenbus_device *dev)
{
	struct tpm_private *tp = tpm_private_from_dev(&dev->dev);
	return tpmfront_suspend_finish(tp);
}

static int tpmfront_resume(struct xenbus_device *dev)
{
	struct tpm_private *tp = tpm_private_from_dev(&dev->dev);
	destroy_tpmring(tp);
	return talk_to_backend(dev, tp);
}

static int tpmif_connect(struct xenbus_device *dev,
                         struct tpm_private *tp,
                         domid_t domid)
{
	int err;

	tp->backend_id = domid;

	err = bind_listening_port_to_irqhandler(
		domid, tpmif_int, SA_SAMPLE_RANDOM, "tpmif", tp);
	if (err <= 0) {
		WPRINTK("bind_listening_port_to_irqhandler failed "
			"(err=%d)\n", err);
		return err;
	}
	tp->irq = err;

	return 0;
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
	.suspend_cancel = tpmfront_suspend_cancel,
};

static void __init init_tpm_xenbus(void)
{
	xenbus_register_frontend(&tpmfront);
}

static int tpmif_allocate_tx_buffers(struct tpm_private *tp)
{
	unsigned int i;

	for (i = 0; i < TPMIF_TX_RING_SIZE; i++) {
		tp->tx_buffers[i] = tx_buffer_alloc();
		if (!tp->tx_buffers[i]) {
			tpmif_free_tx_buffers(tp);
			return -ENOMEM;
		}
	}
	return 0;
}

static void tpmif_free_tx_buffers(struct tpm_private *tp)
{
	unsigned int i;

	for (i = 0; i < TPMIF_TX_RING_SIZE; i++)
		tx_buffer_free(tp->tx_buffers[i]);
}

static void tpmif_rx_action(unsigned long priv)
{
	struct tpm_private *tp = (struct tpm_private *)priv;
	int i = 0;
	unsigned int received;
	unsigned int offset = 0;
	u8 *buffer;
	tpmif_tx_request_t *tx = &tp->tx->ring[i].req;

	atomic_set(&tp->tx_busy, 0);
	wake_up_interruptible(&tp->wait_q);

	received = tx->size;

	buffer = kmalloc(received, GFP_ATOMIC);
	if (!buffer)
		return;

	for (i = 0; i < TPMIF_TX_RING_SIZE && offset < received; i++) {
		struct tx_buffer *txb = tp->tx_buffers[i];
		tpmif_tx_request_t *tx;
		unsigned int tocopy;

		tx = &tp->tx->ring[i].req;
		tocopy = tx->size;
		if (tocopy > PAGE_SIZE)
			tocopy = PAGE_SIZE;

		memcpy(&buffer[offset], txb->data, tocopy);

		gnttab_release_grant_reference(&gref_head, tx->ref);

		offset += tocopy;
	}

	vtpm_vd_recv(tp->chip, buffer, received, tp->tx_remember);
	kfree(buffer);
}


static irqreturn_t tpmif_int(int irq, void *tpm_priv, struct pt_regs *ptregs)
{
	struct tpm_private *tp = tpm_priv;
	unsigned long flags;

	spin_lock_irqsave(&tp->tx_lock, flags);
	tpmif_rx_tasklet.data = (unsigned long)tp;
	tasklet_schedule(&tpmif_rx_tasklet);
	spin_unlock_irqrestore(&tp->tx_lock, flags);

	return IRQ_HANDLED;
}


static int tpm_xmit(struct tpm_private *tp,
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

		if (!txb) {
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

		DPRINTK("First 4 characters sent by TPM-FE are "
			"0x%02x 0x%02x 0x%02x 0x%02x\n",
		        txb->data[0],txb->data[1],txb->data[2],txb->data[3]);

		/* Get the granttable reference for this page. */
		tx->ref = gnttab_claim_grant_reference(&gref_head);
		if (tx->ref == -ENOSPC) {
			spin_unlock_irq(&tp->tx_lock);
			DPRINTK("Grant table claim reference failed in "
				"func:%s line:%d file:%s\n",
				__FUNCTION__, __LINE__, __FILE__);
			return -ENOSPC;
		}
		gnttab_grant_foreign_access_ref(tx->ref,
						tp->backend_id,
						virt_to_mfn(txb->data),
						0 /*RW*/);
		wmb();
	}

	atomic_set(&tp->tx_busy, 1);
	tp->tx_remember = remember;

	mb();

	notify_remote_via_irq(tp->irq);

	spin_unlock_irq(&tp->tx_lock);
	return offset;
}


static void tpmif_notify_upperlayer(struct tpm_private *tp)
{
	/* Notify upper layer about the state of the connection to the BE. */
	vtpm_vd_status(tp->chip, (tp->is_connected
				  ? TPM_VD_STATUS_CONNECTED
				  : TPM_VD_STATUS_DISCONNECTED));
}


static void tpmif_set_connected_state(struct tpm_private *tp, u8 is_connected)
{
	/*
	 * Don't notify upper layer if we are in suspend mode and
	 * should disconnect - assumption is that we will resume
	 * The mutex keeps apps from sending.
	 */
	if (is_connected == 0 && tp->is_suspended == 1)
		return;

	/*
	 * Unlock the mutex if we are connected again
	 * after being suspended - now resuming.
	 * This also removes the suspend state.
	 */
	if (is_connected == 1 && tp->is_suspended == 1)
		tpmfront_suspend_finish(tp);

	if (is_connected != tp->is_connected) {
		tp->is_connected = is_connected;
		tpmif_notify_upperlayer(tp);
	}
}



/* =================================================================
 * Initialization function.
 * =================================================================
 */


static int __init tpmif_init(void)
{
	struct tpm_private *tp;

	if (is_initial_xendomain())
		return -EPERM;

	tp = tpm_private_get();
	if (!tp)
		return -ENOMEM;

	IPRINTK("Initialising the vTPM driver.\n");
	if (gnttab_alloc_grant_references(TPMIF_TX_RING_SIZE,
					  &gref_head) < 0) {
		tpm_private_put();
		return -EFAULT;
	}

	init_tpm_xenbus();
	return 0;
}


module_init(tpmif_init);

MODULE_LICENSE("Dual BSD/GPL");
