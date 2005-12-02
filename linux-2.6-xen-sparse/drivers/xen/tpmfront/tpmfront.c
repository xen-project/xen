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
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
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
#include <asm-xen/tpmfe.h>
#include <linux/err.h>

#include <asm/semaphore.h>
#include <asm/io.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/xen-public/grant_table.h>
#include <asm-xen/xen-public/io/tpmif.h>
#include <asm/uaccess.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/xen-public/grant_table.h>

#include "tpmfront.h"

#undef DEBUG

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
        __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p)
#endif

/* locally visible variables */
static grant_ref_t gref_head;
static struct tpm_private my_private;

/* local function prototypes */
static irqreturn_t tpmif_int(int irq,
                             void *tpm_priv,
                             struct pt_regs *ptregs);
static void tpmif_rx_action(unsigned long unused);
static void tpmif_connect(u16 evtchn, domid_t domid);
static DECLARE_TASKLET(tpmif_rx_tasklet, tpmif_rx_action, 0);
static int tpm_allocate_buffers(struct tpm_private *tp);
static void tpmif_set_connected_state(struct tpm_private *tp,
                                      u8 newstate);
static int tpm_xmit(struct tpm_private *tp,
                    const u8 * buf, size_t count, int userbuffer,
                    void *remember);

#if DEBUG
#define DPRINTK(fmt, args...) \
    printk(KERN_ALERT "xen_tpm_fr (%s:%d) " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define DPRINTK(fmt, args...) ((void)0)
#endif
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
		if (copy_from_user(txb->data,
		                   src,
		                   copied)) {
			return -EFAULT;
		}
	} else {
		memcpy(txb->data, src, copied);
	}
	txb->len = len;
	return copied;
}

static inline struct tx_buffer *tx_buffer_alloc(void)
{
	struct tx_buffer *txb = kmalloc(sizeof (struct tx_buffer),
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

 The interface to let the tpm plugin register its callback
 function and send data to another partition using this module

**************************************************************/

static DECLARE_MUTEX(upperlayer_lock);
static DECLARE_MUTEX(suspend_lock);
static struct tpmfe_device *upperlayer_tpmfe;

/*
 * Send data via this module by calling this function
 */
int tpm_fe_send(const u8 * buf, size_t count, void *ptr)
{
	int sent = 0;
	struct tpm_private *tp = &my_private;

	down(&suspend_lock);
	sent = tpm_xmit(tp, buf, count, 0, ptr);
	up(&suspend_lock);

	return sent;
}
EXPORT_SYMBOL(tpm_fe_send);

/*
 * Register a callback for receiving data from this module
 */
int tpm_fe_register_receiver(struct tpmfe_device *tpmfe_dev)
{
	int rc = 0;

	down(&upperlayer_lock);
	if (NULL == upperlayer_tpmfe) {
		upperlayer_tpmfe = tpmfe_dev;
		tpmfe_dev->max_tx_size = TPMIF_TX_RING_SIZE * PAGE_SIZE;
	} else {
		rc = -EBUSY;
	}
	up(&upperlayer_lock);
	return rc;
}
EXPORT_SYMBOL(tpm_fe_register_receiver);

/*
 * Unregister the callback for receiving data from this module
 */
void tpm_fe_unregister_receiver(void)
{
	down(&upperlayer_lock);
	upperlayer_tpmfe = NULL;
	up(&upperlayer_lock);
}
EXPORT_SYMBOL(tpm_fe_unregister_receiver);

/*
 * Call this function to send data to the upper layer's
 * registered receiver function.
 */
static int tpm_fe_send_upperlayer(const u8 * buf, size_t count,
                                  const void *ptr)
{
	int rc;

	down(&upperlayer_lock);

	if (upperlayer_tpmfe && upperlayer_tpmfe->receive) {
		rc = upperlayer_tpmfe->receive(buf, count, ptr);
	} else {
		rc = 0;
	}

	up(&upperlayer_lock);
	return rc;
}

/**************************************************************
 XENBUS support code
**************************************************************/

static int setup_tpmring(struct xenbus_device *dev,
                         struct tpmfront_info * info)
{
	tpmif_tx_interface_t *sring;
	struct tpm_private *tp = &my_private;
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
	info->ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &tp->evtchn);
	if (err)
		goto fail;

	tpmif_connect(tp->evtchn, dev->otherend_id);

	return 0;
fail:
	return err;
}


static void destroy_tpmring(struct tpmfront_info *info, struct tpm_private *tp)
{
	tpmif_set_connected_state(tp, FALSE);
	if ( tp->tx != NULL ) {
		gnttab_end_foreign_access(info->ring_ref, 0,
					  (unsigned long)tp->tx);
		tp->tx = NULL;
	}

	if (tp->irq)
		unbind_from_irqhandler(tp->irq, NULL);
	tp->evtchn = tp->irq = 0;
}


static int talk_to_backend(struct xenbus_device *dev,
                           struct tpmfront_info *info)
{
	const char *message = NULL;
	int err;
	struct xenbus_transaction *xbt;

	err = setup_tpmring(dev, info);
	if (err) {
		xenbus_dev_fatal(dev, err, "setting up ring");
		goto out;
	}

again:
	xbt = xenbus_transaction_start();
	if (IS_ERR(xbt)) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_tpmring;
	}

	err = xenbus_printf(xbt, dev->nodename,
	                    "ring-ref","%u", info->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel", "%u", my_private.evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_switch_state(dev, xbt, XenbusStateInitialised);
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
	destroy_tpmring(info, &my_private);
out:
	return err;
}

/**
 * Callback received when the backend's state changes.
 */
static void backend_changed(struct xenbus_device *dev,
			    XenbusState backend_state)
{
	struct tpm_private *tp = &my_private;
	DPRINTK("\n");

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitWait:
	case XenbusStateInitialised:
	case XenbusStateUnknown:
		break;

	case XenbusStateConnected:
		tpmif_set_connected_state(tp, TRUE);
		break;

	case XenbusStateClosing:
		tpmif_set_connected_state(tp, FALSE);
		break;

	case XenbusStateClosed:
        	if (tp->is_suspended == FALSE) {
        	        device_unregister(&dev->dev);
        	}
	        break;
	}
}


static int tpmfront_probe(struct xenbus_device *dev,
                          const struct xenbus_device_id *id)
{
	int err;
	struct tpmfront_info *info;
	int handle;

	err = xenbus_scanf(NULL, dev->nodename,
	                   "handle", "%i", &handle);
	if (XENBUS_EXIST_ERR(err))
		return err;

	if (err < 0) {
		xenbus_dev_fatal(dev,err,"reading virtual-device");
		return err;
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		xenbus_dev_fatal(dev,err,"allocating info structure");
		return err;
	}
	memset(info, 0x0, sizeof(*info));

	info->dev = dev;
	dev->data = info;

	err = talk_to_backend(dev, info);
	if (err) {
		kfree(info);
		dev->data = NULL;
		return err;
	}
	return 0;
}


static int tpmfront_remove(struct xenbus_device *dev)
{
	struct tpmfront_info *info = dev->data;

	destroy_tpmring(info, &my_private);

	kfree(info);
	return 0;
}

static int
tpmfront_suspend(struct xenbus_device *dev)
{
	struct tpm_private *tp = &my_private;
	u32 ctr = 0;

	/* lock, so no app can send */
	down(&suspend_lock);
	tp->is_suspended = TRUE;

	while (atomic_read(&tp->tx_busy) && ctr <= 25) {
		if ((ctr % 10) == 0)
			printk("TPM-FE [INFO]: Waiting for outstanding request.\n");
		/*
		 * Wait for a request to be responded to.
		 */
		interruptible_sleep_on_timeout(&tp->wait_q, 100);
		ctr++;
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
	struct tpmfront_info *info = dev->data;
	int err = talk_to_backend(dev, info);


	return err;
}

static void
tpmif_connect(u16 evtchn, domid_t domid)
{
	int err = 0;
	struct tpm_private *tp = &my_private;

	tp->evtchn = evtchn;
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


static int
tpm_allocate_buffers(struct tpm_private *tp)
{
	unsigned int i;

	i = 0;
	while (i < TPMIF_TX_RING_SIZE) {
		tp->tx_buffers[i] = tx_buffer_alloc();
		i++;
	}

	return 1;
}

static void
tpmif_rx_action(unsigned long unused)
{
	struct tpm_private *tp = &my_private;

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

	i = 0;
	while (i < TPMIF_TX_RING_SIZE &&
	       offset < received) {
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
		i++;
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

	if (tp->is_connected != TRUE) {
		spin_unlock_irq(&tp->tx_lock);
		return -EIO;
	}

	i = 0;
	while (count > 0 && i < TPMIF_TX_RING_SIZE) {
		struct tx_buffer *txb = tp->tx_buffers[i];
		int copied;

		if (NULL == txb) {
			DPRINTK("txb (i=%d) is NULL. buffers initilized?\n", i);
			DPRINTK("Not transmitting anything!\n");
			spin_unlock_irq(&tp->tx_lock);
			return -EFAULT;
		}
		copied = tx_buffer_copy(txb, &buf[offset], count,
		                        isuserbuffer);
		if (copied < 0) {
			/* An error occurred */
			return copied;
		}
		count -= copied;
		offset += copied;

		tx = &tp->tx->ring[i].req;

		tx->id = i;
		tx->addr = virt_to_machine(txb->data);
		tx->size = txb->len;

		DPRINTK("First 4 characters sent by TPM-FE are 0x%02x 0x%02x 0x%02x 0x%02x\n",
		        txb->data[0],txb->data[1],txb->data[2],txb->data[3]);

		/* get the granttable reference for this page */
		tx->ref = gnttab_claim_grant_reference( &gref_head );

		if(-ENOSPC == tx->ref ) {
			DPRINTK(" Grant table claim reference failed in func:%s line:%d file:%s\n", __FUNCTION__, __LINE__, __FILE__);
			return -ENOSPC;
		}
		gnttab_grant_foreign_access_ref( tx->ref,
		                                 tp->backend_id,
		                                 (tx->addr >> PAGE_SHIFT),
		                                 0 /*RW*/);
		i++;
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
	down(&upperlayer_lock);

	if (upperlayer_tpmfe != NULL) {
		if (tp->is_connected) {
			upperlayer_tpmfe->status(TPMFE_STATUS_CONNECTED);
		} else {
			upperlayer_tpmfe->status(0);
		}
	}
	up(&upperlayer_lock);
}


static void tpmif_set_connected_state(struct tpm_private *tp, u8 is_connected)
{
	/*
	 * Don't notify upper layer if we are in suspend mode and
	 * should disconnect - assumption is that we will resume
	 * The semaphore keeps apps from sending.
	 */
	if (is_connected == FALSE && tp->is_suspended == TRUE) {
		return;
	}

	/*
	 * Unlock the semaphore if we are connected again
	 * after being suspended - now resuming.
	 * This also removes the suspend state.
	 */
	if (is_connected == TRUE && tp->is_suspended == TRUE) {
		tp->is_suspended = FALSE;
		/* unlock, so apps can resume sending */
		up(&suspend_lock);
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
	/*
	 * Only don't send the driver status when we are in the
	 * INIT domain.
	 */
	spin_lock_init(&my_private.tx_lock);
	init_waitqueue_head(&my_private.wait_q);

	init_tpm_xenbus();

	return 0;
}

__initcall(tpmif_init);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
