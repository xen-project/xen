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
#include <linux/tpmfe.h>
#include <linux/err.h>

#include <asm/semaphore.h>
#include <asm/io.h>
#include <asm-xen/evtchn.h>
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
static void tpmif_set_connected_state(struct tpm_private *tp, int newstate);
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

static void watch_for_status(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	struct tpmfront_info *info;
	int err;
	unsigned long ready;
	struct tpm_private *tp = &my_private;
	const char *node = vec[XS_WATCH_PATH];

	info = container_of(watch, struct tpmfront_info, watch);
	node += strlen(watch->node);

	if (tp->connected)
		return;

	err = xenbus_gather(NULL, watch->node,
	                    "ready", "%lu", &ready,
	                    NULL);
	if (err) {
		xenbus_dev_error(info->dev, err, "reading 'ready' field");
		return;
	}

	tpmif_set_connected_state(tp, 1);

	xenbus_dev_ok(info->dev);
}


static int setup_tpmring(struct xenbus_device *dev,
                         struct tpmfront_info * info,
                         domid_t backend_id)
{
	tpmif_tx_interface_t *sring;
	struct tpm_private *tp = &my_private;
	int err;
	evtchn_op_t op = {
		.cmd = EVTCHNOP_alloc_unbound,
		.u.alloc_unbound.dom = DOMID_SELF,
		.u.alloc_unbound.remote_dom = backend_id } ;

	sring = (void *)__get_free_page(GFP_KERNEL);
	if (!sring) {
		xenbus_dev_error(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	tp->tx = sring;

	tpm_allocate_buffers(tp);

	err = gnttab_grant_foreign_access(backend_id,
					  (virt_to_machine(tp->tx) >> PAGE_SHIFT),
					  0);

	if (err == -ENOSPC) {
		free_page((unsigned long)sring);
		tp->tx = NULL;
		xenbus_dev_error(dev, err, "allocating grant reference");
		return err;
	}
	info->ring_ref = err;

	err = HYPERVISOR_event_channel_op(&op);
	if (err) {
		gnttab_end_foreign_access(info->ring_ref, 0,
					  (unsigned long)sring);
		tp->tx = NULL;
		xenbus_dev_error(dev, err, "allocating event channel");
		return err;
	}

	tpmif_connect(op.u.alloc_unbound.port, backend_id);

	return 0;
}


static void destroy_tpmring(struct tpmfront_info *info, struct tpm_private *tp)
{
	tpmif_set_connected_state(tp,0);

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
	char *backend;
	const char *message;
	int err;
	int backend_id;
	struct xenbus_transaction *xbt;

	backend = NULL;
	err = xenbus_gather(NULL, dev->nodename,
			    "backend-id", "%i", &backend_id,
			    "backend", NULL, &backend,
			    NULL);
	if (XENBUS_EXIST_ERR(err))
		goto out;
	if (backend && strlen(backend) == 0) {
		err = -ENOENT;
		goto out;
	}
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading %s/backend or backend-id",
				 dev->nodename);
		goto out;
	}

	info->backend_id      = backend_id;
	my_private.backend_id = backend_id;

	err = setup_tpmring(dev, info, backend_id);
	if (err) {
		xenbus_dev_error(dev, err, "setting up ring");
		goto out;
	}

again:
	xbt = xenbus_transaction_start();
	if (IS_ERR(xbt)) {
		xenbus_dev_error(dev, err, "starting transaction");
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

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err) {
		xenbus_dev_error(dev, err, "completing transaction");
		goto destroy_tpmring;
	}

	info->watch.node = backend;
	info->watch.callback = watch_for_status;
	err = register_xenbus_watch(&info->watch);
	if (err) {
		xenbus_dev_error(dev, err, "registering watch on backend");
		goto destroy_tpmring;
	}

	info->backend = backend;

	return 0;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_error(dev, err, "%s", message);
destroy_tpmring:
	destroy_tpmring(info, &my_private);
out:
	if (backend)
		kfree(backend);
	return err;
}


static int tpmfront_probe(struct xenbus_device *dev,
                          const struct xenbus_device_id *id)
{
	int err;
	struct tpmfront_info *info;
	int handle;
	int len = max(XS_WATCH_PATH, XS_WATCH_TOKEN) + 1;
	const char *vec[len];

	err = xenbus_scanf(NULL, dev->nodename,
	                   "handle", "%i", &handle);
	if (XENBUS_EXIST_ERR(err))
		return err;

	if (err < 0) {
		xenbus_dev_error(dev,err,"reading virtual-device");
		return err;
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_error(dev,err,"allocating info structure");
		return err;
	}
	memset(info, 0x0, sizeof(*info));

	info->dev = dev;
	info->handle = handle;
	dev->data = info;

	err = talk_to_backend(dev, info);
	if (err) {
		kfree(info);
		dev->data = NULL;
		return err;
	}

	vec[XS_WATCH_PATH]  = info->watch.node;
	vec[XS_WATCH_TOKEN] = NULL;
	watch_for_status(&info->watch, vec, len);

	return 0;
}

static int tpmfront_remove(struct xenbus_device *dev)
{
	struct tpmfront_info *info = dev->data;
	if (info->backend)
		unregister_xenbus_watch(&info->watch);

	destroy_tpmring(info, &my_private);

	kfree(info->backend);
	kfree(info);

	return 0;
}

static int
tpmfront_suspend(struct xenbus_device *dev)
{
	struct tpmfront_info *info = dev->data;
	struct tpm_private *tp = &my_private;
	u32 ctr = 0;

	/* lock, so no app can send */
	down(&suspend_lock);

	while (atomic_read(&tp->tx_busy) && ctr <= 25) {
	        if ((ctr % 10) == 0)
			printk("INFO: Waiting for outstanding request.\n");
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
		printk("WARNING: Resetting busy flag.");
		atomic_set(&tp->tx_busy, 0);
	}

	unregister_xenbus_watch(&info->watch);

	kfree(info->backend);
	info->backend = NULL;

	return 0;
}

static int
tpmfront_resume(struct xenbus_device *dev)
{
	struct tpmfront_info *info = dev->data;
	int err = talk_to_backend(dev, info);

	/* unlock, so apps can resume sending */
	up(&suspend_lock);

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
	.suspend = tpmfront_suspend,
};

static void __init init_tpm_xenbus(void)
{
	xenbus_register_driver(&tpmfront);
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
		printk("There's an outstanding request/response on the way!\n");
		spin_unlock_irq(&tp->tx_lock);
		return -EBUSY;
	}

	if (tp->connected != 1) {
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
		switch (tp->connected) {
			case 1:
				upperlayer_tpmfe->status(TPMFE_STATUS_CONNECTED);
			break;

			default:
				upperlayer_tpmfe->status(0);
			break;
		}
	}
	up(&upperlayer_lock);
}


static void tpmif_set_connected_state(struct tpm_private *tp, int newstate)
{
	if (newstate != tp->connected) {
		tp->connected = newstate;
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
