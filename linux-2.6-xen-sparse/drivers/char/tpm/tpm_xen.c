/*
 * Copyright (C) 2004 IBM Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 * Stefan Berger <stefanb@us.ibm.com>
 *
 * Maintained by: <tpmdd_devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module) for XEN.
 * Specifications at www.trustedcomputinggroup.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#include <asm/uaccess.h>
#include <linux/list.h>
#include <xen/tpmfe.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include "tpm.h"

/* read status bits */
enum {
	STATUS_BUSY = 0x01,
	STATUS_DATA_AVAIL = 0x02,
	STATUS_READY = 0x04
};

#define MIN(x,y)  ((x) < (y)) ? (x) : (y)

struct transmission {
	struct list_head next;
	unsigned char *request;
	unsigned int request_len;
	unsigned char *rcv_buffer;
	unsigned int  buffersize;
	unsigned int flags;
};

enum {
	TRANSMISSION_FLAG_WAS_QUEUED = 0x1
};

struct data_exchange {
	struct transmission *current_request;
	spinlock_t           req_list_lock;
	wait_queue_head_t    req_wait_queue;

	struct list_head     queued_requests;

	struct transmission *current_response;
	spinlock_t           resp_list_lock;
	wait_queue_head_t    resp_wait_queue;     // processes waiting for responses

	struct transmission *req_cancelled;       // if a cancellation was encounterd

	unsigned int         fe_status;
	unsigned int         flags;
};

enum {
	DATAEX_FLAG_QUEUED_ONLY = 0x1
};

static struct data_exchange dataex;

static unsigned long disconnect_time;

static struct tpmfe_device tpmfe;

/* local function prototypes */
static void __exit cleanup_xen(void);


/* =============================================================
 * Some utility functions
 * =============================================================
 */
static inline struct transmission *
transmission_alloc(void)
{
	return kzalloc(sizeof(struct transmission), GFP_KERNEL);
}

static inline unsigned char *
transmission_set_buffer(struct transmission *t,
                        unsigned char *buffer, unsigned int len)
{
	kfree(t->request);
	t->request = kmalloc(len, GFP_KERNEL);
	if (t->request) {
		memcpy(t->request,
		       buffer,
		       len);
		t->request_len = len;
	}
	return t->request;
}

static inline void
transmission_free(struct transmission *t)
{
	kfree(t->request);
	kfree(t->rcv_buffer);
	kfree(t);
}

/* =============================================================
 * Interface with the TPM shared memory driver for XEN
 * =============================================================
 */
static int tpm_recv(const u8 *buffer, size_t count, const void *ptr)
{
	int ret_size = 0;
	struct transmission *t;

	/*
	 * The list with requests must contain one request
	 * only and the element there must be the one that
	 * was passed to me from the front-end.
	 */
	if (dataex.current_request != ptr) {
		printk("WARNING: The request pointer is different than the "
		       "pointer the shared memory driver returned to me. "
		       "%p != %p\n",
		       dataex.current_request, ptr);
	}

	/*
	 * If the request has been cancelled, just quit here
	 */
	if (dataex.req_cancelled == (struct transmission *)ptr) {
		if (dataex.current_request == dataex.req_cancelled) {
			dataex.current_request = NULL;
		}
		transmission_free(dataex.req_cancelled);
		dataex.req_cancelled = NULL;
		return 0;
	}

	if (NULL != (t = dataex.current_request)) {
		transmission_free(t);
		dataex.current_request = NULL;
	}

	t = transmission_alloc();
	if (t) {
		unsigned long flags;
		t->rcv_buffer = kmalloc(count, GFP_KERNEL);
		if (! t->rcv_buffer) {
			transmission_free(t);
			return -ENOMEM;
		}
		t->buffersize = count;
		memcpy(t->rcv_buffer, buffer, count);
		ret_size = count;

		spin_lock_irqsave(&dataex.resp_list_lock ,flags);
		dataex.current_response = t;
		spin_unlock_irqrestore(&dataex.resp_list_lock, flags);
		wake_up_interruptible(&dataex.resp_wait_queue);
	}
	return ret_size;
}


static void tpm_fe_status(unsigned int flags)
{
	dataex.fe_status = flags;
	if ((dataex.fe_status & TPMFE_STATUS_CONNECTED) == 0) {
		disconnect_time = jiffies;
	}
}

/* =============================================================
 * Interface with the generic TPM driver
 * =============================================================
 */
static int tpm_xen_recv(struct tpm_chip *chip, u8 * buf, size_t count)
{
	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(&dataex.resp_list_lock, flags);
	/*
	 * Check if the previous operation only queued the command
	 * In this case there won't be a response, so I just
	 * return from here and reset that flag. In any other
	 * case I should receive a response from the back-end.
	 */
	if ((dataex.flags & DATAEX_FLAG_QUEUED_ONLY) != 0) {
		dataex.flags &= ~DATAEX_FLAG_QUEUED_ONLY;
		spin_unlock_irqrestore(&dataex.resp_list_lock, flags);
		/*
		 * a little hack here. The first few measurements
		 * are queued since there's no way to talk to the
		 * TPM yet (due to slowness of the control channel)
		 * So we just make IMA happy by giving it 30 NULL
		 * bytes back where the most important part is
		 * that the result code is '0'.
		 */

		count = MIN(count, 30);
		memset(buf, 0x0, count);
		return count;
	}
	/*
	 * Check whether something is in the responselist and if
	 * there's nothing in the list wait for something to appear.
	 */

	if (NULL == dataex.current_response) {
		spin_unlock_irqrestore(&dataex.resp_list_lock, flags);
		interruptible_sleep_on_timeout(&dataex.resp_wait_queue,
		                               1000);
		spin_lock_irqsave(&dataex.resp_list_lock ,flags);
	}

	if (NULL != dataex.current_response) {
		struct transmission *t = dataex.current_response;
		dataex.current_response = NULL;
		rc = MIN(count, t->buffersize);
		memcpy(buf, t->rcv_buffer, rc);
		transmission_free(t);
	}

	spin_unlock_irqrestore(&dataex.resp_list_lock, flags);
	return rc;
}

static int tpm_xen_send(struct tpm_chip *chip, u8 * buf, size_t count)
{
	/*
	 * We simply pass the packet onto the XEN shared
	 * memory driver.
	 */
	unsigned long flags;
	int rc;
	struct transmission *t = transmission_alloc();

	spin_lock_irqsave(&dataex.req_list_lock, flags);
	/*
	 * If there's a current request, it must be the
	 * previous request that has timed out.
	 */
	if (dataex.current_request != NULL) {
		printk("WARNING: Sending although there is a request outstanding.\n"
		       "         Previous request must have timed out.\n");
		transmission_free(dataex.current_request);
		dataex.current_request = NULL;
	}

	if (t != NULL) {
		unsigned int error = 0;
		/*
		 * Queue the packet if the driver below is not
		 * ready, yet, or there is any packet already
		 * in the queue.
		 * If the driver below is ready, unqueue all
		 * packets first before sending our current
		 * packet.
		 * For each unqueued packet, except for the
		 * last (=current) packet, call the function
		 * tpm_xen_recv to wait for the response to come
		 * back.
		 */
		if ((dataex.fe_status & TPMFE_STATUS_CONNECTED) == 0) {
			if (time_after(jiffies, disconnect_time + HZ * 10)) {
				rc = -ENOENT;
			} else {
				/*
				 * copy the request into the buffer
				 */
				if (transmission_set_buffer(t, buf, count)
				    == NULL) {
					transmission_free(t);
					rc = -ENOMEM;
					goto exit;
				}
				dataex.flags |= DATAEX_FLAG_QUEUED_ONLY;
				list_add_tail(&t->next, &dataex.queued_requests);
				rc = 0;
			}
		} else {
			/*
			 * Check whether there are any packets in the queue
			 */
			while (!list_empty(&dataex.queued_requests)) {
				/*
				 * Need to dequeue them.
				 * Read the result into a dummy buffer.
				 */
				unsigned char buffer[1];
				struct transmission *qt = (struct transmission *) dataex.queued_requests.next;
				list_del(&qt->next);
				dataex.current_request = qt;
				spin_unlock_irqrestore(&dataex.req_list_lock,
				                       flags);

				rc = tpm_fe_send(tpmfe.tpm_private,
				                 qt->request,
				                 qt->request_len,
				                 qt);

				if (rc < 0) {
					spin_lock_irqsave(&dataex.req_list_lock, flags);
					if ((qt = dataex.current_request) != NULL) {
						/*
						 * requeue it at the beginning
						 * of the list
						 */
						list_add(&qt->next,
						         &dataex.queued_requests);
					}
					dataex.current_request = NULL;
					error = 1;
					break;
				}
				/*
				 * After this point qt is not valid anymore!
				 * It is freed when the front-end is delivering the data
				 * by calling tpm_recv
				 */

				/*
				 * Try to receive the response now into the provided dummy
				 * buffer (I don't really care about this response since
				 * there is no receiver anymore for this response)
				 */
				rc = tpm_xen_recv(chip, buffer, sizeof(buffer));

				spin_lock_irqsave(&dataex.req_list_lock, flags);
			}

			if (error == 0) {
				/*
				 * Finally, send the current request.
				 */
				dataex.current_request = t;
				/*
				 * Call the shared memory driver
				 * Pass to it the buffer with the request, the
				 * amount of bytes in the request and
				 * a void * pointer (here: transmission structure)
				 */
				rc = tpm_fe_send(tpmfe.tpm_private,
				                 buf, count, t);
				/*
				 * The generic TPM driver will call
				 * the function to receive the response.
				 */
				if (rc < 0) {
					dataex.current_request = NULL;
					goto queue_it;
				}
			} else {
queue_it:
				if (transmission_set_buffer(t, buf, count) == NULL) {
					transmission_free(t);
					rc = -ENOMEM;
					goto exit;
				}
				/*
				 * An error occurred. Don't event try
				 * to send the current request. Just
				 * queue it.
				 */
				dataex.flags |= DATAEX_FLAG_QUEUED_ONLY;
				list_add_tail(&t->next,
				              &dataex.queued_requests);
				rc = 0;
			}
		}
	} else {
		rc = -ENOMEM;
	}

exit:
	spin_unlock_irqrestore(&dataex.req_list_lock, flags);
	return rc;
}

static void tpm_xen_cancel(struct tpm_chip *chip)
{
	unsigned long flags;
	spin_lock_irqsave(&dataex.resp_list_lock,flags);

	dataex.req_cancelled = dataex.current_request;

	spin_unlock_irqrestore(&dataex.resp_list_lock,flags);
}

static u8 tpm_xen_status(struct tpm_chip *chip)
{
	unsigned long flags;
	u8 rc = 0;
	spin_lock_irqsave(&dataex.resp_list_lock, flags);
	/*
	 * Data are available if:
	 *  - there's a current response
	 *  - the last packet was queued only (this is fake, but necessary to
	 *      get the generic TPM layer to call the receive function.)
	 */
	if (NULL != dataex.current_response ||
	    0 != (dataex.flags & DATAEX_FLAG_QUEUED_ONLY)) {
		rc = STATUS_DATA_AVAIL;
	}
	spin_unlock_irqrestore(&dataex.resp_list_lock, flags);
	return rc;
}

static struct file_operations tpm_xen_ops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.open = tpm_open,
	.read = tpm_read,
	.write = tpm_write,
	.release = tpm_release,
};

static DEVICE_ATTR(pubek, S_IRUGO, tpm_show_pubek, NULL);
static DEVICE_ATTR(pcrs, S_IRUGO, tpm_show_pcrs, NULL);
static DEVICE_ATTR(caps, S_IRUGO, tpm_show_caps, NULL);
static DEVICE_ATTR(cancel, S_IWUSR |S_IWGRP, NULL, tpm_store_cancel);

static struct attribute* xen_attrs[] = {
	&dev_attr_pubek.attr,
	&dev_attr_pcrs.attr,
	&dev_attr_caps.attr,
	&dev_attr_cancel.attr,
	NULL,
};

static struct attribute_group xen_attr_grp = { .attrs = xen_attrs };

static struct tpm_vendor_specific tpm_xen = {
	.recv = tpm_xen_recv,
	.send = tpm_xen_send,
	.cancel = tpm_xen_cancel,
	.status = tpm_xen_status,
	.req_complete_mask = STATUS_BUSY | STATUS_DATA_AVAIL,
	.req_complete_val  = STATUS_DATA_AVAIL,
	.req_canceled = STATUS_READY,
	.base = 0,
	.attr_group = &xen_attr_grp,
	.miscdev.fops = &tpm_xen_ops,
	.buffersize = 64 * 1024,
};

static struct platform_device *pdev;

static struct tpmfe_device tpmfe = {
	.receive = tpm_recv,
	.status  = tpm_fe_status,
};


static int __init init_xen(void)
{
	int rc;

	if ((xen_start_info->flags & SIF_INITDOMAIN)) {
		return -EPERM;
	}
	/*
	 * Register device with the low lever front-end
	 * driver
	 */
	if ((rc = tpm_fe_register_receiver(&tpmfe)) < 0) {
		goto err_exit;
	}

	/*
	 * Register our device with the system.
	 */
	pdev = platform_device_register_simple("tpm_vtpm", -1, NULL, 0);
	if (IS_ERR(pdev)) {
		rc = PTR_ERR(pdev);
		goto err_unreg_fe;
	}

	tpm_xen.buffersize = tpmfe.max_tx_size;

	if ((rc = tpm_register_hardware(&pdev->dev, &tpm_xen)) < 0) {
		goto err_unreg_pdev;
	}

	dataex.current_request = NULL;
	spin_lock_init(&dataex.req_list_lock);
	init_waitqueue_head(&dataex.req_wait_queue);
	INIT_LIST_HEAD(&dataex.queued_requests);

	dataex.current_response = NULL;
	spin_lock_init(&dataex.resp_list_lock);
	init_waitqueue_head(&dataex.resp_wait_queue);

	disconnect_time = jiffies;

	return 0;


err_unreg_pdev:
	platform_device_unregister(pdev);
err_unreg_fe:
	tpm_fe_unregister_receiver();

err_exit:
	return rc;
}

static void __exit cleanup_xen(void)
{
	struct tpm_chip *chip = dev_get_drvdata(&pdev->dev);
	if (chip) {
		tpm_remove_hardware(chip->dev);
		platform_device_unregister(pdev);
		tpm_fe_unregister_receiver();
	}
}

module_init(init_xen);
module_exit(cleanup_xen);

MODULE_AUTHOR("Stefan Berger (stefanb@us.ibm.com)");
MODULE_DESCRIPTION("TPM Driver for XEN (shared memory)");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
