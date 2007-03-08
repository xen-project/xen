/*
 * Copyright (C) 2006 IBM Corporation
 *
 * Authors:
 * Stefan Berger <stefanb@us.ibm.com>
 *
 * Generic device driver part for device drivers in a virtualized
 * environment.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include "tpm.h"
#include "tpm_vtpm.h"

/* read status bits */
enum {
	STATUS_BUSY = 0x01,
	STATUS_DATA_AVAIL = 0x02,
	STATUS_READY = 0x04
};

struct transmission {
	struct list_head next;

	unsigned char *request;
	size_t  request_len;
	size_t  request_buflen;

	unsigned char *response;
	size_t  response_len;
	size_t  response_buflen;

	unsigned int flags;
};

enum {
	TRANSMISSION_FLAG_WAS_QUEUED = 0x1
};


enum {
	DATAEX_FLAG_QUEUED_ONLY = 0x1
};


/* local variables */

/* local function prototypes */
static int _vtpm_send_queued(struct tpm_chip *chip);


/* =============================================================
 * Some utility functions
 * =============================================================
 */
static void vtpm_state_init(struct vtpm_state *vtpms)
{
	vtpms->current_request = NULL;
	spin_lock_init(&vtpms->req_list_lock);
	init_waitqueue_head(&vtpms->req_wait_queue);
	INIT_LIST_HEAD(&vtpms->queued_requests);

	vtpms->current_response = NULL;
	spin_lock_init(&vtpms->resp_list_lock);
	init_waitqueue_head(&vtpms->resp_wait_queue);

	vtpms->disconnect_time = jiffies;
}


static inline struct transmission *transmission_alloc(void)
{
	return kzalloc(sizeof(struct transmission), GFP_ATOMIC);
}

static unsigned char *
transmission_set_req_buffer(struct transmission *t,
                            unsigned char *buffer, size_t len)
{
	if (t->request_buflen < len) {
		kfree(t->request);
		t->request = kmalloc(len, GFP_KERNEL);
		if (!t->request) {
			t->request_buflen = 0;
			return NULL;
		}
		t->request_buflen = len;
	}

	memcpy(t->request, buffer, len);
	t->request_len = len;

	return t->request;
}

static unsigned char *
transmission_set_res_buffer(struct transmission *t,
                            const unsigned char *buffer, size_t len)
{
	if (t->response_buflen < len) {
		kfree(t->response);
		t->response = kmalloc(len, GFP_ATOMIC);
		if (!t->response) {
			t->response_buflen = 0;
			return NULL;
		}
		t->response_buflen = len;
	}

	memcpy(t->response, buffer, len);
	t->response_len = len;

	return t->response;
}

static inline void transmission_free(struct transmission *t)
{
	kfree(t->request);
	kfree(t->response);
	kfree(t);
}

/* =============================================================
 * Interface with the lower layer driver
 * =============================================================
 */
/*
 * Lower layer uses this function to make a response available.
 */
int vtpm_vd_recv(const struct tpm_chip *chip,
                 const unsigned char *buffer, size_t count,
                 void *ptr)
{
	unsigned long flags;
	int ret_size = 0;
	struct transmission *t;
	struct vtpm_state *vtpms;

	vtpms = (struct vtpm_state *)chip_get_private(chip);

	/*
	 * The list with requests must contain one request
	 * only and the element there must be the one that
	 * was passed to me from the front-end.
	 */
	spin_lock_irqsave(&vtpms->resp_list_lock, flags);
	if (vtpms->current_request != ptr) {
		spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
		return 0;
	}

	if ((t = vtpms->current_request)) {
		transmission_free(t);
		vtpms->current_request = NULL;
	}

	t = transmission_alloc();
	if (t) {
		if (!transmission_set_res_buffer(t, buffer, count)) {
			transmission_free(t);
			spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
			return -ENOMEM;
		}
		ret_size = count;
		vtpms->current_response = t;
		wake_up_interruptible(&vtpms->resp_wait_queue);
	}
	spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);

	return ret_size;
}


/*
 * Lower layer indicates its status (connected/disconnected)
 */
void vtpm_vd_status(const struct tpm_chip *chip, u8 vd_status)
{
	struct vtpm_state *vtpms;

	vtpms = (struct vtpm_state *)chip_get_private(chip);

	vtpms->vd_status = vd_status;
	if ((vtpms->vd_status & TPM_VD_STATUS_CONNECTED) == 0) {
		vtpms->disconnect_time = jiffies;
	}
}

/* =============================================================
 * Interface with the generic TPM driver
 * =============================================================
 */
static int vtpm_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	int rc = 0;
	unsigned long flags;
	struct vtpm_state *vtpms;

	vtpms = (struct vtpm_state *)chip_get_private(chip);

	/*
	 * Check if the previous operation only queued the command
	 * In this case there won't be a response, so I just
	 * return from here and reset that flag. In any other
	 * case I should receive a response from the back-end.
	 */
	spin_lock_irqsave(&vtpms->resp_list_lock, flags);
	if ((vtpms->flags & DATAEX_FLAG_QUEUED_ONLY) != 0) {
		vtpms->flags &= ~DATAEX_FLAG_QUEUED_ONLY;
		spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
		/*
		 * The first few commands (measurements) must be
		 * queued since it might not be possible to talk to the
		 * TPM, yet.
		 * Return a response of up to 30 '0's.
		 */

		count = min_t(size_t, count, 30);
		memset(buf, 0x0, count);
		return count;
	}
	/*
	 * Check whether something is in the responselist and if
	 * there's nothing in the list wait for something to appear.
	 */

	if (!vtpms->current_response) {
		spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
		interruptible_sleep_on_timeout(&vtpms->resp_wait_queue,
		                               1000);
		spin_lock_irqsave(&vtpms->resp_list_lock ,flags);
	}

	if (vtpms->current_response) {
		struct transmission *t = vtpms->current_response;
		vtpms->current_response = NULL;
		rc = min(count, t->response_len);
		memcpy(buf, t->response, rc);
		transmission_free(t);
	}

	spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
	return rc;
}

static int vtpm_send(struct tpm_chip *chip, u8 *buf, size_t count)
{
	int rc = 0;
	unsigned long flags;
	struct transmission *t = transmission_alloc();
	struct vtpm_state *vtpms;

	vtpms = (struct vtpm_state *)chip_get_private(chip);

	if (!t)
		return -ENOMEM;
	/*
	 * If there's a current request, it must be the
	 * previous request that has timed out.
	 */
	spin_lock_irqsave(&vtpms->req_list_lock, flags);
	if (vtpms->current_request != NULL) {
		printk("WARNING: Sending although there is a request outstanding.\n"
		       "         Previous request must have timed out.\n");
		transmission_free(vtpms->current_request);
		vtpms->current_request = NULL;
	}
	spin_unlock_irqrestore(&vtpms->req_list_lock, flags);

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
	if ((vtpms->vd_status & TPM_VD_STATUS_CONNECTED) == 0) {
		if (time_after(jiffies,
		               vtpms->disconnect_time + HZ * 10)) {
			rc = -ENOENT;
		} else {
			goto queue_it;
		}
	} else {
		/*
		 * Send all queued packets.
		 */
		if (_vtpm_send_queued(chip) == 0) {

			vtpms->current_request = t;

			rc = vtpm_vd_send(vtpms->tpm_private,
			                  buf,
			                  count,
			                  t);
			/*
			 * The generic TPM driver will call
			 * the function to receive the response.
			 */
			if (rc < 0) {
				vtpms->current_request = NULL;
				goto queue_it;
			}
		} else {
queue_it:
			if (!transmission_set_req_buffer(t, buf, count)) {
				transmission_free(t);
				rc = -ENOMEM;
				goto exit;
			}
			/*
			 * An error occurred. Don't event try
			 * to send the current request. Just
			 * queue it.
			 */
			spin_lock_irqsave(&vtpms->req_list_lock, flags);
			vtpms->flags |= DATAEX_FLAG_QUEUED_ONLY;
			list_add_tail(&t->next, &vtpms->queued_requests);
			spin_unlock_irqrestore(&vtpms->req_list_lock, flags);
		}
	}

exit:
	return rc;
}


/*
 * Send all queued requests.
 */
static int _vtpm_send_queued(struct tpm_chip *chip)
{
	int rc;
	int error = 0;
	long flags;
	unsigned char buffer[1];
	struct vtpm_state *vtpms;
	vtpms = (struct vtpm_state *)chip_get_private(chip);

	spin_lock_irqsave(&vtpms->req_list_lock, flags);

	while (!list_empty(&vtpms->queued_requests)) {
		/*
		 * Need to dequeue them.
		 * Read the result into a dummy buffer.
		 */
		struct transmission *qt = (struct transmission *)
		                          vtpms->queued_requests.next;
		list_del(&qt->next);
		vtpms->current_request = qt;
		spin_unlock_irqrestore(&vtpms->req_list_lock, flags);

		rc = vtpm_vd_send(vtpms->tpm_private,
		                  qt->request,
		                  qt->request_len,
		                  qt);

		if (rc < 0) {
			spin_lock_irqsave(&vtpms->req_list_lock, flags);
			if ((qt = vtpms->current_request) != NULL) {
				/*
				 * requeue it at the beginning
				 * of the list
				 */
				list_add(&qt->next,
				         &vtpms->queued_requests);
			}
			vtpms->current_request = NULL;
			error = 1;
			break;
		}
		/*
		 * After this point qt is not valid anymore!
		 * It is freed when the front-end is delivering
		 * the data by calling tpm_recv
		 */
		/*
		 * Receive response into provided dummy buffer
		 */
		rc = vtpm_recv(chip, buffer, sizeof(buffer));
		spin_lock_irqsave(&vtpms->req_list_lock, flags);
	}

	spin_unlock_irqrestore(&vtpms->req_list_lock, flags);

	return error;
}

static void vtpm_cancel(struct tpm_chip *chip)
{
	unsigned long flags;
	struct vtpm_state *vtpms = (struct vtpm_state *)chip_get_private(chip);

	spin_lock_irqsave(&vtpms->resp_list_lock,flags);

	if (!vtpms->current_response && vtpms->current_request) {
		spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
		interruptible_sleep_on(&vtpms->resp_wait_queue);
		spin_lock_irqsave(&vtpms->resp_list_lock,flags);
	}

	if (vtpms->current_response) {
		struct transmission *t = vtpms->current_response;
		vtpms->current_response = NULL;
		transmission_free(t);
	}

	spin_unlock_irqrestore(&vtpms->resp_list_lock,flags);
}

static u8 vtpm_status(struct tpm_chip *chip)
{
	u8 rc = 0;
	unsigned long flags;
	struct vtpm_state *vtpms;

	vtpms = (struct vtpm_state *)chip_get_private(chip);

	spin_lock_irqsave(&vtpms->resp_list_lock, flags);
	/*
	 * Data are available if:
	 *  - there's a current response
	 *  - the last packet was queued only (this is fake, but necessary to
	 *      get the generic TPM layer to call the receive function.)
	 */
	if (vtpms->current_response ||
	    0 != (vtpms->flags & DATAEX_FLAG_QUEUED_ONLY)) {
		rc = STATUS_DATA_AVAIL;
	} else if (!vtpms->current_response && !vtpms->current_request) {
		rc = STATUS_READY;
	}

	spin_unlock_irqrestore(&vtpms->resp_list_lock, flags);
	return rc;
}

static struct file_operations vtpm_ops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.open = tpm_open,
	.read = tpm_read,
	.write = tpm_write,
	.release = tpm_release,
};

static DEVICE_ATTR(pubek, S_IRUGO, tpm_show_pubek, NULL);
static DEVICE_ATTR(pcrs, S_IRUGO, tpm_show_pcrs, NULL);
static DEVICE_ATTR(enabled, S_IRUGO, tpm_show_enabled, NULL);
static DEVICE_ATTR(active, S_IRUGO, tpm_show_active, NULL);
static DEVICE_ATTR(owned, S_IRUGO, tpm_show_owned, NULL);
static DEVICE_ATTR(temp_deactivated, S_IRUGO, tpm_show_temp_deactivated,
		   NULL);
static DEVICE_ATTR(caps, S_IRUGO, tpm_show_caps, NULL);
static DEVICE_ATTR(cancel, S_IWUSR |S_IWGRP, NULL, tpm_store_cancel);

static struct attribute *vtpm_attrs[] = {
	&dev_attr_pubek.attr,
	&dev_attr_pcrs.attr,
	&dev_attr_enabled.attr,
	&dev_attr_active.attr,
	&dev_attr_owned.attr,
	&dev_attr_temp_deactivated.attr,
	&dev_attr_caps.attr,
	&dev_attr_cancel.attr,
	NULL,
};

static struct attribute_group vtpm_attr_grp = { .attrs = vtpm_attrs };

#define TPM_LONG_TIMEOUT   (10 * 60 * HZ)

static struct tpm_vendor_specific tpm_vtpm = {
	.recv = vtpm_recv,
	.send = vtpm_send,
	.cancel = vtpm_cancel,
	.status = vtpm_status,
	.req_complete_mask = STATUS_BUSY | STATUS_DATA_AVAIL,
	.req_complete_val  = STATUS_DATA_AVAIL,
	.req_canceled = STATUS_READY,
	.attr_group = &vtpm_attr_grp,
	.miscdev = {
		.fops = &vtpm_ops,
	},
	.duration = {
		TPM_LONG_TIMEOUT,
		TPM_LONG_TIMEOUT,
		TPM_LONG_TIMEOUT,
	},
};

struct tpm_chip *init_vtpm(struct device *dev,
                           struct tpm_private *tp)
{
	long rc;
	struct tpm_chip *chip;
	struct vtpm_state *vtpms;

	vtpms = kzalloc(sizeof(struct vtpm_state), GFP_KERNEL);
	if (!vtpms)
		return ERR_PTR(-ENOMEM);

	vtpm_state_init(vtpms);
	vtpms->tpm_private = tp;

	chip = tpm_register_hardware(dev, &tpm_vtpm);
	if (!chip) {
		rc = -ENODEV;
		goto err_free_mem;
	}

	chip_set_private(chip, vtpms);

	return chip;

err_free_mem:
	kfree(vtpms);

	return ERR_PTR(rc);
}

void cleanup_vtpm(struct device *dev)
{
	struct tpm_chip *chip = dev_get_drvdata(dev);
	struct vtpm_state *vtpms = (struct vtpm_state*)chip_get_private(chip);
	tpm_remove_hardware(dev);
	kfree(vtpms);
}
