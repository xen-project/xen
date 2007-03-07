/******************************************************************************
 * drivers/xen/tpmback/tpmback.c
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * Author: Stefan Berger, stefanb@us.ibm.com
 * Grant table support: Mahadevan Gomathisankaran
 *
 * This code has been derived from drivers/xen/netback/netback.c
 * Copyright (c) 2002-2004, K A Fraser
 *
 */

#include "common.h"
#include <xen/evtchn.h>

#include <linux/types.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <xen/xenbus.h>
#include <xen/interface/grant_table.h>
#include <xen/gnttab.h>

/* local data structures */
struct data_exchange {
	struct list_head pending_pak;
	struct list_head current_pak;
	unsigned int copied_so_far;
	u8 has_opener:1;
	u8 aborted:1;
	rwlock_t pak_lock;	// protects all of the previous fields
	wait_queue_head_t wait_queue;
};

struct vtpm_resp_hdr {
	uint32_t instance_no;
	uint16_t tag_no;
	uint32_t len_no;
	uint32_t ordinal_no;
} __attribute__ ((packed));

struct packet {
	struct list_head next;
	unsigned int data_len;
	u8 *data_buffer;
	tpmif_t *tpmif;
	u32 tpm_instance;
	u8 req_tag;
	u32 last_read;
	u8 flags;
	struct timer_list processing_timer;
};

enum {
	PACKET_FLAG_DISCARD_RESPONSE = 1,
};

/* local variables */
static struct data_exchange dataex;

/* local function prototypes */
static int _packet_write(struct packet *pak,
			 const char *data, size_t size, int userbuffer);
static void processing_timeout(unsigned long ptr);
static int packet_read_shmem(struct packet *pak,
			     tpmif_t * tpmif,
			     u32 offset,
			     char *buffer, int isuserbuffer, u32 left);
static int vtpm_queue_packet(struct packet *pak);

/***************************************************************
 Buffer copying fo user and kernel space buffes.
***************************************************************/
static inline int copy_from_buffer(void *to,
				   const void *from, unsigned long size,
				   int isuserbuffer)
{
	if (isuserbuffer) {
		if (copy_from_user(to, (void __user *)from, size))
			return -EFAULT;
	} else {
		memcpy(to, from, size);
	}
	return 0;
}

static inline int copy_to_buffer(void *to,
				 const void *from, unsigned long size,
				 int isuserbuffer)
{
	if (isuserbuffer) {
		if (copy_to_user((void __user *)to, from, size))
			return -EFAULT;
	} else {
		memcpy(to, from, size);
	}
	return 0;
}


static void dataex_init(struct data_exchange *dataex)
{
	INIT_LIST_HEAD(&dataex->pending_pak);
	INIT_LIST_HEAD(&dataex->current_pak);
	dataex->has_opener = 0;
	rwlock_init(&dataex->pak_lock);
	init_waitqueue_head(&dataex->wait_queue);
}

/***************************************************************
 Packet-related functions
***************************************************************/

static struct packet *packet_find_instance(struct list_head *head,
					   u32 tpm_instance)
{
	struct packet *pak;
	struct list_head *p;

	/*
	 * traverse the list of packets and return the first
	 * one with the given instance number
	 */
	list_for_each(p, head) {
		pak = list_entry(p, struct packet, next);

		if (pak->tpm_instance == tpm_instance) {
			return pak;
		}
	}
	return NULL;
}

static struct packet *packet_find_packet(struct list_head *head, void *packet)
{
	struct packet *pak;
	struct list_head *p;

	/*
	 * traverse the list of packets and return the first
	 * one with the given instance number
	 */
	list_for_each(p, head) {
		pak = list_entry(p, struct packet, next);

		if (pak == packet) {
			return pak;
		}
	}
	return NULL;
}

static struct packet *packet_alloc(tpmif_t * tpmif,
				   u32 size, u8 req_tag, u8 flags)
{
	struct packet *pak = NULL;
	pak = kzalloc(sizeof (struct packet), GFP_ATOMIC);
	if (NULL != pak) {
		if (tpmif) {
			pak->tpmif = tpmif;
			pak->tpm_instance = tpmback_get_instance(tpmif->bi);
			tpmif_get(tpmif);
		}
		pak->data_len = size;
		pak->req_tag = req_tag;
		pak->last_read = 0;
		pak->flags = flags;

		/*
		 * cannot do tpmif_get(tpmif); bad things happen
		 * on the last tpmif_put()
		 */
		init_timer(&pak->processing_timer);
		pak->processing_timer.function = processing_timeout;
		pak->processing_timer.data = (unsigned long)pak;
	}
	return pak;
}

static void inline packet_reset(struct packet *pak)
{
	pak->last_read = 0;
}

static void packet_free(struct packet *pak)
{
	if (timer_pending(&pak->processing_timer)) {
		BUG();
	}

	if (pak->tpmif)
		tpmif_put(pak->tpmif);
	kfree(pak->data_buffer);
	/*
	 * cannot do tpmif_put(pak->tpmif); bad things happen
	 * on the last tpmif_put()
	 */
	kfree(pak);
}


/*
 * Write data to the shared memory and send it to the FE.
 */
static int packet_write(struct packet *pak,
			const char *data, size_t size, int isuserbuffer)
{
	int rc = 0;

	if (0 != (pak->flags & PACKET_FLAG_DISCARD_RESPONSE)) {
		/* Don't send a respone to this packet. Just acknowledge it. */
		rc = size;
	} else {
		rc = _packet_write(pak, data, size, isuserbuffer);
	}

	return rc;
}

int _packet_write(struct packet *pak,
		  const char *data, size_t size, int isuserbuffer)
{
	/*
	 * Write into the shared memory pages directly
	 * and send it to the front end.
	 */
	tpmif_t *tpmif = pak->tpmif;
	grant_handle_t handle;
	int rc = 0;
	unsigned int i = 0;
	unsigned int offset = 0;

	if (tpmif == NULL) {
		return -EFAULT;
	}

	if (tpmif->status == DISCONNECTED) {
		return size;
	}

	while (offset < size && i < TPMIF_TX_RING_SIZE) {
		unsigned int tocopy;
		struct gnttab_map_grant_ref map_op;
		struct gnttab_unmap_grant_ref unmap_op;
		tpmif_tx_request_t *tx;

		tx = &tpmif->tx->ring[i].req;

		if (0 == tx->addr) {
			DPRINTK("ERROR: Buffer for outgoing packet NULL?! i=%d\n", i);
			return 0;
		}

		gnttab_set_map_op(&map_op, idx_to_kaddr(tpmif, i),
				  GNTMAP_host_map, tx->ref, tpmif->domid);

		if (unlikely(HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
						       &map_op, 1))) {
			BUG();
		}

		handle = map_op.handle;

		if (map_op.status) {
			DPRINTK(" Grant table operation failure !\n");
			return 0;
		}

		tocopy = min_t(size_t, size - offset, PAGE_SIZE);

		if (copy_from_buffer((void *)(idx_to_kaddr(tpmif, i) |
					      (tx->addr & ~PAGE_MASK)),
				     &data[offset], tocopy, isuserbuffer)) {
			tpmif_put(tpmif);
			return -EFAULT;
		}
		tx->size = tocopy;

		gnttab_set_unmap_op(&unmap_op, idx_to_kaddr(tpmif, i),
				    GNTMAP_host_map, handle);

		if (unlikely
		    (HYPERVISOR_grant_table_op
		     (GNTTABOP_unmap_grant_ref, &unmap_op, 1))) {
			BUG();
		}

		offset += tocopy;
		i++;
	}

	rc = offset;
	DPRINTK("Notifying frontend via irq %d\n", tpmif->irq);
	notify_remote_via_irq(tpmif->irq);

	return rc;
}

/*
 * Read data from the shared memory and copy it directly into the
 * provided buffer. Advance the read_last indicator which tells
 * how many bytes have already been read.
 */
static int packet_read(struct packet *pak, size_t numbytes,
		       char *buffer, size_t buffersize, int isuserbuffer)
{
	tpmif_t *tpmif = pak->tpmif;

	/*
	 * Read 'numbytes' of data from the buffer. The first 4
	 * bytes are the instance number in network byte order,
	 * after that come the data from the shared memory buffer.
	 */
	u32 to_copy;
	u32 offset = 0;
	u32 room_left = buffersize;

	if (pak->last_read < 4) {
		/*
		 * copy the instance number into the buffer
		 */
		u32 instance_no = htonl(pak->tpm_instance);
		u32 last_read = pak->last_read;

		to_copy = min_t(size_t, 4 - last_read, numbytes);

		if (copy_to_buffer(&buffer[0],
				   &(((u8 *) & instance_no)[last_read]),
				   to_copy, isuserbuffer)) {
			return -EFAULT;
		}

		pak->last_read += to_copy;
		offset += to_copy;
		room_left -= to_copy;
	}

	/*
	 * If the packet has a data buffer appended, read from it...
	 */

	if (room_left > 0) {
		if (pak->data_buffer) {
			u32 to_copy = min_t(u32, pak->data_len - offset, room_left);
			u32 last_read = pak->last_read - 4;

			if (copy_to_buffer(&buffer[offset],
					   &pak->data_buffer[last_read],
					   to_copy, isuserbuffer)) {
				return -EFAULT;
			}
			pak->last_read += to_copy;
			offset += to_copy;
		} else {
			offset = packet_read_shmem(pak,
						   tpmif,
						   offset,
						   buffer,
						   isuserbuffer, room_left);
		}
	}
	return offset;
}

static int packet_read_shmem(struct packet *pak,
			     tpmif_t * tpmif,
			     u32 offset, char *buffer, int isuserbuffer,
			     u32 room_left)
{
	u32 last_read = pak->last_read - 4;
	u32 i = (last_read / PAGE_SIZE);
	u32 pg_offset = last_read & (PAGE_SIZE - 1);
	u32 to_copy;
	grant_handle_t handle;

	tpmif_tx_request_t *tx;

	tx = &tpmif->tx->ring[0].req;
	/*
	 * Start copying data at the page with index 'index'
	 * and within that page at offset 'offset'.
	 * Copy a maximum of 'room_left' bytes.
	 */
	to_copy = min_t(u32, PAGE_SIZE - pg_offset, room_left);
	while (to_copy > 0) {
		void *src;
		struct gnttab_map_grant_ref map_op;
		struct gnttab_unmap_grant_ref unmap_op;

		tx = &tpmif->tx->ring[i].req;

		gnttab_set_map_op(&map_op, idx_to_kaddr(tpmif, i),
				  GNTMAP_host_map, tx->ref, tpmif->domid);

		if (unlikely(HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
						       &map_op, 1))) {
			BUG();
		}

		if (map_op.status) {
			DPRINTK(" Grant table operation failure !\n");
			return -EFAULT;
		}

		handle = map_op.handle;

		if (to_copy > tx->size) {
			/*
			 * User requests more than what's available
			 */
			to_copy = min_t(u32, tx->size, to_copy);
		}

		DPRINTK("Copying from mapped memory at %08lx\n",
			(unsigned long)(idx_to_kaddr(tpmif, i) |
					(tx->addr & ~PAGE_MASK)));

		src = (void *)(idx_to_kaddr(tpmif, i) |
			       ((tx->addr & ~PAGE_MASK) + pg_offset));
		if (copy_to_buffer(&buffer[offset],
				   src, to_copy, isuserbuffer)) {
			return -EFAULT;
		}

		DPRINTK("Data from TPM-FE of domain %d are %d %d %d %d\n",
			tpmif->domid, buffer[offset], buffer[offset + 1],
			buffer[offset + 2], buffer[offset + 3]);

		gnttab_set_unmap_op(&unmap_op, idx_to_kaddr(tpmif, i),
				    GNTMAP_host_map, handle);

		if (unlikely
		    (HYPERVISOR_grant_table_op
		     (GNTTABOP_unmap_grant_ref, &unmap_op, 1))) {
			BUG();
		}

		offset += to_copy;
		pg_offset = 0;
		last_read += to_copy;
		room_left -= to_copy;

		to_copy = min_t(u32, PAGE_SIZE, room_left);
		i++;
	}			/* while (to_copy > 0) */
	/*
	 * Adjust the last_read pointer
	 */
	pak->last_read = last_read + 4;
	return offset;
}

/* ============================================================
 * The file layer for reading data from this device
 * ============================================================
 */
static int vtpm_op_open(struct inode *inode, struct file *f)
{
	int rc = 0;
	unsigned long flags;

	write_lock_irqsave(&dataex.pak_lock, flags);
	if (dataex.has_opener == 0) {
		dataex.has_opener = 1;
	} else {
		rc = -EPERM;
	}
	write_unlock_irqrestore(&dataex.pak_lock, flags);
	return rc;
}

static ssize_t vtpm_op_read(struct file *file,
			    char __user * data, size_t size, loff_t * offset)
{
	int ret_size = -ENODATA;
	struct packet *pak = NULL;
	unsigned long flags;

	write_lock_irqsave(&dataex.pak_lock, flags);
	if (dataex.aborted) {
		dataex.aborted = 0;
		dataex.copied_so_far = 0;
		write_unlock_irqrestore(&dataex.pak_lock, flags);
		return -EIO;
	}

	if (list_empty(&dataex.pending_pak)) {
		write_unlock_irqrestore(&dataex.pak_lock, flags);
		wait_event_interruptible(dataex.wait_queue,
					 !list_empty(&dataex.pending_pak));
		write_lock_irqsave(&dataex.pak_lock, flags);
		dataex.copied_so_far = 0;
	}

	if (!list_empty(&dataex.pending_pak)) {
		unsigned int left;

		pak = list_entry(dataex.pending_pak.next, struct packet, next);
		left = pak->data_len - dataex.copied_so_far;
		list_del(&pak->next);
		write_unlock_irqrestore(&dataex.pak_lock, flags);

		DPRINTK("size given by app: %d, available: %d\n", size, left);

		ret_size = min_t(size_t, size, left);

		ret_size = packet_read(pak, ret_size, data, size, 1);

		write_lock_irqsave(&dataex.pak_lock, flags);

		if (ret_size < 0) {
			del_singleshot_timer_sync(&pak->processing_timer);
			packet_free(pak);
			dataex.copied_so_far = 0;
		} else {
			DPRINTK("Copied %d bytes to user buffer\n", ret_size);

			dataex.copied_so_far += ret_size;
			if (dataex.copied_so_far >= pak->data_len + 4) {
				DPRINTK("All data from this packet given to app.\n");
				/* All data given to app */

				del_singleshot_timer_sync(&pak->
							  processing_timer);
				list_add_tail(&pak->next, &dataex.current_pak);
				/*
				 * The more fontends that are handled at the same time,
				 * the more time we give the TPM to process the request.
				 */
				mod_timer(&pak->processing_timer,
					  jiffies + (num_frontends * 60 * HZ));
				dataex.copied_so_far = 0;
			} else {
				list_add(&pak->next, &dataex.pending_pak);
			}
		}
	}
	write_unlock_irqrestore(&dataex.pak_lock, flags);

	DPRINTK("Returning result from read to app: %d\n", ret_size);

	return ret_size;
}

/*
 * Write operation - only works after a previous read operation!
 */
static ssize_t vtpm_op_write(struct file *file,
			     const char __user * data, size_t size,
			     loff_t * offset)
{
	struct packet *pak;
	int rc = 0;
	unsigned int off = 4;
	unsigned long flags;
	struct vtpm_resp_hdr vrh;

	/*
	 * Minimum required packet size is:
	 * 4 bytes for instance number
	 * 2 bytes for tag
	 * 4 bytes for paramSize
	 * 4 bytes for the ordinal
	 * sum: 14 bytes
	 */
	if (size < sizeof (vrh))
		return -EFAULT;

	if (copy_from_user(&vrh, data, sizeof (vrh)))
		return -EFAULT;

	/* malformed packet? */
	if ((off + ntohl(vrh.len_no)) != size)
		return -EFAULT;

	write_lock_irqsave(&dataex.pak_lock, flags);
	pak = packet_find_instance(&dataex.current_pak,
				   ntohl(vrh.instance_no));

	if (pak == NULL) {
		write_unlock_irqrestore(&dataex.pak_lock, flags);
		DPRINTK(KERN_ALERT "No associated packet! (inst=%d)\n",
		        ntohl(vrh.instance_no));
		return -EFAULT;
	}

	del_singleshot_timer_sync(&pak->processing_timer);
	list_del(&pak->next);

	write_unlock_irqrestore(&dataex.pak_lock, flags);

	/*
	 * The first 'offset' bytes must be the instance number - skip them.
	 */
	size -= off;

	rc = packet_write(pak, &data[off], size, 1);

	if (rc > 0) {
		/* I neglected the first 4 bytes */
		rc += off;
	}
	packet_free(pak);
	return rc;
}

static int vtpm_op_release(struct inode *inode, struct file *file)
{
	unsigned long flags;

	vtpm_release_packets(NULL, 1);
	write_lock_irqsave(&dataex.pak_lock, flags);
	dataex.has_opener = 0;
	write_unlock_irqrestore(&dataex.pak_lock, flags);
	return 0;
}

static unsigned int vtpm_op_poll(struct file *file,
				 struct poll_table_struct *pts)
{
	unsigned int flags = POLLOUT | POLLWRNORM;

	poll_wait(file, &dataex.wait_queue, pts);
	if (!list_empty(&dataex.pending_pak)) {
		flags |= POLLIN | POLLRDNORM;
	}
	return flags;
}

static const struct file_operations vtpm_ops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.open = vtpm_op_open,
	.read = vtpm_op_read,
	.write = vtpm_op_write,
	.release = vtpm_op_release,
	.poll = vtpm_op_poll,
};

static struct miscdevice vtpms_miscdevice = {
	.minor = 225,
	.name = "vtpm",
	.fops = &vtpm_ops,
};

/***************************************************************
 Utility functions
***************************************************************/

static int tpm_send_fail_message(struct packet *pak, u8 req_tag)
{
	int rc;
	static const unsigned char tpm_error_message_fail[] = {
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x0a,
		0x00, 0x00, 0x00, 0x09	/* TPM_FAIL */
	};
	unsigned char buffer[sizeof (tpm_error_message_fail)];

	memcpy(buffer, tpm_error_message_fail,
	       sizeof (tpm_error_message_fail));
	/*
	 * Insert the right response tag depending on the given tag
	 * All response tags are '+3' to the request tag.
	 */
	buffer[1] = req_tag + 3;

	/*
	 * Write the data to shared memory and notify the front-end
	 */
	rc = packet_write(pak, buffer, sizeof (buffer), 0);

	return rc;
}

static int _vtpm_release_packets(struct list_head *head,
				 tpmif_t * tpmif, int send_msgs)
{
	int aborted = 0;
	int c = 0;
	struct packet *pak;
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, head) {
		pak = list_entry(pos, struct packet, next);
		c += 1;

		if (tpmif == NULL || pak->tpmif == tpmif) {
			int can_send = 0;

			del_singleshot_timer_sync(&pak->processing_timer);
			list_del(&pak->next);

			if (pak->tpmif && pak->tpmif->status == CONNECTED) {
				can_send = 1;
			}

			if (send_msgs && can_send) {
				tpm_send_fail_message(pak, pak->req_tag);
			}
			packet_free(pak);
			if (c == 1)
				aborted = 1;
		}
	}
	return aborted;
}

int vtpm_release_packets(tpmif_t * tpmif, int send_msgs)
{
	unsigned long flags;

	write_lock_irqsave(&dataex.pak_lock, flags);

	dataex.aborted = _vtpm_release_packets(&dataex.pending_pak,
					       tpmif,
					       send_msgs);
	_vtpm_release_packets(&dataex.current_pak, tpmif, send_msgs);

	write_unlock_irqrestore(&dataex.pak_lock, flags);
	return 0;
}

static int vtpm_queue_packet(struct packet *pak)
{
	int rc = 0;

	if (dataex.has_opener) {
		unsigned long flags;

		write_lock_irqsave(&dataex.pak_lock, flags);
		list_add_tail(&pak->next, &dataex.pending_pak);
		/* give the TPM some time to pick up the request */
		mod_timer(&pak->processing_timer, jiffies + (30 * HZ));
		write_unlock_irqrestore(&dataex.pak_lock, flags);

		wake_up_interruptible(&dataex.wait_queue);
	} else {
		rc = -EFAULT;
	}
	return rc;
}

static int vtpm_receive(tpmif_t * tpmif, u32 size)
{
	int rc = 0;
	unsigned char buffer[10];
	__be32 *native_size;
	struct packet *pak = packet_alloc(tpmif, size, 0, 0);

	if (!pak)
		return -ENOMEM;
	/*
	 * Read 10 bytes from the received buffer to test its
	 * content for validity.
	 */
	if (sizeof (buffer) != packet_read(pak,
					   sizeof (buffer), buffer,
					   sizeof (buffer), 0)) {
		goto failexit;
	}
	/*
	 * Reset the packet read pointer so we can read all its
	 * contents again.
	 */
	packet_reset(pak);

	native_size = (__force __be32 *) (&buffer[4 + 2]);
	/*
	 * Verify that the size of the packet is correct
	 * as indicated and that there's actually someone reading packets.
	 * The minimum size of the packet is '10' for tag, size indicator
	 * and ordinal.
	 */
	if (size < 10 ||
	    be32_to_cpu(*native_size) != size ||
	    0 == dataex.has_opener || tpmif->status != CONNECTED) {
		rc = -EINVAL;
		goto failexit;
	} else {
		rc = vtpm_queue_packet(pak);
		if (rc < 0)
			goto failexit;
	}
	return 0;

      failexit:
	if (pak) {
		tpm_send_fail_message(pak, buffer[4 + 1]);
		packet_free(pak);
	}
	return rc;
}

/*
 * Timeout function that gets invoked when a packet has not been processed
 * during the timeout period.
 * The packet must be on a list when this function is invoked. This
 * also means that once its taken off a list, the timer must be
 * destroyed as well.
 */
static void processing_timeout(unsigned long ptr)
{
	struct packet *pak = (struct packet *)ptr;
	unsigned long flags;

	write_lock_irqsave(&dataex.pak_lock, flags);
	/*
	 * The packet needs to be searched whether it
	 * is still on the list.
	 */
	if (pak == packet_find_packet(&dataex.pending_pak, pak) ||
	    pak == packet_find_packet(&dataex.current_pak, pak)) {
		if ((pak->flags & PACKET_FLAG_DISCARD_RESPONSE) == 0) {
			tpm_send_fail_message(pak, pak->req_tag);
		}
		/* discard future responses */
		pak->flags |= PACKET_FLAG_DISCARD_RESPONSE;
	}

	write_unlock_irqrestore(&dataex.pak_lock, flags);
}

static void tpm_tx_action(unsigned long unused);
static DECLARE_TASKLET(tpm_tx_tasklet, tpm_tx_action, 0);

static struct list_head tpm_schedule_list;
static spinlock_t tpm_schedule_list_lock;

static inline void maybe_schedule_tx_action(void)
{
	smp_mb();
	tasklet_schedule(&tpm_tx_tasklet);
}

static inline int __on_tpm_schedule_list(tpmif_t * tpmif)
{
	return tpmif->list.next != NULL;
}

static void remove_from_tpm_schedule_list(tpmif_t * tpmif)
{
	spin_lock_irq(&tpm_schedule_list_lock);
	if (likely(__on_tpm_schedule_list(tpmif))) {
		list_del(&tpmif->list);
		tpmif->list.next = NULL;
		tpmif_put(tpmif);
	}
	spin_unlock_irq(&tpm_schedule_list_lock);
}

static void add_to_tpm_schedule_list_tail(tpmif_t * tpmif)
{
	if (__on_tpm_schedule_list(tpmif))
		return;

	spin_lock_irq(&tpm_schedule_list_lock);
	if (!__on_tpm_schedule_list(tpmif) && tpmif->active) {
		list_add_tail(&tpmif->list, &tpm_schedule_list);
		tpmif_get(tpmif);
	}
	spin_unlock_irq(&tpm_schedule_list_lock);
}

void tpmif_schedule_work(tpmif_t * tpmif)
{
	add_to_tpm_schedule_list_tail(tpmif);
	maybe_schedule_tx_action();
}

void tpmif_deschedule_work(tpmif_t * tpmif)
{
	remove_from_tpm_schedule_list(tpmif);
}

static void tpm_tx_action(unsigned long unused)
{
	struct list_head *ent;
	tpmif_t *tpmif;
	tpmif_tx_request_t *tx;

	DPRINTK("%s: Getting data from front-end(s)!\n", __FUNCTION__);

	while (!list_empty(&tpm_schedule_list)) {
		/* Get a tpmif from the list with work to do. */
		ent = tpm_schedule_list.next;
		tpmif = list_entry(ent, tpmif_t, list);
		tpmif_get(tpmif);
		remove_from_tpm_schedule_list(tpmif);

		tx = &tpmif->tx->ring[0].req;

		/* pass it up */
		vtpm_receive(tpmif, tx->size);

		tpmif_put(tpmif);
	}
}

irqreturn_t tpmif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
	tpmif_t *tpmif = (tpmif_t *) dev_id;

	add_to_tpm_schedule_list_tail(tpmif);
	maybe_schedule_tx_action();
	return IRQ_HANDLED;
}

static int __init tpmback_init(void)
{
	int rc;

	if ((rc = misc_register(&vtpms_miscdevice)) != 0) {
		printk(KERN_ALERT
		       "Could not register misc device for TPM BE.\n");
		return rc;
	}

	dataex_init(&dataex);

	spin_lock_init(&tpm_schedule_list_lock);
	INIT_LIST_HEAD(&tpm_schedule_list);

	tpmif_interface_init();
	tpmif_xenbus_init();

	printk(KERN_ALERT "Successfully initialized TPM backend driver.\n");

	return 0;
}

module_init(tpmback_init);

void __exit tpmback_exit(void)
{
	vtpm_release_packets(NULL, 0);
	tpmif_xenbus_exit();
	tpmif_interface_exit();
	misc_deregister(&vtpms_miscdevice);
}

MODULE_LICENSE("Dual BSD/GPL");
