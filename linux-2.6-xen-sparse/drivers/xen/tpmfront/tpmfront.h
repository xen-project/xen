#ifndef TPM_FRONT_H
#define TPM_FRONT_H


struct tpm_private
{
	tpmif_tx_interface_t *tx;
	unsigned int evtchn, irq;
	int connected;

	spinlock_t tx_lock;

	struct tx_buffer *tx_buffers[TPMIF_TX_RING_SIZE];

	atomic_t tx_busy;
	void *tx_remember;
	domid_t backend_id;
	wait_queue_head_t wait_q;
};


struct tpmfront_info
{
	struct xenbus_watch watch;
	int handle;
	struct xenbus_device *dev;
	char *backend;
	int ring_ref;
	domid_t backend_id;
};


struct tx_buffer
{
	unsigned int size;	// available space in data
	unsigned int len;	// used space in data
	unsigned char *data;    // pointer to a page
};

#endif

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
