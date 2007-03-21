#ifndef TPM_VTPM_H
#define TPM_VTPM_H

struct tpm_chip;
struct tpm_private;

struct vtpm_state {
	struct transmission *current_request;
	spinlock_t           req_list_lock;
	wait_queue_head_t    req_wait_queue;

	struct list_head     queued_requests;

	struct transmission *current_response;
	spinlock_t           resp_list_lock;
	wait_queue_head_t    resp_wait_queue;     // processes waiting for responses

	u8                   vd_status;
	u8                   flags;

	unsigned long        disconnect_time;

	/*
	 * The following is a private structure of the underlying
	 * driver. It is passed as parameter in the send function.
	 */
	struct tpm_private *tpm_private;
};


enum vdev_status {
	TPM_VD_STATUS_DISCONNECTED = 0x0,
	TPM_VD_STATUS_CONNECTED = 0x1
};

/* this function is called from tpm_vtpm.c */
int vtpm_vd_send(struct tpm_private * tp,
                 const u8 * buf, size_t count, void *ptr);

/* these functions are offered by tpm_vtpm.c */
struct tpm_chip *init_vtpm(struct device *,
                           struct tpm_private *);
void cleanup_vtpm(struct device *);
int vtpm_vd_recv(const struct tpm_chip* chip,
                 const unsigned char *buffer, size_t count, void *ptr);
void vtpm_vd_status(const struct tpm_chip *, u8 status);

static inline struct tpm_private *tpm_private_from_dev(struct device *dev)
{
	struct tpm_chip *chip = dev_get_drvdata(dev);
	struct vtpm_state *vtpms = chip_get_private(chip);
	return vtpms->tpm_private;
}

#endif
