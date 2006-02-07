#ifndef TPM_FE_H
#define TPM_FE_H

struct tpm_private;

struct tpmfe_device {
	/*
	 * Let upper layer receive data from front-end
	 */
	int (*receive)(const u8 *buffer, size_t count, const void *ptr);
	/*
	 * Indicate the status of the front-end to the upper
	 * layer.
	 */
	void (*status)(unsigned int flags);

	/*
	 * This field indicates the maximum size the driver can
	 * transfer in one chunk. It is filled out by the front-end
	 * driver and should be propagated to the generic tpm driver
	 * for allocation of buffers.
	 */
	unsigned int max_tx_size;
	/*
	 * The following is a private structure of the underlying
	 * driver. It's expected as first parameter in the send function.
	 */
	struct tpm_private *tpm_private;
};

enum {
	TPMFE_STATUS_DISCONNECTED = 0x0,
	TPMFE_STATUS_CONNECTED = 0x1
};

int tpm_fe_send(struct tpm_private * tp, const u8 * buf, size_t count, void *ptr);
int tpm_fe_register_receiver(struct tpmfe_device *);
void tpm_fe_unregister_receiver(void);

#endif
