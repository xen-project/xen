#ifndef TPM_VTPM_H
#define TPM_VTPM_H

struct tpm_chip;
struct tpm_private;

struct tpm_virtual_device {
	/*
	 * This field indicates the maximum size the driver can
	 * transfer in one chunk. It is filled in by the front-end
	 * driver and should be propagated to the generic tpm driver
	 * for allocation of buffers.
	 */
	unsigned int max_tx_size;
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
int vtpm_vd_send(struct tpm_chip *tc,
                 struct tpm_private * tp,
                 const u8 * buf, size_t count, void *ptr);

/* these functions are offered by tpm_vtpm.c */
int __init init_vtpm(struct tpm_virtual_device *);
void __exit cleanup_vtpm(void);
int vtpm_vd_recv(const unsigned char *buffer, size_t count, const void *ptr);
void vtpm_vd_status(u8 status);

#endif
