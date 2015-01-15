#ifndef __VTPMMGR_DISK_VTPM_H
#define __VTPMMGR_DISK_VTPM_H
#include "vtpm_disk.h"

/* Read PCR values to determine which unseal to try */
void TPM_read_pcrs(void);
void TPM_pcr_digest(struct hash160 *buf, le32_t selection);

/* Sealing for key storage */
int TPM_disk_seal(struct disk_seal_entry *dst, const void* src, size_t size);
int TPM_disk_unseal(void *dst, size_t size, const struct disk_seal_entry *src);

/*TPM 2.0 Bind and Unbind */
TPM_RC TPM2_disk_bind(struct disk_seal_entry *dst, void* src, unsigned int size);
TPM_RC TPM2_disk_unbind(void *dst, unsigned int *size, const struct disk_seal_entry *src);

/* NVRAM to allow revocation of TM-KEY */
int TPM_disk_nvalloc(be32_t *nvram_slot, struct tpm_authdata auth);
int TPM_disk_nvread(void *buf, size_t bufsiz, be32_t nvram_slot, struct tpm_authdata auth);
int TPM_disk_nvwrite(void *buf, size_t bufsiz, be32_t nvram_slot, struct tpm_authdata auth);
int TPM_disk_nvchange(be32_t nvram_slot, struct tpm_authdata old, struct tpm_authdata noo);

/* Monotonic counters to detect rollback */
int TPM_disk_alloc_counter(be32_t *slot, struct tpm_authdata auth, be32_t *value);
int TPM_disk_check_counter(be32_t slot, struct tpm_authdata auth, be32_t value);
int TPM_disk_incr_counter(be32_t slot, struct tpm_authdata auth);
int TPM_disk_change_counter(be32_t slot, struct tpm_authdata old, struct tpm_authdata noo);

#endif
