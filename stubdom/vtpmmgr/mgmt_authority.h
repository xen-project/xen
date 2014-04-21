#ifndef __VTPMMGR_MGMT_AUTHORITY_H
#define __VTPMMGR_MGMT_AUTHORITY_H

struct mem_group *vtpm_new_group(const struct tpm_authdata *privCADigest);
int group_do_activate(struct mem_group *group, void* blob, int blobSize,
	void* resp, unsigned int *rlen);
int vtpm_do_quote(struct mem_group *group, const uuid_t uuid,
	const uint8_t* kern_hash, const struct tpm_authdata *data, TPM_PCR_SELECTION *sel,
	void* pcr_out, uint32_t *pcr_size, void* sig_out);

#endif
