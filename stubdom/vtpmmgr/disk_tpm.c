/* TPM disk interface */
#include <blkfront.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mini-os/byteorder.h>
#include <mini-os/lib.h>
#include <polarssl/aes.h>
#include <polarssl/sha1.h>

#include "tpm.h"
#include "tpm2.h"
#include "tcg.h"

#include "vtpmmgr.h"
#include "vtpm_disk.h"
#include "disk_tpm.h"

#include "log.h"
// Print out input/output of seal/unseal operations (includes keys)
#undef DEBUG_SEAL_OPS

#ifdef DEBUG_SEAL_OPS
#include "marshal.h"
#include "tpm2_marshal.h"
#endif

struct pcr_list {
	TPM_DIGEST pcrs[24];
};

static struct pcr_list hwtpm;

/*Ignore PCR on TPM 2.0, read PCR values for TPM 1.x seal | unseal*/
void TPM_read_pcrs(void)
{
	int i;
	for (i=0; i < 24; i++) {
        if (hw_is_tpm2())
            tpm2_pcr_read(i, (uint8_t *)&hwtpm.pcrs[i]);
        else
		    TPM_PCR_Read(i, &hwtpm.pcrs[i]);
    }
}

struct pcr_composite_3 {
	be16_t sel_size;
	uint8_t sel[3];
	be32_t val_size;
	uint8_t val[0];
} __attribute__((packed));

void TPM_pcr_digest(struct hash160 *buf, le32_t selection)
{
	int i;
	int count = 0;
	uint32_t sel = le32_native(selection);
	struct pcr_composite_3 *v;
	for(i=0; i < 24; i++) {
		if (sel & (1 << i))
			count++;
	}
	v = alloca(sizeof(*v) + 20 * count);
	v->sel_size = native_be16(3);
	memcpy(v->sel, &selection, 3);
	v->val_size = native_be32(20 * count);

	count = 0;
	for(i=0; i < 24; i++) {
		if (sel & (1 << i)) {
			memcpy(v->val + 20 * count, &hwtpm.pcrs[i], 20);
			count++;
		}
	}

	sha1((void*)v, sizeof(*v) + 20 * count, buf->bits);
}


int TPM_disk_seal(struct disk_seal_entry *dst, const void* src, size_t size)
{
	uint32_t rc;
	uint32_t infoSize;
	TPM_PCR_INFO_LONG info;
	TPM_STORED_DATA12 out;
	TPM_AUTH_SESSION osap = TPM_AUTH_SESSION_INIT;
	TPM_AUTHDATA sharedsecret;
	TPM_AUTHDATA auth;

	printk("Calling TPM_disk_seal\n");

	rc = TPM_OSAP(TPM_ET_KEYHANDLE, TPM_SRK_KEYHANDLE, (void*)&vtpm_globals.srk_auth,
			&sharedsecret, &osap);

	if (rc) abort();

#ifdef DEBUG_SEAL_OPS
	int i;
	printk("to-seal:");
	for(i=0; i < size; i++)
		printk(" %02x", ((uint8_t*)src)[i]);
	printk("\n");
#endif

	memset(auth, 0, 20);
	info.tag = TPM_TAG_PCR_INFO_LONG;
	info.localityAtCreation = 1 << vtpm_globals.hw_locality;
	info.localityAtRelease = 1 << vtpm_globals.hw_locality;
	info.creationPCRSelection.sizeOfSelect = 3;
	info.creationPCRSelection.pcrSelect = (void*)&dst->pcr_selection;
	info.releasePCRSelection.sizeOfSelect = 3;
	info.releasePCRSelection.pcrSelect = (void*)&dst->pcr_selection;
	memcpy(&info.digestAtCreation, &dst->digest_at_seal, 20);
	memcpy(&info.digestAtRelease, &dst->digest_release, 20);

	infoSize = 2 + 1 + 1 + 2 + 3 + 2 + 3 + 20 + 20;
	//infoSize = sizeof_TPM_PCR_INFO_LONG(&info);

	rc = TPM_Seal(TPM_SRK_KEYHANDLE, infoSize, &info, size, src, &out,
			(void*)&sharedsecret, (void*)&auth, &osap);

	TPM_TerminateHandle(osap.AuthHandle);

#ifdef DEBUG_SEAL_OPS
	printk("TPM_Seal rc=%d encDataSize=%d sealInfoSize=%d\n", rc, out.encDataSize, out.sealInfoLongSize);
#endif
	if (!rc)
		memcpy(dst->sealed_data, out.encData, 256);

#ifdef DEBUG_SEAL_OPS
	uint8_t buf[512];
	uint8_t *start = buf;
	uint8_t *end = pack_TPM_STORED_DATA12(buf, &out);
	printk("stored_data:");
	while (start != end) {
		printk(" %02x", *start);
		start++;
	}
	printk("\n");
#endif

	free_TPM_STORED_DATA12(&out);
	return rc;
}

TPM_RC TPM2_disk_bind(struct disk_seal_entry *dst, void* src, unsigned int size)
{
    TPM_RESULT status = TPM_SUCCESS;

    TPMTRYRETURN(TPM2_Bind(vtpm_globals.sk_handle,
                           src,
                           size,
                           dst->sealed_data));

abort_egress:
egress:
   return status;
}

TPM_RC TPM2_disk_unbind(void *dst, unsigned int *size, const struct disk_seal_entry *src)
{
    TPM_RESULT status = TPM_SUCCESS;
    unsigned char buf[RSA_CIPHER_SIZE];

    memcpy(buf, src->sealed_data, RSA_CIPHER_SIZE);
    TPMTRYRETURN(TPM2_UnBind(vtpm_globals.sk_handle,
                             RSA_CIPHER_SIZE,
                             buf,
                             size,
                             dst));
abort_egress:
egress:
   return status;
}

int TPM_disk_unseal(void *dst, size_t size, const struct disk_seal_entry *src)
{
	uint32_t rc;
	TPM_STORED_DATA12 in;
	TPM_AUTH_SESSION oiap = TPM_AUTH_SESSION_INIT;
	TPM_AUTHDATA auth;
	uint32_t outSize = 0;
	uint8_t *out = NULL;

	printk("Calling TPM_disk_unseal\n");

	rc = TPM_OIAP(&oiap);
	if (rc) abort();

	memset(auth, 0, 20);

	in.tag = TPM_TAG_STORED_DATA12;
	in.et = 0;
	//in.sealInfoLongSize = sizeof_TPM_PCR_INFO_LONG(&in.sealInfoLong);
	in.sealInfoLongSize = 2 + 1 + 1 + 2 + 3 + 2 + 3 + 20 + 20;
	in.sealInfoLong.tag = TPM_TAG_PCR_INFO_LONG;
	in.sealInfoLong.localityAtCreation = 1 << vtpm_globals.hw_locality;
	in.sealInfoLong.localityAtRelease = 1 << vtpm_globals.hw_locality;
	in.sealInfoLong.creationPCRSelection.sizeOfSelect = 3;
	in.sealInfoLong.creationPCRSelection.pcrSelect = (void*)&src->pcr_selection;
	in.sealInfoLong.releasePCRSelection.sizeOfSelect = 3;
	in.sealInfoLong.releasePCRSelection.pcrSelect = (void*)&src->pcr_selection;
	memcpy(&in.sealInfoLong.digestAtCreation, &src->digest_at_seal, 20);
	memcpy(&in.sealInfoLong.digestAtRelease, &src->digest_release, 20);
	in.encDataSize = 256;
	in.encData = (void*)src->sealed_data;

#ifdef DEBUG_SEAL_OPS
	uint8_t buf[512];
	uint8_t *start = buf;
	uint8_t *end = pack_TPM_STORED_DATA12(buf, &in);
	printk("stored_data:");
	while (start != end) {
		printk(" %02x", *start);
		start++;
	}
	printk("\n");
#endif

	rc = TPM_Unseal(TPM_SRK_KEYHANDLE, &in, &outSize, &out,
			(void*)&vtpm_globals.srk_auth, (void*)&auth, &vtpm_globals.oiap, &oiap);

	TPM_TerminateHandle(oiap.AuthHandle);

#ifdef DEBUG_SEAL_OPS
	printk("TPM_Unseal rc=%d outSize=%d size=%d\n", rc, outSize, size);
#endif
	if (!rc) {
		memcpy(dst, out, size);
#ifdef DEBUG_SEAL_OPS
		printk("unsealed:");
		int i;
		for(i=0; i < size; i++)
			printk(" %02x", ((uint8_t*)dst)[i]);
		printk("\n");
#endif
	}

	free(out);

	return rc;
}

int TPM_disk_nvalloc(be32_t *nvram_slot, struct tpm_authdata auth)
{
	// TODO-3
	nvram_slot->value = 0;
	return 0;
}

int TPM_disk_nvread(void *buf, size_t bufsiz, be32_t nvram_slot, struct tpm_authdata auth)
{
	// TODO-3
	memset(buf, 0, bufsiz);
	return 0;
}

int TPM_disk_nvwrite(void *buf, size_t bufsiz, be32_t nvram_slot, struct tpm_authdata auth)
{
	// TODO-3
	return 0;
}

int TPM_disk_nvchange(be32_t nvram_slot, struct tpm_authdata old, struct tpm_authdata noo)
{
	// TODO-3
	return 0;
}

int TPM_disk_alloc_counter(be32_t *slot, struct tpm_authdata auth, be32_t *value)
{
	// TODO-3
	slot->value = 0;
	value->value = 0;
	return 0;
}

int TPM_disk_check_counter(be32_t slot, struct tpm_authdata auth, be32_t value)
{
	// TODO-3
	return 0;
}

int TPM_disk_incr_counter(be32_t slot, struct tpm_authdata auth)
{
	// TODO-3
	return 0;
}

int TPM_disk_change_counter(be32_t slot, struct tpm_authdata old, struct tpm_authdata noo)
{
	// TODO-3
	return 0;
}
