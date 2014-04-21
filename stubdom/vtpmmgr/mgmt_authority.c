#include <console.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mini-os/byteorder.h>
#include <polarssl/sha1.h>

#include "vtpm_manager.h"
#include "log.h"
#include "uuid.h"

#include "tpm.h"
#include "tcg.h"
#include "marshal.h"
#include "vtpmmgr.h"
#include "vtpm_disk.h"
#include "disk_tpm.h"
#include "disk_io.h"
#include "disk_crypto.h"
#include "disk_format.h"
#include "mgmt_authority.h"

static int do_provision_aik(struct mem_group *group,
		const struct tpm_authdata *privCADigest)
{
	TPM_KEY kinfo = {
		.ver = TPM_STRUCT_VER_1_1,
		.keyUsage = TPM_KEY_IDENTITY,
		.keyFlags = 0,
		.authDataUsage = TPM_AUTH_ALWAYS,
		.algorithmParms = {
			.algorithmID = TPM_ALG_RSA,
			.encScheme = TPM_ES_NONE,
			.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1,
			.parmSize = 12,
			.parms.rsa = {
				.keyLength = RSA_KEY_SIZE,
				.numPrimes = 2,
				.exponentSize = 0,
				.exponent = NULL,
			},
		},
		.PCRInfoSize = 0,
		.pubKey.keyLength = 0,
		.encDataSize = 0,
	};

	TPM_AUTH_SESSION srkAuth = TPM_AUTH_SESSION_INIT;
	TPM_AUTH_SESSION ownAuth = TPM_AUTH_SESSION_INIT;
	TPM_SECRET osapMask;

	TPM_KEY key = TPM_KEY_INIT;
	UINT32 identityBindingSize;
	BYTE* identityBinding = NULL;

	TPM_RESULT rc;

	rc = TPM_OSAP(TPM_ET_OWNER, 0, (void*)&vtpm_globals.owner_auth, &osapMask, &ownAuth);
	if (rc)
		return rc;

	rc = TPM_OIAP(&srkAuth);
	if (rc)
		return rc;

	rc = TPM_MakeIdentity((void*)&group->aik_authdata, (void*)privCADigest, &kinfo,
			(void*)&vtpm_globals.srk_auth, (void*)&osapMask, &srkAuth, &ownAuth,
			&key, &identityBindingSize, &identityBinding);

	TPM_TerminateHandle(srkAuth.AuthHandle);
	TPM_TerminateHandle(ownAuth.AuthHandle);

	if (rc) {
		printk("TPM_MakeIdentity failed: %d\n", rc);
		return rc;
	}

	if (key.pubKey.keyLength != 256)
		rc = TPM_FAIL;
	if (key.encDataSize != 256)
		rc = TPM_FAIL;
	if (identityBindingSize != 256)
		rc = TPM_FAIL;
	if (rc) {
		printk("TPM_MakeIdentity TPM_KEY mismatch: %d %d %d\n",
			key.pubKey.keyLength, key.encDataSize, identityBindingSize);
	} else {
		memcpy(group->id_data.tpm_aik_public, key.pubKey.key, 256);
		memcpy(group->id_data.tpm_aik_edata, key.encData, 256);
		memcpy(group->details.recovery_data, identityBinding, 256);
	}

	free_TPM_KEY(&key);
	free(identityBinding);

	return rc;
}

static int do_load_aik(struct mem_group *group, TPM_HANDLE *handle)
{
	TPM_KEY key = {
		.ver = TPM_STRUCT_VER_1_1,
		.keyUsage = TPM_KEY_IDENTITY,
		.keyFlags = 0,
		.authDataUsage = TPM_AUTH_ALWAYS,
		.algorithmParms = {
			.algorithmID = TPM_ALG_RSA,
			.encScheme = TPM_ES_NONE,
			.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1,
			.parmSize = 12,
			.parms.rsa = {
				.keyLength = RSA_KEY_SIZE,
				.numPrimes = 2,
				.exponentSize = 0,
				.exponent = NULL,
			},
		},
		.PCRInfoSize = 0,
		.pubKey.keyLength = 256,
		.pubKey.key = group->id_data.tpm_aik_public,
		.encDataSize = 256,
		.encData = group->id_data.tpm_aik_edata,
	};

	return TPM_LoadKey(TPM_SRK_KEYHANDLE, &key, handle, (void*)&vtpm_globals.srk_auth, &vtpm_globals.oiap);
}

/* 
 * Sets up resettable PCRs for a vTPM deep quote request
 */
static int do_pcr_setup(struct mem_group *group, const void* uuid, const uint8_t* kern_hash)
{
	uint32_t reset_sel = (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);
	sha1_context ctx;
	TPM_DIGEST extended;
	TPM_PCR_SELECTION sel = {
		.sizeOfSelect = 3,
		.pcrSelect = (void*)&reset_sel,
	};
	int rc;
	int i;

	rc = TPM_Reset(&sel);
	if (rc)
		return rc;

	sha1((void*)&group->id_data.saa_pubkey, sizeof(group->id_data.saa_pubkey), extended.digest);
	rc = TPM_Extend(20, &extended, &extended);
	if (rc)
		return rc;

	sha1_starts(&ctx);
	sha1_update(&ctx, (void*)&group->details.cfg_seq, 8);
	sha1_update(&ctx, (void*)&group->seal_bits.nr_cfgs, 4);
	for(i=0; i < group->nr_seals; i++)
		sha1_update(&ctx, (void*)&group->seals[i].digest_release, 20);
	sha1_update(&ctx, (void*)&group->seal_bits.nr_kerns, 4);
	sha1_update(&ctx, (void*)&group->seal_bits.kernels, 20 * be32_native(group->seal_bits.nr_kerns));
	sha1_finish(&ctx, extended.digest);
	rc = TPM_Extend(21, &extended, &extended);
	if (rc)
		return rc;

	if (kern_hash) {
		rc = TPM_Extend(22, (void*)kern_hash, &extended);
		if (rc)
			return rc;
	}

	memset(&extended, 0, 20);
	memcpy(&extended, group->id_data.uuid, 16);
	rc = TPM_Extend(23, &extended, &extended);
	if (rc)
		return rc;

	if (uuid) {
		memset(&extended, 0, 20);
		memcpy(&extended, uuid, 16);
		rc = TPM_Extend(23, &extended, &extended);
		if (rc)
			return rc;
	}

	return rc;
}

struct mem_group *vtpm_new_group(const struct tpm_authdata *privCADigest)
{
	static struct mem_group* group0_delayed = NULL;
	struct mem_group *group;

	if (group0_delayed) {
		group = group0_delayed;
		group0_delayed = NULL;
	} else {
		group = calloc(1, sizeof(*group));

		group->flags = MEM_GROUP_FLAG_FIRSTBOOT;

		do_random(&group->id_data.uuid, 16);
		do_random(&group->group_key, 16);
		do_random(&group->rollback_mac_key, 16);
		do_random(&group->aik_authdata, 20);

		group->id_data.uuid[6] = 0x40 | (group->id_data.uuid[6] & 0x0F);
		group->id_data.uuid[8] = 0x80 | (group->id_data.uuid[8] & 0x3F);
	}

	if (privCADigest) {
		int rc;
		rc = do_provision_aik(group, privCADigest);
		if (rc) {
			free(group);
			return NULL;
		}
	} else {
		group0_delayed = group;
	}

	return group;
}

int group_do_activate(struct mem_group *group, void* blob, int blobSize,
	void* resp, unsigned int *rlen)
{
	int rc;
	TPM_HANDLE handle;
	TPM_AUTH_SESSION aikAuth = TPM_AUTH_SESSION_INIT;
	TPM_AUTH_SESSION ownAuth = TPM_AUTH_SESSION_INIT;
	TPM_SYMMETRIC_KEY symKey;

	/* ActivateIdentity with TPM_EK_BLOB_ACTIVATE can check PCRs */
	rc = do_pcr_setup(group, NULL, NULL);
	if (rc)
		return rc;

	rc = do_load_aik(group, &handle);
	if (rc)
		return rc;

	rc = TPM_OIAP(&aikAuth);
	if (rc) {
		TPM_TerminateHandle(handle);
		return rc;
	}

	rc = TPM_OIAP(&ownAuth);
	if (rc) {
		TPM_TerminateHandle(aikAuth.AuthHandle);
		TPM_TerminateHandle(handle);
		return rc;
	}

	rc = TPM_ActivateIdentity(handle, blob, blobSize, (void*)&group->aik_authdata,
			(void*)&vtpm_globals.owner_auth, &aikAuth, &ownAuth, &symKey);

	TPM_TerminateHandle(ownAuth.AuthHandle);
	TPM_TerminateHandle(aikAuth.AuthHandle);
	TPM_TerminateHandle(handle);

	if (rc)
		return rc;

	pack_TPM_SYMMETRIC_KEY(resp + *rlen, &symKey);
	*rlen += 8 + symKey.size;
	free(symKey.data);

	return rc;
}

int vtpm_do_quote(struct mem_group *group, const uuid_t uuid,
	const uint8_t* kern_hash, const struct tpm_authdata *data, TPM_PCR_SELECTION *sel,
	void* pcr_out, uint32_t *pcr_size, void* sig_out)
{
	TPM_HANDLE handle;
	TPM_AUTH_SESSION oiap = TPM_AUTH_SESSION_INIT;
	TPM_PCR_COMPOSITE pcrs;
	BYTE* sig;
	UINT32 size;
	int rc;

	rc = do_pcr_setup(group, uuid, kern_hash);
	if (rc)
		return rc;

	rc = do_load_aik(group, &handle);
	if (rc)
		return rc;

	rc = TPM_OIAP(&oiap);
	if (rc) {
		TPM_TerminateHandle(handle);
		return rc;
	}

	rc = TPM_Quote(handle, (void*)data, sel, (void*)&group->aik_authdata, &oiap, &pcrs, &sig, &size);
	printk("TPM_Quote: %d\n", rc);

	TPM_TerminateHandle(oiap.AuthHandle);
	TPM_FlushSpecific(handle, TPM_RT_KEY);

	if (rc)
		return rc;
	if (size != 256) {
		printk("Bad size\n");
		return TPM_FAIL;
	}

	if (pcr_out) {
		*pcr_size = pcrs.valueSize;
		memcpy(pcr_out, pcrs.pcrValue, *pcr_size);
	}

	memcpy(sig_out, sig, size);

	free_TPM_PCR_COMPOSITE(&pcrs);
	free(sig);

	return rc;
}
