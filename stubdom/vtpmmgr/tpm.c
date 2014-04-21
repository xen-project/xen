/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>

#include <polarssl/sha1.h>

#include "tcg.h"
#include "tpm.h"
#include "log.h"
#include "marshal.h"
#include "tpmrsa.h"
#include "vtpmmgr.h"

#define TCPA_MAX_BUFFER_LENGTH 0x2000

#define TPM_BEGIN_CMD(ord) \
	const TPM_COMMAND_CODE ordinal = ord; \
	TPM_RESULT status = TPM_SUCCESS; \
	BYTE _io_buffer[TCPA_MAX_BUFFER_LENGTH]; \
	UINT32 _io_bufsize_in; \
	UINT32 _io_bufsize_out; \
	vtpmloginfo(VTPM_LOG_TPM, "%s\n", __func__); \
	do { \
		BYTE *in_buf = _io_buffer; \
		UINT32 in_pos = 6; \
		PACK_IN(UINT32, ordinal);

#define IN_PTR (in_buf + in_pos)

#define PACK_IN(type, item...) do { \
	UINT32 isize = sizeof_ ## type(item); \
	if (isize + in_pos > TCPA_MAX_BUFFER_LENGTH) { \
		status = TPM_SIZE; \
		goto abort_egress; \
	} \
	pack_ ## type (IN_PTR, item); \
	in_pos += isize; \
} while (0)

#define TPM_HASH_IN_BEGIN \
	sha1_context sha1_ctx; \
	sha1_starts(&sha1_ctx); \
	sha1_update(&sha1_ctx, in_buf + 6, 4); \
	TPM_HASH_IN_START

#define TPM_HASH_IN_START \
	do { \
		UINT32 _hash_in_start = in_pos;

#define TPM_HASH_IN_STOP \
		sha1_update(&sha1_ctx, in_buf + _hash_in_start, in_pos - _hash_in_start); \
	} while (0)

#define TPM_TAG_COMMON(req_tag) \
		_io_bufsize_in = in_pos; \
		pack_TPM_TAG(in_buf, req_tag); \
		pack_UINT32(in_buf + sizeof(TPM_TAG), in_pos); \
	} while (0); \
	_io_bufsize_out = TCPA_MAX_BUFFER_LENGTH; \
	status = TPM_TransmitData(_io_buffer, _io_bufsize_in, _io_buffer, &_io_bufsize_out); \
	if (status != TPM_SUCCESS) { \
		goto abort_egress; \
	} \
	do { \
		BYTE *out_buf = _io_buffer; \
		UINT32 out_pos = 0; \
		UINT32 out_len = _io_bufsize_out; \
		do { \
			TPM_TAG rsp_tag; \
			UINT32 rsp_len; \
			UINT32 rsp_status; \
			UNPACK_OUT(TPM_RSP_HEADER, &rsp_tag, &rsp_len, &rsp_status); \
			if (rsp_status != TPM_SUCCESS) { \
				vtpmlogerror(VTPM_LOG_TPM, "Failed with return code %s\n", tpm_get_error_name(rsp_status)); \
				status = rsp_status; \
				goto abort_egress; \
			} \
			if (rsp_tag != req_tag + 3 || rsp_len != out_len) { \
				status = TPM_FAIL; \
				goto abort_egress; \
			} \
		} while(0)

#define OUT_PTR (out_buf + out_pos)

#define UNPACK_OUT(type, item...) do { \
	if (unpack3_ ## type (out_buf, &out_pos, TCPA_MAX_BUFFER_LENGTH, item)) { \
		status = TPM_SIZE; \
		goto abort_egress; \
	} \
} while (0)

#define TPM_XMIT_REQ() \
	TPM_TAG_COMMON(TPM_TAG_RQU_COMMAND)

#define TPM_XMIT_AUTH1(sec1, auth1) \
	TPM_HASH_IN_STOP; \
	do { \
		TPM_DIGEST paramDigest; \
		sha1_finish(&sha1_ctx, paramDigest.digest); \
		generateAuth(&paramDigest, sec1, auth1); \
		PACK_IN(TPM_AUTH_SESSION, auth1); \
	} while (0); \
	TPM_TAG_COMMON(TPM_TAG_RQU_AUTH1_COMMAND); \
	TPM_HASH_OUT_BEGIN

#define TPM_XMIT_AUTH2(sec1, auth1, sec2, auth2) \
	TPM_HASH_IN_STOP; \
	do { \
		TPM_DIGEST paramDigest; \
		sha1_finish(&sha1_ctx, paramDigest.digest); \
		generateAuth(&paramDigest, sec1, auth1); \
		PACK_IN(TPM_AUTH_SESSION, auth1); \
		generateAuth(&paramDigest, sec2, auth2); \
		PACK_IN(TPM_AUTH_SESSION, auth2); \
	} while (0); \
	TPM_TAG_COMMON(TPM_TAG_RQU_AUTH2_COMMAND); \
	TPM_HASH_OUT_BEGIN

#define TPM_HASH_OUT_BEGIN \
	sha1_context sha1_ctx; \
	sha1_starts(&sha1_ctx); \
	do { \
		UINT32 buf[2] = { cpu_to_be32(status), cpu_to_be32(ordinal) }; \
		sha1_update(&sha1_ctx, (BYTE*)buf, sizeof(buf)); \
	} while(0); \
	TPM_HASH_OUT_START

#define TPM_HASH_OUT_START \
	do { \
		UINT32 _hash_out_start = out_pos;

#define TPM_HASH_OUT_STOP \
		sha1_update(&sha1_ctx, out_buf + _hash_out_start, out_pos - _hash_out_start); \
	} while (0)

#define TPM_END_AUTH1(sec1, auth1) \
	TPM_HASH_OUT_STOP; \
	do { \
		TPM_DIGEST paramDigest; \
		sha1_finish(&sha1_ctx, paramDigest.digest); \
		UNPACK_OUT(TPM_AUTH_SESSION, auth1); \
		status = verifyAuth(&paramDigest, sec1, auth1); \
		if (status != TPM_SUCCESS) \
			goto abort_egress; \
	} while(0); \
	TPM_END_COMMON

#define TPM_END_AUTH2(sec1, auth1, sec2, auth2) \
	TPM_HASH_OUT_STOP; \
	do { \
		TPM_DIGEST paramDigest; \
		sha1_finish(&sha1_ctx, paramDigest.digest); \
		UNPACK_OUT(TPM_AUTH_SESSION, auth1); \
		status = verifyAuth(&paramDigest, sec1, auth1); \
		if (status != TPM_SUCCESS) \
			goto abort_egress; \
		UNPACK_OUT(TPM_AUTH_SESSION, auth2); \
		status = verifyAuth(&paramDigest, sec2, auth2); \
		if (status != TPM_SUCCESS) \
			goto abort_egress; \
	} while(0); \
	TPM_END_COMMON

#define TPM_END() TPM_END_COMMON

#define TPM_END_COMMON \
		if (out_pos != out_len) { \
			vtpmloginfo(VTPM_LOG_TPM, "Response too long (%d != %d)", out_pos, out_len);\
			status = TPM_SIZE; \
			goto abort_egress; \
		} \
	} while (0); \

#define TPM_AUTH_ERR_CHECK(auth) do {\
	if(status != TPM_SUCCESS || auth->fContinueAuthSession == FALSE) {\
		vtpmloginfo(VTPM_LOG_TPM, "Auth Session: 0x%x closed by TPM\n", auth->AuthHandle);\
		auth->AuthHandle = 0;\
	}\
} while(0)

static void xorEncrypt(const TPM_SECRET* sharedSecret,
		TPM_NONCE* nonce,
		const TPM_AUTHDATA* inAuth0,
		TPM_ENCAUTH outAuth0,
		const TPM_AUTHDATA* inAuth1,
		TPM_ENCAUTH outAuth1) {
	BYTE XORbuffer[sizeof(TPM_SECRET) + sizeof(TPM_NONCE)];
	BYTE XORkey[TPM_DIGEST_SIZE];
	BYTE* ptr = XORbuffer;
	ptr = pack_TPM_SECRET(ptr, sharedSecret);
	ptr = pack_TPM_NONCE(ptr, nonce);

	sha1(XORbuffer, ptr - XORbuffer, XORkey);

	if(inAuth0) {
		for(int i = 0; i < TPM_DIGEST_SIZE; ++i) {
			outAuth0[i] = XORkey[i] ^ (*inAuth0)[i];
		}
	}
	if(inAuth1) {
		for(int i = 0; i < TPM_DIGEST_SIZE; ++i) {
			outAuth1[i] = XORkey[i] ^ (*inAuth1)[i];
		}
	}

}

static void generateAuth(const TPM_DIGEST* paramDigest,
		const TPM_SECRET* HMACkey,
		TPM_AUTH_SESSION *auth)
{
	//Generate new OddNonce
	vtpmmgr_rand((BYTE*)auth->NonceOdd.nonce, sizeof(TPM_NONCE));

	// Create HMAC text. (Concat inParamsDigest with inAuthSetupParams).
	BYTE hmacText[sizeof(TPM_DIGEST) + (2 * sizeof(TPM_NONCE)) + sizeof(BOOL)];
	BYTE* ptr = hmacText;

	ptr = pack_TPM_DIGEST(ptr, paramDigest);
	ptr = pack_TPM_NONCE(ptr, &auth->NonceEven);
	ptr = pack_TPM_NONCE(ptr, &auth->NonceOdd);
	ptr = pack_BOOL(ptr, auth->fContinueAuthSession);

	sha1_hmac((BYTE *) HMACkey, sizeof(TPM_DIGEST),
			(BYTE *) hmacText, sizeof(hmacText),
			auth->HMAC);
}

static TPM_RESULT verifyAuth(const TPM_DIGEST* paramDigest,
		/*[IN]*/ const TPM_SECRET *HMACkey,
		/*[IN,OUT]*/ TPM_AUTH_SESSION *auth)
{

	// Create HMAC text. (Concat inParamsDigest with inAuthSetupParams).
	TPM_AUTHDATA hm;
	BYTE hmacText[sizeof(TPM_DIGEST) + (2 * sizeof(TPM_NONCE)) + sizeof(BOOL)];
	BYTE* ptr = hmacText;

	ptr = pack_TPM_DIGEST(ptr, paramDigest);
	ptr = pack_TPM_NONCE(ptr, &auth->NonceEven);
	ptr = pack_TPM_NONCE(ptr, &auth->NonceOdd);
	ptr = pack_BOOL(ptr, auth->fContinueAuthSession);

	sha1_hmac( (BYTE *) HMACkey, sizeof(TPM_DIGEST),
			(BYTE *) hmacText, sizeof(hmacText),
			hm);

	// Compare correct HMAC with provided one.
	if (memcmp(hm, auth->HMAC, sizeof(TPM_DIGEST)) == 0) { // 0 indicates equality
		return TPM_SUCCESS;
	} else {
		vtpmlogerror(VTPM_LOG_TPM, "Auth Session verification failed! %x %x\n",
			*(UINT32*)auth->HMAC, *(UINT32*)hm);
		return TPM_AUTHFAIL;
	}
}



// ------------------------------------------------------------------
// Authorization Commands
// ------------------------------------------------------------------

TPM_RESULT TPM_OIAP(TPM_AUTH_SESSION*	auth)  // out
{
	TPM_BEGIN_CMD(TPM_ORD_OIAP);

	TPM_XMIT_REQ();

	memset(&auth->HMAC, 0, sizeof(TPM_DIGEST));
	auth->fContinueAuthSession = TRUE;

	UNPACK_OUT(UINT32, &auth->AuthHandle);
	UNPACK_OUT(TPM_NONCE, &auth->NonceEven);
	TPM_END();

	vtpmloginfo(VTPM_LOG_TPM, "Auth Session: 0x%x opened by TPM_OIAP.\n", auth->AuthHandle);

abort_egress:
	return status;
}

TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE  entityType,  // in
		UINT32	 entityValue, // in
		const TPM_AUTHDATA* usageAuth, //in
		TPM_SECRET *sharedSecret, //out
		TPM_AUTH_SESSION *auth)
{
	TPM_DIGEST nonceOddOSAP;
	vtpmmgr_rand(nonceOddOSAP.digest, TPM_DIGEST_SIZE);
	TPM_BEGIN_CMD(TPM_ORD_OSAP);

	PACK_IN(TPM_ENTITY_TYPE, entityType);
	PACK_IN(UINT32, entityValue);
	PACK_IN(TPM_DIGEST, &nonceOddOSAP);

	TPM_XMIT_REQ();

	UNPACK_OUT(UINT32, &auth->AuthHandle);
	UNPACK_OUT(TPM_NONCE, &auth->NonceEven);

	//Calculate session secret
	sha1_context ctx;
	sha1_hmac_starts(&ctx, *usageAuth, TPM_DIGEST_SIZE);
	sha1_hmac_update(&ctx, OUT_PTR, TPM_DIGEST_SIZE); // nonceEvenOSAP
	sha1_hmac_update(&ctx, nonceOddOSAP.digest, TPM_DIGEST_SIZE);
	sha1_hmac_finish(&ctx, *sharedSecret);

	out_pos += TPM_DIGEST_SIZE;
	TPM_END();

	memset(&auth->HMAC, 0, sizeof(TPM_DIGEST));
	auth->fContinueAuthSession = FALSE;

	vtpmloginfo(VTPM_LOG_TPM, "Auth Session: 0x%x opened by TPM_OSAP.\n", auth->AuthHandle);

abort_egress:
	return status;
}

TPM_RESULT TPM_TakeOwnership(
		const TPM_PUBKEY *pubEK, //in
		const TPM_AUTHDATA* ownerAuth, //in
		const TPM_AUTHDATA* srkAuth, //in
		const TPM_KEY* inSrk, //in
		TPM_KEY* outSrk, //out, optional
		TPM_AUTH_SESSION*	auth)	// in, out
{
	int keyAlloced = 0;
	tpmrsa_context ek_rsa = TPMRSA_CTX_INIT;

	TPM_BEGIN_CMD(TPM_ORD_TakeOwnership);
	TPM_HASH_IN_BEGIN;

	tpmrsa_set_pubkey(&ek_rsa,
			pubEK->pubKey.key, pubEK->pubKey.keyLength,
			pubEK->algorithmParms.parms.rsa.exponent,
			pubEK->algorithmParms.parms.rsa.exponentSize);

	/* Pack the protocol ID */
	PACK_IN(UINT16, TPM_PID_OWNER);

	/* Pack the encrypted owner auth */
	PACK_IN(UINT32, pubEK->algorithmParms.parms.rsa.keyLength / 8);
	tpmrsa_pub_encrypt_oaep(&ek_rsa,
			ctr_drbg_random, &vtpm_globals.ctr_drbg,
			sizeof(TPM_SECRET),
			(BYTE*) ownerAuth,
			IN_PTR);
	in_pos += pubEK->algorithmParms.parms.rsa.keyLength / 8;

	/* Pack the encrypted srk auth */
	PACK_IN(UINT32, pubEK->algorithmParms.parms.rsa.keyLength / 8);
	tpmrsa_pub_encrypt_oaep(&ek_rsa,
			ctr_drbg_random, &vtpm_globals.ctr_drbg,
			sizeof(TPM_SECRET),
			(BYTE*) srkAuth,
			IN_PTR);
	in_pos += pubEK->algorithmParms.parms.rsa.keyLength / 8;

	PACK_IN(TPM_KEY, inSrk);

	TPM_XMIT_AUTH1(ownerAuth, auth);

	if (outSrk != NULL) {
		/* If the user wants a copy of the srk we give it to them */
		keyAlloced = 1;
		UNPACK_OUT(TPM_KEY, outSrk, UNPACK_ALLOC);
	} else {
		/*otherwise just parse past it */
		TPM_KEY temp;
		UNPACK_OUT(TPM_KEY, &temp, UNPACK_ALIAS);
	}

	TPM_END_AUTH1(ownerAuth, auth);

	goto egress;
abort_egress:
	if(keyAlloced) {
		free_TPM_KEY(outSrk);
	}
egress:
	tpmrsa_free(&ek_rsa);
	TPM_AUTH_ERR_CHECK(auth);
	return status;
}


TPM_RESULT TPM_DisablePubekRead (
		const TPM_AUTHDATA* ownerAuth,
		TPM_AUTH_SESSION*	auth)
{
	TPM_BEGIN_CMD(TPM_ORD_DisablePubekRead);
	TPM_HASH_IN_BEGIN;

	TPM_XMIT_AUTH1(ownerAuth, auth);

	TPM_END_AUTH1(ownerAuth, auth);

abort_egress:
	TPM_AUTH_ERR_CHECK(auth);
	return status;
}


TPM_RESULT TPM_TerminateHandle(TPM_AUTHHANDLE  handle)  // in
{
	if(handle == 0) {
		return TPM_SUCCESS;
	}

	TPM_BEGIN_CMD(TPM_ORD_Terminate_Handle);

	PACK_IN(TPM_AUTHHANDLE, handle);

	TPM_XMIT_REQ();
	TPM_END();

	vtpmloginfo(VTPM_LOG_TPM, "Auth Session: 0x%x closed by TPM_TerminateHandle\n", handle);

abort_egress:
	return status;
}

TPM_RESULT TPM_Extend( TPM_PCRINDEX  pcrNum,  // in
		TPM_DIGEST* inDigest, // in
		TPM_PCRVALUE*  outDigest) // out
{
	TPM_BEGIN_CMD(TPM_ORD_Extend);

	PACK_IN(TPM_PCRINDEX, pcrNum);
	PACK_IN(TPM_DIGEST, inDigest);

	TPM_XMIT_REQ();

	UNPACK_OUT(TPM_PCRVALUE, outDigest);

	TPM_END();

abort_egress:
	return status;
}

TPM_RESULT TPM_Reset(TPM_PCR_SELECTION *sel)
{
	TPM_BEGIN_CMD(TPM_ORD_PCR_Reset);
	PACK_IN(TPM_PCR_SELECTION, sel);
	TPM_XMIT_REQ();
	TPM_END();
abort_egress:
	return status;
}

TPM_RESULT TPM_Seal(
		TPM_KEY_HANDLE  keyHandle,  // in
		UINT32	 pcrInfoLongSize, // in
		TPM_PCR_INFO_LONG*	 pcrInfoLong,  // in
		UINT32	 inDataSize,  // in
		const BYTE*	 inData,	// in
		TPM_STORED_DATA12* sealedData, //out
		const TPM_SECRET* osapSharedSecret, //in
		const TPM_AUTHDATA* sealedDataAuth, //in
		TPM_AUTH_SESSION*	pubAuth  // in, out
		)
{
	memset(sealedData, 0, sizeof(*sealedData));
	TPM_BEGIN_CMD(TPM_ORD_Seal);
	PACK_IN(TPM_KEY_HANDLE, keyHandle);
	TPM_HASH_IN_BEGIN;

	xorEncrypt(osapSharedSecret, &pubAuth->NonceEven, sealedDataAuth, IN_PTR, NULL, NULL);
	in_pos += sizeof(TPM_ENCAUTH);

	PACK_IN(UINT32, pcrInfoLongSize);
	if (pcrInfoLongSize) {
		PACK_IN(TPM_PCR_INFO_LONG, pcrInfoLong);
	}
	PACK_IN(UINT32, inDataSize);
	PACK_IN(BUFFER, inData, inDataSize);

	TPM_XMIT_AUTH1(osapSharedSecret, pubAuth);

	UNPACK_OUT(TPM_STORED_DATA12, sealedData, UNPACK_ALLOC);

	TPM_END_AUTH1(osapSharedSecret, pubAuth);

 abort_egress:
	if (status)
		free_TPM_STORED_DATA12(sealedData);
	TPM_AUTH_ERR_CHECK(pubAuth);
	return status;
}

TPM_RESULT TPM_Unseal(
		TPM_KEY_HANDLE parentHandle, // in
		const TPM_STORED_DATA12* sealedData,
		UINT32*	outSize,  // out
		BYTE**	 out, //out
		const TPM_AUTHDATA* key_usage_auth, //in
		const TPM_AUTHDATA* data_usage_auth, //in
		TPM_AUTH_SESSION*	keyAuth,  // in, out
		TPM_AUTH_SESSION*	dataAuth  // in, out
		)
{
	TPM_BEGIN_CMD(TPM_ORD_Unseal);

	PACK_IN(TPM_KEY_HANDLE, parentHandle);

	TPM_HASH_IN_BEGIN;
	PACK_IN(TPM_STORED_DATA12, sealedData);

	TPM_XMIT_AUTH2(key_usage_auth, keyAuth, data_usage_auth, dataAuth);

	UNPACK_OUT(UINT32, outSize);
	UNPACK_OUT(PTR, out, *outSize, UNPACK_ALLOC);

	TPM_END_AUTH2(key_usage_auth, keyAuth, data_usage_auth, dataAuth);

abort_egress:
	TPM_AUTH_ERR_CHECK(keyAuth);
	TPM_AUTH_ERR_CHECK(dataAuth);
	return status;
}

TPM_RESULT TPM_LoadKey(
		TPM_KEY_HANDLE  parentHandle, //
		const TPM_KEY* key, //in
		TPM_HANDLE*  keyHandle,	 // out
		const TPM_AUTHDATA* usage_auth,
		TPM_AUTH_SESSION* auth)
{
	TPM_BEGIN_CMD(TPM_ORD_LoadKey);
	PACK_IN(TPM_KEY_HANDLE, parentHandle);

	TPM_HASH_IN_BEGIN;

	PACK_IN(TPM_KEY, key);

	TPM_XMIT_AUTH1(usage_auth, auth);

	UNPACK_OUT(UINT32, keyHandle);

	TPM_END_AUTH1(usage_auth, auth);

	vtpmloginfo(VTPM_LOG_TPM, "Key Handle: 0x%x opened by TPM_LoadKey\n", *keyHandle);
abort_egress:
	TPM_AUTH_ERR_CHECK(auth);
	return status;
}

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle,
		TPM_RESOURCE_TYPE rt) {
	if(handle == 0) {
		return TPM_SUCCESS;
	}
	TPM_BEGIN_CMD(TPM_ORD_FlushSpecific);

	PACK_IN(TPM_HANDLE, handle);
	PACK_IN(TPM_RESOURCE_TYPE, rt);

	TPM_XMIT_REQ();
	TPM_END();

abort_egress:
	return status;
}

TPM_RESULT TPM_GetRandom( UINT32*	 bytesRequested, // in, out
		BYTE*	 randomBytes) // out
{
	UINT32 req_len = *bytesRequested;
	TPM_BEGIN_CMD(TPM_ORD_GetRandom);
	PACK_IN(UINT32, req_len);

	TPM_XMIT_REQ();

	UNPACK_OUT(UINT32, bytesRequested);
	if (*bytesRequested > req_len)
		return TPM_FAIL;
	UNPACK_OUT(BUFFER, randomBytes, *bytesRequested);
	TPM_END();

abort_egress:
	return status;
}


TPM_RESULT TPM_ReadPubek(
		TPM_PUBKEY* pubEK //out
		)
{
	TPM_DIGEST antiReplay;
	BYTE* kptr = NULL;
	BYTE digest[TPM_DIGEST_SIZE];
	sha1_context ctx;

	vtpmmgr_rand(antiReplay.digest, TPM_DIGEST_SIZE);

	TPM_BEGIN_CMD(TPM_ORD_ReadPubek);

	PACK_IN(TPM_DIGEST, &antiReplay);

	TPM_XMIT_REQ();

	//unpack and allocate the key
	kptr = OUT_PTR;
	UNPACK_OUT(TPM_PUBKEY, pubEK, UNPACK_ALLOC);

	//Verify the checksum
	sha1_starts(&ctx);
	sha1_update(&ctx, kptr, OUT_PTR - kptr);
	sha1_update(&ctx, antiReplay.digest, TPM_DIGEST_SIZE);
	sha1_finish(&ctx, digest);

	UNPACK_OUT(TPM_DIGEST, &antiReplay);

	TPM_END();

	//ptr points to the checksum computed by TPM
	if(memcmp(digest, antiReplay.digest, TPM_DIGEST_SIZE)) {
		vtpmlogerror(VTPM_LOG_TPM, "TPM_ReadPubek: Checksum returned by TPM was invalid!\n");
		status = TPM_FAIL;
		goto abort_egress;
	}

	goto egress;
abort_egress:
	if(kptr != NULL) { //If we unpacked the pubEK, we have to free it
		free_TPM_PUBKEY(pubEK);
	}
egress:
	return status;
}

TPM_RESULT TPM_PCR_Read(UINT32 pcr, TPM_DIGEST *value)
{
	TPM_BEGIN_CMD(TPM_ORD_PcrRead);
	PACK_IN(UINT32, pcr);
	TPM_XMIT_REQ();
	UNPACK_OUT(TPM_DIGEST, value);
	TPM_END();
abort_egress:
	return status;
}

TPM_RESULT TPM_SaveState(void)
{
	TPM_BEGIN_CMD(TPM_ORD_SaveState);
	TPM_XMIT_REQ();
	TPM_END();

abort_egress:
	return status;
}

TPM_RESULT TPM_GetCapability(
		TPM_CAPABILITY_AREA capArea,
		UINT32 subCapSize,
		const BYTE* subCap,
		UINT32* respSize,
		BYTE** resp)
{
	TPM_BEGIN_CMD(TPM_ORD_GetCapability);

	PACK_IN(TPM_CAPABILITY_AREA, capArea);
	PACK_IN(UINT32, subCapSize);
	PACK_IN(BUFFER, subCap, subCapSize);

	TPM_XMIT_REQ();

	UNPACK_OUT(UINT32, respSize);
	UNPACK_OUT(PTR, resp, *respSize, UNPACK_ALLOC);

	TPM_END();

abort_egress:
	return status;
}

TPM_RESULT TPM_CreateEndorsementKeyPair(
		const TPM_KEY_PARMS* keyInfo,
		TPM_PUBKEY* pubEK)
{
	BYTE* kptr = NULL;
	sha1_context ctx;
	TPM_DIGEST checksum;
	TPM_DIGEST hash;
	TPM_NONCE antiReplay;
	TPM_BEGIN_CMD(TPM_ORD_CreateEndorsementKeyPair);

	//Make anti replay nonce
	vtpmmgr_rand(antiReplay.nonce, sizeof(antiReplay.nonce));

	PACK_IN(TPM_NONCE, &antiReplay);
	PACK_IN(TPM_KEY_PARMS, keyInfo);

	TPM_XMIT_REQ();

	kptr = OUT_PTR;
	UNPACK_OUT(TPM_PUBKEY, pubEK, UNPACK_ALLOC);

	/* Hash the pub key blob */
	sha1_starts(&ctx);
	sha1_update(&ctx, kptr, OUT_PTR - kptr);
	sha1_update(&ctx, antiReplay.nonce, sizeof(antiReplay.nonce));
	sha1_finish(&ctx, hash.digest);

	UNPACK_OUT(TPM_DIGEST, &checksum);

	TPM_END();

	if (memcmp(checksum.digest, hash.digest, TPM_DIGEST_SIZE)) {
		vtpmloginfo(VTPM_LOG_VTPM, "TPM_CreateEndorsementKey: Checkum verification failed!\n");
		status = TPM_FAIL;
		goto abort_egress;
	}

	goto egress;
abort_egress:
	if(kptr) {
		free_TPM_PUBKEY(pubEK);
	}
egress:
	return status;
}

TPM_RESULT TPM_MakeIdentity(
	const TPM_AUTHDATA* identityAuth, // in
	const TPM_AUTHDATA* privCADigest, // in
	const TPM_KEY* kinfo, // in
	const TPM_AUTHDATA* srk_auth, // in
	const TPM_AUTHDATA* own_auth, // in
	TPM_AUTH_SESSION* srkAuth, // in,out
	TPM_AUTH_SESSION* ownAuth, // in,out
	TPM_KEY* key, // out
	UINT32* identityBindingSize, // out
	BYTE** identityBinding) // out
{
	TPM_BEGIN_CMD(TPM_ORD_MakeIdentity);
	TPM_HASH_IN_BEGIN;

	xorEncrypt(own_auth, &ownAuth->NonceEven, identityAuth, IN_PTR, NULL, NULL);
	in_pos += sizeof(TPM_ENCAUTH);

	PACK_IN(TPM_AUTHDATA, privCADigest);
	PACK_IN(TPM_KEY, kinfo);

	TPM_XMIT_AUTH2(srk_auth, srkAuth, own_auth, ownAuth);

	UNPACK_OUT(TPM_KEY, key, UNPACK_ALLOC);
	UNPACK_OUT(UINT32, identityBindingSize);
	UNPACK_OUT(PTR, identityBinding, *identityBindingSize, UNPACK_ALLOC);

	TPM_END_AUTH2(srk_auth, srkAuth, own_auth, ownAuth);

abort_egress:
	TPM_AUTH_ERR_CHECK(srkAuth);
	TPM_AUTH_ERR_CHECK(ownAuth);
	return status;
}

TPM_RESULT TPM_ActivateIdentity(
	TPM_KEY_HANDLE aikHandle, // in
	BYTE* blob, // in
	UINT32 blobSize, // in
	const TPM_AUTHDATA* aik_auth, // in
	const TPM_AUTHDATA* owner_auth, // in
	TPM_AUTH_SESSION* aikAuth, // in,out
	TPM_AUTH_SESSION* ownAuth, // in,out
	TPM_SYMMETRIC_KEY* symKey) // out
{
	TPM_BEGIN_CMD(TPM_ORD_ActivateIdentity);
	PACK_IN(TPM_KEY_HANDLE, aikHandle);
	TPM_HASH_IN_BEGIN;
	PACK_IN(UINT32, blobSize);
	PACK_IN(BUFFER, blob, blobSize);
	
	TPM_XMIT_AUTH2(aik_auth, aikAuth, owner_auth, ownAuth);

	UNPACK_OUT(TPM_SYMMETRIC_KEY, symKey, UNPACK_ALLOC);

	TPM_END_AUTH2(aik_auth, aikAuth, owner_auth, ownAuth);

abort_egress:
	TPM_AUTH_ERR_CHECK(aikAuth);
	TPM_AUTH_ERR_CHECK(ownAuth);
	return status;
}

TPM_RESULT TPM_Quote(
	TPM_KEY_HANDLE keyh, // in
	const TPM_NONCE* data, // in
	const TPM_PCR_SELECTION *pcrSelect, // in
	const TPM_AUTHDATA* auth, // in
	TPM_AUTH_SESSION* oiap, // in,out
	TPM_PCR_COMPOSITE *pcrs, // out
	BYTE** sig, // out
	UINT32* sigSize) // out
{
	TPM_BEGIN_CMD(TPM_ORD_Quote);
	PACK_IN(TPM_KEY_HANDLE, keyh);
	TPM_HASH_IN_BEGIN;
	PACK_IN(TPM_NONCE, data);
	PACK_IN(TPM_PCR_SELECTION, pcrSelect);

	TPM_XMIT_AUTH1(auth, oiap);

	UNPACK_OUT(TPM_PCR_COMPOSITE, pcrs, UNPACK_ALLOC);
	UNPACK_OUT(UINT32, sigSize);
	UNPACK_OUT(PTR, sig, *sigSize, UNPACK_ALLOC);

	TPM_END_AUTH1(auth, oiap);

abort_egress:
	TPM_AUTH_ERR_CHECK(oiap);
	return status;
}

TPM_RESULT TPM_TransmitData(
		BYTE* in,
		UINT32 insize,
		BYTE* out,
		UINT32* outsize) {
	TPM_RESULT status = TPM_SUCCESS;

	UINT32 i;
	vtpmloginfo(VTPM_LOG_TXDATA, "Sending buffer = 0x");
	for(i = 0 ; i < insize ; i++)
		vtpmloginfomore(VTPM_LOG_TXDATA, "%2.2x ", in[i]);

	vtpmloginfomore(VTPM_LOG_TXDATA, "\n");

	ssize_t size = 0;

	// send the request
	size = write (vtpm_globals.tpm_fd, in, insize);
	if (size < 0) {
		vtpmlogerror(VTPM_LOG_TXDATA, "write() failed : %s\n", strerror(errno));
		ERRORDIE (TPM_IOERROR);
	}
	else if ((UINT32) size < insize) {
		vtpmlogerror(VTPM_LOG_TXDATA, "Wrote %d instead of %d bytes!\n", (int) size, insize);
		ERRORDIE (TPM_IOERROR);
	}

	// read the response
	size = read (vtpm_globals.tpm_fd, out, *outsize);
	if (size < 0) {
		vtpmlogerror(VTPM_LOG_TXDATA, "read() failed : %s\n", strerror(errno));
		ERRORDIE (TPM_IOERROR);
	}

	vtpmloginfo(VTPM_LOG_TXDATA, "Receiving buffer = 0x");
	for(i = 0 ; i < size ; i++)
		vtpmloginfomore(VTPM_LOG_TXDATA, "%2.2x ", out[i]);

	vtpmloginfomore(VTPM_LOG_TXDATA, "\n");

	*outsize = size;
	goto egress;

abort_egress:
egress:
	return status;
}
