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

#define TPM_BEGIN(TAG, ORD) \
   const TPM_TAG intag = TAG;\
TPM_TAG tag = intag;\
UINT32 paramSize;\
const TPM_COMMAND_CODE ordinal = ORD;\
TPM_RESULT status = TPM_SUCCESS;\
BYTE in_buf[TCPA_MAX_BUFFER_LENGTH];\
BYTE out_buf[TCPA_MAX_BUFFER_LENGTH];\
UINT32 out_len = sizeof(out_buf);\
BYTE* ptr = in_buf;\
/*Print a log message */\
vtpmloginfo(VTPM_LOG_TPM, "%s\n", __func__);\
/* Pack the header*/\
ptr = pack_TPM_TAG(ptr, tag);\
ptr += sizeof(UINT32);\
ptr = pack_TPM_COMMAND_CODE(ptr, ordinal)\

#define TPM_AUTH_BEGIN() \
   sha1_context sha1_ctx;\
BYTE* authbase = ptr - sizeof(TPM_COMMAND_CODE);\
TPM_DIGEST paramDigest;\
sha1_starts(&sha1_ctx)

#define TPM_AUTH1_GEN(HMACkey, auth) do {\
   sha1_finish(&sha1_ctx, paramDigest.digest);\
   generateAuth(&paramDigest, HMACkey, auth);\
   ptr = pack_TPM_AUTH_SESSION(ptr, auth);\
} while(0)

#define TPM_AUTH2_GEN(HMACkey, auth) do {\
   generateAuth(&paramDigest, HMACkey, auth);\
   ptr = pack_TPM_AUTH_SESSION(ptr, auth);\
} while(0)

#define TPM_TRANSMIT() do {\
   /* Pack the command size */\
   paramSize = ptr - in_buf;\
   pack_UINT32(in_buf + sizeof(TPM_TAG), paramSize);\
   if((status = TPM_TransmitData(in_buf, paramSize, out_buf, &out_len)) != TPM_SUCCESS) {\
      goto abort_egress;\
   }\
} while(0)

#define TPM_AUTH_VERIFY_BEGIN() do {\
   UINT32 buf[2] = { cpu_to_be32(status), cpu_to_be32(ordinal) };\
   sha1_starts(&sha1_ctx);\
   sha1_update(&sha1_ctx, (unsigned char*)buf, sizeof(buf));\
   authbase = ptr;\
} while(0)

#define TPM_AUTH1_VERIFY(HMACkey, auth) do {\
   sha1_finish(&sha1_ctx, paramDigest.digest);\
   ptr = unpack_TPM_AUTH_SESSION(ptr, auth);\
   if((status = verifyAuth(&paramDigest, HMACkey, auth)) != TPM_SUCCESS) {\
      goto abort_egress;\
   }\
} while(0)

#define TPM_AUTH2_VERIFY(HMACkey, auth) do {\
   ptr = unpack_TPM_AUTH_SESSION(ptr, auth);\
   if((status = verifyAuth(&paramDigest, HMACkey, auth)) != TPM_SUCCESS) {\
      goto abort_egress;\
   }\
} while(0)



#define TPM_UNPACK_VERIFY() do { \
   ptr = out_buf;\
   ptr = unpack_TPM_RSP_HEADER(ptr, \
         &(tag), &(paramSize), &(status));\
   if((status) != TPM_SUCCESS || (tag) != (intag +3)) { \
      vtpmlogerror(VTPM_LOG_TPM, "Failed with return code %s\n", tpm_get_error_name(status));\
      goto abort_egress;\
   }\
} while(0)

#define TPM_AUTH_HASH() do {\
   sha1_update(&sha1_ctx, authbase, ptr - authbase);\
   authbase = ptr;\
} while(0)

#define TPM_AUTH_SKIP() do {\
   authbase = ptr;\
} while(0)

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
      vtpmlogerror(VTPM_LOG_TPM, "Auth Session verification failed!\n");
      return TPM_AUTHFAIL;
   }
}



// ------------------------------------------------------------------
// Authorization Commands
// ------------------------------------------------------------------

TPM_RESULT TPM_OIAP(TPM_AUTH_SESSION*   auth)  // out
{
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   memset(&auth->HMAC, 0, sizeof(TPM_DIGEST));
   auth->fContinueAuthSession = TRUE;

   ptr = unpack_UINT32(ptr, &auth->AuthHandle);
   ptr = unpack_TPM_NONCE(ptr, &auth->NonceEven);

   vtpmloginfo(VTPM_LOG_TPM, "Auth Session: 0x%x opened by TPM_OIAP.\n", auth->AuthHandle);

abort_egress:
   return status;
}

TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE  entityType,  // in
      UINT32    entityValue, // in
      const TPM_AUTHDATA* usageAuth, //in
      TPM_SECRET *sharedSecret, //out
      TPM_AUTH_SESSION *auth)
{
   BYTE* nonceOddOSAP;
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_OSAP);

   ptr = pack_TPM_ENTITY_TYPE(ptr, entityType);
   ptr = pack_UINT32(ptr, entityValue);

   //nonce Odd OSAP
   nonceOddOSAP = ptr;
   vtpmmgr_rand(ptr, TPM_DIGEST_SIZE);
   ptr += TPM_DIGEST_SIZE;

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   ptr = unpack_UINT32(ptr, &auth->AuthHandle);
   ptr = unpack_TPM_NONCE(ptr, &auth->NonceEven);

   //Calculate session secret
   sha1_context ctx;
   sha1_hmac_starts(&ctx, *usageAuth, TPM_DIGEST_SIZE);
   sha1_hmac_update(&ctx, ptr, TPM_DIGEST_SIZE); //ptr = nonceEvenOSAP
   sha1_hmac_update(&ctx, nonceOddOSAP, TPM_DIGEST_SIZE);
   sha1_hmac_finish(&ctx, *sharedSecret);

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
      TPM_AUTH_SESSION*   auth)   // in, out
{
   int keyAlloced = 0;
   tpmrsa_context ek_rsa = TPMRSA_CTX_INIT;

   TPM_BEGIN(TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_TakeOwnership);
   TPM_AUTH_BEGIN();

   tpmrsa_set_pubkey(&ek_rsa,
         pubEK->pubKey.key, pubEK->pubKey.keyLength,
         pubEK->algorithmParms.parms.rsa.exponent,
         pubEK->algorithmParms.parms.rsa.exponentSize);

   /* Pack the protocol ID */
   ptr = pack_UINT16(ptr, TPM_PID_OWNER);

   /* Pack the encrypted owner auth */
   ptr = pack_UINT32(ptr, pubEK->algorithmParms.parms.rsa.keyLength / 8);
   tpmrsa_pub_encrypt_oaep(&ek_rsa,
         ctr_drbg_random, &vtpm_globals.ctr_drbg,
         sizeof(TPM_SECRET),
         (BYTE*) ownerAuth,
         ptr);
   ptr += pubEK->algorithmParms.parms.rsa.keyLength / 8;

   /* Pack the encrypted srk auth */
   ptr = pack_UINT32(ptr, pubEK->algorithmParms.parms.rsa.keyLength / 8);
   tpmrsa_pub_encrypt_oaep(&ek_rsa,
         ctr_drbg_random, &vtpm_globals.ctr_drbg,
         sizeof(TPM_SECRET),
         (BYTE*) srkAuth,
         ptr);
   ptr += pubEK->algorithmParms.parms.rsa.keyLength / 8;

   /* Pack the Srk key */
   ptr = pack_TPM_KEY(ptr, inSrk);

   /* Hash everything up to here */
   TPM_AUTH_HASH();

   /* Generate the authorization */
   TPM_AUTH1_GEN(ownerAuth, auth);

   /* Send the command to the tpm*/
   TPM_TRANSMIT();
   /* Unpack and validate the header */
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   if(outSrk != NULL) {
      /* If the user wants a copy of the srk we give it to them */
      keyAlloced = 1;
      ptr = unpack_TPM_KEY(ptr, outSrk, UNPACK_ALLOC);
   } else {
      /*otherwise just parse past it */
      TPM_KEY temp;
      ptr = unpack_TPM_KEY(ptr, &temp, UNPACK_ALIAS);
   }

   /* Hash the output key */
   TPM_AUTH_HASH();

   /* Verify authorizaton */
   TPM_AUTH1_VERIFY(ownerAuth, auth);

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
      TPM_AUTH_SESSION*   auth)
{
   TPM_BEGIN(TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_DisablePubekRead);
   TPM_AUTH_BEGIN();

   TPM_AUTH_HASH();

   TPM_AUTH1_GEN(ownerAuth, auth);
   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   TPM_AUTH1_VERIFY(ownerAuth, auth);

abort_egress:
   TPM_AUTH_ERR_CHECK(auth);
   return status;
}


TPM_RESULT TPM_TerminateHandle(TPM_AUTHHANDLE  handle)  // in
{
   if(handle == 0) {
      return TPM_SUCCESS;
   }

   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_Terminate_Handle);

   ptr = pack_TPM_AUTHHANDLE(ptr, handle);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   vtpmloginfo(VTPM_LOG_TPM, "Auth Session: 0x%x closed by TPM_TerminateHandle\n", handle);

abort_egress:
   return status;
}

TPM_RESULT TPM_Extend( TPM_PCRINDEX  pcrNum,  // in
      TPM_DIGEST  inDigest, // in
      TPM_PCRVALUE*  outDigest) // out
{
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_Extend);

   ptr = pack_TPM_PCRINDEX(ptr, pcrNum);
   ptr = pack_TPM_DIGEST(ptr, &inDigest);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   ptr = unpack_TPM_PCRVALUE(ptr, outDigest);

abort_egress:
   return status;
}

TPM_RESULT TPM_Seal(
      TPM_KEY_HANDLE  keyHandle,  // in
      UINT32    pcrInfoSize, // in
      TPM_PCR_INFO*    pcrInfo,  // in
      UINT32    inDataSize,  // in
      const BYTE*    inData,   // in
      TPM_STORED_DATA* sealedData, //out
      const TPM_SECRET* osapSharedSecret, //in
      const TPM_AUTHDATA* sealedDataAuth, //in
      TPM_AUTH_SESSION*   pubAuth  // in, out
      )
{
   int dataAlloced = 0;
   TPM_BEGIN(TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_Seal);
   TPM_AUTH_BEGIN();

   TPM_AUTH_HASH();

   ptr = pack_TPM_KEY_HANDLE(ptr, keyHandle);

   TPM_AUTH_SKIP();

   xorEncrypt(osapSharedSecret, &pubAuth->NonceEven,
         sealedDataAuth, ptr,
         NULL, NULL);
   ptr += sizeof(TPM_ENCAUTH);

   ptr = pack_UINT32(ptr, pcrInfoSize);
   ptr = pack_TPM_PCR_INFO(ptr, pcrInfo);

   ptr = pack_UINT32(ptr, inDataSize);
   ptr = pack_BUFFER(ptr, inData, inDataSize);

   TPM_AUTH_HASH();

   TPM_AUTH1_GEN(osapSharedSecret, pubAuth);
   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   ptr = unpack_TPM_STORED_DATA(ptr, sealedData, UNPACK_ALLOC);
   dataAlloced = 1;

   TPM_AUTH_HASH();

   TPM_AUTH1_VERIFY(osapSharedSecret, pubAuth);

   goto egress;
abort_egress:
   if(dataAlloced) {
      free_TPM_STORED_DATA(sealedData);
   }
egress:
   TPM_AUTH_ERR_CHECK(pubAuth);
   return status;
}

TPM_RESULT TPM_Unseal(
      TPM_KEY_HANDLE parentHandle, // in
      const TPM_STORED_DATA* sealedData,
      UINT32*   outSize,  // out
      BYTE**    out, //out
      const TPM_AUTHDATA* key_usage_auth, //in
      const TPM_AUTHDATA* data_usage_auth, //in
      TPM_AUTH_SESSION*   keyAuth,  // in, out
      TPM_AUTH_SESSION*   dataAuth  // in, out
      )
{
   TPM_BEGIN(TPM_TAG_RQU_AUTH2_COMMAND, TPM_ORD_Unseal);
   TPM_AUTH_BEGIN();

   TPM_AUTH_HASH();

   ptr = pack_TPM_KEY_HANDLE(ptr, parentHandle);

   TPM_AUTH_SKIP();

   ptr = pack_TPM_STORED_DATA(ptr, sealedData);

   TPM_AUTH_HASH();

   TPM_AUTH1_GEN(key_usage_auth, keyAuth);
   TPM_AUTH2_GEN(data_usage_auth, dataAuth);
   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   ptr = unpack_UINT32(ptr, outSize);
   ptr = unpack_ALLOC(ptr, out, *outSize);

   TPM_AUTH_HASH();

   TPM_AUTH1_VERIFY(key_usage_auth, keyAuth);
   TPM_AUTH2_VERIFY(data_usage_auth, dataAuth);

abort_egress:
   TPM_AUTH_ERR_CHECK(keyAuth);
   TPM_AUTH_ERR_CHECK(dataAuth);
   return status;
}

TPM_RESULT TPM_Bind(
      const TPM_KEY* key,
      const BYTE* in,
      UINT32 ilen,
      BYTE* out)
{
   TPM_RESULT status;
   tpmrsa_context rsa = TPMRSA_CTX_INIT;
   TPM_BOUND_DATA boundData;
   uint8_t plain[TCPA_MAX_BUFFER_LENGTH];
   BYTE* ptr = plain;

   vtpmloginfo(VTPM_LOG_TPM, "%s\n", __func__);

   tpmrsa_set_pubkey(&rsa,
         key->pubKey.key, key->pubKey.keyLength,
         key->algorithmParms.parms.rsa.exponent,
         key->algorithmParms.parms.rsa.exponentSize);

   // Fill boundData's accessory information
   boundData.ver = TPM_STRUCT_VER_1_1;
   boundData.payload = TPM_PT_BIND;
   boundData.payloadData = (BYTE*)in;

   //marshall the bound data object
   ptr = pack_TPM_BOUND_DATA(ptr, &boundData, ilen);

   // Encrypt the data
   TPMTRYRETURN(tpmrsa_pub_encrypt_oaep(&rsa,
            ctr_drbg_random, &vtpm_globals.ctr_drbg,
            ptr - plain,
            plain,
            out));

abort_egress:
   tpmrsa_free(&rsa);
   return status;

}

TPM_RESULT TPM_UnBind(
      TPM_KEY_HANDLE  keyHandle,  // in
      UINT32 ilen, //in
      const BYTE* in, //
      UINT32* olen, //
      BYTE*    out, //out
      const TPM_AUTHDATA* usage_auth,
      TPM_AUTH_SESSION* auth //in, out
      )
{
   TPM_BEGIN(TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_UnBind);
   TPM_AUTH_BEGIN();

   TPM_AUTH_HASH();

   ptr = pack_TPM_KEY_HANDLE(ptr, keyHandle);

   TPM_AUTH_SKIP();

   ptr = pack_UINT32(ptr, ilen);
   ptr = pack_BUFFER(ptr, in, ilen);

   TPM_AUTH_HASH();

   TPM_AUTH1_GEN(usage_auth, auth);
   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   ptr = unpack_UINT32(ptr, olen);
   if(*olen > ilen) {
      vtpmlogerror(VTPM_LOG_TPM, "Output length < input length!\n");
      status = TPM_IOERROR;
      goto abort_egress;
   }
   ptr = unpack_BUFFER(ptr, out, *olen);

   TPM_AUTH_HASH();

   TPM_AUTH1_VERIFY(usage_auth, auth);

abort_egress:
egress:
   TPM_AUTH_ERR_CHECK(auth);
   return status;
}

TPM_RESULT TPM_CreateWrapKey(
      TPM_KEY_HANDLE  hWrappingKey,  // in
      const TPM_AUTHDATA* osapSharedSecret,
      const TPM_AUTHDATA* dataUsageAuth, //in
      const TPM_AUTHDATA* dataMigrationAuth, //in
      TPM_KEY*     key, //in, out
      TPM_AUTH_SESSION*   pAuth)    // in, out
{
   int keyAlloced = 0;
   TPM_BEGIN(TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_CreateWrapKey);
   TPM_AUTH_BEGIN();

   TPM_AUTH_HASH();

   ptr = pack_TPM_KEY_HANDLE(ptr, hWrappingKey);

   TPM_AUTH_SKIP();

   //Encrypted auths
   xorEncrypt(osapSharedSecret, &pAuth->NonceEven,
         dataUsageAuth, ptr,
         dataMigrationAuth, ptr + sizeof(TPM_ENCAUTH));
   ptr += sizeof(TPM_ENCAUTH) * 2;

   ptr = pack_TPM_KEY(ptr, key);

   TPM_AUTH_HASH();

   TPM_AUTH1_GEN(osapSharedSecret, pAuth);
   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   keyAlloced = 1;
   ptr = unpack_TPM_KEY(ptr, key, UNPACK_ALLOC);

   TPM_AUTH_HASH();

   TPM_AUTH1_VERIFY(osapSharedSecret, pAuth);

   goto egress;
abort_egress:
   if(keyAlloced) {
      free_TPM_KEY(key);
   }
egress:
   TPM_AUTH_ERR_CHECK(pAuth);
   return status;
}

TPM_RESULT TPM_LoadKey(
      TPM_KEY_HANDLE  parentHandle, //
      const TPM_KEY* key, //in
      TPM_HANDLE*  keyHandle,    // out
      const TPM_AUTHDATA* usage_auth,
      TPM_AUTH_SESSION* auth)
{
   TPM_BEGIN(TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_LoadKey);
   TPM_AUTH_BEGIN();

   TPM_AUTH_HASH();

   ptr = pack_TPM_KEY_HANDLE(ptr, parentHandle);

   TPM_AUTH_SKIP();

   ptr = pack_TPM_KEY(ptr, key);

   TPM_AUTH_HASH();

   TPM_AUTH1_GEN(usage_auth, auth);
   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();
   TPM_AUTH_VERIFY_BEGIN();

   ptr = unpack_UINT32(ptr, keyHandle);

   TPM_AUTH_HASH();

   TPM_AUTH1_VERIFY(usage_auth, auth);

   vtpmloginfo(VTPM_LOG_TPM, "Key Handle: 0x%x opened by TPM_LoadKey\n", *keyHandle);

abort_egress:
   TPM_AUTH_ERR_CHECK(auth);
   return status;
}

TPM_RESULT TPM_EvictKey( TPM_KEY_HANDLE  hKey)  // in
{
   if(hKey == 0) {
      return TPM_SUCCESS;
   }

   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_EvictKey);

   ptr = pack_TPM_KEY_HANDLE(ptr, hKey);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   vtpmloginfo(VTPM_LOG_TPM, "Key handle: 0x%x closed by TPM_EvictKey\n", hKey);

abort_egress:
   return status;
}

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle,
      TPM_RESOURCE_TYPE rt) {
   if(handle == 0) {
      return TPM_SUCCESS;
   }

   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_FlushSpecific);

   ptr = pack_TPM_HANDLE(ptr, handle);
   ptr = pack_TPM_RESOURCE_TYPE(ptr, rt);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

abort_egress:
   return status;
}

TPM_RESULT TPM_GetRandom( UINT32*    bytesRequested, // in, out
      BYTE*    randomBytes) // out
{
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_GetRandom);

   // check input params
   if (bytesRequested == NULL || randomBytes == NULL){
      return TPM_BAD_PARAMETER;
   }

   ptr = pack_UINT32(ptr, *bytesRequested);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   ptr = unpack_UINT32(ptr, bytesRequested);
   ptr = unpack_BUFFER(ptr, randomBytes, *bytesRequested);

abort_egress:
   return status;
}


TPM_RESULT TPM_ReadPubek(
      TPM_PUBKEY* pubEK //out
      )
{
   BYTE* antiReplay = NULL;
   BYTE* kptr = NULL;
   BYTE digest[TPM_DIGEST_SIZE];
   sha1_context ctx;

   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_ReadPubek);

   //antiReplay nonce
   vtpmmgr_rand(ptr, TPM_DIGEST_SIZE);
   antiReplay = ptr;
   ptr += TPM_DIGEST_SIZE;

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   //unpack and allocate the key
   kptr = ptr;
   ptr = unpack_TPM_PUBKEY(ptr, pubEK, UNPACK_ALLOC);

   //Verify the checksum
   sha1_starts(&ctx);
   sha1_update(&ctx, kptr, ptr - kptr);
   sha1_update(&ctx, antiReplay, TPM_DIGEST_SIZE);
   sha1_finish(&ctx, digest);

   //ptr points to the checksum computed by TPM
   if(memcmp(digest, ptr, TPM_DIGEST_SIZE)) {
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


TPM_RESULT TPM_SaveState(void)
{
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_SaveState);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

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
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_GetCapability);

   ptr = pack_TPM_CAPABILITY_AREA(ptr, capArea);
   ptr = pack_UINT32(ptr, subCapSize);
   ptr = pack_BUFFER(ptr, subCap, subCapSize);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   ptr = unpack_UINT32(ptr, respSize);
   ptr = unpack_ALLOC(ptr, resp, *respSize);

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
   TPM_BEGIN(TPM_TAG_RQU_COMMAND, TPM_ORD_CreateEndorsementKeyPair);

   //Make anti replay nonce
   vtpmmgr_rand(antiReplay.nonce, sizeof(antiReplay.nonce));

   ptr = pack_TPM_NONCE(ptr, &antiReplay);
   ptr = pack_TPM_KEY_PARMS(ptr, keyInfo);

   TPM_TRANSMIT();
   TPM_UNPACK_VERIFY();

   sha1_starts(&ctx);

   kptr = ptr;
   ptr = unpack_TPM_PUBKEY(ptr, pubEK, UNPACK_ALLOC);

   /* Hash the pub key blob */
   sha1_update(&ctx, kptr, ptr - kptr);
   ptr = unpack_TPM_DIGEST(ptr, &checksum);

   sha1_update(&ctx, antiReplay.nonce, sizeof(antiReplay.nonce));

   sha1_finish(&ctx, hash.digest);
   if(memcmp(checksum.digest, hash.digest, TPM_DIGEST_SIZE)) {
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
