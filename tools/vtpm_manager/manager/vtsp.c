// ===================================================================
// 
// Copyright (c) 2005, Intel Corp.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions 
// are met:
//
//   * Redistributions of source code must retain the above copyright 
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above 
//     copyright notice, this list of conditions and the following 
//     disclaimer in the documentation and/or other materials provided 
//     with the distribution.
//   * Neither the name of Intel Corporation nor the names of its 
//     contributors may be used to endorse or promote products derived
//     from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.
// ===================================================================
// 
// vtsp.c
// 
//  Higher level interface to TCS for use in service.
//
// ==================================================================

#include <string.h>
#include "tcg.h"
#include "tcs.h"
#include "bsg.h"
#include "log.h"
#include "crypto.h"
#include "vtsp.h"
#include "buffer.h"

#define  RSA_KEY_SIZE 0x0800

/***********************************************************************************
 * GenerateAuth: Generate authorization info to be sent back to application
 *
 * Parameters: outParamDigestText  The concatenation of output parameters to be SHA1ed
 *    outParamDigestTextSize Size of inParamDigestText
 *    HMACkey     Key to be used for HMACing
 *          For OIAP use key.authUsage or PersistStore.ownerAuth
 *          For OSAP use shared secret
 *    pAuth     Authorization information from the application
 *
 * Return:  TPM_SUCCESS   Authorization data created
 *    TPM_AUTHFAIL   Invalid (NULL) HMACkey presented for OSAP
 *************************************************************************************/
TPM_RESULT GenerateAuth( /*[IN]*/ const BYTE *inParamDigestText,
			 /*[IN]*/ UINT32 inParamDigestTextSize,
			 /*[IN]*/ const TPM_SECRET *HMACkey,  
			 /*[IN,OUT]*/ TCS_AUTH *auth) {
    
  if (inParamDigestText == NULL || auth == NULL) 
    return (TPM_AUTHFAIL);
  else {
    
    //Generate new OddNonce
    Crypto_GetRandom(auth->NonceOdd.nonce, sizeof(TPM_NONCE));
    
    // Create SHA1 inParamDigest
    TPM_DIGEST inParamDigest;
    Crypto_SHA1Full(inParamDigestText, inParamDigestTextSize, (BYTE *) &inParamDigest);
    
    // Create HMAC text. (Concat inParamsDigest with inAuthSetupParams).
    BYTE hmacText[sizeof(TPM_DIGEST) + (2 * sizeof(TPM_NONCE)) + sizeof(BOOL)];
    
    BSG_PackList(   hmacText, 4, 
		    BSG_TPM_DIGEST, &inParamDigest,
		    BSG_TPM_NONCE, &(auth->NonceEven),
		    BSG_TPM_NONCE, &(auth->NonceOdd), 
		    BSG_TYPE_BOOL, &(auth->fContinueAuthSession) );
    
    Crypto_HMAC((BYTE *) hmacText, sizeof(hmacText), (BYTE *) HMACkey, sizeof(TPM_DIGEST), (BYTE *) &(auth->HMAC));
    
    return(TPM_SUCCESS);
    
  }
}

/***********************************************************************************
 * VerifyAuth: Verify the authdata for a command requiring authorization
 *
 * Parameters: inParamDigestText  The concatenation of parameters to be SHA1ed
 *    inParamDigestTextSize Size of inParamDigestText
 *    authDataUsage   AuthDataUsage for the Entity being used
 *          Key->authDataUsage or TPM_AUTH_OWNER
 *    HMACkey     Key to be used for HMACing
 *          For OIAP use key.authUsage or PersistStore.ownerAuth
 *          For OSAP use NULL (It will be aquired from the Auth Session)
 *          If unknown (default), assume OIAP
 *    sessionAuth    A TCS_AUTH info for the session
 *    pAuth     Authorization information from the application
 *              hContext        If specified, on failed Auth, VerifyAuth will
 *                                      generate a new OIAP session in place of themselves
 *                                      destroyed session.
 *
 * Return:  TPM_SUCCESS   Authorization Verified
 *    TPM_AUTHFAIL   Authorization Failed
 *    TPM_FAIL    Failure during SHA1 routines
 *************************************************************************************/
TPM_RESULT VerifyAuth( /*[IN]*/ const BYTE *outParamDigestText,
		       /*[IN]*/ UINT32 outParamDigestTextSize,
		       /*[IN]*/ const TPM_SECRET *HMACkey,  
		       /*[IN,OUT]*/ TCS_AUTH *auth,
		       /*[IN]*/  TCS_CONTEXT_HANDLE hContext) {
  if (outParamDigestText == NULL || auth == NULL) 
    return (TPM_AUTHFAIL);
  
  
  // Create SHA1 inParamDigest
  TPM_DIGEST outParamDigest;
  Crypto_SHA1Full(outParamDigestText, outParamDigestTextSize, (BYTE *) &outParamDigest);
  
  // Create HMAC text. (Concat inParamsDigest with inAuthSetupParams).
  TPM_DIGEST hm;
  BYTE hmacText[sizeof(TPM_DIGEST) + (2 * sizeof(TPM_NONCE)) + sizeof(BOOL)];
  
  BSG_PackList(   hmacText, 4, 
		  BSG_TPM_DIGEST, &outParamDigest,
		  BSG_TPM_NONCE, &(auth->NonceEven),
		  BSG_TPM_NONCE, &(auth->NonceOdd), 
		  BSG_TYPE_BOOL, &(auth->fContinueAuthSession) );
  
  Crypto_HMAC((BYTE *) hmacText, sizeof(hmacText),
	      (BYTE *) HMACkey, sizeof(TPM_DIGEST), (BYTE *) &hm);
    
  // Compare correct HMAC with provided one.
  if (memcmp (&hm, &(auth->HMAC), sizeof(TPM_DIGEST)) == 0) { // 0 indicates equality
    if (!auth->fContinueAuthSession) 
      vtpmloginfo(VTPM_LOG_VTSP_DEEP, "Auth Session: 0x%x closed by TPM by fContinue=0.\n", auth->AuthHandle);
    
    return (TPM_SUCCESS);
  } else {
    // If specified, reconnect the OIAP session.
    // NOTE: This only works for TCS's that never have a 0 context. 
    if (hContext) {
      vtpmloginfo(VTPM_LOG_VTSP_DEEP, "Auth Session: 0x%x closed by TPM due to failure.\n", auth->AuthHandle);
      VTSP_OIAP( hContext, auth);
    }
    return (TPM_AUTHFAIL);
  }
}

TPM_RESULT VTSP_OIAP(const TCS_CONTEXT_HANDLE hContext,
		     TCS_AUTH *auth) {
  
  vtpmloginfo(VTPM_LOG_VTSP, "OIAP.\n");
  TPM_RESULT status = TPM_SUCCESS;                           
  TPMTRYRETURN( TCSP_OIAP(hContext,
			  &auth->AuthHandle,
			  &auth->NonceEven) );

  memset(&auth->HMAC, 0, sizeof(TPM_DIGEST));
  auth->fContinueAuthSession = FALSE;

  vtpmloginfo(VTPM_LOG_VTSP_DEEP, "Auth Session: 0x%x opened by TPM_OIAP.\n", auth->AuthHandle);
  goto egress;
  
 abort_egress:
  
 egress:
  
  return status;
}

TPM_RESULT VTSP_OSAP(const TCS_CONTEXT_HANDLE hContext,
		     const TPM_ENTITY_TYPE entityType,
		     const UINT32 entityValue,
		     const TPM_AUTHDATA *usageAuth,
		     TPM_SECRET *sharedSecret, 
		     TCS_AUTH *auth) {
  
  vtpmloginfo(VTPM_LOG_VTSP, "OSAP.\n");
  TPM_RESULT status = TPM_SUCCESS;
  TPM_NONCE nonceEvenOSAP, nonceOddOSAP;
  
  Crypto_GetRandom((BYTE *) &nonceOddOSAP, sizeof(TPM_NONCE) ); 
  
  TPMTRYRETURN( TCSP_OSAP(    hContext,
			      entityType,
			      entityValue, 
			      nonceOddOSAP,
			      &auth->AuthHandle, 
			      &auth->NonceEven, 
			      &nonceEvenOSAP) );
  
  // Calculating Session Secret
  BYTE sharedSecretText[TPM_DIGEST_SIZE * 2];
  
  BSG_PackList(  sharedSecretText, 2,
		 BSG_TPM_NONCE, &nonceEvenOSAP,
		 BSG_TPM_NONCE, &nonceOddOSAP);
  
  Crypto_HMAC(sharedSecretText, sizeof(sharedSecretText), (BYTE *) usageAuth, TPM_DIGEST_SIZE, (BYTE *) sharedSecret);       

  memset(&auth->HMAC, 0, sizeof(TPM_DIGEST));
  auth->fContinueAuthSession = FALSE;
   
  vtpmloginfo(VTPM_LOG_VTSP_DEEP, "Auth Session: 0x%x opened by TPM_OSAP.\n", auth->AuthHandle);

  goto egress;
  
 abort_egress:
  
 egress:
  
  return status;
}


TPM_RESULT VTSP_TerminateHandle(const TCS_CONTEXT_HANDLE hContext,
                                const TCS_AUTH *auth) {

  vtpmloginfo(VTPM_LOG_VTSP, "Terminate Handle.\n");
  TPM_RESULT status = TPM_SUCCESS;
  TPMTRYRETURN( TCSP_TerminateHandle(hContext, auth->AuthHandle) );

  vtpmloginfo(VTPM_LOG_VTSP_DEEP, "Auth Session: 0x%x closed by TPM_TerminateHandle.\n", auth->AuthHandle);
  goto egress;

 abort_egress:

 egress:

  return status;
}


TPM_RESULT VTSP_ReadPubek(   const TCS_CONTEXT_HANDLE hContext,
                             CRYPTO_INFO *crypto_info) {
  
  TPM_RESULT status;
  TPM_NONCE antiReplay;
  TPM_DIGEST   checksum;
  BYTE *pubEKtext;
  UINT32 pubEKtextsize;
  
  vtpmloginfo(VTPM_LOG_VTSP, "Reading Public EK.\n");
  
  // GenerateAuth new nonceOdd    
  Crypto_GetRandom(&antiReplay, sizeof(TPM_NONCE) );
  
  
  TPMTRYRETURN( TCSP_ReadPubek(  hContext,
				 antiReplay,
				 &pubEKtextsize,
				 &pubEKtext,
				 &checksum) );
  
  
  // Extract the remaining output parameters
  TPM_PUBKEY pubEK;
  
  BSG_Unpack(BSG_TPM_PUBKEY, pubEKtext, (BYTE *) &pubEK);
  
  // Build CryptoInfo for the bindingKey
  TPM_RSA_KEY_PARMS rsaKeyParms;
  
  BSG_Unpack(BSG_TPM_RSA_KEY_PARMS, 
	     pubEK.algorithmParms.parms, 
	     &rsaKeyParms);
  
  Crypto_RSABuildCryptoInfoPublic(rsaKeyParms.exponentSize, 
				  rsaKeyParms.exponent, 
				  pubEK.pubKey.keyLength, 
				  pubEK.pubKey.key, 
				  crypto_info);
    
  // Destroy rsaKeyParms
  BSG_Destroy(BSG_TPM_RSA_KEY_PARMS, &rsaKeyParms);

  // Set encryption scheme
  crypto_info->encScheme = CRYPTO_ES_RSAESOAEP_SHA1_MGF1;
  //crypto_info->encScheme = pubEK.algorithmParms.encScheme;
  crypto_info->algorithmID = pubEK.algorithmParms.algorithmID;
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  return status;
}

TPM_RESULT VTSP_TakeOwnership(   const TCS_CONTEXT_HANDLE hContext,
                                 const TPM_AUTHDATA *ownerAuth, 
                                 const TPM_AUTHDATA *srkAuth,
                                 CRYPTO_INFO *ek_cryptoInfo,
                                 TCS_AUTH *auth) {
  
  vtpmloginfo(VTPM_LOG_VTSP, "Taking Ownership of TPM.\n");
  
  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_TakeOwnership;
  TPM_PROTOCOL_ID proto_id = TPM_PID_OWNER;
  BYTE *new_srk;
  
  BYTE *paramText;        // Digest to make Auth.
  UINT32 paramTextSize;
  
  // vars for srkpubkey parameter
  TPM_KEY srkPub;
  TPM_KEY_PARMS srkKeyInfo = {TPM_ALG_RSA, TPM_ES_RSAESOAEP_SHA1_MGF1, TPM_SS_NONE, 12, 0};
  BYTE srkRSAkeyInfo[12] = { 0x00, 0x00, (RSA_KEY_SIZE >> 8), 0x00,   0x00, 0x00, 0x00, 0x02,   0x00, 0x00, 0x00, 0x00};
  srkKeyInfo.parms = (BYTE *) &srkRSAkeyInfo;
  
  struct pack_buf_t srkText;
  
  //These values are accurate for an enc(AuthData).
  struct pack_buf_t encOwnerAuth, encSrkAuth;
  
  encOwnerAuth.data = (BYTE *)malloc(sizeof(BYTE) * 256);
  encSrkAuth.data = (BYTE *)malloc(sizeof(BYTE) * 256);
  
  if (encOwnerAuth.data == NULL || encSrkAuth.data == NULL) {
    vtpmloginfo(VTPM_LOG_VTSP, "Could not malloc encrypted auths.\n");
    status = TPM_RESOURCES;
    goto abort_egress;
  }
  
  Crypto_RSAEnc(ek_cryptoInfo, sizeof(TPM_SECRET), (BYTE *) ownerAuth, &encOwnerAuth.size, encOwnerAuth.data);
  Crypto_RSAEnc(ek_cryptoInfo, sizeof(TPM_SECRET), (BYTE *) srkAuth, &encSrkAuth.size, encSrkAuth.data);
  
  
  // Build srk public key struct
  srkPub.ver = TPM_STRUCT_VER_1_1;
  srkPub.keyUsage = TPM_KEY_STORAGE;
  srkPub.keyFlags = 0x00;
  srkPub.authDataUsage = TPM_AUTH_ALWAYS;
  memcpy(&srkPub.algorithmParms, &srkKeyInfo, sizeof(TPM_KEY_PARMS));
  srkPub.PCRInfoSize = 0;
  srkPub.PCRInfo = 0;
  srkPub.pubKey.keyLength= 0;
  srkPub.encDataSize = 0;
  
  srkText.data = (BYTE *) malloc(sizeof(BYTE) * TCPA_MAX_BUFFER_LENGTH);
  srkText.size = BSG_Pack(BSG_TPM_KEY, (BYTE *) &srkPub, srkText.data);
  
  paramText = (BYTE *) malloc(sizeof(BYTE) *  TCPA_MAX_BUFFER_LENGTH);
  
  paramTextSize = BSG_PackList(paramText, 5,
			       BSG_TPM_COMMAND_CODE,&command,
			       BSG_TPM_PROTOCOL_ID, &proto_id,
			       BSG_TPM_SIZE32_DATA, &encOwnerAuth,
			       BSG_TPM_SIZE32_DATA, &encSrkAuth,
			       BSG_TPM_KEY, &srkPub);
  
  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize, ownerAuth, auth) );
  
  new_srk = srkText.data;
  TPMTRYRETURN( TCSP_TakeOwnership ( hContext,
				     proto_id,
				     encOwnerAuth.size, 
				     encOwnerAuth.data,
				     encSrkAuth.size,
				     encSrkAuth.data,
				     &srkText.size,
				     &new_srk, 
				     auth ) );
  
  
  paramTextSize = BSG_PackList(paramText, 2, 
			       BSG_TPM_RESULT, &status,
			       BSG_TPM_COMMAND_CODE, &command);
  memcpy(paramText + paramTextSize, new_srk, srkText.size);
  paramTextSize += srkText.size;
  
  
  TPMTRYRETURN( VerifyAuth(  paramText, paramTextSize,
			     ownerAuth, auth, 
			     hContext) );
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  free(srkText.data);
  free(encSrkAuth.data);
  free(encOwnerAuth.data);
  free(paramText);
  
  TCS_FreeMemory(hContext, new_srk);
  
  return status;
}

TPM_RESULT VTSP_DisablePubekRead( const TCS_CONTEXT_HANDLE    hContext,
                                  const TPM_AUTHDATA          *ownerAuth, 
                                  TCS_AUTH                    *auth) {
  
  vtpmloginfo(VTPM_LOG_VTSP, "Disabling Pubek Read.\n");
  
  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_DisablePubekRead;
  
  BYTE *paramText;        // Digest to make Auth.
  UINT32 paramTextSize;
    
  paramText = (BYTE *) malloc(sizeof(BYTE) * TCPA_MAX_BUFFER_LENGTH);
  
  paramTextSize = BSG_PackList(paramText, 1,
			       BSG_TPM_COMMAND_CODE, &command);
  
  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
			      ownerAuth, auth) );
  
  // Call TCS
  TPMTRYRETURN( TCSP_DisablePubekRead ( hContext, // in
                                        auth) );
  
  // Verify Auth
  paramTextSize = BSG_PackList(paramText, 2,
			       BSG_TPM_RESULT, &status,
			       BSG_TPM_COMMAND_CODE, &command);
  
  TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
			    ownerAuth, auth, 
			    hContext) );
  goto egress;
  
 abort_egress:
 egress:
  free(paramText);
  return status;
}

TPM_RESULT VTSP_CreateWrapKey(  const TCS_CONTEXT_HANDLE hContext,
                                const TPM_KEY_USAGE      usage,
                                const TPM_AUTHDATA       *newKeyAuth,
                                const TCS_KEY_HANDLE     parentHandle, 
                                const TPM_AUTHDATA       *osapSharedSecret,
                                buffer_t                 *pubKeyBuf,
                                TCS_AUTH                 *auth) {
  
  int i;
  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_CreateWrapKey;
  
  vtpmloginfo(VTPM_LOG_VTSP, "Creating new key of type %d.\n", usage);
  
  // vars for Calculate encUsageAuth
  BYTE *paramText;      
  UINT32 paramTextSize;
  
  // vars for Calculate encUsageAuth
  BYTE XORbuffer[sizeof(TPM_SECRET) + sizeof(TPM_NONCE)];
  TPM_DIGEST XORKey1;
  UINT32 XORbufferSize;
  TPM_SECRET encUsageAuth, encMigrationAuth;
  
  // vars for Flatten newKey prototype
  BYTE *flatKey = (BYTE *) malloc(sizeof(BYTE) *  TCPA_MAX_BUFFER_LENGTH);
  UINT32 flatKeySize = TCPA_MAX_BUFFER_LENGTH;                                    
  struct pack_buf_t newKeyText;
  
  // Fill in newKey
  TPM_KEY newKey;
  
  BYTE RSAkeyInfo[12] = { 0x00, 0x00, (RSA_KEY_SIZE >> 8), 0x00,   0x00, 0x00, 0x00, 0x02,   0x00, 0x00, 0x00, 0x00};
  newKey.algorithmParms.algorithmID = TPM_ALG_RSA;
  newKey.algorithmParms.parms = (BYTE *) &RSAkeyInfo;
  newKey.algorithmParms.parmSize = 12;
  
  switch (usage) {
  case TPM_KEY_SIGNING:
    vtpmloginfo(VTPM_LOG_VTSP, "Creating Signing Key...\n");
    newKey.keyUsage = TPM_KEY_SIGNING;
    newKey.algorithmParms.encScheme = TPM_ES_NONE;
    newKey.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    break;
  case TPM_KEY_STORAGE:
    vtpmloginfo(VTPM_LOG_VTSP, "Creating Storage Key...\n");
    newKey.keyUsage = TPM_KEY_STORAGE;
    newKey.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
    newKey.algorithmParms.sigScheme = TPM_SS_NONE;
    break;
  case TPM_KEY_BIND:
    vtpmloginfo(VTPM_LOG_VTSP, "Creating Binding Key...\n");
    newKey.keyUsage = TPM_KEY_BIND;
    newKey.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
    newKey.algorithmParms.sigScheme = TPM_SS_NONE;
    break;
  default:
    vtpmloginfo(VTPM_LOG_VTSP, "Cannot create key. Invalid Key Type.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
  
  
  newKey.ver = TPM_STRUCT_VER_1_1;
  
  newKey.keyFlags = 0;
  newKey.authDataUsage = TPM_AUTH_ALWAYS;
  newKey.pubKey.keyLength= 0;
  newKey.encDataSize = 0;
  newKey.encData = NULL;
  
  // FIXME: Support PCR bindings
  newKey.PCRInfoSize = 0;
  newKey.PCRInfo = NULL;
  
  // Calculate encUsageAuth                                    
  XORbufferSize = BSG_PackList(  XORbuffer, 2, 
				 BSG_TPM_SECRET, osapSharedSecret,
				 BSG_TPM_NONCE, &auth->NonceEven);
  Crypto_SHA1Full(XORbuffer, XORbufferSize, (BYTE *) &XORKey1);
  
  // FIXME: No support for migratable keys.
  for (i=0; i < TPM_DIGEST_SIZE; i++) 
    ((BYTE *) &encUsageAuth)[i] = ((BYTE *) &XORKey1)[i] ^ ((BYTE *) newKeyAuth)[i];
  
  // Flatten newKey prototype
  flatKeySize = BSG_Pack(BSG_TPM_KEY, (BYTE *) &newKey, flatKey);
  newKeyText.data = flatKey;
  newKeyText.size = flatKeySize;
  
  // Generate HMAC
  paramText = (BYTE *) malloc(sizeof(BYTE) * TCPA_MAX_BUFFER_LENGTH);
  
  paramTextSize = BSG_PackList(paramText, 3,
			       BSG_TPM_COMMAND_CODE, &command,
			       BSG_TPM_AUTHDATA, &encUsageAuth,
			       BSG_TPM_AUTHDATA, &encMigrationAuth);
  memcpy(paramText + paramTextSize, newKeyText.data, newKeyText.size);
  paramTextSize += newKeyText.size;
  
  
  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
			      osapSharedSecret, auth) );
  
  // Call TCS
  TPMTRYRETURN( TCSP_CreateWrapKey(  hContext, 
				     parentHandle,
				     encUsageAuth,
				     encMigrationAuth,
				     &newKeyText.size,
				     &newKeyText.data,
				     auth) );
  
  // Verify Auth
  paramTextSize = BSG_PackList(paramText, 2,
			       BSG_TPM_RESULT, &status,
			       BSG_TPM_COMMAND_CODE, &command);
  memcpy(paramText + paramTextSize, newKeyText.data, newKeyText.size);
  paramTextSize += newKeyText.size;
  
  TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
			    osapSharedSecret, auth, 0) );
  
  // Unpack/return key structure
  TPMTRYRETURN(buffer_init(pubKeyBuf, 0, 0) );
  TPMTRYRETURN(buffer_append_raw(pubKeyBuf, newKeyText.size, newKeyText.data) );
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  free(flatKey);
  free(paramText);
  TCS_FreeMemory(hContext, newKeyText.data);
  
  return status;
}

TPM_RESULT VTSP_LoadKey(const TCS_CONTEXT_HANDLE    hContext,
                        const TCS_KEY_HANDLE        hUnwrappingKey,
                        const buffer_t              *rgbWrappedKeyBlob,
                        const TPM_AUTHDATA          *parentAuth,
                        TPM_HANDLE                  *newKeyHandle,
                        TCS_AUTH                    *auth,
                        CRYPTO_INFO                 *cryptoinfo,
                        const BOOL                  skipTPMLoad) { 
  
  
  vtpmloginfo(VTPM_LOG_VTSP, "Loading Key %s.\n", (!skipTPMLoad ? "into TPM" : "only into memory"));
  
  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_LoadKey;

  BYTE *paramText=NULL;        // Digest to make Auth.
  UINT32 paramTextSize;

  // SkipTPMLoad stops key from being loaded into TPM, but still generates CRYPTO_INFO for it
  if (! skipTPMLoad) { 
  
    if ((rgbWrappedKeyBlob == NULL) || (parentAuth == NULL) || 
        (newKeyHandle==NULL) || (auth==NULL)) {
      status = TPM_BAD_PARAMETER;
      goto abort_egress;
    }
  
    // Generate Extra TCS Parameters
    TPM_HANDLE phKeyHMAC;
  
    paramText = (BYTE *) malloc(sizeof(BYTE) *  TCPA_MAX_BUFFER_LENGTH);
  
    paramTextSize = BSG_PackList(paramText, 1,
  			         BSG_TPM_COMMAND_CODE, &command);
  
    memcpy(paramText + paramTextSize, rgbWrappedKeyBlob->bytes, buffer_len(rgbWrappedKeyBlob));
    paramTextSize += buffer_len(rgbWrappedKeyBlob);
  
    TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
			      parentAuth, auth) );
  
    // Call TCS
    TPMTRYRETURN( TCSP_LoadKeyByBlob(  hContext,
				       hUnwrappingKey,
				       buffer_len(rgbWrappedKeyBlob),
				       rgbWrappedKeyBlob->bytes,
				       auth,
				       newKeyHandle,
				       &phKeyHMAC) );
  
    // Verify Auth
    paramTextSize = BSG_PackList(paramText, 3,
			         BSG_TPM_RESULT, &status,
			         BSG_TPM_COMMAND_CODE, &command,
			         BSG_TPM_HANDLE, newKeyHandle);
  
    TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
			      parentAuth, auth, 
			      hContext) );
  } 
  
  // Build cryptoinfo structure for software crypto function. 
  if (cryptoinfo != NULL) {
    TPM_KEY newKey;
    
    // Unpack/return key structure
    BSG_Unpack(BSG_TPM_KEY, rgbWrappedKeyBlob->bytes , &newKey);
    TPM_RSA_KEY_PARMS rsaKeyParms;
    
    BSG_Unpack(BSG_TPM_RSA_KEY_PARMS, 
	       newKey.algorithmParms.parms, 
	       &rsaKeyParms);
    
    Crypto_RSABuildCryptoInfoPublic(rsaKeyParms.exponentSize, 
				    rsaKeyParms.exponent, 
				    newKey.pubKey.keyLength, 
				    newKey.pubKey.key, 
				    cryptoinfo);
    
    // Destroy rsaKeyParms
    BSG_Destroy(BSG_TPM_RSA_KEY_PARMS, &rsaKeyParms);
    
    // Set encryption scheme
    cryptoinfo->encScheme = CRYPTO_ES_RSAESOAEP_SHA1_MGF1;
  }
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  free(paramText);
  return status;
}

TPM_RESULT VTSP_Unbind( const TCS_CONTEXT_HANDLE    hContext,
                        const TPM_KEY_HANDLE        key_handle,
                        const buffer_t              *bound_data,
                        const TPM_AUTHDATA          *usage_auth,
                        buffer_t                    *clear_data,
                        TCS_AUTH                    *auth) {
  
  vtpmloginfo(VTPM_LOG_VTSP, "Unbinding %d bytes of data.\n", buffer_len(bound_data));
  
  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_UnBind;
  
  BYTE *paramText;        // Digest to make Auth.
  UINT32 paramTextSize;
  
  // Generate Extra TCS Parameters
  struct pack_buf_t clear_data32;
  BYTE *clear_data_text;
  UINT32 clear_data_size;
  
  struct pack_buf_t bound_data32 = {bound_data->size, bound_data->bytes};
  
  paramText = (BYTE *) malloc(sizeof(BYTE) * TCPA_MAX_BUFFER_LENGTH);
  
  paramTextSize = BSG_PackList(paramText, 2,
			       BSG_TPM_COMMAND_CODE, &command,
			       BSG_TPM_SIZE32_DATA, &bound_data32);
  
  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
			      usage_auth, auth) );
  
  // Call TCS
  TPMTRYRETURN( TCSP_UnBind( hContext,
			     key_handle,
			     buffer_len(bound_data),
			     bound_data->bytes,
			     auth,
			     &clear_data_size,
			     &clear_data_text) );
  
  
  // Verify Auth
  clear_data32.size = clear_data_size;
  clear_data32.data = clear_data_text;
  paramTextSize = BSG_PackList(paramText, 3,
			       BSG_TPM_RESULT, &status,
			       BSG_TPM_COMMAND_CODE, &command,
			       BSG_TPM_SIZE32_DATA, &clear_data32);
  
  TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
			    usage_auth, auth, 
			    hContext) );
  
  // Unpack/return key structure
  TPMTRYRETURN(buffer_init(clear_data, 0, 0));
  TPMTRYRETURN(buffer_append_raw (clear_data, clear_data_size, clear_data_text) );
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  free(paramText);
  TCS_FreeMemory(hContext, clear_data_text);
  
  return status;
}

TPM_RESULT VTSP_Bind(   CRYPTO_INFO *cryptoInfo, 
			const buffer_t *inData, 
			buffer_t *outData)               
{
  vtpmloginfo(VTPM_LOG_VTSP, "Binding %d bytes of data.\n", buffer_len(inData));
  TPM_RESULT status = TPM_SUCCESS;
  TPM_BOUND_DATA boundData;
  UINT32 i;
  
  // Fill boundData's accessory information
  boundData.ver = TPM_STRUCT_VER_1_1;
  boundData.payload = TPM_PT_BIND;
  boundData.payloadData = inData->bytes;
  
  // Pack boundData before encryption
  BYTE* flatBoundData = (BYTE *)malloc(sizeof(BYTE) * 
				       (sizeof(TPM_VERSION) +
					sizeof(TPM_PAYLOAD_TYPE) +
					buffer_len(inData)));
  if (flatBoundData == NULL) {
    return TPM_NOSPACE;
  }
  UINT32 flatBoundDataSize = 0;
  flatBoundDataSize = BSG_PackList(  flatBoundData, 2, 
				     BSG_TPM_VERSION, &boundData.ver, 
				     BSG_TYPE_BYTE, &boundData.payload);
  
  memcpy(flatBoundData+flatBoundDataSize, inData->bytes, buffer_len(inData));
  flatBoundDataSize += buffer_len(inData);
  
  BYTE out_tmp[RSA_KEY_SIZE/8]; // RSAEnc does not do blocking, So this is what will come out.
  UINT32 out_tmp_size;
  
  // Encrypt flatBoundData
  TPMTRY(TPM_ENCRYPT_ERROR, Crypto_RSAEnc( cryptoInfo, 
                                           flatBoundDataSize, 
                                           flatBoundData, 
                                           &out_tmp_size, 
                                           out_tmp) );
  
  if (out_tmp_size > RSA_KEY_SIZE/8) {
    // The result of RSAEnc should be a fixed size based on key size.
    vtpmlogerror(VTPM_LOG_VTSP, "Enc buffer just overflowed.\n");
  }
  
  buffer_init(outData, 0, NULL);
  buffer_append_raw(outData, out_tmp_size, out_tmp);
  
  vtpmloginfo(VTPM_LOG_TXDATA, "Bind Generated[%d] = 0x", out_tmp_size);
  for(i = 0 ; i < out_tmp_size ; i++) {
    vtpmloginfomore(VTPM_LOG_TXDATA, "%2.2x ", out_tmp[i]);
  }
  vtpmloginfomore(VTPM_LOG_TXDATA, "\n");

  goto egress;
  abort_egress: 
  egress:
 
  // Free flatBoundData
  free(flatBoundData);
  
  return TPM_SUCCESS;
}

TPM_RESULT VTSP_Seal(const TCS_CONTEXT_HANDLE    hContext,
                     const TPM_KEY_HANDLE        keyHandle,
                     const TPM_AUTHDATA          *sealDataAuth,
                     const TPM_PCR_COMPOSITE     *pcrComp,
                     const buffer_t              *inData,
                     TPM_STORED_DATA             *sealedData,                                   
                     const TPM_SECRET            *osapSharedSecret,
                     TCS_AUTH                    *auth) {

  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_Seal;

  BYTE *paramText;        // Digest to make Auth.
  UINT32 paramTextSize;

  // Generate PCR_Info Struct from Comp
  TPM_PCR_INFO pcrInfo;
  UINT32 pcrInfoSize, flatpcrSize;
  BYTE flatpcr[3 +                          // PCR_Select = 3 1 byte banks
               sizeof(UINT16) +             //              2 byte UINT16
               sizeof(UINT32) +             // PCR_Comp   = 4 byte UINT32
               24 * sizeof(TPM_PCRVALUE) ]; //              up to 24 PCRs

  if (pcrComp != NULL) {
      //printf("\n\tBinding to PCRs: ");
      //for(int i = 0 ; i < pcrComp->select.sizeOfSelect ; i++)
      //printf("%2.2x", pcrComp->select.pcrSelect[i]);

      memcpy(&pcrInfo.pcrSelection, &pcrComp->select, sizeof(TPM_PCR_SELECTION));

      flatpcrSize = BSG_Pack(BSG_TPM_PCR_COMPOSITE, (BYTE *) pcrComp, flatpcr);
      Crypto_SHA1Full((BYTE *) flatpcr, flatpcrSize, (BYTE *) &(pcrInfo.digestAtRelease));
      memset(&(pcrInfo.digestAtCreation), 0, sizeof(TPM_DIGEST));
      pcrInfoSize = BSG_Pack(BSG_TPM_PCR_INFO, (BYTE *) &pcrInfo, flatpcr);
  } else {
      //printf("\n\tBinding to no PCRS.");
      pcrInfoSize = 0;
  }

  // Calculate encUsageAuth
  BYTE XORbuffer[sizeof(TPM_SECRET) + sizeof(TPM_NONCE)];
  UINT32 XORbufferSize = sizeof(XORbuffer);
  TPM_DIGEST XORKey;
  TPM_ENCAUTH encAuth;

  BSG_PackList( XORbuffer, 2,
                BSG_TPM_SECRET, osapSharedSecret,
                BSG_TPM_NONCE, &auth->NonceEven );

  Crypto_SHA1Full(XORbuffer, XORbufferSize, (BYTE *) &XORKey);

  int i;
  for (i=0; i < TPM_DIGEST_SIZE; i++)
    ((BYTE *) &encAuth)[i] = ((BYTE *) &XORKey)[i] ^ ((BYTE *) sealDataAuth)[i];

  // Generate Extra TCS Parameters
  UINT32 inDataSize = buffer_len(inData);
  struct pack_buf_t inData_pack = {inDataSize, inData->bytes};
  struct pack_buf_t pcrInfo_pack = {pcrInfoSize, flatpcr};

  UINT32 sealedDataSize;
  BYTE *flatSealedData=NULL;

  paramText = (BYTE *) malloc(sizeof(BYTE) *  TCPA_MAX_BUFFER_LENGTH);

  paramTextSize = BSG_PackList(paramText, 4,
                               BSG_TPM_COMMAND_CODE, &command,
                               BSG_TPM_ENCAUTH, &encAuth,
                               BSG_TPM_SIZE32_DATA, &pcrInfo_pack,
                               BSG_TPM_SIZE32_DATA, &inData_pack);

  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
                              osapSharedSecret, auth) );

  // Call TCS
  TPMTRYRETURN( TCSP_Seal( hContext,
                           keyHandle,
                           encAuth,
                           pcrInfoSize,
                           flatpcr,
                           inDataSize,
                           inData->bytes,
                           auth,
                           &sealedDataSize,
                           &flatSealedData) );

  // Unpack/return key structure
  BSG_Unpack( BSG_TPM_STORED_DATA, flatSealedData, sealedData );

  paramTextSize = BSG_PackList(paramText, 3,
                               BSG_TPM_RESULT, &status,
                               BSG_TPM_COMMAND_CODE, &command,
                               BSG_TPM_STORED_DATA, sealedData);

  TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
                            osapSharedSecret, auth,
                            0) );


  goto egress;

 abort_egress:
 egress:

  if (flatSealedData)
    TCS_FreeMemory( hContext, flatSealedData);

  free(paramText);
  return status;
}


TPM_RESULT VTSP_Unseal(const TCS_CONTEXT_HANDLE    hContext,
                       const TPM_KEY_HANDLE        keyHandle,
                       const TPM_STORED_DATA       *sealedData,
                       const TPM_AUTHDATA          *key_usage_auth,
                       const TPM_AUTHDATA          *data_usage_auth,
                       buffer_t                    *outData,
                       TCS_AUTH                    *auth,
                       TCS_AUTH                    *dataAuth) {

  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE command = TPM_ORD_Unseal;

  BYTE *paramText;        // Digest to make Auth.
  UINT32 paramTextSize;

  // Generate Extra TCS Parameters
  UINT32 sealDataSize, clearDataSize;
  BYTE *flatSealedData= (BYTE *) malloc(sizeof(TPM_VERSION) +
                                        2 * sizeof(UINT32) +
                                        sealedData->sealInfoSize +
                                        sealedData->encDataSize),
       *clearData=NULL;

  sealDataSize = BSG_Pack(BSG_TPM_STORED_DATA, sealedData, flatSealedData );

  paramText = (BYTE *) malloc(sizeof(BYTE) *  TCPA_MAX_BUFFER_LENGTH);

  paramTextSize = BSG_PackList(paramText, 2,
                               BSG_TPM_COMMAND_CODE, &command,
                               BSG_TPM_STORED_DATA, sealedData);

  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
                              key_usage_auth, auth) );

  TPMTRYRETURN( GenerateAuth( paramText, paramTextSize,
                              data_usage_auth, dataAuth) );
  // Call TCS
  TPMTRYRETURN( TCSP_Unseal(  hContext,
                              keyHandle,
                              sealDataSize,
                              flatSealedData,
                              auth,
                              dataAuth,
                              &clearDataSize,
                              &clearData) );

  // Verify Auth
  struct pack_buf_t clearData_pack = {clearDataSize, clearData};

  paramTextSize = BSG_PackList(paramText, 3,
                               BSG_TPM_RESULT, &status,
                               BSG_TPM_COMMAND_CODE, &command,
                               BSG_TPM_SIZE32_DATA, &clearData_pack);

  TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
                            key_usage_auth, auth,
                            hContext) );

  TPMTRYRETURN( VerifyAuth( paramText, paramTextSize,
                            data_usage_auth, dataAuth,
                            hContext) );

  // Unpack/return key structure
  TPMTRYRETURN( buffer_init(outData, clearDataSize, clearData) );

  goto egress;

 abort_egress:
 egress:

  if (flatSealedData)
    TCS_FreeMemory( hContext, clearData);

  free(paramText);
  return status;
}

TPM_RESULT VTSP_SaveState( const TCS_CONTEXT_HANDLE    hContext) {

  vtpmloginfo(VTPM_LOG_VTSP, "Calling TPM_SaveState.\n");

  TPM_RESULT status = TPM_SUCCESS;

  // Call TCS
  return ( TCSP_SaveState ( hContext ) );

}


// Function Reaches into unsupported TCS command, beware.
TPM_RESULT VTSP_RawTransmit(const TCS_CONTEXT_HANDLE    hContext,
                            const buffer_t *inbuf,
                            buffer_t *outbuf ) {
  
  vtpmloginfo(VTPM_LOG_VTSP, "Passthrough in use.\n");
  TPM_RESULT status = TPM_SUCCESS;
  
  // Generate Extra TCS Parameters
  BYTE *resultText = (BYTE *) malloc(sizeof(BYTE) * TCPA_MAX_BUFFER_LENGTH);
  UINT32 resultTextSize =  TCPA_MAX_BUFFER_LENGTH;
  
  // Call TCS                          
  TPMTRYRETURN( TCSP_RawTransmitData(buffer_len(inbuf), inbuf->bytes, 
				     &resultTextSize, resultText) );
  
  // Unpack/return key structure
  TPMTRYRETURN(buffer_init (outbuf, resultTextSize, resultText) );                                
  goto egress;
  
 abort_egress:
  
 egress:
  TCS_FreeMemory(hContext, resultText);
  free(resultText);
  return status;
}
