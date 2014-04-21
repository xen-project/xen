/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005/2006, Intel Corp.
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

#ifndef __TPM_H__
#define __TPM_H__

#include "tcg.h"

// ------------------------------------------------------------------
// Exposed API
// ------------------------------------------------------------------

// TPM v1.1B Command Set

// Authorzation
TPM_RESULT TPM_OIAP(
      TPM_AUTH_SESSION*   auth //out
      );

TPM_RESULT TPM_OSAP (
      TPM_ENTITY_TYPE entityType,  // in
      UINT32    entityValue, // in
      const TPM_AUTHDATA* usageAuth, //in
      TPM_SECRET *sharedSecret, //out
      TPM_AUTH_SESSION *auth);

TPM_RESULT TPM_TakeOwnership(
      const TPM_PUBKEY *pubEK, //in
      const TPM_AUTHDATA* ownerAuth, //in
      const TPM_AUTHDATA* srkAuth, //in
      const TPM_KEY* inSrk, //in
      TPM_KEY* outSrk, //out, optional
      TPM_AUTH_SESSION*   auth   // in, out
      );

TPM_RESULT TPM_DisablePubekRead (
      const TPM_AUTHDATA* ownerAuth,
      TPM_AUTH_SESSION*   auth
      );

TPM_RESULT TPM_TerminateHandle ( TPM_AUTHHANDLE  handle  // in
      );

TPM_RESULT TPM_FlushSpecific ( TPM_HANDLE  handle,  // in
      TPM_RESOURCE_TYPE resourceType //in
      );

// TPM Mandatory
TPM_RESULT TPM_Extend ( TPM_PCRINDEX  pcrNum,  // in
      TPM_DIGEST*  inDigest, // in
      TPM_PCRVALUE*   outDigest // out
      );

TPM_RESULT TPM_Reset(TPM_PCR_SELECTION *sel);

TPM_RESULT TPM_Seal(
      TCS_KEY_HANDLE  keyHandle,  // in
      UINT32    pcrInfoLongSize, // in
      TPM_PCR_INFO_LONG*    pcrInfoLong,  // in
      UINT32    inDataSize,  // in
      const BYTE*    inData,   // in
      TPM_STORED_DATA12* sealedData, //out
      const TPM_SECRET* osapSharedSecret, //in
      const TPM_AUTHDATA* sealDataAuth, //in
      TPM_AUTH_SESSION*   pubAuth  // in, out
      );

TPM_RESULT TPM_Unseal (
      TPM_KEY_HANDLE parentHandle, // in
      const TPM_STORED_DATA12* sealedData,
      UINT32*   outSize,  // out
      BYTE**    out, //out
      const TPM_AUTHDATA* key_usage_auth, //in
      const TPM_AUTHDATA* data_usage_auth, //in
      TPM_AUTH_SESSION*   keyAuth,  // in, out
      TPM_AUTH_SESSION*   dataAuth  // in, out
      );

TPM_RESULT TPM_LoadKey (
      TPM_KEY_HANDLE  parentHandle, //
      const TPM_KEY* key, //in
      TPM_HANDLE*  keyHandle,    // out
      const TPM_AUTHDATA* usage_auth,
      TPM_AUTH_SESSION* auth
      );

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle, //in
      TPM_RESOURCE_TYPE rt //in
      );

TPM_RESULT TPM_GetRandom (  UINT32*    bytesRequested, // in, out
      BYTE*    randomBytes  // out
      );

TPM_RESULT TPM_ReadPubek (
      TPM_PUBKEY* pubEK //out
      );

TPM_RESULT TPM_GetCapability(
      TPM_CAPABILITY_AREA capArea,
      UINT32 subCapSize,
      const BYTE* subCap,
      UINT32* respSize,
      BYTE** resp);

TPM_RESULT TPM_PCR_Read(UINT32 pcr, TPM_DIGEST *value);
TPM_RESULT TPM_SaveState(void);

TPM_RESULT TPM_CreateEndorsementKeyPair(
      const TPM_KEY_PARMS* keyInfo,
      TPM_PUBKEY* pubEK);

TPM_RESULT TPM_MakeIdentity(
	const TPM_AUTHDATA* identityAuth, // in
	const TPM_AUTHDATA* privCADigest, // in
	const TPM_KEY* kinfo, // in
	const TPM_AUTHDATA* srk_auth, // in
	const TPM_AUTHDATA* owner_auth, // in
	TPM_AUTH_SESSION* srkAuth, // in,out
	TPM_AUTH_SESSION* ownAuth, // in,out
	TPM_KEY* key, // out
	UINT32* identityBindingSize, // out
	BYTE** identityBinding); // out

TPM_RESULT TPM_ActivateIdentity(
	TPM_KEY_HANDLE aikHandle, // in
	BYTE* blob, // in
	UINT32 blobSize, // in
	const TPM_AUTHDATA* aik_auth, // in
	const TPM_AUTHDATA* owner_auth, // in
	TPM_AUTH_SESSION* aikAuth, // in,out
	TPM_AUTH_SESSION* ownAuth, // in,out
	TPM_SYMMETRIC_KEY* symKey); // out

TPM_RESULT TPM_Quote(
	TPM_KEY_HANDLE keyh, // in
	const TPM_NONCE* data, // in
	const TPM_PCR_SELECTION *pcrSelect, // in
	const TPM_AUTHDATA* auth, // in
	TPM_AUTH_SESSION* oiap, // in,out
	TPM_PCR_COMPOSITE *pcrs, // out
	BYTE** sig, // out
	UINT32* sigSize); // out

TPM_RESULT TPM_TransmitData(
      BYTE* in,
      UINT32 insize,
      BYTE* out,
      UINT32* outsize);

#endif //TPM_H
