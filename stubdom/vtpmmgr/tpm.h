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
      TPM_DIGEST   inDigest, // in
      TPM_PCRVALUE*   outDigest // out
      );

TPM_RESULT TPM_PcrRead ( TPM_PCRINDEX  pcrNum,  // in
      TPM_PCRVALUE*  outDigest // out
      );

TPM_RESULT TPM_Quote ( TCS_KEY_HANDLE  keyHandle,  // in
      TPM_NONCE   antiReplay,  // in
      UINT32*    PcrDataSize, // in, out
      BYTE**    PcrData,  // in, out
      TPM_AUTH_SESSION*   privAuth,  // in, out
      UINT32*    sigSize,  // out
      BYTE**    sig    // out
      );

TPM_RESULT TPM_Seal(
      TCS_KEY_HANDLE  keyHandle,  // in
      UINT32    pcrInfoSize, // in
      TPM_PCR_INFO*    pcrInfo,  // in
      UINT32    inDataSize,  // in
      const BYTE*    inData,   // in
      TPM_STORED_DATA* sealedData, //out
      const TPM_SECRET* osapSharedSecret, //in
      const TPM_AUTHDATA* sealDataAuth, //in
      TPM_AUTH_SESSION*   pubAuth  // in, out
      );

TPM_RESULT TPM_Unseal (
      TPM_KEY_HANDLE parentHandle, // in
      const TPM_STORED_DATA* sealedData,
      UINT32*   outSize,  // out
      BYTE**    out, //out
      const TPM_AUTHDATA* key_usage_auth, //in
      const TPM_AUTHDATA* data_usage_auth, //in
      TPM_AUTH_SESSION*   keyAuth,  // in, out
      TPM_AUTH_SESSION*   dataAuth  // in, out
      );

TPM_RESULT TPM_DirWriteAuth ( TPM_DIRINDEX  dirIndex,  // in
      TPM_DIRVALUE  newContents, // in
      TPM_AUTH_SESSION*   ownerAuth  // in, out
      );

TPM_RESULT TPM_DirRead ( TPM_DIRINDEX  dirIndex, // in
      TPM_DIRVALUE*  dirValue // out
      );

TPM_RESULT TPM_Bind(
      const TPM_KEY* key, //in
      const BYTE* in, //in
      UINT32 ilen, //in
      BYTE* out //out, must be at least cipher block size
      );

TPM_RESULT TPM_UnBind (
      TCS_KEY_HANDLE  keyHandle,  // in
      UINT32 ilen, //in
      const BYTE* in, //
      UINT32*   outDataSize, // out
      BYTE*    outData, //out
      const TPM_AUTHDATA* usage_auth,
      TPM_AUTH_SESSION* auth //in, out
      );

TPM_RESULT TPM_CreateWrapKey (
      TCS_KEY_HANDLE  hWrappingKey,  // in
      const TPM_AUTHDATA* osapSharedSecret,
      const TPM_AUTHDATA* dataUsageAuth, //in
      const TPM_AUTHDATA* dataMigrationAuth, //in
      TPM_KEY*     key, //in
      TPM_AUTH_SESSION*   pAuth    // in, out
      );

TPM_RESULT TPM_LoadKey (
      TPM_KEY_HANDLE  parentHandle, //
      const TPM_KEY* key, //in
      TPM_HANDLE*  keyHandle,    // out
      const TPM_AUTHDATA* usage_auth,
      TPM_AUTH_SESSION* auth
      );

TPM_RESULT TPM_GetPubKey (  TCS_KEY_HANDLE  hKey,   // in
      TPM_AUTH_SESSION*   pAuth,   // in, out
      UINT32*    pcPubKeySize, // out
      BYTE**    prgbPubKey  // out
      );

TPM_RESULT TPM_EvictKey ( TCS_KEY_HANDLE  hKey  // in
      );

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle, //in
      TPM_RESOURCE_TYPE rt //in
      );

TPM_RESULT TPM_Sign ( TCS_KEY_HANDLE  keyHandle,  // in
      UINT32    areaToSignSize, // in
      BYTE*    areaToSign,  // in
      TPM_AUTH_SESSION*   privAuth,  // in, out
      UINT32*    sigSize,  // out
      BYTE**    sig    // out
      );

TPM_RESULT TPM_GetRandom (  UINT32*    bytesRequested, // in, out
      BYTE*    randomBytes  // out
      );

TPM_RESULT TPM_StirRandom (  UINT32    inDataSize, // in
      BYTE*    inData  // in
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

TPM_RESULT TPM_SaveState(void);

TPM_RESULT TPM_CreateEndorsementKeyPair(
      const TPM_KEY_PARMS* keyInfo,
      TPM_PUBKEY* pubEK);

TPM_RESULT TPM_TransmitData(
      BYTE* in,
      UINT32 insize,
      BYTE* out,
      UINT32* outsize);

#endif //TPM_H
