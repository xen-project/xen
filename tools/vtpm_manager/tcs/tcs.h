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
// tcs.h
// 
//  This file declares the TCS API
// 
// ==================================================================

#ifndef __TCS_H__
#define __TCS_H__

#include "tcg.h"
#include "contextmgr.h"
#include "buffer.h"

#define HANDLE_NULL 0

// ------------------------------------------------------------------
// Exposed API
// ------------------------------------------------------------------

TPM_RESULT TCS_create();
void TCS_destroy();

TPM_RESULT TCS_OpenContext( /* OUT */ TCS_CONTEXT_HANDLE* hContext );

TPM_RESULT TCS_CloseContext ( /* IN */ TCS_CONTEXT_HANDLE hContext );

TPM_RESULT TCS_Malloc ( TCS_CONTEXT_HANDLE hContext, // in
			UINT32   MemSize, // in
			BYTE**   ppMemPtr ); //out

TPM_RESULT TCS_FreeMemory ( TCS_CONTEXT_HANDLE hContext, // in
			    BYTE*    pMemory);  // in

// ------------------------------------------------------------------
// Exposed API
// ------------------------------------------------------------------

// TPM v1.1B Command Set

// Authorzation
TPM_RESULT TCSP_OIAP( TCS_CONTEXT_HANDLE hContext, // in
		      TCS_AUTHHANDLE*  authHandle, // out 
		      TPM_NONCE*   nonce0  // out
		      );

TPM_RESULT TCSP_OSAP (  TCS_CONTEXT_HANDLE hContext,  // in
			TPM_ENTITY_TYPE entityType,  // in
			UINT32    entityValue, // in
			TPM_NONCE   nonceOddOSAP, // in
			TCS_AUTHHANDLE*  authHandle,  // out 
			TPM_NONCE*   nonceEven,  // out
			TPM_NONCE*   nonceEvenOSAP // out
			);

TPM_RESULT TCSP_TakeOwnership (  TCS_CONTEXT_HANDLE hContext,   // in
				 UINT16    protocolID,   // in
				 UINT32    encOwnerAuthSize, // in 
				 BYTE*    encOwnerAuth,  // in
				 UINT32    encSrkAuthSize,  // in
				 BYTE*    encSrkAuth,   // in
				 UINT32*    SrkSize,   // in, out
				 BYTE**    Srk,    // in, out
				 TCS_AUTH*   ownerAuth   // in, out
				 );

TPM_RESULT TCSP_DisablePubekRead (  TCS_CONTEXT_HANDLE hContext, // in
                                    TCS_AUTH*   ownerAuth // in, out
                                    );

TPM_RESULT TCSP_TerminateHandle (  TCS_CONTEXT_HANDLE hContext, // in
				   TCS_AUTHHANDLE  handle  // in
				   );

TPM_RESULT TCSP_FlushSpecific (  TCS_CONTEXT_HANDLE hContext, // in
				 TCS_AUTHHANDLE  handle,  // in
				 TPM_RESOURCE_TYPE resourceType //in 
				 );

// TPM Mandatory
TPM_RESULT TCSP_Extend (  TCS_CONTEXT_HANDLE hContext, // in
			  TPM_PCRINDEX  pcrNum,  // in
			  TPM_DIGEST   inDigest, // in
			  TPM_PCRVALUE*   outDigest // out
			  );

TPM_RESULT TCSP_PcrRead (  TCS_CONTEXT_HANDLE hContext, // in
			   TPM_PCRINDEX  pcrNum,  // in
			   TPM_PCRVALUE*  outDigest // out
			   );

TPM_RESULT TCSP_Quote (  TCS_CONTEXT_HANDLE hContext,  // in
			 TCS_KEY_HANDLE  keyHandle,  // in
			 TPM_NONCE   antiReplay,  // in
			 UINT32*    PcrDataSize, // in, out
			 BYTE**    PcrData,  // in, out
			 TCS_AUTH*   privAuth,  // in, out
			 UINT32*    sigSize,  // out
			 BYTE**    sig    // out
			 );

TPM_RESULT TCSP_Seal (  TCS_CONTEXT_HANDLE hContext,  // in
			TCS_KEY_HANDLE  keyHandle,  // in
			TPM_ENCAUTH  encAuth,  // in
			UINT32    pcrInfoSize, // in
			BYTE*    PcrInfo,  // in
			UINT32    inDataSize,  // in
			BYTE*    inData,   // in
			TCS_AUTH*   pubAuth,  // in, out
			UINT32*    SealedDataSize, // out
			BYTE**    SealedData  // out
			);

TPM_RESULT TCSP_Unseal (  TCS_CONTEXT_HANDLE hContext,  // in
			  TCS_KEY_HANDLE  parentHandle, // in
			  UINT32    SealedDataSize, // in
			  BYTE*    SealedData,  // in
			  TCS_AUTH*   parentAuth,  // in, out
			  TCS_AUTH*   dataAuth,  // in, out
			  UINT32*    DataSize,  // out
			  BYTE**    Data   // out
			  );

TPM_RESULT TCSP_DirWriteAuth (  TCS_CONTEXT_HANDLE hContext,  // in
				TPM_DIRINDEX  dirIndex,  // in
				TPM_DIRVALUE  newContents, // in
				TCS_AUTH*   ownerAuth  // in, out
				);

TPM_RESULT TCSP_DirRead (  TCS_CONTEXT_HANDLE hContext, // in
			   TPM_DIRINDEX  dirIndex, // in
			   TPM_DIRVALUE*  dirValue // out
			   );

TPM_RESULT TCSP_UnBind (  TCS_CONTEXT_HANDLE hContext,  // in
			  TCS_KEY_HANDLE  keyHandle,  // in
			  UINT32    inDataSize,  // in
			  BYTE*    inData,   // in
			  TCS_AUTH*   privAuth,  // in, out
			  UINT32*    outDataSize, // out
			  BYTE**    outData   // out
			  );

TPM_RESULT TCSP_CreateWrapKey (  TCS_CONTEXT_HANDLE hContext,   // in
				 TCS_KEY_HANDLE  hWrappingKey,  // in
				 TPM_ENCAUTH  KeyUsageAuth,  // in
				 TPM_ENCAUTH  KeyMigrationAuth, // in
				 UINT32*    pcKeySize,   // in, out
				 BYTE**    prgbKey,   // in, out
				 TCS_AUTH*   pAuth    // in, out
				 );

TPM_RESULT TCSP_LoadKeyByBlob (  TCS_CONTEXT_HANDLE hContext,    // in
				 TCS_KEY_HANDLE  hUnwrappingKey,   // in
				 UINT32    cWrappedKeyBlobSize, // in
				 BYTE*    rgbWrappedKeyBlob,  // in
				 TCS_AUTH*   pAuth,     // in, out
				 TCS_KEY_HANDLE*  phKeyTCSI,    // out
				 TCS_KEY_HANDLE*  phKeyHMAC    // out
				 );

TPM_RESULT TCSP_GetPubKey (  TCS_CONTEXT_HANDLE hContext,  // in
			     TCS_KEY_HANDLE  hKey,   // in
			     TCS_AUTH*   pAuth,   // in, out
			     UINT32*    pcPubKeySize, // out
			     BYTE**    prgbPubKey  // out
			     ); 

TPM_RESULT TCSP_EvictKey (  TCS_CONTEXT_HANDLE hContext, // in
			    TCS_KEY_HANDLE  hKey  // in
			    );

TPM_RESULT TCSP_Sign (  TCS_CONTEXT_HANDLE hContext,  // in
			TCS_KEY_HANDLE  keyHandle,  // in
			UINT32    areaToSignSize, // in
			BYTE*    areaToSign,  // in
			TCS_AUTH*   privAuth,  // in, out
			UINT32*    sigSize,  // out
			BYTE**    sig    // out
			);

TPM_RESULT TCSP_GetRandom (  TCS_CONTEXT_HANDLE hContext,  // in
			     UINT32*    bytesRequested, // in, out
			     BYTE**    randomBytes  // out
			     );

TPM_RESULT TCSP_StirRandom (  TCS_CONTEXT_HANDLE hContext, // in
			      UINT32    inDataSize, // in
			      BYTE*    inData  // in
			      );

TPM_RESULT TCSP_ReadPubek (  TCS_CONTEXT_HANDLE hContext,    // in
			     TPM_NONCE   antiReplay,    // in
			     UINT32*    pubEndorsementKeySize, // out
			     BYTE**    pubEndorsementKey,  // out
			     TPM_DIGEST*  checksum    // out
			     );


// Non-Standard TCSP calls
TPM_RESULT TCSP_SaveState(TCS_CONTEXT_HANDLE   hContext);  // in

//Give direct access to TransmitData.
// Key and Auth Management is done before transfering command to TDDL.
TPM_RESULT TCSP_RawTransmitData(UINT32 inDataSize,  // in
				BYTE *inData,       // in
				UINT32 *outDataSize,// in/out
				BYTE *outData);     // out

///////////// Private Functions ////////////////////
CONTEXT_HANDLE* LookupContext( TCS_CONTEXT_HANDLE hContext);

#endif //TCS_H
