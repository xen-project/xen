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
// vtsp.h
// 
//  Higher level interface to TCS.
//
// ==================================================================

#ifndef __VTSP_H__
#define __VTSP_H__

#include "tcg.h"
#include "tcs.h"

#define KEY_BUFFER_SIZE 2048

TPM_RESULT VTSP_RawTransmit(const TCS_CONTEXT_HANDLE    hContext,
                            const buffer_t *inbuf,
                            buffer_t *outbuf );

TPM_RESULT VTSP_OIAP(  const TCS_CONTEXT_HANDLE hContext,
                       TCS_AUTH *auth);
                       
TPM_RESULT VTSP_OSAP(  const TCS_CONTEXT_HANDLE hContext,
                       const TPM_ENTITY_TYPE entityType,
                       const UINT32 entityValue,
                       const TPM_AUTHDATA *usageAuth,
                       TPM_SECRET *sharedsecret, 
                       TCS_AUTH *auth);

TPM_RESULT VTSP_TerminateHandle(const TCS_CONTEXT_HANDLE hContext,
                                const TCS_AUTH *auth);

TPM_RESULT VTSP_ReadPubek(   const TCS_CONTEXT_HANDLE hContext,
                             CRYPTO_INFO *cypto_info);

TPM_RESULT VTSP_TakeOwnership(   const TCS_CONTEXT_HANDLE hContext,
                                 const TPM_AUTHDATA *ownerAuth, 
                                 const TPM_AUTHDATA *srkAuth,
                                 CRYPTO_INFO *ek_cryptoInfo,
                                 TCS_AUTH *auth);
                               
TPM_RESULT VTSP_DisablePubekRead( const TCS_CONTEXT_HANDLE    hContext,
                                  const TPM_AUTHDATA *ownerAuth, 
                                  TCS_AUTH                    *auth);
                               
TPM_RESULT VTSP_CreateWrapKey(  const TCS_CONTEXT_HANDLE hContext,
                                const TPM_KEY_USAGE      usage,
                                const TPM_AUTHDATA       *newKeyAuth,
                                const TCS_KEY_HANDLE     parentHandle, 
                                const TPM_AUTHDATA       *osapSharedSecret,
                                buffer_t                 *pubKeyBuf,
                                TCS_AUTH                 *auth);

TPM_RESULT VTSP_LoadKey(const TCS_CONTEXT_HANDLE    hContext,
                        const TCS_KEY_HANDLE        hUnwrappingKey,
                        const buffer_t              *rgbWrappedKeyBlob,
                        const TPM_AUTHDATA          *parentAuth,
                        TPM_HANDLE                  *newKeyHandle,
                        TCS_AUTH                    *pAuth,
                        CRYPTO_INFO                 *cryptoinfo,
                        const BOOL                  skipTPMLoad);

TPM_RESULT VTSP_Unbind( const TCS_CONTEXT_HANDLE    hContext,
                        const TPM_KEY_HANDLE        key_handle,
                        const buffer_t              *bound_data,
                        const TPM_AUTHDATA          *usage_auth,
                        buffer_t                    *clear_data,
                        TCS_AUTH                    *auth);
                        
TPM_RESULT VTSP_Bind(   CRYPTO_INFO *cryptoInfo,
            const buffer_t *inData, 
            buffer_t *outData);
                        
TPM_RESULT VTSP_Seal(const TCS_CONTEXT_HANDLE    hContext,
                     const TPM_KEY_HANDLE        keyHandle,
                     const TPM_AUTHDATA          *sealDataAuth,
                     const TPM_PCR_COMPOSITE     *pcrComp,
                     const buffer_t              *inData,
                     TPM_STORED_DATA             *sealedData,                                   
                     const TPM_SECRET            *osapSharedSecret,
                     TCS_AUTH                    *auth);

TPM_RESULT VTSP_Unseal(const TCS_CONTEXT_HANDLE    hContext,
                       const TPM_KEY_HANDLE        keyHandle,
                       const TPM_STORED_DATA       *sealedData,
                       const TPM_AUTHDATA          *key_usage_auth,
                       const TPM_AUTHDATA          *data_usage_auth,
                       buffer_t                    *outData,
                       TCS_AUTH                    *auth,
                       TCS_AUTH                    *dataAuth);

TPM_RESULT VTSP_SaveState( const TCS_CONTEXT_HANDLE    hContext);

#endif //_VTSP_H_
