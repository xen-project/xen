/*
 * Copyright (c) 2014 Intel Corporation.
 *
 * Authors:
 *   Quan Xu <quan.xu@intel.com>
 *
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

#ifndef __TPM2_H__
#define __TPM2_H__

#include "tcg.h"
#include "tpm2_types.h"

// ------------------------------------------------------------------
// TPM 2.0 Exposed API
// ------------------------------------------------------------------

TPM_RC TPM2_PCR_Read(TPML_PCR_SELECTION pcrSelectionIn,
                     UINT32 *pcrUpdateCounter,
                     TPML_PCR_SELECTION *pcrSelectionOut,
                     TPML_DIGEST *pcrValues);

TPM_RC TPM2_Load(TPMI_DH_OBJECT parentHandle,
                 TPM2B_PRIVATE *inPrivate,
                 TPM2B_PUBLIC *inPublic,
                 TPM2_HANDLE *objectHandle,
                 TPM2B_NAME *name);

TPM_RC TPM2_Create(TPMI_DH_OBJECT parentHandle,
                   TPM2_Create_Params_in *in,
                   TPM2_Create_Params_out *out);

TPM_RC TPM2_CreatePrimary(TPMI_RH_HIERARCHY primaryHandle,
                          TPM2_Create_Params_in *objHandle,
                          TPM2_HANDLE *in,
                          TPM2_Create_Params_out *out);

TPM_RC TPM2_HierachyChangeAuth(TPM2I_RH_HIERARCHY_AUTH authHandle,
                               TPM2B_AUTH *newAuth);

TPM_RC TPM2_RSA_ENCRYPT(TPMI_DH_OBJECT keyHandle,
                        TPM2B_PUBLIC_KEY_RSA *message,
                        TPMT_RSA_DECRYPT *inScheme,
                        TPM2B_DATA *label,
                        TPM2B_PUBLIC_KEY_RSA *outData);

TPM_RC TPM2_Bind(TPMI_DH_OBJECT keyHandle,
                 void *buf,
                 UINT32 len,
                 void *out);

TPM_RC TPM2_RSA_Decrypt(TPMI_DH_OBJECT keyHandle,
                        TPM2B_PUBLIC_KEY_RSA *cipherText,
                        TPMT_RSA_DECRYPT *inScheme,
                        TPM2B_DATA *label,
                        TPM2B_PUBLIC_KEY_RSA *message);

TPM_RC TPM2_UnBind(TPMI_DH_OBJECT keyHandle,
                   UINT32 ilen,
                   void *in,
                   UINT32 *olen,
                   void *out);

TPM_RESULT TPM2_GetRandom(UINT32* bytesRequested,
                          BYTE* randomBytes);

TPM_RC TPM2_CLEAR(void);

TPM_RC TPM2_FlushContext(TPMI_DH_CONTEXT);
#endif //TPM2_H
