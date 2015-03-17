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

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <polarssl/sha1.h>

#include "tcg.h"
#include "tpm.h"
#include "tpm2.h"
#include "log.h"
#include "marshal.h"
#include "tpm2_marshal.h"
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
    if ((status = TPM_TransmitData(in_buf, paramSize, out_buf, &out_len)) != TPM_SUCCESS) {\
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
    if ((status = verifyAuth(&paramDigest, HMACkey, auth)) != TPM_SUCCESS) {\
        goto abort_egress;\
    }\
} while(0)

#define TPM_AUTH2_VERIFY(HMACkey, auth) do {\
    ptr = unpack_TPM_AUTH_SESSION(ptr, auth);\
    if ((status = verifyAuth(&paramDigest, HMACkey, auth)) != TPM_SUCCESS) {\
        goto abort_egress;\
    }\
} while(0)

#define TPM_UNPACK_VERIFY() do { \
    ptr = out_buf;\
    ptr = unpack_TPM_RSP_HEADER(ptr, \
          &(tag), &(paramSize), &(status));\
    if ((status) != TPM_SUCCESS){ \
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

TPM_RC TPM2_PCR_Read(TPML_PCR_SELECTION pcrSelectionIn,
                     UINT32 *pcrUpdateCounter,
                     TPML_PCR_SELECTION *pcrSelectionOut,
                     TPML_DIGEST *pcrValues)
{
    TPM_BEGIN(TPM_ST_NO_SESSIONS,TPM_CC_PCR_Read);

    /*pack in*/
    ptr =  pack_TPML_PCR_SELECTION(ptr, &pcrSelectionIn);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

    /*unpack out*/
    ptr = unpack_UINT32(ptr, pcrUpdateCounter);
    ptr = unpack_TPML_PCR_SELECTION(ptr, pcrSelectionOut);
    ptr = unpack_TPML_DIGEST(ptr, pcrValues);

    goto egress;
abort_egress:
egress:
    return status;
}

TPM_RC TPM2_Load(TPMI_DH_OBJECT parentHandle,
                 TPM2B_PRIVATE *inPrivate, /* in */
                 TPM2B_PUBLIC *inPublic, /* in */
                 TPM2_HANDLE *objectHandle, /* out */
                 TPM2B_NAME *name /* out */)
{
    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_Load);

    /* pack handle of parent for new object */
    ptr =  pack_UINT32(ptr, parentHandle);

    ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.srk_auth_area);
    ptr = pack_TPM2B_PRIVATE(ptr, inPrivate);
    ptr = pack_TPM2B_PUBLIC(ptr, inPublic);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

    if (objectHandle != NULL) {
        ptr = unpack_TPM_HANDLE(ptr, objectHandle);
    } else {
        TPM2_HANDLE tmp;
        ptr = unpack_TPM_HANDLE(ptr, &tmp);
    }

    if (name != NULL)
        ptr = unpack_TPM2B_NAME(ptr, name);
    goto egress;

abort_egress:
egress:
    return status;
}

TPM_RC TPM2_Create(TPMI_DH_OBJECT parentHandle,
                   TPM2_Create_Params_in *in,
                   TPM2_Create_Params_out *out)
{
    UINT32 param_size;
    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_Create);

    /* pack handle of parent for new object */
    ptr =  pack_UINT32(ptr, parentHandle);

    /* pack Auth Area */
    ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.srk_auth_area);

    /* pack inSensitive */
    ptr = pack_TPM2B_SENSITIVE_CREATE(ptr, &in->inSensitive);

    /* pack inPublic */
    ptr = pack_TPM2B_PUBLIC(ptr, &in->inPublic);

    /* pack outside Info */
    ptr = pack_TPM2B_DATA(ptr, &in->outsideInfo);

    /* pack createPCR */
    ptr = pack_TPML_PCR_SELECTION(ptr, &in->creationPCR);

    /* Send the command to the tpm */
    TPM_TRANSMIT();

    /* Unpack and validate the header */
    TPM_UNPACK_VERIFY();

    ptr = unpack_UINT32(ptr, &param_size);
    if (out != NULL) {
        ptr = unpack_TPM2B_PRIVATE(ptr, &vtpm_globals.tpm2_storage_key.Private);
        ptr = unpack_TPM2B_PUBLIC(ptr, &vtpm_globals.tpm2_storage_key.Public);
        ptr = unpack_TPM2B_CREATION_DATA(ptr, &out->creationData);
        ptr = unpack_TPM2B_DIGEST(ptr, &out->creationHash);
        ptr = unpack_TPMT_TK_CREATION(ptr, &out->creationTicket);
    } else {
           ptr += param_size;
    }
    goto egress;

abort_egress:
egress:
    return status;
}

TPM_RC TPM2_CreatePrimary(TPMI_RH_HIERARCHY primaryHandle,
                          TPM2_Create_Params_in *in,
                          TPM2_HANDLE *objHandle,
                          TPM2_Create_Params_out *out)
{
    UINT32 param_size;
    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_CreatePrimary);

    /* pack primary handle */
    ptr = pack_UINT32(ptr, primaryHandle);

    /* pack Auth Area */
    ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.pw_auth);

    /* pack inSenstive */
    ptr = pack_TPM2B_SENSITIVE_CREATE(ptr, &in->inSensitive);

    /* pack inPublic */
    ptr = pack_TPM2B_PUBLIC(ptr, &in->inPublic);

    /* pack outsideInfo */
    ptr = pack_TPM2B_DATA(ptr, &in->outsideInfo);

    /* pack creationPCR */
    ptr = pack_TPML_PCR_SELECTION(ptr, &in->creationPCR);

    /* Send the command to the tpm */
    TPM_TRANSMIT();

    /* Unpack and validate the header */
    TPM_UNPACK_VERIFY();

    if (objHandle != NULL)
        ptr = unpack_TPM_HANDLE(ptr, objHandle);
    else {
        TPM2_HANDLE handle;
        ptr = unpack_TPM_HANDLE(ptr, &handle);
    }
    ptr = unpack_UINT32(ptr, &param_size);

    if (out != NULL) {
        ptr = unpack_TPM2B_PUBLIC(ptr, &out->outPublic);
        ptr = unpack_TPM2B_CREATION_DATA(ptr, &out->creationData);
        ptr = unpack_TPM2B_DIGEST(ptr, &out->creationHash);
        ptr = unpack_TPMT_TK_CREATION(ptr, &out->creationTicket);
    } else {
        ptr += param_size;
    }

goto egress;

abort_egress:
egress:
   return status;
}

TPM_RC TPM2_HierachyChangeAuth(TPM2I_RH_HIERARCHY_AUTH authHandle, TPM2B_AUTH *newAuth)
{
    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_HierarchyChangeAuth);
    ptr = pack_UINT32(ptr, authHandle);
    ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.pw_auth);
    ptr = pack_TPM2B_AUTH(ptr, newAuth);
    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

abort_egress:
    return status;
}

TPM_RC TPM2_RSA_ENCRYPT(TPMI_DH_OBJECT keyHandle,
                        TPM2B_PUBLIC_KEY_RSA *message,
                        TPMT_RSA_DECRYPT *inScheme,
                        TPM2B_DATA *label,
                        TPM2B_PUBLIC_KEY_RSA *outData)
{
    TPM_BEGIN(TPM_ST_NO_SESSIONS, TPM_CC_RSA_Encrypt);

    ptr = pack_UINT32(ptr, keyHandle);
    ptr = pack_TPM2B_PUBLIC_KEY_RSA(ptr, message);
    ptr = pack_TPMT_RSA_DECRYPT(ptr, inScheme);
    ptr = pack_TPM2B_DATA(ptr, label);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

    if (outData != NULL)
        unpack_TPM2B_PUBLIC_KEY_RSA(ptr, outData);
abort_egress:
    return status;
}

TPM_RC TPM2_Bind(TPMI_DH_OBJECT keyHandle,
                 void *buf,
                 UINT32 len,
                 void *out)
{
    TPM_RC status = TPM_SUCCESS;
    TPM2B_PUBLIC_KEY_RSA message;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA outData;

    message.size = len;
    memcpy(message.buffer, buf, len);
    inScheme.scheme = TPM2_ALG_NULL;
    label.size = 0;
    TPMTRYRETURN(TPM2_RSA_ENCRYPT(keyHandle, &message, &inScheme, &label, &outData));
    memcpy(out, outData.buffer, outData.size);

abort_egress:
    return status;
}

TPM_RC TPM2_RSA_Decrypt(TPMI_DH_OBJECT keyHandle,
                        TPM2B_PUBLIC_KEY_RSA *cipherText,
                        TPMT_RSA_DECRYPT *inScheme,
                        TPM2B_DATA *label,
                        TPM2B_PUBLIC_KEY_RSA *message)
{
    UINT32 param_size;

    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_RSA_Decrypt);
    ptr = pack_UINT32(ptr, keyHandle);
    ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.srk_auth_area);
    ptr = pack_TPM2B_PUBLIC_KEY_RSA(ptr, cipherText);
    ptr = pack_TPMT_RSA_DECRYPT(ptr, inScheme);
    ptr = pack_TPM2B_DATA(ptr, label);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

    ptr = unpack_UINT32(ptr, &param_size);

    if (message)
        ptr = unpack_TPM2B_PUBLIC_KEY_RSA(ptr, message);

abort_egress:
    return status;
}

TPM_RC TPM2_UnBind(TPMI_DH_OBJECT keyHandle,
                   UINT32 ilen,
                   void *in,
                   UINT32 *olen,
                   void *out)
{
    UINT32 status;
    TPM2B_PUBLIC_KEY_RSA cipher, message;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;

    cipher.size = ilen;
    memcpy(cipher.buffer, in, ilen);
    inScheme.scheme = TPM2_ALG_NULL;
    label.size = 0;

    TPMTRYRETURN(TPM2_RSA_Decrypt(keyHandle, &cipher, &inScheme, &label, &message));

    *olen = message.size;
    memcpy(out, message.buffer, *olen);

abort_egress:
    return status;
}

TPM_RC TPM2_CLEAR(void)
{
    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_Clear);

    ptr = pack_UINT32(ptr, TPM_RH_PLATFORM);
    ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.pw_auth);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

abort_egress:
    return status;
}

TPM_RC TPM2_GetRandom(UINT32 * bytesRequested, BYTE * randomBytes)
{
    TPM_BEGIN(TPM_ST_NO_SESSIONS, TPM_CC_GetRandom);

    ptr = pack_UINT16(ptr, (UINT16)*bytesRequested);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

    ptr = unpack_UINT16(ptr, (UINT16 *)bytesRequested);
    ptr = unpack_TPM_BUFFER(ptr, randomBytes, *bytesRequested);

abort_egress:
    return status;
}

TPM_RC TPM2_FlushContext(TPMI_DH_CONTEXT flushHandle)
{
    TPM_BEGIN(TPM_ST_NO_SESSIONS, TPM_CC_FlushContext);

    ptr = pack_UINT32(ptr, flushHandle);

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

abort_egress:
    return status;
}
