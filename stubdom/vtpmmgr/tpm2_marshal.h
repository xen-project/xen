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

#ifndef TPM2_MARSHAL_H
#define TPM2_MARSHAL_H

#include <stdlib.h>
#include <mini-os/byteorder.h>
#include <mini-os/endian.h>
#include "tcg.h"
#include "tpm2_types.h"
#include <assert.h>

#define pack_TPM_BUFFER(ptr, buf, size) pack_BUFFER(ptr, buf, size)
#define unpack_TPM_BUFFER(ptr, buf, size) unpack_BUFFER(ptr, buf, size)

static
inline BYTE* pack_BYTE_ARRAY(BYTE* ptr, const BYTE* array, UINT32 size)
{
    int i;
    for (i = 0; i < size; i++)
         ptr = pack_BYTE(ptr, array[i]);
    return ptr;
}

static
inline BYTE* pack_TPMA_SESSION(BYTE* ptr, const TPMA_SESSION *attr)
{
    return pack_BYTE(ptr, (BYTE)(*attr));
}

static
inline BYTE* unpack_TPMA_SESSION(BYTE* ptr, TPMA_SESSION *attr)
{
    return unpack_BYTE(ptr, (BYTE *)attr);
}

static
inline BYTE* pack_TPMI_ALG_HASH(BYTE* ptr, const TPMI_ALG_HASH *hash)
{
    return pack_UINT16(ptr, *hash);
}

static
inline BYTE* unpack_TPMI_ALG_HASH(BYTE *ptr, TPMI_ALG_HASH *hash)
{
    return unpack_UINT16(ptr, hash);
}

#define pack_TPMA_OBJECT(ptr, t)                pack_UINT32(ptr, (UINT32)(*t))
#define unpack_TPMA_OBJECT(ptr, t)              unpack_UINT32(ptr, (UINT32 *)(t))
#define pack_TPM_RH(ptr, t)                     pack_UINT32(ptr, (UINT32)(*t))
#define unpack_TPM_RH(ptr, t)                   unpack_UINT32(ptr, (UINT32 *)(t))
#define pack_TPMA_LOCALITY(ptr, locality)       pack_BYTE(ptr, (BYTE)*locality)
#define unpack_TPMA_LOCALITY(ptr, locality)     unpack_BYTE(ptr, (BYTE *)locality)
#define pack_TPM_ST(ptr, tag)                   pack_UINT16(ptr, *tag)
#define unpack_TPM_ST(ptr, tag)                 unpack_UINT16(ptr, tag)
#define pack_TPM_KEY_BITS(ptr, t)               pack_UINT16(ptr, *t)
#define unpack_TPM_KEY_BITS(ptr, t)             unpack_UINT16(ptr, t)
#define pack_TPMI_AES_KEY_BITS(ptr, t)          pack_TPM_KEY_BITS(ptr, t)
#define unpack_TPMI_AES_KEY_BITS(ptr, t)        unpack_TPM_KEY_BITS(ptr, t)
#define pack_TPMI_RSA_KEY_BITS(ptr, t)          pack_TPM_KEY_BITS(ptr, t)
#define unpack_TPMI_RSA_KEY_BITS(ptr, t)        unpack_TPM_KEY_BITS(ptr, t)
#define pack_TPM_ALG_ID(ptr, id)                pack_UINT16(ptr, *id)
#define unpack_TPM_ALG_ID(ptr, id)              unpack_UINT16(ptr, id)
#define pack_TPM_ALG_SYM(ptr, t)                pack_TPM_ALG_ID(ptr, t)
#define unpack_TPM_ALG_SYM(ptr, t)              unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_ASYM(ptr, asym)           pack_TPM_ALG_ID(ptr, asym)
#define unpack_TPMI_ALG_ASYM(ptr, asym)         unpack_TPM_ALG_ID(ptr, asym)
#define pack_TPMI_ALG_SYM_OBJECT(ptr, t)        pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_SYM_OBJECT(ptr, t)      unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_SYM_MODE(ptr, t)          pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_SYM_MODE(ptr, t)        unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_KDF(ptr, t)               pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_KDF(ptr, t)             unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_PUBLIC(ptr, t)            pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_PUBLIC(ptr, t)          unpack_TPM_ALG_ID(ptr, t)
#define pack_TPM2_HANDLE(ptr, h)                pack_UINT32(ptr, *h)
#define unpack_TPM2_HANDLE(ptr, h)              unpack_UINT32(ptr, h)
#define pack_TPMI_ALG_RSA_SCHEME(ptr, t)        pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_RSA_SCHEME(ptr, t)      unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_DH_OBJECT(ptr, o)             pack_TPM2_HANDLE(ptr, o)
#define unpack_TPMI_DH_OBJECT(PTR, O)           unpack_TPM2_HANDLE(ptr, o)
#define pack_TPMI_RH_HIERACHY(ptr, h)           pack_TPM2_HANDLE(ptr, h)
#define unpack_TPMI_RH_HIERACHY(ptr, h)         unpack_TPM2_HANDLE(ptr, h)
#define pack_TPMI_RH_PLATFORM(ptr, p)           pack_TPM2_HANDLE(ptr, p)
#define unpack_TPMI_RH_PLATFORM(ptr, p)         unpack_TPM2_HANDLE(ptr, p)
#define pack_TPMI_RH_OWNER(ptr, o)              pack_TPM2_HANDLE(ptr, o)
#define unpack_TPMI_RH_OWNER(ptr, o)            unpack_TPM2_HANDLE(ptr, o)
#define pack_TPMI_RH_ENDORSEMENT(ptr, e)        pack_TPM2_HANDLE(ptr, e)
#define unpack_TPMI_RH_ENDORSEMENT(ptr, e)      unpack_TPM2_HANDLE(ptr, e)
#define pack_TPMI_RH_LOCKOUT(ptr, l)            pack_TPM2_HANDLE(ptr, l)
#define unpack_TPMI_RH_LOCKOUT(ptr, l)          unpack_TPM2_HANDLE(ptr, l)

static
inline BYTE* pack_TPM2B_DIGEST(BYTE* ptr, const TPM2B_DIGEST *digest)
{
    ptr = pack_UINT16(ptr, digest->size);
    ptr = pack_BUFFER(ptr, digest->buffer, digest->size);
    return ptr;
}

static
inline BYTE* unpack_TPM2B_DIGEST(BYTE* ptr, TPM2B_DIGEST *digest)
{
    ptr = unpack_UINT16(ptr, &digest->size);
    ptr = unpack_BUFFER(ptr, digest->buffer, digest->size);
    return ptr;
}

static
inline BYTE* pack_TPMT_TK_CREATION(BYTE* ptr,const TPMT_TK_CREATION *ticket )
{
    ptr = pack_TPM_ST(ptr , &ticket->tag);
    ptr = pack_TPMI_RH_HIERACHY(ptr , &ticket->hierarchy);
    ptr = pack_TPM2B_DIGEST(ptr, &ticket->digest);
    return ptr;
}

static
inline BYTE* unpack_TPMT_TK_CREATION(BYTE* ptr, TPMT_TK_CREATION *ticket )
{
    ptr = unpack_TPM_ST(ptr, &ticket->tag);
    ptr = unpack_TPMI_RH_HIERACHY(ptr, &ticket->hierarchy);
    ptr = unpack_TPM2B_DIGEST(ptr, &ticket->digest);
    return ptr;
}

static
inline BYTE* pack_TPM2B_NAME(BYTE* ptr,const TPM2B_NAME *name )
{
    ptr = pack_UINT16(ptr, name->size);
    ptr = pack_TPM_BUFFER(ptr, name->name, name->size);
    return ptr;
}

static
inline BYTE* unpack_TPM2B_NAME(BYTE* ptr, TPM2B_NAME *name)
{
    ptr = unpack_UINT16(ptr, &name->size);
    ptr = unpack_TPM_BUFFER(ptr, name->name, name->size);
    return ptr;
}

static
inline BYTE* pack_TPM2B_NONCE(BYTE* ptr, const TPM2B_NONCE *nonce)
{
    return pack_TPM2B_DIGEST(ptr, (const TPM2B_DIGEST*)nonce);
}

#define unpack_TPM2B_NONCE(ptr, nonce)  unpack_TPM2B_DIGEST(ptr, (TPM2B_DIGEST*)nonce)

static
inline BYTE* pack_TPM2B_AUTH(BYTE* ptr, const TPM2B_AUTH *auth)
{
    return pack_TPM2B_DIGEST(ptr, (const TPM2B_DIGEST*)auth);
}

#define unpack_TPM2B_AUTH(ptr, auth)    unpack_TPM2B_DIGEST(ptr, (TPM2B_DIGEST*)auth)

static
inline BYTE* pack_TPM2B_DATA(BYTE* ptr, const TPM2B_DATA *data)
{
    return pack_TPM2B_DIGEST(ptr, (const TPM2B_DIGEST*)data);
}

#define unpack_TPM2B_DATA(ptr, data)    unpack_TPM2B_DIGEST(ptr, (TPM2B_DIGEST*)data)

static
inline BYTE* pack_TPM2B_SENSITIVE_DATA(BYTE* ptr, const TPM2B_SENSITIVE_DATA *data)
{
    return pack_TPM2B_DIGEST(ptr, (const TPM2B_DIGEST*)data);
}

#define unpack_TPM2B_SENSITIVE_DATA(ptr, data)  unpack_TPM2B_DIGEST(ptr, (TPM2B_DIGEST*)data)

static
inline BYTE* pack_TPM2B_PUBLIC_KEY_RSA(BYTE* ptr, const TPM2B_PUBLIC_KEY_RSA *rsa)
{
    return pack_TPM2B_DIGEST(ptr, (const TPM2B_DIGEST*)rsa);
}

#define unpack_TPM2B_PUBLIC_KEY_RSA(ptr, rsa)   unpack_TPM2B_DIGEST(ptr, (TPM2B_DIGEST*)rsa)

static
inline BYTE* pack_TPM2B_PRIVATE(BYTE* ptr, const TPM2B_PRIVATE *Private)
{
    ptr = pack_UINT16(ptr, Private->size);
    ptr = pack_TPM_BUFFER(ptr, Private->buffer, Private->size);
    return ptr;
}

static
inline BYTE* unpack_TPM2B_PRIVATE(BYTE* ptr, TPM2B_PRIVATE *Private)
{
    ptr = unpack_UINT16(ptr, &Private->size);
    ptr = unpack_BUFFER(ptr, Private->buffer, Private->size);
    return ptr;
}

static
inline BYTE* pack_TPMS_PCR_SELECTION_ARRAY(BYTE* ptr, const TPMS_PCR_SELECTION *sel, UINT32 count)
{
    int i;
    for (i = 0; i < count; i++) {
        ptr = pack_TPMI_ALG_HASH(ptr, &sel[i].hash);
        ptr = pack_BYTE(ptr, sel[i].sizeofSelect);
        ptr = pack_BUFFER(ptr, sel[i].pcrSelect, sel[i].sizeofSelect);
    }
    return ptr;
}

static
inline BYTE* unpack_TPMS_PCR_SELECTION_ARRAY(BYTE* ptr, TPMS_PCR_SELECTION *sel, UINT32 count)
{
    int i;
    for (i = 0; i < count; i++) {
        ptr = unpack_TPMI_ALG_HASH(ptr, &sel[i].hash);
        ptr = unpack_BYTE(ptr, &sel[i].sizeofSelect);
        ptr = unpack_BUFFER(ptr, sel[i].pcrSelect, sel[i].sizeofSelect);
    }
    return ptr;
}

static
inline BYTE* pack_TPML_PCR_SELECTION(BYTE* ptr, const TPML_PCR_SELECTION *sel)
{
    ptr = pack_UINT32(ptr, sel->count);
    ptr = pack_TPMS_PCR_SELECTION_ARRAY(ptr, sel->pcrSelections, sel->count);
    return ptr;
}

static
inline BYTE* unpack_TPML_PCR_SELECTION(BYTE* ptr, TPML_PCR_SELECTION *sel)
{
    ptr = unpack_UINT32(ptr, &sel->count);
    ptr = unpack_TPMS_PCR_SELECTION_ARRAY(ptr, sel->pcrSelections, sel->count);
    return ptr;
}

static
inline BYTE* unpack_TPML_DIGEST(BYTE* ptr,TPML_DIGEST *digest)
{
    int i;
    ptr = unpack_UINT32(ptr, &digest->count);
    for (i=0;i<digest->count;i++)
    {
        ptr = unpack_TPM2B_DIGEST(ptr, &digest->digests[i]);
    }
    return ptr;
}

static
inline BYTE* pack_TPMS_CREATION_DATA(BYTE* ptr,const TPMS_CREATION_DATA *data)
{
    ptr = pack_TPML_PCR_SELECTION(ptr, &data->pcrSelect);
    ptr = pack_TPM2B_DIGEST(ptr, &data->pcrDigest);
    ptr = pack_TPMA_LOCALITY(ptr, &data->locality);
    ptr = pack_TPM_ALG_ID(ptr, &data->parentNameAlg);
    ptr = pack_TPM2B_NAME(ptr, &data->parentQualifiedName);
    ptr = pack_TPM2B_DATA(ptr, &data->outsideInfo);
    return ptr;
}

static
inline BYTE* unpack_TPMS_CREATION_DATA(BYTE* ptr, TPMS_CREATION_DATA *data)
{
    ptr = unpack_TPML_PCR_SELECTION(ptr, &data->pcrSelect);
    ptr = unpack_TPM2B_DIGEST(ptr, &data->pcrDigest);
    ptr = unpack_TPMA_LOCALITY(ptr, &data->locality);
    ptr = unpack_TPM_ALG_ID(ptr, &data->parentNameAlg);
    ptr = unpack_TPM2B_NAME(ptr, &data->parentName);
    ptr = unpack_TPM2B_NAME(ptr, &data->parentQualifiedName);
    ptr = unpack_TPM2B_DATA(ptr, &data->outsideInfo);
    return ptr;
}

static
inline BYTE* pack_TPM2B_CREATION_DATA(BYTE* ptr, const TPM2B_CREATION_DATA *data )
{
    ptr = pack_UINT16(ptr, data->size);
    ptr = pack_TPMS_CREATION_DATA(ptr, &data->creationData);
    return ptr;
}

static
inline BYTE* unpack_TPM2B_CREATION_DATA(BYTE* ptr, TPM2B_CREATION_DATA * data)
{
    ptr = unpack_UINT16(ptr, &data->size);
    ptr = unpack_TPMS_CREATION_DATA(ptr, &data->creationData);
    return ptr;
}

static
inline BYTE* pack_TPMS_SENSITIVE_CREATE(BYTE* ptr, const TPMS_SENSITIVE_CREATE *create)
{
    ptr = pack_TPM2B_AUTH(ptr, &create->userAuth);
    ptr = pack_TPM2B_SENSITIVE_DATA(ptr, &create->data);
    return ptr;
}

static
inline BYTE* pack_TPM2B_SENSITIVE_CREATE(BYTE* ptr, const TPM2B_SENSITIVE_CREATE *create)
{
    BYTE* sizePtr = ptr;
    ptr += 2;
    ptr = pack_TPMS_SENSITIVE_CREATE(ptr, &create->sensitive);
    pack_UINT16(sizePtr, (UINT16)(ptr - sizePtr - 2));
    return ptr;
}

static
inline BYTE* pack_TPMU_SYM_MODE(BYTE* ptr, const TPMU_SYM_MODE *p,
                                const TPMI_ALG_SYM_OBJECT *sel)
{
    switch(*sel) {
    case TPM2_ALG_AES:
        ptr = pack_TPMI_ALG_SYM_MODE(ptr, &p->aes);
        break;
    case TPM2_ALG_SM4:
        assert(false);
        break;
    case TPM2_ALG_NULL:
        case TPM2_ALG_XOR:
        break;
    default:
        ptr = pack_TPMI_ALG_SYM_MODE(ptr, &p->sym);
    }
    return ptr;
}
static
inline BYTE* unpack_TPMU_SYM_MODE(BYTE* ptr, TPMU_SYM_MODE *p,
                                  const TPMI_ALG_SYM_OBJECT *sel)
{
    switch(*sel) {
    case TPM2_ALG_AES:
        ptr = unpack_TPMI_ALG_SYM_MODE(ptr, &p->aes);
        break;
    case TPM2_ALG_SM4:
        assert(false);
        break;
    case TPM2_ALG_NULL:
    case TPM2_ALG_XOR:
        break;
    default:
        ptr = unpack_TPMI_ALG_SYM_MODE(ptr, &p->sym);
    }
    return ptr;
}

static
inline BYTE* pack_TPMU_SYM_KEY_BITS(BYTE* ptr, const TPMU_SYM_KEY_BITS *p,
                                    const TPMI_ALG_SYM_OBJECT *sel)
{
    switch(*sel) {
    case TPM2_ALG_AES:
        ptr = pack_TPMI_AES_KEY_BITS(ptr, &p->aes);
        break;
    case TPM2_ALG_SM4:
        assert(false);
        break;
    case TPM2_ALG_XOR:
        assert(false);
        break;
    case TPM2_ALG_NULL:
        break;
    default:
        ptr = pack_TPM_KEY_BITS(ptr, &p->sym);
    }
    return ptr;
}

static
inline BYTE* unpack_TPMU_SYM_KEY_BITS(BYTE* ptr, TPMU_SYM_KEY_BITS *p,
                                      const TPMI_ALG_SYM_OBJECT *sel)
{
    switch(*sel) {
    case TPM2_ALG_AES:
        ptr = unpack_TPMI_AES_KEY_BITS(ptr, &p->aes);
        break;
    case TPM2_ALG_SM4:
        assert(false);
        break;
    case TPM2_ALG_XOR:
        assert(false);
        break;
    case TPM2_ALG_NULL:
        break;
    default:
        ptr = unpack_TPM_KEY_BITS(ptr, &p->sym);
    }
    return ptr;
}

static
inline BYTE* pack_TPMT_SYM_DEF_OBJECT(BYTE* ptr, const TPMT_SYM_DEF_OBJECT *p)
{
    ptr = pack_TPMI_ALG_SYM_OBJECT(ptr, &p->algorithm);
    ptr = pack_TPMU_SYM_KEY_BITS(ptr, &p->keyBits, &p->algorithm);
    ptr = pack_TPMU_SYM_MODE(ptr, &p->mode, &p->algorithm);
    return ptr;
}

static
inline BYTE* unpack_TPMT_SYM_DEF_OBJECT(BYTE *ptr, TPMT_SYM_DEF_OBJECT *p)
{
    ptr = unpack_TPMI_ALG_SYM_OBJECT(ptr, &p->algorithm);
    ptr = unpack_TPMU_SYM_KEY_BITS(ptr, &p->keyBits, &p->algorithm);
    ptr = unpack_TPMU_SYM_MODE(ptr, &p->mode, &p->algorithm);
    return ptr;
}

#define pack_TPMS_SCHEME_OAEP(p, t)     pack_TPMI_ALG_HASH(p, &((t)->hashAlg))
#define unpack_TPMS_SCHEME_OAEP(p, t)   unpack_TPMI_ALG_HASH(p, &((t)->hashAlg))

static
inline BYTE* pack_TPMU_ASYM_SCHEME(BYTE *ptr, const TPMU_ASYM_SCHEME *p,
                                   const TPMI_ALG_RSA_SCHEME *s)
{
    switch(*s) {
#ifdef TPM2_ALG_RSASSA
    case TPM2_ALG_RSASSA:
        assert(false || "TPM2_ALG_RSASSA");
        break;
#endif
#ifdef TPM2_ALG_OAEP
    case TPM2_ALG_OAEP:
        ptr = pack_TPMS_SCHEME_OAEP(ptr, &p->oaep);
        break;
#endif
    case TPM2_ALG_NULL:
        break;
    default:
        assert(false || "DEFAULT");
    }
    return ptr;
}

static
inline BYTE* unpack_TPMU_ASYM_SCHEME(BYTE *ptr, TPMU_ASYM_SCHEME *p,
                                     const TPMI_ALG_RSA_SCHEME *s)
{
    switch(*s) {
    #ifdef TPM2_ALG_RSASSA
    case TPM2_ALG_RSASSA:
        printf("not support TPM_ALG_RSASSA\n");
        assert(false);
        break;
    #endif
    #ifdef TPM2_ALG_OAEP
    case TPM2_ALG_OAEP:
        ptr = unpack_TPMS_SCHEME_OAEP(ptr, &p->oaep);
        break;
    #endif
    case TPM2_ALG_NULL:
        break;
    default:
        printf("default TPMI_ALG_RSA_SCHEME 0x%X\n", (UINT32)*s);
        ptr = unpack_TPMI_ALG_HASH(ptr, &p->anySig.hashAlg);
    }
    return ptr;
}

static
inline BYTE* pack_TPMT_RSA_SCHEME(BYTE* ptr, const TPMT_RSA_SCHEME *p)
{
    ptr = pack_TPMI_ALG_RSA_SCHEME(ptr, &p->scheme);
    ptr = pack_TPMU_ASYM_SCHEME(ptr, &p->details, &p->scheme);
    return ptr;
}

static
inline BYTE* unpack_TPMT_RSA_SCHEME(BYTE* ptr, TPMT_RSA_SCHEME *p)
{
    ptr = unpack_TPMI_ALG_RSA_SCHEME(ptr, &p->scheme);
    ptr = unpack_TPMU_ASYM_SCHEME(ptr, &p->details, &p->scheme);
    return ptr;
}

static
inline BYTE* pack_TPMT_RSA_DECRYPT(BYTE* ptr, const TPMT_RSA_DECRYPT *p)
{
    ptr = pack_TPMI_ALG_RSA_SCHEME(ptr, &p->scheme);
    ptr = pack_TPMU_ASYM_SCHEME(ptr, &p->details, &p->scheme);
    return ptr;
}

static
inline BYTE* pack_TPMS_RSA_PARMS(BYTE* ptr, const TPMS_RSA_PARMS *p)
{
    ptr = pack_TPMT_SYM_DEF_OBJECT(ptr, &p->symmetric);
    ptr = pack_TPMT_RSA_SCHEME(ptr, &p->scheme);
    ptr = pack_TPMI_RSA_KEY_BITS(ptr, &p->keyBits);
    ptr = pack_UINT32(ptr, p->exponent);
    return ptr;
}

static
inline BYTE* unpack_TPMS_RSA_PARMS(BYTE *ptr, TPMS_RSA_PARMS *p)
{
    ptr = unpack_TPMT_SYM_DEF_OBJECT(ptr, &p->symmetric);
    ptr = unpack_TPMT_RSA_SCHEME(ptr, &p->scheme);
    ptr = unpack_TPMI_RSA_KEY_BITS(ptr, &p->keyBits);
    ptr = unpack_UINT32(ptr, &p->exponent);
    return ptr;
}

static
inline BYTE* pack_TPMU_PUBLIC_PARMS(BYTE* ptr, const TPMU_PUBLIC_PARMS *param,
                                    const TPMI_ALG_PUBLIC *selector)
{
    switch(*selector) {
    case TPM2_ALG_KEYEDHASH:
        assert(false);
    case TPM2_ALG_SYMCIPHER:
        assert(false);
    case TPM2_ALG_RSA:
        return pack_TPMS_RSA_PARMS(ptr, &param->rsaDetail);
    case TPM2_ALG_ECC:
        assert(false);
    }
    assert(false);
    return NULL;
}

static
inline BYTE* unpack_TPMU_PUBLIC_PARMS(BYTE* ptr, TPMU_PUBLIC_PARMS *param,
                                      const TPMI_ALG_PUBLIC *selector)
{
    switch(*selector) {
    case TPM2_ALG_KEYEDHASH:
        assert(false);
    case TPM2_ALG_SYMCIPHER:
        assert(false);
    case TPM2_ALG_RSA:
        return unpack_TPMS_RSA_PARMS(ptr, &param->rsaDetail);
    case TPM2_ALG_ECC:
        assert(false);
    }
    assert(false);
    return NULL;
}

static
inline BYTE* pack_TPMS_ECC_POINT(BYTE* ptr, const TPMS_ECC_POINT *point)
{
    assert(false);
    return ptr;
}

static
inline BYTE* unpack_TPMS_ECC_POINT(BYTE* ptr, TPMS_ECC_POINT *point)
{
    assert(false);
    return ptr;
}

static
inline BYTE* pack_TPMU_PUBLIC_ID(BYTE* ptr, const TPMU_PUBLIC_ID *id,
                                 const TPMI_ALG_PUBLIC *selector)
{
    switch (*selector) {
    case TPM2_ALG_KEYEDHASH:
        return pack_TPM2B_DIGEST(ptr, &id->keyedHash);
    case TPM2_ALG_SYMCIPHER:
        return pack_TPM2B_DIGEST(ptr, &id->sym);
    case TPM2_ALG_RSA:
        return pack_TPM2B_PUBLIC_KEY_RSA(ptr, &id->rsa);
    case TPM2_ALG_ECC:
        return pack_TPMS_ECC_POINT(ptr, &id->ecc);
    }
    assert(false);
    return NULL;
}

static
inline BYTE* unpack_TPMU_PUBLIC_ID(BYTE* ptr, TPMU_PUBLIC_ID *id, TPMI_ALG_PUBLIC *selector)
{
    switch (*selector) {
    case TPM2_ALG_KEYEDHASH:
        return unpack_TPM2B_DIGEST(ptr, &id->keyedHash);
    case TPM2_ALG_SYMCIPHER:
        return unpack_TPM2B_DIGEST(ptr, &id->sym);
    case TPM2_ALG_RSA:
        return unpack_TPM2B_PUBLIC_KEY_RSA(ptr, &id->rsa);
    case TPM2_ALG_ECC:
        return unpack_TPMS_ECC_POINT(ptr, &id->ecc);
    }
    assert(false);
    return NULL;
}

static
inline BYTE* pack_TPMT_PUBLIC(BYTE* ptr, const TPMT_PUBLIC *public)
{
    ptr = pack_TPMI_ALG_PUBLIC(ptr, &public->type);
    ptr = pack_TPMI_ALG_HASH(ptr, &public->nameAlg);
    ptr = pack_TPMA_OBJECT(ptr, &public->objectAttributes);
    ptr = pack_TPM2B_DIGEST(ptr, &public->authPolicy);
    ptr = pack_TPMU_PUBLIC_PARMS(ptr, &public->parameters, &public->type);
    ptr = pack_TPMU_PUBLIC_ID(ptr, &public->unique, &public->type);
    return ptr;
}

static
inline BYTE* unpack_TPMT_PUBLIC(BYTE* ptr, TPMT_PUBLIC *public)
{
    ptr = unpack_TPMI_ALG_PUBLIC(ptr, &public->type);
    ptr = unpack_TPMI_ALG_HASH(ptr, &public->nameAlg);
    ptr = unpack_TPMA_OBJECT(ptr, &public->objectAttributes);
    ptr = unpack_TPM2B_DIGEST(ptr, &public->authPolicy);
    ptr = unpack_TPMU_PUBLIC_PARMS(ptr, &public->parameters, &public->type);
    ptr = unpack_TPMU_PUBLIC_ID(ptr, &public->unique, &public->type);
    return ptr;
}

static
inline BYTE* pack_TPM2B_PUBLIC(BYTE* ptr, const TPM2B_PUBLIC *public)
{
    BYTE *sizePtr = ptr;
    ptr += 2;
    ptr = pack_TPMT_PUBLIC(ptr, &public->publicArea);
    pack_UINT16(sizePtr, (UINT16)(ptr - sizePtr - 2));
    return ptr;
}

static
inline BYTE* unpack_TPM2B_PUBLIC(BYTE* ptr, TPM2B_PUBLIC *public)
{
    ptr = unpack_UINT16(ptr, &public->size);
    ptr = unpack_TPMT_PUBLIC(ptr, &public->publicArea);
    return ptr;
}

static
inline BYTE* pack_TPMS_PCR_SELECTION(BYTE* ptr, const TPMS_PCR_SELECTION *selection)
{
    ptr = pack_TPMI_ALG_HASH(ptr, &selection->hash);
    ptr = pack_BYTE(ptr, selection->sizeofSelect);
    ptr = pack_BYTE_ARRAY(ptr, selection->pcrSelect, selection->sizeofSelect);
    return ptr;
}

static
inline BYTE* pack_TPMS_PCR_SELECTION_Array(BYTE* ptr, const TPMS_PCR_SELECTION *selections,
                                           const UINT32 cnt)
{
    int i;
    for (i = 0; i < cnt; i++)
        ptr = pack_TPMS_PCR_SELECTION(ptr, selections + i);
    return ptr;
}

static
inline BYTE* pack_TPM_AuthArea(BYTE* ptr, const TPM_AuthArea *auth)
{
    BYTE* sizePtr = ptr;
    ptr += sizeof(UINT32);
    ptr = pack_TPM_RH(ptr, &auth->sessionHandle);
    ptr = pack_TPM2B_NONCE(ptr, &auth->nonce);
    ptr = pack_TPMA_SESSION(ptr, &auth->sessionAttributes);
    ptr = pack_TPM2B_AUTH(ptr, &auth->auth);
    pack_UINT32(sizePtr, ptr - sizePtr - sizeof(UINT32));
    return ptr;
}

static
inline BYTE* unpack_TPM_AuthArea(BYTE* ptr, TPM_AuthArea *auth)
{
    ptr = unpack_UINT32(ptr, &auth->size);
    ptr = unpack_TPM_RH(ptr, &auth->sessionHandle);
    ptr = unpack_TPM2B_NONCE(ptr, &auth->nonce);
    ptr = unpack_TPMA_SESSION(ptr, &auth->sessionAttributes);
    ptr = unpack_TPM2B_AUTH(ptr, &auth->auth);
    return ptr;
}

static
inline BYTE* pack_TPM2_RSA_KEY(BYTE* ptr, const TPM2_RSA_KEY *key)
{
    ptr = pack_TPM2B_PRIVATE(ptr, &key->Private);
    ptr = pack_TPM2B_PUBLIC(ptr, &key->Public);
    return ptr;
}

static
inline BYTE* unpack_TPM2_RSA_KEY(BYTE* ptr, TPM2_RSA_KEY *key)
{
    ptr = unpack_TPM2B_PRIVATE(ptr, &key->Private);
    ptr = unpack_TPM2B_PUBLIC(ptr, &key->Public);
    return ptr;
}
#endif
