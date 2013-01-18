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

#ifndef MARSHAL_H
#define MARSHAL_H

#include <stdlib.h>
#include <mini-os/byteorder.h>
#include <mini-os/endian.h>
#include "tcg.h"

typedef enum UnpackPtr {
   UNPACK_ALIAS,
   UNPACK_ALLOC
} UnpackPtr;

inline BYTE* pack_BYTE(BYTE* ptr, BYTE t) {
   ptr[0] = t;
   return ++ptr;
}

inline BYTE* unpack_BYTE(BYTE* ptr, BYTE* t) {
   t[0] = ptr[0];
   return ++ptr;
}

#define pack_BOOL(p, t) pack_BYTE(p, t)
#define unpack_BOOL(p, t) unpack_BYTE(p, t)

inline BYTE* pack_UINT16(BYTE* ptr, UINT16 t) {
   BYTE* b = (BYTE*)&t;
#if __BYTE_ORDER == __LITTLE_ENDIAN
   ptr[0] = b[1];
   ptr[1] = b[0];
#elif __BYTE_ORDER == __BIG_ENDIAN
   ptr[0] = b[0];
   ptr[1] = b[1];
#endif
   return ptr + sizeof(UINT16);
}

inline BYTE* unpack_UINT16(BYTE* ptr, UINT16* t) {
   BYTE* b = (BYTE*)t;
#if __BYTE_ORDER == __LITTLE_ENDIAN
   b[0] = ptr[1];
   b[1] = ptr[0];
#elif __BYTE_ORDER == __BIG_ENDIAN
   b[0] = ptr[0];
   b[1] = ptr[1];
#endif
   return ptr + sizeof(UINT16);
}

inline BYTE* pack_UINT32(BYTE* ptr, UINT32 t) {
   BYTE* b = (BYTE*)&t;
#if __BYTE_ORDER == __LITTLE_ENDIAN
   ptr[3] = b[0];
   ptr[2] = b[1];
   ptr[1] = b[2];
   ptr[0] = b[3];
#elif __BYTE_ORDER == __BIG_ENDIAN
   ptr[0] = b[0];
   ptr[1] = b[1];
   ptr[2] = b[2];
   ptr[3] = b[3];
#endif
   return ptr + sizeof(UINT32);
}

inline BYTE* unpack_UINT32(BYTE* ptr, UINT32* t) {
   BYTE* b = (BYTE*)t;
#if __BYTE_ORDER == __LITTLE_ENDIAN
   b[0] = ptr[3];
   b[1] = ptr[2];
   b[2] = ptr[1];
   b[3] = ptr[0];
#elif __BYTE_ORDER == __BIG_ENDIAN
   b[0] = ptr[0];
   b[1] = ptr[1];
   b[2] = ptr[2];
   b[3] = ptr[3];
#endif
   return ptr + sizeof(UINT32);
}

#define pack_TPM_RESULT(p, t) pack_UINT32(p, t)
#define pack_TPM_PCRINDEX(p, t) pack_UINT32(p, t)
#define pack_TPM_DIRINDEX(p, t) pack_UINT32(p, t)
#define pack_TPM_HANDLE(p, t) pack_UINT32(p, t)
#define pack_TPM_AUTHHANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TCPA_HASHHANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TCPA_HMACHANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TCPA_ENCHANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TPM_KEY_HANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TCPA_ENTITYHANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TPM_RESOURCE_TYPE(p, t) pack_UINT32(p, t)
#define pack_TPM_COMMAND_CODE(p, t) pack_UINT32(p, t)
#define pack_TPM_PROTOCOL_ID(p, t) pack_UINT16(p, t)
#define pack_TPM_AUTH_DATA_USAGE(p, t) pack_BYTE(p, t)
#define pack_TPM_ENTITY_TYPE(p, t) pack_UINT16(p, t)
#define pack_TPM_ALGORITHM_ID(p, t) pack_UINT32(p, t)
#define pack_TPM_KEY_USAGE(p, t) pack_UINT16(p, t)
#define pack_TPM_STARTUP_TYPE(p, t) pack_UINT16(p, t)
#define pack_TPM_CAPABILITY_AREA(p, t) pack_UINT32(p, t)
#define pack_TPM_ENC_SCHEME(p, t) pack_UINT16(p, t)
#define pack_TPM_SIG_SCHEME(p, t) pack_UINT16(p, t)
#define pack_TPM_MIGRATE_SCHEME(p, t) pack_UINT16(p, t)
#define pack_TPM_PHYSICAL_PRESENCE(p, t) pack_UINT16(p, t)
#define pack_TPM_KEY_FLAGS(p, t) pack_UINT32(p, t)

#define unpack_TPM_RESULT(p, t) unpack_UINT32(p, t)
#define unpack_TPM_PCRINDEX(p, t) unpack_UINT32(p, t)
#define unpack_TPM_DIRINDEX(p, t) unpack_UINT32(p, t)
#define unpack_TPM_HANDLE(p, t) unpack_UINT32(p, t)
#define unpack_TPM_AUTHHANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TCPA_HASHHANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TCPA_HMACHANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TCPA_ENCHANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TPM_KEY_HANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TCPA_ENTITYHANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TPM_RESOURCE_TYPE(p, t) unpack_UINT32(p, t)
#define unpack_TPM_COMMAND_CODE(p, t) unpack_UINT32(p, t)
#define unpack_TPM_PROTOCOL_ID(p, t) unpack_UINT16(p, t)
#define unpack_TPM_AUTH_DATA_USAGE(p, t) unpack_BYTE(p, t)
#define unpack_TPM_ENTITY_TYPE(p, t) unpack_UINT16(p, t)
#define unpack_TPM_ALGORITHM_ID(p, t) unpack_UINT32(p, t)
#define unpack_TPM_KEY_USAGE(p, t) unpack_UINT16(p, t)
#define unpack_TPM_STARTUP_TYPE(p, t) unpack_UINT16(p, t)
#define unpack_TPM_CAPABILITY_AREA(p, t) unpack_UINT32(p, t)
#define unpack_TPM_ENC_SCHEME(p, t) unpack_UINT16(p, t)
#define unpack_TPM_SIG_SCHEME(p, t) unpack_UINT16(p, t)
#define unpack_TPM_MIGRATE_SCHEME(p, t) unpack_UINT16(p, t)
#define unpack_TPM_PHYSICAL_PRESENCE(p, t) unpack_UINT16(p, t)
#define unpack_TPM_KEY_FLAGS(p, t) unpack_UINT32(p, t)

#define pack_TPM_AUTH_HANDLE(p, t) pack_UINT32(p, t);
#define pack_TCS_CONTEXT_HANDLE(p, t) pack_UINT32(p, t);
#define pack_TCS_KEY_HANDLE(p, t) pack_UINT32(p, t);

#define unpack_TPM_AUTH_HANDLE(p, t) unpack_UINT32(p, t);
#define unpack_TCS_CONTEXT_HANDLE(p, t) unpack_UINT32(p, t);
#define unpack_TCS_KEY_HANDLE(p, t) unpack_UINT32(p, t);

inline BYTE* pack_BUFFER(BYTE* ptr, const BYTE* buf, UINT32 size) {
   memcpy(ptr, buf, size);
   return ptr + size;
}

inline BYTE* unpack_BUFFER(BYTE* ptr, BYTE* buf, UINT32 size) {
   memcpy(buf, ptr, size);
   return ptr + size;
}

inline BYTE* unpack_ALIAS(BYTE* ptr, BYTE** buf, UINT32 size) {
   *buf = ptr;
   return ptr + size;
}

inline BYTE* unpack_ALLOC(BYTE* ptr, BYTE** buf, UINT32 size) {
   if(size) {
      *buf = malloc(size);
      memcpy(*buf, ptr, size);
   } else {
      *buf = NULL;
   }
   return ptr + size;
}

inline BYTE* unpack_PTR(BYTE* ptr, BYTE** buf, UINT32 size, UnpackPtr alloc) {
   if(alloc == UNPACK_ALLOC) {
      return unpack_ALLOC(ptr, buf, size);
   } else {
      return unpack_ALIAS(ptr, buf, size);
   }
}

inline BYTE* pack_TPM_AUTHDATA(BYTE* ptr, const TPM_AUTHDATA* d) {
   return pack_BUFFER(ptr, *d, TPM_DIGEST_SIZE);
}

inline BYTE* unpack_TPM_AUTHDATA(BYTE* ptr, TPM_AUTHDATA* d) {
   return unpack_BUFFER(ptr, *d, TPM_DIGEST_SIZE);
}

#define pack_TPM_SECRET(p, t) pack_TPM_AUTHDATA(p, t)
#define pack_TPM_ENCAUTH(p, t) pack_TPM_AUTHDATA(p, t)
#define pack_TPM_PAYLOAD_TYPE(p, t) pack_BYTE(p, t)
#define pack_TPM_TAG(p, t) pack_UINT16(p, t)
#define pack_TPM_STRUCTURE_TAG(p, t) pack_UINT16(p, t)

#define unpack_TPM_SECRET(p, t) unpack_TPM_AUTHDATA(p, t)
#define unpack_TPM_ENCAUTH(p, t) unpack_TPM_AUTHDATA(p, t)
#define unpack_TPM_PAYLOAD_TYPE(p, t) unpack_BYTE(p, t)
#define unpack_TPM_TAG(p, t) unpack_UINT16(p, t)
#define unpack_TPM_STRUCTURE_TAG(p, t) unpack_UINT16(p, t)

inline BYTE* pack_TPM_VERSION(BYTE* ptr, const TPM_VERSION* t) {
   ptr[0] = t->major;
   ptr[1] = t->minor;
   ptr[2] = t->revMajor;
   ptr[3] = t->revMinor;
   return ptr + 4;
}

inline BYTE* unpack_TPM_VERSION(BYTE* ptr, TPM_VERSION* t) {
   t->major = ptr[0];
   t->minor = ptr[1];
   t->revMajor = ptr[2];
   t->revMinor = ptr[3];
   return ptr + 4;
}

inline BYTE* pack_TPM_CAP_VERSION_INFO(BYTE* ptr, const TPM_CAP_VERSION_INFO* v) {
   ptr = pack_TPM_STRUCTURE_TAG(ptr, v->tag);
   ptr = pack_TPM_VERSION(ptr, &v->version);
   ptr = pack_UINT16(ptr, v->specLevel);
   ptr = pack_BYTE(ptr, v->errataRev);
   ptr = pack_BUFFER(ptr, v->tpmVendorID, sizeof(v->tpmVendorID));
   ptr = pack_UINT16(ptr, v->vendorSpecificSize);
   ptr = pack_BUFFER(ptr, v->vendorSpecific, v->vendorSpecificSize);
   return ptr;
}

inline BYTE* unpack_TPM_CAP_VERSION_INFO(BYTE* ptr, TPM_CAP_VERSION_INFO* v, UnpackPtr alloc) {
   ptr = unpack_TPM_STRUCTURE_TAG(ptr, &v->tag);
   ptr = unpack_TPM_VERSION(ptr, &v->version);
   ptr = unpack_UINT16(ptr, &v->specLevel);
   ptr = unpack_BYTE(ptr, &v->errataRev);
   ptr = unpack_BUFFER(ptr, v->tpmVendorID, sizeof(v->tpmVendorID));
   ptr = unpack_UINT16(ptr, &v->vendorSpecificSize);
   ptr = unpack_PTR(ptr, &v->vendorSpecific, v->vendorSpecificSize, alloc);
   return ptr;
}

inline BYTE* pack_TPM_DIGEST(BYTE* ptr, const TPM_DIGEST* d) {
   return pack_BUFFER(ptr, d->digest, TPM_DIGEST_SIZE);
}

inline BYTE* unpack_TPM_DIGEST(BYTE* ptr, TPM_DIGEST* d) {
   return unpack_BUFFER(ptr, d->digest, TPM_DIGEST_SIZE);
}

#define pack_TPM_PCRVALUE(ptr, d) pack_TPM_DIGEST(ptr, d);
#define unpack_TPM_PCRVALUE(ptr, d) unpack_TPM_DIGEST(ptr, d);

#define pack_TPM_COMPOSITE_HASH(ptr, d) pack_TPM_DIGEST(ptr, d);
#define unpack_TPM_COMPOSITE_HASH(ptr, d) unpack_TPM_DIGEST(ptr, d);

#define pack_TPM_DIRVALUE(ptr, d) pack_TPM_DIGEST(ptr, d);
#define unpack_TPM_DIRVALUE(ptr, d) unpack_TPM_DIGEST(ptr, d);

#define pack_TPM_HMAC(ptr, d) pack_TPM_DIGEST(ptr, d);
#define unpack_TPM_HMAC(ptr, d) unpack_TPM_DIGEST(ptr, d);

#define pack_TPM_CHOSENID_HASH(ptr, d) pack_TPM_DIGEST(ptr, d);
#define unpack_TPM_CHOSENID_HASH(ptr, d) unpack_TPM_DIGEST(ptr, d);

inline BYTE* pack_TPM_NONCE(BYTE* ptr, const TPM_NONCE* n) {
   return pack_BUFFER(ptr, n->nonce, TPM_DIGEST_SIZE);
}

inline BYTE* unpack_TPM_NONCE(BYTE* ptr, TPM_NONCE* n) {
   return unpack_BUFFER(ptr, n->nonce, TPM_DIGEST_SIZE);
}

inline BYTE* pack_TPM_SYMMETRIC_KEY_PARMS(BYTE* ptr, const TPM_SYMMETRIC_KEY_PARMS* k) {
   ptr = pack_UINT32(ptr, k->keyLength);
   ptr = pack_UINT32(ptr, k->blockSize);
   ptr = pack_UINT32(ptr, k->ivSize);
   return pack_BUFFER(ptr, k->IV, k->ivSize);
}

inline BYTE* unpack_TPM_SYMMETRIC_KEY_PARMS(BYTE* ptr, TPM_SYMMETRIC_KEY_PARMS* k, UnpackPtr alloc) {
   ptr = unpack_UINT32(ptr, &k->keyLength);
   ptr = unpack_UINT32(ptr, &k->blockSize);
   ptr = unpack_UINT32(ptr, &k->ivSize);
   return unpack_PTR(ptr, &k->IV, k->ivSize, alloc);
}

inline BYTE* pack_TPM_RSA_KEY_PARMS(BYTE* ptr, const TPM_RSA_KEY_PARMS* k) {
   ptr = pack_UINT32(ptr, k->keyLength);
   ptr = pack_UINT32(ptr, k->numPrimes);
   ptr = pack_UINT32(ptr, k->exponentSize);
   return pack_BUFFER(ptr, k->exponent, k->exponentSize);
}

inline BYTE* unpack_TPM_RSA_KEY_PARMS(BYTE* ptr, TPM_RSA_KEY_PARMS* k, UnpackPtr alloc) {
   ptr = unpack_UINT32(ptr, &k->keyLength);
   ptr = unpack_UINT32(ptr, &k->numPrimes);
   ptr = unpack_UINT32(ptr, &k->exponentSize);
   return unpack_PTR(ptr, &k->exponent, k->exponentSize, alloc);
}

inline BYTE* pack_TPM_KEY_PARMS(BYTE* ptr, const TPM_KEY_PARMS* k) {
   ptr = pack_TPM_ALGORITHM_ID(ptr, k->algorithmID);
   ptr = pack_TPM_ENC_SCHEME(ptr, k->encScheme);
   ptr = pack_TPM_SIG_SCHEME(ptr, k->sigScheme);
   ptr = pack_UINT32(ptr, k->parmSize);

   if(k->parmSize) {
      switch(k->algorithmID) {
         case TPM_ALG_RSA:
            return pack_TPM_RSA_KEY_PARMS(ptr, &k->parms.rsa);
         case TPM_ALG_AES128:
         case TPM_ALG_AES192:
         case TPM_ALG_AES256:
            return pack_TPM_SYMMETRIC_KEY_PARMS(ptr, &k->parms.sym);
      }
   }
   return ptr;
}

inline BYTE* unpack_TPM_KEY_PARMS(BYTE* ptr, TPM_KEY_PARMS* k, UnpackPtr alloc) {
   ptr = unpack_TPM_ALGORITHM_ID(ptr, &k->algorithmID);
   ptr = unpack_TPM_ENC_SCHEME(ptr, &k->encScheme);
   ptr = unpack_TPM_SIG_SCHEME(ptr, &k->sigScheme);
   ptr = unpack_UINT32(ptr, &k->parmSize);

   if(k->parmSize) {
      switch(k->algorithmID) {
         case TPM_ALG_RSA:
            return unpack_TPM_RSA_KEY_PARMS(ptr, &k->parms.rsa, alloc);
         case TPM_ALG_AES128:
         case TPM_ALG_AES192:
         case TPM_ALG_AES256:
            return unpack_TPM_SYMMETRIC_KEY_PARMS(ptr, &k->parms.sym, alloc);
      }
   }
   return ptr;
}

inline BYTE* pack_TPM_STORE_PUBKEY(BYTE* ptr, const TPM_STORE_PUBKEY* k) {
   ptr = pack_UINT32(ptr, k->keyLength);
   ptr = pack_BUFFER(ptr, k->key, k->keyLength);
   return ptr;
}

inline BYTE* unpack_TPM_STORE_PUBKEY(BYTE* ptr, TPM_STORE_PUBKEY* k, UnpackPtr alloc) {
   ptr = unpack_UINT32(ptr, &k->keyLength);
   ptr = unpack_PTR(ptr, &k->key, k->keyLength, alloc);
   return ptr;
}

inline BYTE* pack_TPM_PUBKEY(BYTE* ptr, const TPM_PUBKEY* k) {
   ptr = pack_TPM_KEY_PARMS(ptr, &k->algorithmParms);
   return pack_TPM_STORE_PUBKEY(ptr, &k->pubKey);
}

inline BYTE* unpack_TPM_PUBKEY(BYTE* ptr, TPM_PUBKEY* k, UnpackPtr alloc) {
   ptr = unpack_TPM_KEY_PARMS(ptr, &k->algorithmParms, alloc);
   return unpack_TPM_STORE_PUBKEY(ptr, &k->pubKey, alloc);
}

inline BYTE* pack_TPM_PCR_SELECTION(BYTE* ptr, const TPM_PCR_SELECTION* p) {
   ptr = pack_UINT16(ptr, p->sizeOfSelect);
   ptr = pack_BUFFER(ptr, p->pcrSelect, p->sizeOfSelect);
   return ptr;
}

inline BYTE* unpack_TPM_PCR_SELECTION(BYTE* ptr, TPM_PCR_SELECTION* p, UnpackPtr alloc) {
   ptr = unpack_UINT16(ptr, &p->sizeOfSelect);
   ptr = unpack_PTR(ptr, &p->pcrSelect, p->sizeOfSelect, alloc);
   return ptr;
}

inline BYTE* pack_TPM_PCR_INFO(BYTE* ptr, const TPM_PCR_INFO* p) {
   ptr = pack_TPM_PCR_SELECTION(ptr, &p->pcrSelection);
   ptr = pack_TPM_COMPOSITE_HASH(ptr, &p->digestAtRelease);
   ptr = pack_TPM_COMPOSITE_HASH(ptr, &p->digestAtCreation);
   return ptr;
}

inline BYTE* unpack_TPM_PCR_INFO(BYTE* ptr, TPM_PCR_INFO* p, UnpackPtr alloc) {
   ptr = unpack_TPM_PCR_SELECTION(ptr, &p->pcrSelection, alloc);
   ptr = unpack_TPM_COMPOSITE_HASH(ptr, &p->digestAtRelease);
   ptr = unpack_TPM_COMPOSITE_HASH(ptr, &p->digestAtCreation);
   return ptr;
}

inline BYTE* pack_TPM_PCR_COMPOSITE(BYTE* ptr, const TPM_PCR_COMPOSITE* p) {
   ptr = pack_TPM_PCR_SELECTION(ptr, &p->select);
   ptr = pack_UINT32(ptr, p->valueSize);
   ptr = pack_BUFFER(ptr, (const BYTE*)p->pcrValue, p->valueSize);
   return ptr;
}

inline BYTE* unpack_TPM_PCR_COMPOSITE(BYTE* ptr, TPM_PCR_COMPOSITE* p, UnpackPtr alloc) {
   ptr = unpack_TPM_PCR_SELECTION(ptr, &p->select, alloc);
   ptr = unpack_UINT32(ptr, &p->valueSize);
   ptr = unpack_PTR(ptr, (BYTE**)&p->pcrValue, p->valueSize, alloc);
   return ptr;
}

inline BYTE* pack_TPM_KEY(BYTE* ptr, const TPM_KEY* k) {
   ptr = pack_TPM_VERSION(ptr, &k->ver);
   ptr = pack_TPM_KEY_USAGE(ptr, k->keyUsage);
   ptr = pack_TPM_KEY_FLAGS(ptr, k->keyFlags);
   ptr = pack_TPM_AUTH_DATA_USAGE(ptr, k->authDataUsage);
   ptr = pack_TPM_KEY_PARMS(ptr, &k->algorithmParms);
   ptr = pack_UINT32(ptr, k->PCRInfoSize);
   if(k->PCRInfoSize) {
      ptr = pack_TPM_PCR_INFO(ptr, &k->PCRInfo);
   }
   ptr = pack_TPM_STORE_PUBKEY(ptr, &k->pubKey);
   ptr = pack_UINT32(ptr, k->encDataSize);
   return pack_BUFFER(ptr, k->encData, k->encDataSize);
}

inline BYTE* unpack_TPM_KEY(BYTE* ptr, TPM_KEY* k, UnpackPtr alloc) {
   ptr = unpack_TPM_VERSION(ptr, &k->ver);
   ptr = unpack_TPM_KEY_USAGE(ptr, &k->keyUsage);
   ptr = unpack_TPM_KEY_FLAGS(ptr, &k->keyFlags);
   ptr = unpack_TPM_AUTH_DATA_USAGE(ptr, &k->authDataUsage);
   ptr = unpack_TPM_KEY_PARMS(ptr, &k->algorithmParms, alloc);
   ptr = unpack_UINT32(ptr, &k->PCRInfoSize);
   if(k->PCRInfoSize) {
      ptr = unpack_TPM_PCR_INFO(ptr, &k->PCRInfo, alloc);
   }
   ptr = unpack_TPM_STORE_PUBKEY(ptr, &k->pubKey, alloc);
   ptr = unpack_UINT32(ptr, &k->encDataSize);
   return unpack_PTR(ptr, &k->encData, k->encDataSize, alloc);
}

inline BYTE* pack_TPM_BOUND_DATA(BYTE* ptr, const TPM_BOUND_DATA* b, UINT32 payloadSize) {
   ptr = pack_TPM_VERSION(ptr, &b->ver);
   ptr = pack_TPM_PAYLOAD_TYPE(ptr, b->payload);
   return pack_BUFFER(ptr, b->payloadData, payloadSize);
}

inline BYTE* unpack_TPM_BOUND_DATA(BYTE* ptr, TPM_BOUND_DATA* b, UINT32 payloadSize, UnpackPtr alloc) {
   ptr = unpack_TPM_VERSION(ptr, &b->ver);
   ptr = unpack_TPM_PAYLOAD_TYPE(ptr, &b->payload);
   return unpack_PTR(ptr, &b->payloadData, payloadSize, alloc);
}

inline BYTE* pack_TPM_STORED_DATA(BYTE* ptr, const TPM_STORED_DATA* d) {
   ptr = pack_TPM_VERSION(ptr, &d->ver);
   ptr = pack_UINT32(ptr, d->sealInfoSize);
   if(d->sealInfoSize) {
      ptr = pack_TPM_PCR_INFO(ptr, &d->sealInfo);
   }
   ptr = pack_UINT32(ptr, d->encDataSize);
   ptr = pack_BUFFER(ptr, d->encData, d->encDataSize);
   return ptr;
}

inline BYTE* unpack_TPM_STORED_DATA(BYTE* ptr, TPM_STORED_DATA* d, UnpackPtr alloc) {
   ptr = unpack_TPM_VERSION(ptr, &d->ver);
   ptr = unpack_UINT32(ptr, &d->sealInfoSize);
   if(d->sealInfoSize) {
      ptr = unpack_TPM_PCR_INFO(ptr, &d->sealInfo, alloc);
   }
   ptr = unpack_UINT32(ptr, &d->encDataSize);
   ptr = unpack_PTR(ptr, &d->encData, d->encDataSize, alloc);
   return ptr;
}

inline BYTE* pack_TPM_AUTH_SESSION(BYTE* ptr, const TPM_AUTH_SESSION* auth) {
   ptr = pack_TPM_AUTH_HANDLE(ptr, auth->AuthHandle);
   ptr = pack_TPM_NONCE(ptr, &auth->NonceOdd);
   ptr = pack_BOOL(ptr, auth->fContinueAuthSession);
   ptr = pack_TPM_AUTHDATA(ptr, &auth->HMAC);
   return ptr;
}

inline BYTE* unpack_TPM_AUTH_SESSION(BYTE* ptr, TPM_AUTH_SESSION* auth) {
   ptr = unpack_TPM_NONCE(ptr, &auth->NonceEven);
   ptr = unpack_BOOL(ptr, &auth->fContinueAuthSession);
   ptr = unpack_TPM_AUTHDATA(ptr, &auth->HMAC);
   return ptr;
}

inline BYTE* pack_TPM_RQU_HEADER(BYTE* ptr,
      TPM_TAG tag,
      UINT32 size,
      TPM_COMMAND_CODE ord) {
   ptr = pack_UINT16(ptr, tag);
   ptr = pack_UINT32(ptr, size);
   return pack_UINT32(ptr, ord);
}

inline BYTE* unpack_TPM_RQU_HEADER(BYTE* ptr,
      TPM_TAG* tag,
      UINT32* size,
      TPM_COMMAND_CODE* ord) {
   ptr = unpack_UINT16(ptr, tag);
   ptr = unpack_UINT32(ptr, size);
   ptr = unpack_UINT32(ptr, ord);
   return ptr;
}

#define pack_TPM_RSP_HEADER(p, t, s, r) pack_TPM_RQU_HEADER(p, t, s, r);
#define unpack_TPM_RSP_HEADER(p, t, s, r) unpack_TPM_RQU_HEADER(p, t, s, r);

#endif
