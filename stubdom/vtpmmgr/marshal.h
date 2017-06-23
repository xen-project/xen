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

static
inline BYTE* pack_BYTE(BYTE* ptr, BYTE t) {
	ptr[0] = t;
	return ++ptr;
}

static
inline BYTE* unpack_BYTE(BYTE* ptr, BYTE* t) {
	t[0] = ptr[0];
	return ++ptr;
}

static
inline int unpack3_BYTE(BYTE* ptr, UINT32* pos, UINT32 max, BYTE *t)
{
	if (*pos + 1 > max)
		return TPM_SIZE;
	unpack_BYTE(ptr + *pos, t);
	*pos += 1;
	return 0;
}


#define pack_BOOL(p, t) pack_BYTE(p, t)
#define unpack_BOOL(p, t) unpack_BYTE(p, t)
#define unpack3_BOOL(p, x, m, t) unpack3_BYTE(p, x, m, t)
#define sizeof_BOOL(t) 1

static
inline BYTE* pack_UINT16(void* ptr, UINT16 t) {
	UINT16* p = ptr;
	*p = cpu_to_be16(t);
	return ptr + sizeof(UINT16);
}

static
inline BYTE* unpack_UINT16(void* ptr, UINT16* t) {
	UINT16* p = ptr;
	*t = be16_to_cpu(*p);
	return ptr + sizeof(UINT16);
}

static
inline int unpack3_UINT16(BYTE* ptr, UINT32* pos, UINT32 max, UINT16 *t)
{
	if (*pos + 2 > max)
		return TPM_SIZE;
	unpack_UINT16(ptr + *pos, t);
	*pos += 2;
	return 0;
}

static
inline BYTE* pack_UINT32(void* ptr, UINT32 t) {
	UINT32* p = ptr;
	*p = cpu_to_be32(t);
	return ptr + sizeof(UINT32);
}

static
inline BYTE* unpack_UINT32(void* ptr, UINT32* t) {
	UINT32* p = ptr;
	*t = be32_to_cpu(*p);
	return ptr + sizeof(UINT32);
}

static
inline int unpack3_UINT32(BYTE* ptr, UINT32* pos, UINT32 max, UINT32 *t)
{
	if (*pos + 4 > max)
		return TPM_SIZE;
	unpack_UINT32(ptr + *pos, t);
	*pos += 4;
	return 0;
}

#define sizeof_BYTE(x) 1
#define sizeof_UINT16(x) 2
#define sizeof_UINT32(x) 4

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
#define pack_TPM_LOCALITY_SELECTION(p, t) pack_BYTE(p, t)

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
#define unpack_TPM_LOCALITY_SELECTION(p, t) unpack_BYTE(p, t)

#define unpack3_TPM_RESULT(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_PCRINDEX(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_DIRINDEX(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_HANDLE(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_AUTHHANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TCPA_HASHHANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TCPA_HMACHANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TCPA_ENCHANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TPM_KEY_HANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TCPA_ENTITYHANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TPM_RESOURCE_TYPE(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_COMMAND_CODE(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_PROTOCOL_ID(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_AUTH_DATA_USAGE(p, l, m, t) unpack3_BYTE(p, l, m, t)
#define unpack3_TPM_ENTITY_TYPE(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_ALGORITHM_ID(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_KEY_USAGE(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_STARTUP_TYPE(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_CAPABILITY_AREA(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_ENC_SCHEME(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_SIG_SCHEME(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_MIGRATE_SCHEME(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_PHYSICAL_PRESENCE(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_KEY_FLAGS(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_LOCALITY_SELECTION(p, l, m, t) unpack3_BYTE(p, l, m, t)
#define unpack3_TPM_DEEP_QUOTE_INFO(p, l, m, t) unpack3_UINT32(p, l, m, t)

#define sizeof_TPM_RESULT(t) sizeof_UINT32(t)
#define sizeof_TPM_PCRINDEX(t) sizeof_UINT32(t)
#define sizeof_TPM_DIRINDEX(t) sizeof_UINT32(t)
#define sizeof_TPM_HANDLE(t) sizeof_UINT32(t)
#define sizeof_TPM_AUTHHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_HASHHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_HMACHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_ENCHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TPM_KEY_HANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_ENTITYHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TPM_RESOURCE_TYPE(t) sizeof_UINT32(t)
#define sizeof_TPM_COMMAND_CODE(t) sizeof_UINT32(t)
#define sizeof_TPM_PROTOCOL_ID(t) sizeof_UINT16(t)
#define sizeof_TPM_AUTH_DATA_USAGE(t) sizeof_BYTE(t)
#define sizeof_TPM_ENTITY_TYPE(t) sizeof_UINT16(t)
#define sizeof_TPM_ALGORITHM_ID(t) sizeof_UINT32(t)
#define sizeof_TPM_KEY_USAGE(t) sizeof_UINT16(t)
#define sizeof_TPM_STARTUP_TYPE(t) sizeof_UINT16(t)
#define sizeof_TPM_CAPABILITY_AREA(t) sizeof_UINT32(t)
#define sizeof_TPM_ENC_SCHEME(t) sizeof_UINT16(t)
#define sizeof_TPM_SIG_SCHEME(t) sizeof_UINT16(t)
#define sizeof_TPM_MIGRATE_SCHEME(t) sizeof_UINT16(t)
#define sizeof_TPM_PHYSICAL_PRESENCE(t) sizeof_UINT16(t)
#define sizeof_TPM_KEY_FLAGS(t) sizeof_UINT32(t)
#define sizeof_TPM_LOCALITY_SELECTION(t) sizeof_BYTE(t)

#define pack_TPM_AUTH_HANDLE(p, t) pack_UINT32(p, t)
#define pack_TCS_CONTEXT_HANDLE(p, t) pack_UINT32(p, t)
#define pack_TCS_KEY_HANDLE(p, t) pack_UINT32(p, t)

#define unpack_TPM_AUTH_HANDLE(p, t) unpack_UINT32(p, t)
#define unpack_TCS_CONTEXT_HANDLE(p, t) unpack_UINT32(p, t)
#define unpack_TCS_KEY_HANDLE(p, t) unpack_UINT32(p, t)

#define sizeof_TPM_AUTH_HANDLE(t) sizeof_UINT32(t)
#define sizeof_TCS_CONTEXT_HANDLE(t) sizeof_UINT32(t)
#define sizeof_TCS_KEY_HANDLE(t) sizeof_UINT32(t)


static
inline BYTE* pack_BUFFER(BYTE* ptr, const BYTE* buf, UINT32 size) {
	memcpy(ptr, buf, size);
	return ptr + size;
}

static
inline BYTE* unpack_BUFFER(BYTE* ptr, BYTE* buf, UINT32 size) {
	memcpy(buf, ptr, size);
	return ptr + size;
}

static
inline int unpack3_BUFFER(BYTE* ptr, UINT32* pos, UINT32 max, BYTE* buf, UINT32 size) {
	if (*pos + size > max)
		return TPM_SIZE;
	memcpy(buf, ptr + *pos, size);
	*pos += size;
	return 0;
}

#define sizeof_BUFFER(b, s) s

static
inline BYTE* unpack_ALIAS(BYTE* ptr, BYTE** buf, UINT32 size) {
	*buf = ptr;
	return ptr + size;
}

static
inline BYTE* unpack_ALLOC(BYTE* ptr, BYTE** buf, UINT32 size) {
	if(size) {
		*buf = malloc(size);
		memcpy(*buf, ptr, size);
	} else {
		*buf = NULL;
	}
	return ptr + size;
}

static
inline BYTE* unpack_PTR(BYTE* ptr, BYTE** buf, UINT32 size, UnpackPtr alloc) {
	if(alloc == UNPACK_ALLOC) {
		return unpack_ALLOC(ptr, buf, size);
	} else {
		return unpack_ALIAS(ptr, buf, size);
	}
}

static
inline int unpack3_PTR(BYTE* ptr, UINT32* pos, UINT32 max, BYTE** buf, UINT32 size, UnpackPtr alloc) {
	if (size > max || *pos + size > max)
		return TPM_SIZE;
	if (alloc == UNPACK_ALLOC) {
		unpack_ALLOC(ptr + *pos, buf, size);
	} else {
		unpack_ALIAS(ptr + *pos, buf, size);
	}
	*pos += size;
	return 0;
}
#define unpack3_VPTR(ptr, pos, max, buf, size, alloc) unpack3_PTR(ptr, pos, max, (void*)(buf), size, alloc)

static
inline BYTE* pack_TPM_AUTHDATA(BYTE* ptr, const TPM_AUTHDATA* d) {
	return pack_BUFFER(ptr, *d, TPM_DIGEST_SIZE);
}

static
inline BYTE* unpack_TPM_AUTHDATA(BYTE* ptr, TPM_AUTHDATA* d) {
	return unpack_BUFFER(ptr, *d, TPM_DIGEST_SIZE);
}

static
inline int unpack3_TPM_AUTHDATA(BYTE* ptr, UINT32* pos, UINT32 len, TPM_AUTHDATA* d) {
	return unpack3_BUFFER(ptr, pos, len, *d, TPM_DIGEST_SIZE);
}

#define sizeof_TPM_AUTHDATA(d) TPM_DIGEST_SIZE

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
#define unpack3_TPM_STRUCTURE_TAG(p, l, m, t) unpack3_UINT16(p, l, m, t)

#define sizeof_TPM_SECRET(t) sizeof_TPM_AUTHDATA(t)
#define sizeof_TPM_ENCAUTH(t) sizeof_TPM_AUTHDATA(t)
#define sizeof_TPM_PAYLOAD_TYPE(t) sizeof_BYTE(t)
#define sizeof_TPM_TAG(t) sizeof_UINT16(t)
#define sizeof_TPM_STRUCTURE_TAG(t) sizeof_UINT16(t)

static
inline BYTE* pack_TPM_VERSION(BYTE* ptr, const TPM_VERSION* t) {
	ptr[0] = t->major;
	ptr[1] = t->minor;
	ptr[2] = t->revMajor;
	ptr[3] = t->revMinor;
	return ptr + 4;
}

static
inline BYTE* unpack_TPM_VERSION(BYTE* ptr, TPM_VERSION* t) {
	t->major = ptr[0];
	t->minor = ptr[1];
	t->revMajor = ptr[2];
	t->revMinor = ptr[3];
	return ptr + 4;
}

static
inline int unpack3_TPM_VERSION(BYTE* ptr, UINT32 *pos, UINT32 max, TPM_VERSION* t) {
	if (*pos + 4 > max)
		return TPM_SIZE;
	ptr += *pos;
	t->major = ptr[0];
	t->minor = ptr[1];
	t->revMajor = ptr[2];
	t->revMinor = ptr[3];
	*pos += 4;
	return 0;
}

#define sizeof_TPM_VERSION(x) 4

static
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

static
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

static
inline BYTE* pack_TPM_DIGEST(BYTE* ptr, const TPM_DIGEST* d) {
	return pack_BUFFER(ptr, d->digest, TPM_DIGEST_SIZE);
}

static
inline BYTE* unpack_TPM_DIGEST(BYTE* ptr, TPM_DIGEST* d) {
	return unpack_BUFFER(ptr, d->digest, TPM_DIGEST_SIZE);
}

static
inline int unpack3_TPM_DIGEST(BYTE* ptr, UINT32* pos, UINT32 max, TPM_DIGEST* d) {
	return unpack3_BUFFER(ptr, pos, max, d->digest, TPM_DIGEST_SIZE);
}

#define sizeof_TPM_DIGEST(d) TPM_DIGEST_SIZE

#define pack_TPM_PCRVALUE(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_PCRVALUE(ptr, d) unpack_TPM_DIGEST(ptr, d)
#define unpack3_TPM_PCRVALUE(p...) unpack3_TPM_DIGEST(p)

#define pack_TPM_COMPOSITE_HASH(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_COMPOSITE_HASH(ptr, d) unpack_TPM_DIGEST(ptr, d)
#define unpack3_TPM_COMPOSITE_HASH(ptr, p, m, d) unpack3_TPM_DIGEST(ptr, p, m, d)
#define sizeof_TPM_COMPOSITE_HASH(d) TPM_DIGEST_SIZE

#define pack_TPM_DIRVALUE(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_DIRVALUE(ptr, d) unpack_TPM_DIGEST(ptr, d)

#define pack_TPM_HMAC(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_HMAC(ptr, d) unpack_TPM_DIGEST(ptr, d)

#define pack_TPM_CHOSENID_HASH(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_CHOSENID_HASH(ptr, d) unpack_TPM_DIGEST(ptr, d)

static
inline BYTE* pack_TPM_NONCE(BYTE* ptr, const TPM_NONCE* n) {
	return pack_BUFFER(ptr, n->nonce, TPM_DIGEST_SIZE);
}

static
inline BYTE* unpack_TPM_NONCE(BYTE* ptr, TPM_NONCE* n) {
	return unpack_BUFFER(ptr, n->nonce, TPM_DIGEST_SIZE);
}

#define sizeof_TPM_NONCE(x) TPM_DIGEST_SIZE

static
inline int unpack3_TPM_NONCE(BYTE* ptr, UINT32* pos, UINT32 max, TPM_NONCE* n) {
	return unpack3_BUFFER(ptr, pos, max, n->nonce, TPM_DIGEST_SIZE);
}

static
inline BYTE* pack_TPM_SYMMETRIC_KEY_PARMS(BYTE* ptr, const TPM_SYMMETRIC_KEY_PARMS* k) {
	ptr = pack_UINT32(ptr, k->keyLength);
	ptr = pack_UINT32(ptr, k->blockSize);
	ptr = pack_UINT32(ptr, k->ivSize);
	return pack_BUFFER(ptr, k->IV, k->ivSize);
}

static
inline BYTE* pack_TPM_SYMMETRIC_KEY(BYTE* ptr, const TPM_SYMMETRIC_KEY* k) {
	ptr = pack_UINT32(ptr, k->algId);
	ptr = pack_UINT16(ptr, k->encScheme);
	ptr = pack_UINT16(ptr, k->size);
	return pack_BUFFER(ptr, k->data, k->size);
}

static
inline int unpack3_TPM_SYMMETRIC_KEY_PARMS(BYTE* ptr, UINT32* pos, UINT32 max, TPM_SYMMETRIC_KEY_PARMS* k, UnpackPtr alloc) {
	return unpack3_UINT32(ptr, pos, max, &k->keyLength) ||
		unpack3_UINT32(ptr, pos, max, &k->blockSize) ||
		unpack3_UINT32(ptr, pos, max, &k->ivSize) ||
		unpack3_PTR(ptr, pos, max, &k->IV, k->ivSize, alloc);
}

static
inline int sizeof_TPM_SYMMETRIC_KEY_PARMS(const TPM_SYMMETRIC_KEY_PARMS* k) {
	return 12 + k->ivSize;
}

static
inline int unpack3_TPM_SYMMETRIC_KEY(BYTE* ptr, UINT32* pos, UINT32 max, TPM_SYMMETRIC_KEY* k, UnpackPtr alloc) {
	return unpack3_UINT32(ptr, pos, max, &k->algId) ||
		unpack3_UINT16(ptr, pos, max, &k->encScheme) ||
		unpack3_UINT16(ptr, pos, max, &k->size) ||
		unpack3_PTR(ptr, pos, max, &k->data, k->size, alloc);
}

static
inline BYTE* pack_TPM_RSA_KEY_PARMS(BYTE* ptr, const TPM_RSA_KEY_PARMS* k) {
	ptr = pack_UINT32(ptr, k->keyLength);
	ptr = pack_UINT32(ptr, k->numPrimes);
	ptr = pack_UINT32(ptr, k->exponentSize);
	return pack_BUFFER(ptr, k->exponent, k->exponentSize);
}

static
inline int unpack3_TPM_RSA_KEY_PARMS(BYTE* ptr, UINT32* pos, UINT32 max, TPM_RSA_KEY_PARMS* k, UnpackPtr alloc) {
	return unpack3_UINT32(ptr, pos, max, &k->keyLength) ||
		unpack3_UINT32(ptr, pos, max, &k->numPrimes) ||
		unpack3_UINT32(ptr, pos, max, &k->exponentSize) ||
		unpack3_PTR(ptr, pos, max, &k->exponent, k->exponentSize, alloc);
}

static
inline int sizeof_TPM_RSA_KEY_PARMS(const TPM_RSA_KEY_PARMS* k) {
	return 12 + k->exponentSize;
}


static
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

static
inline int unpack3_TPM_KEY_PARMS(BYTE* ptr, UINT32* pos, UINT32 len, TPM_KEY_PARMS* k, UnpackPtr alloc) {
	int rc = unpack3_TPM_ALGORITHM_ID(ptr, pos, len, &k->algorithmID) ||
		unpack3_TPM_ENC_SCHEME(ptr, pos, len, &k->encScheme) ||
		unpack3_TPM_SIG_SCHEME(ptr, pos, len, &k->sigScheme) ||
		unpack3_UINT32(ptr, pos, len, &k->parmSize);
	if (rc || k->parmSize == 0)
		return rc;
	switch(k->algorithmID) {
	case TPM_ALG_RSA:
		return unpack3_TPM_RSA_KEY_PARMS(ptr, pos, len, &k->parms.rsa, alloc);
	case TPM_ALG_AES128:
	case TPM_ALG_AES192:
	case TPM_ALG_AES256:
		return unpack3_TPM_SYMMETRIC_KEY_PARMS(ptr, pos, len, &k->parms.sym, alloc);
	}
	return TPM_FAIL;
}

static
inline int sizeof_TPM_KEY_PARMS(const TPM_KEY_PARMS* k) {
	int rc = 0;
	rc += sizeof_TPM_ALGORITHM_ID(&k->algorithmID);
	rc += sizeof_TPM_ENC_SCHEME(&k->encScheme);
	rc += sizeof_TPM_SIG_SCHEME(&k->sigScheme);
	rc += sizeof_UINT32(&k->parmSize);
	if (!k->parmSize)
		return rc;
	switch(k->algorithmID) {
	case TPM_ALG_RSA:
		rc += sizeof_TPM_RSA_KEY_PARMS(&k->parms.rsa);
		break;
	case TPM_ALG_AES128:
	case TPM_ALG_AES192:
	case TPM_ALG_AES256:
		rc += sizeof_TPM_SYMMETRIC_KEY_PARMS(&k->parms.sym);
		break;
	}
	return rc;
}

static
inline BYTE* pack_TPM_STORE_PUBKEY(BYTE* ptr, const TPM_STORE_PUBKEY* k) {
	ptr = pack_UINT32(ptr, k->keyLength);
	ptr = pack_BUFFER(ptr, k->key, k->keyLength);
	return ptr;
}

static
inline int unpack3_TPM_STORE_PUBKEY(BYTE* ptr, UINT32* pos, UINT32 max, TPM_STORE_PUBKEY* k, UnpackPtr alloc) {
	return unpack3_UINT32(ptr, pos, max, &k->keyLength) ||
		unpack3_PTR(ptr, pos, max, &k->key, k->keyLength, alloc);
}

static
inline int sizeof_TPM_STORE_PUBKEY(const TPM_STORE_PUBKEY* k) {
	return 4 + k->keyLength;
}

static
inline BYTE* pack_TPM_PUBKEY(BYTE* ptr, const TPM_PUBKEY* k) {
	ptr = pack_TPM_KEY_PARMS(ptr, &k->algorithmParms);
	return pack_TPM_STORE_PUBKEY(ptr, &k->pubKey);
}

static
inline int unpack3_TPM_PUBKEY(BYTE* ptr, UINT32* pos, UINT32 len, TPM_PUBKEY* k, UnpackPtr alloc) {
	return unpack3_TPM_KEY_PARMS(ptr, pos, len, &k->algorithmParms, alloc) ||
		unpack3_TPM_STORE_PUBKEY(ptr, pos, len, &k->pubKey, alloc);
}

static
inline BYTE* pack_TPM_PCR_SELECTION(BYTE* ptr, const TPM_PCR_SELECTION* p) {
	ptr = pack_UINT16(ptr, p->sizeOfSelect);
	ptr = pack_BUFFER(ptr, p->pcrSelect, p->sizeOfSelect);
	return ptr;
}

static
inline BYTE* unpack_TPM_PCR_SELECTION(BYTE* ptr, TPM_PCR_SELECTION* p, UnpackPtr alloc) {
	ptr = unpack_UINT16(ptr, &p->sizeOfSelect);
	ptr = unpack_PTR(ptr, &p->pcrSelect, p->sizeOfSelect, alloc);
	return ptr;
}

static
inline int unpack3_TPM_PCR_SELECTION(BYTE* ptr, UINT32* pos, UINT32 max, TPM_PCR_SELECTION* p, UnpackPtr alloc) {
	return unpack3_UINT16(ptr, pos, max, &p->sizeOfSelect) ||
		unpack3_PTR(ptr, pos, max, &p->pcrSelect, p->sizeOfSelect, alloc);
}

static
inline int sizeof_TPM_PCR_SELECTION(const TPM_PCR_SELECTION* p) {
	return 2 + p->sizeOfSelect;
}

static
inline BYTE* pack_TPM_PCR_INFO(BYTE* ptr, const TPM_PCR_INFO* p) {
	ptr = pack_TPM_PCR_SELECTION(ptr, &p->pcrSelection);
	ptr = pack_TPM_COMPOSITE_HASH(ptr, &p->digestAtRelease);
	ptr = pack_TPM_COMPOSITE_HASH(ptr, &p->digestAtCreation);
	return ptr;
}

static
inline int unpack3_TPM_PCR_INFO(BYTE* ptr, UINT32* pos, UINT32 max, TPM_PCR_INFO* p, UnpackPtr alloc) {
	return unpack3_TPM_PCR_SELECTION(ptr, pos, max, &p->pcrSelection, alloc) ||
		unpack3_TPM_COMPOSITE_HASH(ptr, pos, max, &p->digestAtRelease) ||
		unpack3_TPM_COMPOSITE_HASH(ptr, pos, max, &p->digestAtCreation);
}

static
inline int sizeof_TPM_PCR_INFO(const TPM_PCR_INFO* p) {
	int rc = 0;
	rc += sizeof_TPM_PCR_SELECTION(&p->pcrSelection);
	rc += sizeof_TPM_COMPOSITE_HASH(&p->digestAtRelease);
	rc += sizeof_TPM_COMPOSITE_HASH(&p->digestAtCreation);
	return rc;
}

static
inline BYTE* pack_TPM_PCR_INFO_LONG(BYTE* ptr, const TPM_PCR_INFO_LONG* p) {
	ptr = pack_TPM_STRUCTURE_TAG(ptr, p->tag);
	ptr = pack_TPM_LOCALITY_SELECTION(ptr, p->localityAtCreation);
	ptr = pack_TPM_LOCALITY_SELECTION(ptr, p->localityAtRelease);
	ptr = pack_TPM_PCR_SELECTION(ptr, &p->creationPCRSelection);
	ptr = pack_TPM_PCR_SELECTION(ptr, &p->releasePCRSelection);
	ptr = pack_TPM_COMPOSITE_HASH(ptr, &p->digestAtCreation);
	ptr = pack_TPM_COMPOSITE_HASH(ptr, &p->digestAtRelease);
	return ptr;
}

static
inline int sizeof_TPM_PCR_INFO_LONG(const TPM_PCR_INFO_LONG* p) {
	int rc = 0;
	rc += sizeof_TPM_STRUCTURE_TAG(p->tag);
	rc += sizeof_TPM_LOCALITY_SELECTION(p->localityAtCreation);
	rc += sizeof_TPM_LOCALITY_SELECTION(p->localityAtRelease);
	rc += sizeof_TPM_PCR_SELECTION(&p->creationPCRSelection);
	rc += sizeof_TPM_PCR_SELECTION(&p->releasePCRSelection);
	rc += sizeof_TPM_COMPOSITE_HASH(&p->digestAtCreation);
	rc += sizeof_TPM_COMPOSITE_HASH(&p->digestAtRelease);
	return rc;
}

static
inline int unpack3_TPM_PCR_INFO_LONG(BYTE* ptr, UINT32* pos, UINT32 max, TPM_PCR_INFO_LONG* p, UnpackPtr alloc) {
	return unpack3_TPM_STRUCTURE_TAG(ptr, pos, max, &p->tag) ||
		unpack3_TPM_LOCALITY_SELECTION(ptr, pos, max,
					       &p->localityAtCreation) ||
		unpack3_TPM_LOCALITY_SELECTION(ptr, pos, max,
					       &p->localityAtRelease) ||
		unpack3_TPM_PCR_SELECTION(ptr, pos, max,
					  &p->creationPCRSelection, alloc) ||
		unpack3_TPM_PCR_SELECTION(ptr, pos, max,
					  &p->releasePCRSelection, alloc) ||
		unpack3_TPM_COMPOSITE_HASH(ptr, pos, max,
					  &p->digestAtCreation) ||
		unpack3_TPM_COMPOSITE_HASH(ptr, pos, max, &p->digestAtRelease);
}

static
inline BYTE* pack_TPM_PCR_COMPOSITE(BYTE* ptr, const TPM_PCR_COMPOSITE* p) {
	ptr = pack_TPM_PCR_SELECTION(ptr, &p->select);
	ptr = pack_UINT32(ptr, p->valueSize);
	ptr = pack_BUFFER(ptr, (const BYTE*)p->pcrValue, p->valueSize);
	return ptr;
}

static
inline int unpack3_TPM_PCR_COMPOSITE(BYTE* ptr, UINT32* pos, UINT32 max, TPM_PCR_COMPOSITE* p, UnpackPtr alloc) {
	return unpack3_TPM_PCR_SELECTION(ptr, pos, max, &p->select, alloc) ||
		unpack3_UINT32(ptr, pos, max, &p->valueSize) ||
		unpack3_PTR(ptr, pos, max, (BYTE**)&p->pcrValue, p->valueSize, alloc);
}

static
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

static
inline int unpack3_TPM_KEY(BYTE* ptr, UINT32* pos, UINT32 max, TPM_KEY* k, UnpackPtr alloc) {
	int rc = unpack3_TPM_VERSION(ptr, pos, max, &k->ver) ||
		unpack3_TPM_KEY_USAGE(ptr, pos, max, &k->keyUsage) ||
		unpack3_TPM_KEY_FLAGS(ptr, pos, max, &k->keyFlags) ||
		unpack3_TPM_AUTH_DATA_USAGE(ptr, pos, max, &k->authDataUsage) ||
		unpack3_TPM_KEY_PARMS(ptr, pos, max, &k->algorithmParms, alloc) ||
		unpack3_UINT32(ptr, pos, max, &k->PCRInfoSize);
	if (rc) return rc;
	if(k->PCRInfoSize) {
		rc = unpack3_TPM_PCR_INFO(ptr, pos, max, &k->PCRInfo, alloc);
	}
	if (rc) return rc;
	return unpack3_TPM_STORE_PUBKEY(ptr, pos, max, &k->pubKey, alloc) ||
		unpack3_UINT32(ptr, pos, max, &k->encDataSize) ||
		unpack3_PTR(ptr, pos, max, &k->encData, k->encDataSize, alloc);
}

static
inline int sizeof_TPM_KEY(const TPM_KEY* k) {
	int rc = 0;
	rc += sizeof_TPM_VERSION(&k->ver);
	rc += sizeof_TPM_KEY_USAGE(k->keyUsage);
	rc += sizeof_TPM_KEY_FLAGS(k->keyFlags);
	rc += sizeof_TPM_AUTH_DATA_USAGE(k->authDataUsage);
	rc += sizeof_TPM_KEY_PARMS(&k->algorithmParms);
	rc += sizeof_UINT32(k->PCRInfoSize);
	if(k->PCRInfoSize) {
		rc += sizeof_TPM_PCR_INFO(&k->PCRInfo);
	}
	rc += sizeof_TPM_STORE_PUBKEY(&k->pubKey);
	rc += sizeof_UINT32(k->encDataSize);
	rc += k->encDataSize;
	return rc;
}

static
inline BYTE* pack_TPM_BOUND_DATA(BYTE* ptr, const TPM_BOUND_DATA* b, UINT32 payloadSize) {
	ptr = pack_TPM_VERSION(ptr, &b->ver);
	ptr = pack_TPM_PAYLOAD_TYPE(ptr, b->payload);
	return pack_BUFFER(ptr, b->payloadData, payloadSize);
}

static
inline BYTE* unpack_TPM_BOUND_DATA(BYTE* ptr, TPM_BOUND_DATA* b, UINT32 payloadSize, UnpackPtr alloc) {
	ptr = unpack_TPM_VERSION(ptr, &b->ver);
	ptr = unpack_TPM_PAYLOAD_TYPE(ptr, &b->payload);
	return unpack_PTR(ptr, &b->payloadData, payloadSize, alloc);
}

static
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

static
inline int sizeof_TPM_STORED_DATA(const TPM_STORED_DATA* d) {
	int rv = sizeof_TPM_VERSION(&d->ver) + sizeof_UINT32(d->sealInfoSize);
	if (d->sealInfoSize) {
		rv += sizeof_TPM_PCR_INFO(&d->sealInfo);
	}
	rv += sizeof_UINT32(d->encDataSize);
	rv += sizeof_BUFFER(d->encData, d->encDataSize);
	return rv;
}

static
inline int unpack3_TPM_STORED_DATA(BYTE* ptr, UINT32* pos, UINT32 len, TPM_STORED_DATA* d, UnpackPtr alloc) {
	int rc = unpack3_TPM_VERSION(ptr, pos, len, &d->ver) ||
		unpack3_UINT32(ptr, pos, len, &d->sealInfoSize);
	if (rc)
		return rc;
	if (d->sealInfoSize)
		rc = unpack3_TPM_PCR_INFO(ptr, pos, len, &d->sealInfo, alloc);
	if (rc)
		return rc;
	rc = unpack3_UINT32(ptr, pos, len, &d->encDataSize) ||
		unpack3_PTR(ptr, pos, len, &d->encData, d->encDataSize, alloc);
	return rc;
}

static
inline BYTE* pack_TPM_STORED_DATA12(BYTE* ptr, const TPM_STORED_DATA12* d) {
	ptr = pack_TPM_STRUCTURE_TAG(ptr, d->tag);
	ptr = pack_TPM_ENTITY_TYPE(ptr, d->et);
	ptr = pack_UINT32(ptr, d->sealInfoLongSize);
	if(d->sealInfoLongSize) {
		ptr = pack_TPM_PCR_INFO_LONG(ptr, &d->sealInfoLong);
	}
	ptr = pack_UINT32(ptr, d->encDataSize);
	ptr = pack_BUFFER(ptr, d->encData, d->encDataSize);
	return ptr;
}

static
inline int sizeof_TPM_STORED_DATA12(const TPM_STORED_DATA12* d) {
	int rv = sizeof_TPM_STRUCTURE_TAG(&d->ver) +
		 sizeof_TPM_ENTITY_TYPE(&d->et) +
		 sizeof_UINT32(d->sealInfoLongSize);
	if (d->sealInfoLongSize) {
		rv += sizeof_TPM_PCR_INFO_LONG(&d->sealInfoLong);
	}
	rv += sizeof_UINT32(d->encDataSize);
	rv += sizeof_BUFFER(d->encData, d->encDataSize);
	return rv;
}

static
inline int unpack3_TPM_STORED_DATA12(BYTE* ptr, UINT32* pos, UINT32 len, TPM_STORED_DATA12* d, UnpackPtr alloc) {
	int rc = unpack3_TPM_STRUCTURE_TAG(ptr, pos, len, &d->tag) ||
		unpack3_TPM_ENTITY_TYPE(ptr, pos, len, &d->et) ||
		unpack3_UINT32(ptr, pos, len, &d->sealInfoLongSize);
	if (rc)
		return rc;
	if (d->sealInfoLongSize)
		rc = unpack3_TPM_PCR_INFO_LONG(ptr, pos, len, &d->sealInfoLong,
					       alloc);
	if (rc)
		return rc;
	rc = unpack3_UINT32(ptr, pos, len, &d->encDataSize) ||
		unpack3_PTR(ptr, pos, len, &d->encData, d->encDataSize, alloc);
	return rc;
}

static
inline BYTE* pack_TPM_AUTH_SESSION(BYTE* ptr, const TPM_AUTH_SESSION* auth) {
	ptr = pack_TPM_AUTH_HANDLE(ptr, auth->AuthHandle);
	ptr = pack_TPM_NONCE(ptr, &auth->NonceOdd);
	ptr = pack_BOOL(ptr, auth->fContinueAuthSession);
	ptr = pack_TPM_AUTHDATA(ptr, &auth->HMAC);
	return ptr;
}

static
inline BYTE* unpack_TPM_AUTH_SESSION(BYTE* ptr, TPM_AUTH_SESSION* auth) {
	ptr = unpack_TPM_NONCE(ptr, &auth->NonceEven);
	ptr = unpack_BOOL(ptr, &auth->fContinueAuthSession);
	ptr = unpack_TPM_AUTHDATA(ptr, &auth->HMAC);
	return ptr;
}

static
inline int unpack3_TPM_AUTH_SESSION(BYTE* ptr, UINT32* pos, UINT32 len, TPM_AUTH_SESSION* auth) {
	return unpack3_TPM_NONCE(ptr, pos, len, &auth->NonceEven) ||
		unpack3_BOOL(ptr, pos, len, &auth->fContinueAuthSession) ||
		unpack3_TPM_AUTHDATA(ptr, pos, len, &auth->HMAC);
}


static
inline int sizeof_TPM_AUTH_SESSION(const TPM_AUTH_SESSION* auth) {
	int rv = 0;
	rv += sizeof_TPM_AUTH_HANDLE(auth->AuthHandle);
	rv += sizeof_TPM_NONCE(&auth->NonceOdd);
	rv += sizeof_BOOL(auth->fContinueAuthSession);
	rv += sizeof_TPM_AUTHDATA(&auth->HMAC);
	return rv;
}

static
inline BYTE* pack_TPM_RQU_HEADER(BYTE* ptr,
		TPM_TAG tag,
		UINT32 size,
		TPM_COMMAND_CODE ord) {
	ptr = pack_UINT16(ptr, tag);
	ptr = pack_UINT32(ptr, size);
	return pack_UINT32(ptr, ord);
}

static
inline BYTE* unpack_TPM_RQU_HEADER(BYTE* ptr,
		TPM_TAG* tag,
		UINT32* size,
		TPM_COMMAND_CODE* ord) {
	ptr = unpack_UINT16(ptr, tag);
	ptr = unpack_UINT32(ptr, size);
	ptr = unpack_UINT32(ptr, ord);
	return ptr;
}

static
inline int unpack3_TPM_RQU_HEADER(BYTE* ptr, UINT32* pos, UINT32 max,
		TPM_TAG* tag, UINT32* size, TPM_COMMAND_CODE* ord) {
	return
		unpack3_UINT16(ptr, pos, max, tag) ||
		unpack3_UINT32(ptr, pos, max, size) ||
		unpack3_UINT32(ptr, pos, max, ord);
}

#define pack_TPM_RSP_HEADER(p, t, s, r) pack_TPM_RQU_HEADER(p, t, s, r)
#define unpack_TPM_RSP_HEADER(p, t, s, r) unpack_TPM_RQU_HEADER(p, t, s, r)
#define unpack3_TPM_RSP_HEADER(p, l, m, t, s, r) unpack3_TPM_RQU_HEADER(p, l, m, t, s, r)

#endif
