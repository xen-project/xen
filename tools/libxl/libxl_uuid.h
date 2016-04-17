/*
 * Copyright (C) 2008,2010 Citrix Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef __LIBXL_UUID_H__
#define __LIBXL_UUID_H__

#define LIBXL_UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define LIBXL_UUID_FMTLEN ((2*16)+4) /* 16 hex bytes plus 4 hypens */
#define LIBXL__UUID_BYTES(uuid) uuid[0], uuid[1], uuid[2], uuid[3], \
                                uuid[4], uuid[5], uuid[6], uuid[7], \
                                uuid[8], uuid[9], uuid[10], uuid[11], \
                                uuid[12], uuid[13], uuid[14], uuid[15]
#define LIBXL_UUID_BYTES(arg) LIBXL__UUID_BYTES((arg).uuid)

typedef struct {
    /* UUID as an octet stream in big-endian byte-order. */
    unsigned char uuid[16];
} libxl_uuid;

#if defined(LIBXL_API_VERSION) && LIBXL_API_VERSION < 0x040700
#if defined(__linux__)

#include <uuid/uuid.h>
#include <stdint.h>

#elif defined(__FreeBSD__) || defined(__NetBSD__)

#include <uuid.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#else

#error "Please update libxl_uuid.h for your OS"

#endif
#endif

int libxl_uuid_is_nil(const libxl_uuid *uuid);
void libxl_uuid_generate(libxl_uuid *uuid);
int libxl_uuid_from_string(libxl_uuid *uuid, const char *in);
void libxl_uuid_copy(libxl_ctx *ctx_opt, libxl_uuid *dst,
                     const libxl_uuid *src);
#if defined(LIBXL_API_VERSION) && LIBXL_API_VERSION < 0x040500
static inline void libxl_uuid_copy_0x040400(libxl_uuid *dst,
                                            const libxl_uuid *src)
{
    libxl_uuid_copy(NULL, dst, src);
}
#define libxl_uuid_copy libxl_uuid_copy_0x040400
#endif

void libxl_uuid_clear(libxl_uuid *uuid);
int libxl_uuid_compare(const libxl_uuid *uuid1, const libxl_uuid *uuid2);
const uint8_t *libxl_uuid_bytearray_const(const libxl_uuid *uuid);
uint8_t *libxl_uuid_bytearray(libxl_uuid *uuid);

#endif /* __LIBXL_UUID_H__ */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
