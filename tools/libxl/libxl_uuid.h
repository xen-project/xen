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
#define LIBXL__UUID_BYTES(uuid) uuid[0], uuid[1], uuid[2], uuid[3], \
                                uuid[4], uuid[5], uuid[6], uuid[7], \
                                uuid[8], uuid[9], uuid[10], uuid[11], \
                                uuid[12], uuid[13], uuid[14], uuid[15]

#if defined(__linux__)

#include <uuid/uuid.h>

typedef struct {
    uuid_t uuid;
} libxl_uuid;

#define LIBXL_UUID_BYTES(arg) LIBXL__UUID_BYTES(((uint8_t *)arg.uuid))

static inline int libxl_uuid_is_nil(libxl_uuid *uuid)
{
     return uuid_is_null(uuid->uuid);
}

static inline void libxl_uuid_generate(libxl_uuid *uuid)
{
     uuid_generate(uuid->uuid);
}

static inline int libxl_uuid_from_string(libxl_uuid *uuid, const char *in)
{
     return uuid_parse(in, uuid->uuid);
}

static inline void libxl_uuid_copy(libxl_uuid *dst, libxl_uuid *src)
{
     uuid_copy(dst->uuid, src->uuid);
}

static inline void libxl_uuid_clear(libxl_uuid *uuid)
{
     uuid_clear(uuid->uuid);
}

static inline int libxl_uuid_compare(libxl_uuid *uuid1, libxl_uuid *uuid2)
{
     return uuid_compare(uuid1->uuid, uuid2->uuid);
}

static inline uint8_t *libxl_uuid_bytearray(libxl_uuid *uuid)
{
    return uuid->uuid;
}

#elif defined(__NetBSD__)

#include <uuid.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define LIBXL_UUID_BYTES(arg) LIBXL__UUID_BYTES(arg.uuid)

typedef struct {
    uint8_t uuid[16];
} libxl_uuid;

static inline int libxl_uuid_is_nil(libxl_uuid *uuid)
{
    uint32_t status;
    return uuid_is_nil((uuid_t *)uuid->uuid, &status);
}

static inline void libxl_uuid_generate(libxl_uuid *uuid)
{
    uint32_t status;
    uuid_create((uuid_t *)uuid->uuid, &status);
    assert(status == uuid_s_ok);
}

#define LIBXL__UUID_PTRS(uuid) &uuid[0], &uuid[1], &uuid[2], &uuid[3], \
                               &uuid[4], &uuid[5], &uuid[6], &uuid[7], \
                               &uuid[8], &uuid[9], &uuid[10],&uuid[11], \
                               &uuid[12],&uuid[13],&uuid[14],&uuid[15]
static inline int libxl_uuid_from_string(libxl_uuid *uuid, const char *in)
{
    if ( sscanf(in, LIBXL_UUID_FMT, LIBXL__UUID_PTRS(uuid->uuid)) != sizeof(uuid->uuid) )
        return -1;
    return 0;
}
#undef LIBXL__UUID_PTRS

static inline void libxl_uuid_copy(libxl_uuid *dst, libxl_uuid *src)
{
     memcpy(dst->uuid, src->uuid, sizeof(dst->uuid));
}

static inline void libxl_uuid_clear(libxl_uuid *uuid)
{
     memset(uuid->uuid, 0, sizeof(uuid->uuid));
}

static inline int libxl_uuid_compare(libxl_uuid *uuid1, libxl_uuid *uuid2)
{
     return memcmp(uuid1->uuid, uuid2->uuid, sizeof(uuid1->uuid));
}

static inline uint8_t *libxl_uuid_bytearray(libxl_uuid *uuid)
{
    return uuid->uuid;
}

#else

#error "Please update libxl_uuid.h for your OS"

#endif

#endif /* __LIBXL_UUID_H__ */
