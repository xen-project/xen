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

#include "libxl_osdeps.h" /* must come before any other headers */

#include <libxl_uuid.h>

#include "libxl_internal.h"

#if defined(__linux__)

int libxl_uuid_is_nil(libxl_uuid *uuid)
{
     return uuid_is_null(uuid->uuid);
}

void libxl_uuid_generate(libxl_uuid *uuid)
{
     uuid_generate(uuid->uuid);
}

int libxl_uuid_from_string(libxl_uuid *uuid, const char *in)
{
     return uuid_parse(in, uuid->uuid);
}

void libxl_uuid_copy(libxl_uuid *dst, const libxl_uuid *src)
{
     uuid_copy(dst->uuid, src->uuid);
}

void libxl_uuid_clear(libxl_uuid *uuid)
{
     uuid_clear(uuid->uuid);
}

int libxl_uuid_compare(libxl_uuid *uuid1, libxl_uuid *uuid2)
{
     return uuid_compare(uuid1->uuid, uuid2->uuid);
}

uint8_t *libxl_uuid_bytearray(libxl_uuid *uuid)
{
    return uuid->uuid;
}

#elif defined(__NetBSD__)

int libxl_uuid_is_nil(libxl_uuid *uuid)
{
    uint32_t status;
    return uuid_is_nil((uuid_t *)uuid->uuid, &status);
}

void libxl_uuid_generate(libxl_uuid *uuid)
{
    uint32_t status;
    uuid_create((uuid_t *)uuid->uuid, &status);
    assert(status == uuid_s_ok);
}

#define LIBXL__UUID_PTRS(uuid) &uuid[0], &uuid[1], &uuid[2], &uuid[3], \
                               &uuid[4], &uuid[5], &uuid[6], &uuid[7], \
                               &uuid[8], &uuid[9], &uuid[10],&uuid[11], \
                               &uuid[12],&uuid[13],&uuid[14],&uuid[15]
int libxl_uuid_from_string(libxl_uuid *uuid, const char *in)
{
    if ( sscanf(in, LIBXL_UUID_FMT, LIBXL__UUID_PTRS(uuid->uuid)) != sizeof(uuid->uuid) )
        return -1;
    return 0;
}
#undef LIBXL__UUID_PTRS

void libxl_uuid_copy(libxl_uuid *dst, const libxl_uuid *src)
{
     memcpy(dst->uuid, src->uuid, sizeof(dst->uuid));
}

void libxl_uuid_clear(libxl_uuid *uuid)
{
     memset(uuid->uuid, 0, sizeof(uuid->uuid));
}

int libxl_uuid_compare(libxl_uuid *uuid1, libxl_uuid *uuid2)
{
     return memcmp(uuid1->uuid, uuid2->uuid, sizeof(uuid1->uuid));
}

uint8_t *libxl_uuid_bytearray(libxl_uuid *uuid)
{
    return uuid->uuid;
}

#else

#error "Please update libxl_uuid.c for your OS"

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
