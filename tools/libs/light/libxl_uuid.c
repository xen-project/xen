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

#include "libxl_internal.h"

#if defined(__linux__)

int libxl_uuid_is_nil(const libxl_uuid *uuid)
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

void libxl_uuid_copy(libxl_ctx *ctx_opt, libxl_uuid *dst,
                     const libxl_uuid *src)
{
     uuid_copy(dst->uuid, src->uuid);
}

void libxl_uuid_clear(libxl_uuid *uuid)
{
     uuid_clear(uuid->uuid);
}

int libxl_uuid_compare(const libxl_uuid *uuid1, const libxl_uuid *uuid2)
{
     return uuid_compare(uuid1->uuid, uuid2->uuid);
}

const uint8_t *libxl_uuid_bytearray_const(const libxl_uuid *uuid)
{
    return uuid->uuid;
}

uint8_t *libxl_uuid_bytearray(libxl_uuid *uuid)
{
    return uuid->uuid;
}

#elif defined(__FreeBSD__) || defined(__NetBSD__)

int libxl_uuid_is_nil(const libxl_uuid *uuid)
{
    uint32_t status;
    uuid_t nat_uuid;

    uuid_dec_be(uuid->uuid, &nat_uuid);

    return uuid_is_nil(&nat_uuid, &status);
}

void libxl_uuid_generate(libxl_uuid *uuid)
{
    uint32_t status;
    uuid_t nat_uuid;

    uuid_create(&nat_uuid, &status);
    assert(status == uuid_s_ok);

    uuid_enc_be(uuid->uuid, &nat_uuid);
}

int libxl_uuid_from_string(libxl_uuid *uuid, const char *in)
{
    uint32_t status;
    uuid_t nat_uuid;

    uuid_from_string(in, &nat_uuid, &status);
    if (status != uuid_s_ok)
        return ERROR_FAIL;
    uuid_enc_be(uuid->uuid, &nat_uuid);

    return 0;
}

void libxl_uuid_copy(libxl_ctx *ctx_opt, libxl_uuid *dst,
                     const libxl_uuid *src)
{
    memcpy(&dst->uuid, &src->uuid, sizeof(dst->uuid));
}

void libxl_uuid_clear(libxl_uuid *uuid)
{
    memset(&uuid->uuid, 0, sizeof(uuid->uuid));
}

int libxl_uuid_compare(const libxl_uuid *uuid1, const libxl_uuid *uuid2)
{
    uuid_t nat_uuid1, nat_uuid2;

    uuid_dec_be(uuid1->uuid, &nat_uuid1);
    uuid_dec_be(uuid2->uuid, &nat_uuid2);

    return uuid_compare(&nat_uuid1, &nat_uuid2, NULL);
}

const uint8_t *libxl_uuid_bytearray_const(const libxl_uuid *uuid)
{

    return uuid->uuid;
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
