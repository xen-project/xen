/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

/* TMEM is gone. Leave some stubs here. */

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long)
{
    GC_INIT(ctx);
    LOGED(ERROR, domid, "Can not get tmem list");
    GC_FREE;
    return NULL;
}

int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    LOGED(ERROR, domid, "Can not freeze tmem pools");
    GC_FREE;
    return ERROR_FAIL;
}

int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    LOGED(ERROR, domid, "Can not thaw tmem pools");
    GC_FREE;
    return ERROR_FAIL;
}

int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name, uint32_t set)
{
    GC_INIT(ctx);
    LOGED(ERROR, domid, "Can not set tmem %s", name);
    GC_FREE;
    return ERROR_FAIL;
}

int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid,
                           char* uuid, int auth)
{
    GC_INIT(ctx);
    LOGED(ERROR, domid, "Can not set tmem shared auth");
    GC_FREE;
    return ERROR_FAIL;
}

int libxl_tmem_freeable(libxl_ctx *ctx)
{
    GC_INIT(ctx);
    LOGE(ERROR, "Can not get tmem freeable memory");
    GC_FREE;
    return ERROR_FAIL;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
