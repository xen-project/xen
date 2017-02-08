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

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long)
{
    int r;
    char _buf[32768];
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_LIST, domid, 32768,
                        use_long, _buf);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not get tmem list");
        GC_FREE;
        return NULL;
    }

    GC_FREE;
    return strdup(_buf);
}

int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_FREEZE, domid, 0, 0,
                        NULL);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not freeze tmem pools");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_THAW, domid, 0, 0,
                        NULL);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not thaw tmem pools");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

static int32_t tmem_setop_from_string(char *set_name, uint32_t val,
                                      xen_tmem_client_t *info)
{
    if (!strcmp(set_name, "weight"))
        info->weight = val;
    else if (!strcmp(set_name, "compress"))
        info->flags.u.compress = val;
    else
        return -1;

    return 0;
}

int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name, uint32_t set)
{
    int r, rc;
    xen_tmem_client_t info;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1 /* pool_id */,
                        XEN_SYSCTL_TMEM_OP_GET_CLIENT_INFO,
                        domid, sizeof(info), 0 /* arg */, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not get tmem data!");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = tmem_setop_from_string(name, set, &info);
    if (rc == -1) {
        LOGEVD(ERROR, -1, domid, "Invalid set, valid sets are <weight|compress>");
        rc = ERROR_INVAL;
        goto out;
    }
    r = xc_tmem_control(ctx->xch, -1 /* pool_id */,
                        XEN_SYSCTL_TMEM_OP_SET_CLIENT_INFO,
                        domid, sizeof(info), 0 /* arg */, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not set tmem %s", name);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid,
                           char* uuid, int auth)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_auth(ctx->xch, domid, uuid, auth);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not set tmem shared auth");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_tmem_freeable(libxl_ctx *ctx)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_QUERY_FREEABLE_MB,
                        -1, 0, 0, 0);
    if (r < 0) {
        LOGE(ERROR, "Can not get tmem freeable memory");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
