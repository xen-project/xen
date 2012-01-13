/*
 *
 *  Author: Machon Gregory, <mbgrego@tycho.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

int libxl_flask_context_to_sid(libxl_ctx *ctx, char *buf, size_t len,
                               uint32_t *ssidref)
{
    int rc;

    rc = xc_flask_context_to_sid(ctx->xch, buf, len, ssidref);

    return rc;
}

int libxl_flask_sid_to_context(libxl_ctx *ctx, uint32_t ssidref,
                               char **buf, size_t *len)
{
    int rc;
    char tmp[XC_PAGE_SIZE];

    rc = xc_flask_sid_to_context(ctx->xch, ssidref, tmp, sizeof(tmp));

    if (!rc) {
        *len = strlen(tmp);
        *buf = strdup(tmp);
    }

    return rc;
}

int libxl_flask_getenforce(libxl_ctx *ctx)
{
    int rc;

    rc = xc_flask_getenforce(ctx->xch);

    return rc;
}

int libxl_flask_setenforce(libxl_ctx *ctx, int mode)
{
    int rc;

    rc = xc_flask_setenforce(ctx->xch, mode);

    return rc;
}

int libxl_flask_loadpolicy(libxl_ctx *ctx, void *policy, uint32_t size)
{

    int rc;

    rc = xc_flask_load(ctx->xch, policy, size);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
