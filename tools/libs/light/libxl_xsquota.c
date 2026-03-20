/* SPDX-License-Identifier: LGPL-2.1-only */

/* Xenstore quota handling functions. */

#include "libxl_internal.h"

static int get_quota(libxl_ctx *ctx, unsigned int domid,
                     libxl_xs_quota_list *q_out,
                     bool (func)(struct xs_handle *h, unsigned int domid,
                                 const char *quota, unsigned int *value))
{
    const char **names;
    unsigned int num, i;
    bool ok;
    int rc;
    GC_INIT(ctx);

    libxl_xs_quota_list_init(q_out);
    names = xs_get_quota_names(ctx->xsh, &num);
    if (!names) {
        /* Xenstore quota support is optional! */
        if (errno != ENOSYS) {
            libxl_xs_quota_list_dispose(q_out);
            rc = ERROR_FAIL;
        } else {
            rc = 0;
        }
        goto out;
    }

    q_out->num_quota = num;
    q_out->quota = libxl__calloc(NOGC, num, sizeof(*q_out->quota));
    for (i = 0; i < num; i++) {
        q_out->quota[i].name = libxl__strdup(NOGC, names[i]);
        ok = func(ctx->xsh, domid, q_out->quota[i].name, &q_out->quota[i].val);
        if (!ok) {
            libxl_xs_quota_list_dispose(q_out);
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = 0;

 out:
    free(names);

    GC_FREE;
    return rc;
}

static int set_quota(libxl_ctx *ctx, unsigned int domid, libxl_xs_quota_list *q,
                     bool (func)(struct xs_handle *h, unsigned int domid,
                                 const char *quota, unsigned int value))
{
    unsigned int i;
    bool ok;
    int rc;
    GC_INIT(ctx);

    for (i = 0; i < q->num_quota; i++) {
        ok = func(ctx->xsh, domid, q->quota[i].name, q->quota[i].val);
        if (!ok) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = 0;

 out:
    GC_FREE;
    return rc;
}

static bool get_global_quota(struct xs_handle *h, unsigned int domid,
                             const char *quota, unsigned int *value)
{
    return xs_get_global_quota(h, quota, value);
}

int libxl_xs_quota_global_get(libxl_ctx *ctx, libxl_xs_quota_list *q_out)
{
    return get_quota(ctx, 0, q_out, get_global_quota);
}

static bool set_global_quota(struct xs_handle *h, unsigned int domid,
                             const char *quota, unsigned int value)
{
    return xs_set_global_quota(h, quota, value);
}

int libxl_xs_quota_global_set(libxl_ctx *ctx, libxl_xs_quota_list *q)
{
    return set_quota(ctx, 0, q, set_global_quota);;
}

int libxl_xs_quota_domain_get(libxl_ctx *ctx, uint32_t domid,
                              libxl_xs_quota_list *q_out)
{
    return get_quota(ctx, domid, q_out, xs_get_domain_quota);
}

int libxl_xs_quota_domain_set(libxl_ctx *ctx, uint32_t domid,
                              libxl_xs_quota_list *q)
{
    return set_quota(ctx, domid, q, xs_set_domain_quota);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
