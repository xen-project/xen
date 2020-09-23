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

/* Returns:
 *   0 - success
 *   ERROR_FAIL + errno == ENOENT - no entry found
 *   ERROR_$FOO + errno != ENOENT - other failure
 */
static int cpupool_info(libxl__gc *gc,
                        libxl_cpupoolinfo *info,
                        uint32_t poolid,
                        bool exact /* exactly poolid or >= poolid */)
{
    xc_cpupoolinfo_t *xcinfo;
    int rc = ERROR_FAIL;

    xcinfo = xc_cpupool_getinfo(CTX->xch, poolid);
    if (xcinfo == NULL)
    {
        if (exact || errno != ENOENT)
            LOGE(ERROR, "failed to get info for cpupool%d", poolid);
        return ERROR_FAIL;
    }

    if (exact && xcinfo->cpupool_id != poolid)
    {
        LOG(ERROR, "got info for cpupool%d, wanted cpupool%d\n",
            xcinfo->cpupool_id, poolid);
        goto out;
    }

    info->poolid = xcinfo->cpupool_id;
    info->pool_name = libxl_cpupoolid_to_name(CTX, info->poolid);
    if (!info->pool_name) {
        rc = ERROR_FAIL;
        goto out;
    }
    info->sched = xcinfo->sched_id;
    info->n_dom = xcinfo->n_dom;
    rc = libxl_cpu_bitmap_alloc(CTX, &info->cpumap, 0);
    if (rc)
        goto out;

    memcpy(info->cpumap.map, xcinfo->cpumap, info->cpumap.size);

    rc = 0;
out:
    xc_cpupool_infofree(CTX->xch, xcinfo);
    return rc;
}

int libxl_cpupool_info(libxl_ctx *ctx,
                       libxl_cpupoolinfo *info, uint32_t poolid)
{
    GC_INIT(ctx);
    int rc = cpupool_info(gc, info, poolid, true);
    GC_FREE;
    return rc;
}

libxl_cpupoolinfo * libxl_list_cpupool(libxl_ctx *ctx, int *nb_pool_out)
{
    GC_INIT(ctx);
    libxl_cpupoolinfo info, *ptr;

    int i;
    uint32_t poolid;

    ptr = NULL;

    poolid = 0;
    for (i = 0;; i++) {
        libxl_cpupoolinfo_init(&info);
        if (cpupool_info(gc, &info, poolid, false)) {
            libxl_cpupoolinfo_dispose(&info);
            if (errno != ENOENT) goto out;
            break;
        }

        ptr = libxl__realloc(NOGC, ptr, (i+1) * sizeof(libxl_cpupoolinfo));
        ptr[i] = info;
        poolid = info.poolid + 1;
        /* Don't dispose of info because it will be returned to caller */
    }

    *nb_pool_out = i;

    GC_FREE;
    return ptr;

out:
    libxl_cpupoolinfo_list_free(ptr, i);
    *nb_pool_out = 0;
    GC_FREE;
    return NULL;
}

int libxl_get_freecpus(libxl_ctx *ctx, libxl_bitmap *cpumap)
{
    int ncpus;

    ncpus = libxl_get_max_cpus(ctx);
    if (ncpus < 0)
        return ncpus;

    cpumap->map = xc_cpupool_freeinfo(ctx->xch);
    if (cpumap->map == NULL)
        return ERROR_FAIL;

    cpumap->size = (ncpus + 7) / 8;

    return 0;
}

int libxl_cpupool_create(libxl_ctx *ctx, const char *name,
                         libxl_scheduler sched,
                         libxl_bitmap cpumap, libxl_uuid *uuid,
                         uint32_t *poolid)
{
    GC_INIT(ctx);
    int rc;
    int i;
    xs_transaction_t t;
    char *uuid_string;
    uint32_t xcpoolid;

    /* Accept '0' as 'any poolid' for backwards compatibility */
    if ( *poolid == LIBXL_CPUPOOL_POOLID_ANY
         || *poolid == 0 )
        xcpoolid = XC_CPUPOOL_POOLID_ANY;
    else
        xcpoolid = *poolid;

    uuid_string = libxl__uuid2string(gc, *uuid);
    if (!uuid_string) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    rc = xc_cpupool_create(ctx->xch, &xcpoolid, sched);
    if (rc) {
        LOGEV(ERROR, rc, "Could not create cpupool");
        GC_FREE;
        return ERROR_FAIL;
    }
    *poolid = xcpoolid;

    libxl_for_each_bit(i, cpumap)
        if (libxl_bitmap_test(&cpumap, i)) {
            rc = xc_cpupool_addcpu(ctx->xch, *poolid, i);
            if (rc) {
                LOGEV(ERROR, rc, "Error moving cpu to cpupool");
                libxl_cpupool_destroy(ctx, *poolid);
                GC_FREE;
                return ERROR_FAIL;
            }
        }

    for (;;) {
        t = xs_transaction_start(ctx->xsh);

        xs_mkdir(ctx->xsh, t, GCSPRINTF("/local/pool/%d", *poolid));
        libxl__xs_printf(gc, t,
                         GCSPRINTF("/local/pool/%d/uuid", *poolid),
                         "%s", uuid_string);
        libxl__xs_printf(gc, t,
                         GCSPRINTF("/local/pool/%d/name", *poolid),
                         "%s", name);

        if (xs_transaction_end(ctx->xsh, t, 0) || (errno != EAGAIN)) {
            GC_FREE;
            return 0;
        }
    }
}

int libxl_cpupool_destroy(libxl_ctx *ctx, uint32_t poolid)
{
    GC_INIT(ctx);
    int rc, i;
    xc_cpupoolinfo_t *info;
    xs_transaction_t t;
    libxl_bitmap cpumap;

    info = xc_cpupool_getinfo(ctx->xch, poolid);
    if (info == NULL) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    rc = ERROR_INVAL;
    if ((info->cpupool_id != poolid) || (info->n_dom))
        goto out;

    rc = libxl_cpu_bitmap_alloc(ctx, &cpumap, 0);
    if (rc)
        goto out;

    memcpy(cpumap.map, info->cpumap, cpumap.size);
    libxl_for_each_bit(i, cpumap)
        if (libxl_bitmap_test(&cpumap, i)) {
            rc = xc_cpupool_removecpu(ctx->xch, poolid, i);
            if (rc) {
                LOGEV(ERROR, rc, "Error removing cpu from cpupool");
                rc = ERROR_FAIL;
                goto out1;
            }
        }

    rc = xc_cpupool_destroy(ctx->xch, poolid);
    if (rc) {
        LOGEV(ERROR, rc, "Could not destroy cpupool");
        rc = ERROR_FAIL;
        goto out1;
    }

    for (;;) {
        t = xs_transaction_start(ctx->xsh);

        xs_rm(ctx->xsh, XBT_NULL, GCSPRINTF("/local/pool/%d", poolid));

        if (xs_transaction_end(ctx->xsh, t, 0) || (errno != EAGAIN))
            break;
    }

    rc = 0;

out1:
    libxl_bitmap_dispose(&cpumap);
out:
    xc_cpupool_infofree(ctx->xch, info);
    GC_FREE;

    return rc;
}

int libxl_cpupool_rename(libxl_ctx *ctx, const char *name, uint32_t poolid)
{
    GC_INIT(ctx);
    xs_transaction_t t;
    xc_cpupoolinfo_t *info;
    int rc;

    info = xc_cpupool_getinfo(ctx->xch, poolid);
    if (info == NULL) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    rc = ERROR_INVAL;
    if (info->cpupool_id != poolid)
        goto out;

    rc = 0;

    for (;;) {
        t = xs_transaction_start(ctx->xsh);

        libxl__xs_printf(gc, t,
                         GCSPRINTF("/local/pool/%d/name", poolid),
                         "%s", name);

        if (xs_transaction_end(ctx->xsh, t, 0))
            break;

        if (errno == EAGAIN)
            continue;

        rc = ERROR_FAIL;
        break;
    }

out:
    xc_cpupool_infofree(ctx->xch, info);
    GC_FREE;

    return rc;
}

int libxl_cpupool_cpuadd(libxl_ctx *ctx, uint32_t poolid, int cpu)
{
    GC_INIT(ctx);
    int rc = 0;

    rc = xc_cpupool_addcpu(ctx->xch, poolid, cpu);
    if (rc) {
        LOGE(ERROR, "Error moving cpu %d to cpupool", cpu);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_cpupool_cpuadd_cpumap(libxl_ctx *ctx, uint32_t poolid,
                                const libxl_bitmap *cpumap)
{
    int c, ncpus = 0, rc = 0;

    libxl_for_each_set_bit(c, *cpumap) {
        if (!libxl_cpupool_cpuadd(ctx, poolid, c))
            ncpus++;
    }

    if (ncpus != libxl_bitmap_count_set(cpumap))
        rc = ERROR_FAIL;

    return rc;
}

int libxl_cpupool_cpuadd_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus)
{
    int rc = 0;
    int cpu, nr;
    libxl_bitmap freemap;
    libxl_cputopology *topology;

    if (libxl_get_freecpus(ctx, &freemap)) {
        return ERROR_FAIL;
    }

    topology = libxl_get_cpu_topology(ctx, &nr);
    if (!topology) {
        rc = ERROR_FAIL;
        goto out;
    }

    *cpus = 0;
    for (cpu = 0; cpu < nr; cpu++) {
        if (libxl_bitmap_test(&freemap, cpu) && (topology[cpu].node == node) &&
            !libxl_cpupool_cpuadd(ctx, poolid, cpu)) {
                (*cpus)++;
        }
        libxl_cputopology_dispose(&topology[cpu]);
    }

    free(topology);
out:
    libxl_bitmap_dispose(&freemap);
    return rc;
}

int libxl_cpupool_cpuremove(libxl_ctx *ctx, uint32_t poolid, int cpu)
{
    GC_INIT(ctx);
    int rc = 0;

    rc = xc_cpupool_removecpu(ctx->xch, poolid, cpu);
    if (rc) {
        LOGE(ERROR, "Error removing cpu %d from cpupool", cpu);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_cpupool_cpuremove_cpumap(libxl_ctx *ctx, uint32_t poolid,
                                   const libxl_bitmap *cpumap)
{
    int c, ncpus = 0, rc = 0;

    libxl_for_each_set_bit(c, *cpumap) {
        if (!libxl_cpupool_cpuremove(ctx, poolid, c))
            ncpus++;
    }

    if (ncpus != libxl_bitmap_count_set(cpumap))
        rc = ERROR_FAIL;

    return rc;
}

int libxl_cpupool_cpuremove_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus)
{
    int ret = 0;
    int n_pools;
    int p;
    int cpu, nr_cpus;
    libxl_cputopology *topology;
    libxl_cpupoolinfo *poolinfo;

    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        return ERROR_NOMEM;
    }

    topology = libxl_get_cpu_topology(ctx, &nr_cpus);
    if (!topology) {
        ret = ERROR_FAIL;
        goto out;
    }

    *cpus = 0;
    for (p = 0; p < n_pools; p++) {
        if (poolinfo[p].poolid == poolid) {
            for (cpu = 0; cpu < nr_cpus; cpu++) {
                if ((topology[cpu].node == node) &&
                    libxl_bitmap_test(&poolinfo[p].cpumap, cpu) &&
                    !libxl_cpupool_cpuremove(ctx, poolid, cpu)) {
                        (*cpus)++;
                }
            }
        }
    }

    libxl_cputopology_list_free(topology, nr_cpus);

out:
    libxl_cpupoolinfo_list_free(poolinfo, n_pools);

    return ret;
}

int libxl_cpupool_movedomain(libxl_ctx *ctx, uint32_t poolid, uint32_t domid)
{
    GC_INIT(ctx);
    int rc;

    rc = xc_cpupool_movedomain(ctx->xch, poolid, domid);
    if (rc) {
        LOGEVD(ERROR, rc, domid, "Error moving domain to cpupool");
        GC_FREE;
        return ERROR_FAIL;
    }

    GC_FREE;
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
