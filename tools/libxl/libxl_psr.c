/*
 * Copyright (C) 2014      Intel Corporation
 * Author Dongxiao Xu <dongxiao.xu@intel.com>
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


#define IA32_QM_CTR_ERROR_MASK         (0x3ul << 62)

static void libxl__psr_cmt_log_err_msg(libxl__gc *gc, int err)
{
    char *msg;

    switch (err) {
    case ENOSYS:
        msg = "unsupported operation";
        break;
    case ENODEV:
        msg = "CMT is not supported in this system";
        break;
    case EEXIST:
        msg = "CMT is already attached to this domain";
        break;
    case ENOENT:
        msg = "CMT is not attached to this domain";
        break;
    case EUSERS:
        msg = "no free RMID available";
        break;
    case ESRCH:
        msg = "invalid domain ID";
        break;
    case EFAULT:
        msg = "failed to exchange data with Xen";
        break;
    default:
        msg = "unknown error";
        break;
    }

    LOGE(ERROR, "%s", msg);
}

static int libxl__pick_socket_cpu(libxl__gc *gc, uint32_t socketid)
{
    int i, nr_cpus;
    libxl_cputopology *topology;
    int cpu = ERROR_FAIL;

    topology = libxl_get_cpu_topology(CTX, &nr_cpus);
    if (!topology)
        return ERROR_FAIL;

    for (i = 0; i < nr_cpus; i++)
        if (topology[i].socket == socketid) {
            cpu = i;
            break;
        }

    libxl_cputopology_list_free(topology, nr_cpus);
    return cpu;
}

int libxl_psr_cmt_attach(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    int rc;

    rc = xc_psr_cmt_attach(ctx->xch, domid);
    if (rc < 0) {
        libxl__psr_cmt_log_err_msg(gc, errno);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_psr_cmt_detach(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    int rc;

    rc = xc_psr_cmt_detach(ctx->xch, domid);
    if (rc < 0) {
        libxl__psr_cmt_log_err_msg(gc, errno);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_psr_cmt_domain_attached(libxl_ctx *ctx, uint32_t domid)
{
    int rc;
    uint32_t rmid;

    rc = xc_psr_cmt_get_domain_rmid(ctx->xch, domid, &rmid);
    if (rc < 0)
        return 0;

    return !!rmid;
}

int libxl_psr_cmt_enabled(libxl_ctx *ctx)
{
    return xc_psr_cmt_enabled(ctx->xch);
}

int libxl_psr_cmt_get_total_rmid(libxl_ctx *ctx, uint32_t *total_rmid)
{
    GC_INIT(ctx);
    int rc;

    rc = xc_psr_cmt_get_total_rmid(ctx->xch, total_rmid);
    if (rc < 0) {
        libxl__psr_cmt_log_err_msg(gc, errno);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_psr_cmt_get_l3_cache_size(libxl_ctx *ctx, uint32_t socketid,
                                         uint32_t *l3_cache_size)
{
    GC_INIT(ctx);

    int rc;
    int cpu = libxl__pick_socket_cpu(gc, socketid);

    if (cpu < 0) {
        LOGE(ERROR, "failed to get socket cpu");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = xc_psr_cmt_get_l3_cache_size(ctx->xch, cpu, l3_cache_size);
    if (rc < 0) {
        libxl__psr_cmt_log_err_msg(gc, errno);
        rc = ERROR_FAIL;
    }

out:
    GC_FREE;
    return rc;
}

int libxl_psr_cmt_get_cache_occupancy(libxl_ctx *ctx, uint32_t domid,
    uint32_t socketid, uint32_t *l3_cache_occupancy)
{
    GC_INIT(ctx);

    unsigned int rmid;
    uint32_t upscaling_factor;
    uint64_t monitor_data;
    int cpu, rc;
    xc_psr_cmt_type type;

    rc = xc_psr_cmt_get_domain_rmid(ctx->xch, domid, &rmid);
    if (rc < 0 || rmid == 0) {
        LOGE(ERROR, "fail to get the domain rmid, "
            "or domain is not attached with platform QoS monitoring service");
        rc = ERROR_FAIL;
        goto out;
    }

    cpu = libxl__pick_socket_cpu(gc, socketid);
    if (cpu < 0) {
        LOGE(ERROR, "failed to get socket cpu");
        rc = ERROR_FAIL;
        goto out;
    }

    type = XC_PSR_CMT_L3_OCCUPANCY;
    rc = xc_psr_cmt_get_data(ctx->xch, rmid, cpu, type, &monitor_data);
    if (rc < 0) {
        LOGE(ERROR, "failed to get monitoring data");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = xc_psr_cmt_get_l3_upscaling_factor(ctx->xch, &upscaling_factor);
    if (rc < 0) {
        LOGE(ERROR, "failed to get L3 upscaling factor");
        rc = ERROR_FAIL;
        goto out;
    }

    *l3_cache_occupancy = upscaling_factor * monitor_data / 1024;
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
