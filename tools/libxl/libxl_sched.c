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

static int libxl__set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid,
                                   uint32_t vcpuid,
                                   const libxl_bitmap *cpumap_hard,
                                   const libxl_bitmap *cpumap_soft,
                                   unsigned flags)
{
    GC_INIT(ctx);
    libxl_bitmap hard, soft;
    int rc;

    libxl_bitmap_init(&hard);
    libxl_bitmap_init(&soft);

    if (!cpumap_hard && !cpumap_soft && !flags) {
        rc = ERROR_INVAL;
        goto out;
    }

    /*
     * Xen wants writable hard and/or soft cpumaps, to put back in them
     * the effective hard and/or soft affinity that will be used.
     */
    if (cpumap_hard) {
        rc = libxl_cpu_bitmap_alloc(ctx, &hard, 0);
        if (rc)
            goto out;

        libxl__bitmap_copy_best_effort(gc, &hard, cpumap_hard);
        flags |= XEN_VCPUAFFINITY_HARD;
    }
    if (cpumap_soft) {
        rc = libxl_cpu_bitmap_alloc(ctx, &soft, 0);
        if (rc)
            goto out;

        libxl__bitmap_copy_best_effort(gc, &soft, cpumap_soft);
        flags |= XEN_VCPUAFFINITY_SOFT;
    }

    if (xc_vcpu_setaffinity(ctx->xch, domid, vcpuid,
                            cpumap_hard ? hard.map : NULL,
                            cpumap_soft ? soft.map : NULL,
                            flags)) {
        LOGED(ERROR, domid, "Setting vcpu affinity");
        rc = ERROR_FAIL;
        goto out;
    }

    /*
     * Let's check the results. Hard affinity will never be empty, but it
     * is possible that Xen will use something different from what we asked
     * for various reasons. If that's the case, report it.
     */
    if (cpumap_hard &&
        !libxl_bitmap_equal(cpumap_hard, &hard, 0))
        LOGD(DEBUG, domid, "New hard affinity for vcpu %d has unreachable cpus", vcpuid);
    /*
     * Soft affinity can both be different from what asked and empty. Check
     * for (and report) both.
     */
    if (cpumap_soft) {
        if (!libxl_bitmap_equal(cpumap_soft, &soft, 0))
            LOGD(DEBUG, domid, "New soft affinity for vcpu %d has unreachable cpus",
                 vcpuid);
        if (libxl_bitmap_is_empty(&soft))
            LOGD(WARN, domid, "All cpus in soft affinity of vcpu %d are unreachable."
                 " Only hard affinity will be considered for scheduling",
                 vcpuid);
    }

    rc = 0;
 out:
    libxl_bitmap_dispose(&hard);
    libxl_bitmap_dispose(&soft);
    GC_FREE;
    return rc;
}

int libxl_set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           const libxl_bitmap *cpumap_hard,
                           const libxl_bitmap *cpumap_soft)
{
    return libxl__set_vcpuaffinity(ctx, domid, vcpuid, cpumap_hard,
                                   cpumap_soft, 0);
}

int libxl_set_vcpuaffinity_force(libxl_ctx *ctx, uint32_t domid,
                                 uint32_t vcpuid,
                                 const libxl_bitmap *cpumap_hard,
                                 const libxl_bitmap *cpumap_soft)
{
    return libxl__set_vcpuaffinity(ctx, domid, vcpuid, cpumap_hard,
                                   cpumap_soft, XEN_VCPUAFFINITY_FORCE);
}

int libxl_set_vcpuaffinity_all(libxl_ctx *ctx, uint32_t domid,
                               unsigned int max_vcpus,
                               const libxl_bitmap *cpumap_hard,
                               const libxl_bitmap *cpumap_soft)
{
    GC_INIT(ctx);
    int i, rc = 0;

    for (i = 0; i < max_vcpus; i++) {
        if (libxl_set_vcpuaffinity(ctx, domid, i, cpumap_hard, cpumap_soft)) {
            LOGD(WARN, domid, "Failed to set affinity for %d", i);
            rc = ERROR_FAIL;
        }
    }

    GC_FREE;
    return rc;
}

int libxl_domain_set_nodeaffinity(libxl_ctx *ctx, uint32_t domid,
                                  libxl_bitmap *nodemap)
{
    GC_INIT(ctx);
    if (xc_domain_node_setaffinity(ctx->xch, domid, nodemap->map)) {
        LOGED(ERROR, domid, "Setting node affinity");
        GC_FREE;
        return ERROR_FAIL;
    }
    GC_FREE;
    return 0;
}

int libxl_domain_get_nodeaffinity(libxl_ctx *ctx, uint32_t domid,
                                  libxl_bitmap *nodemap)
{
    GC_INIT(ctx);
    if (xc_domain_node_getaffinity(ctx->xch, domid, nodemap->map)) {
        LOGED(ERROR, domid, "Getting node affinity");
        GC_FREE;
        return ERROR_FAIL;
    }
    GC_FREE;
    return 0;
}

int libxl_get_scheduler(libxl_ctx *ctx)
{
    int r, sched;

    GC_INIT(ctx);
    r = xc_sched_id(ctx->xch, &sched);
    if (r != 0) {
        LOGE(ERROR, "getting current scheduler id");
        sched = ERROR_FAIL;
    }
    GC_FREE;
    return sched;
}

static int sched_arinc653_domain_set(libxl__gc *gc, uint32_t domid,
                                     const libxl_domain_sched_params *scinfo)
{
    /* Currently, the ARINC 653 scheduler does not take any domain-specific
         configuration, so we simply return success. */
    return 0;
}

static int sched_null_domain_set(libxl__gc *gc, uint32_t domid,
                                 const libxl_domain_sched_params *scinfo)
{
    /* There aren't any domain-specific parameters to be set. */
    return 0;
}

static int sched_null_domain_get(libxl__gc *gc, uint32_t domid,
                                 libxl_domain_sched_params *scinfo)
{
    /* There aren't any domain-specific parameters to return. */
    return 0;
}

static int sched_credit_domain_get(libxl__gc *gc, uint32_t domid,
                                   libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    int rc;

    rc = xc_sched_credit_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGED(ERROR, domid, "Getting domain sched credit");
        return ERROR_FAIL;
    }

    libxl_domain_sched_params_init(scinfo);
    scinfo->sched = LIBXL_SCHEDULER_CREDIT;
    scinfo->weight = sdom.weight;
    scinfo->cap = sdom.cap;

    return 0;
}

static int sched_credit_domain_set(libxl__gc *gc, uint32_t domid,
                                   const libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    xc_domaininfo_t domaininfo;
    int rc;

    rc = xc_domain_getinfolist(CTX->xch, domid, 1, &domaininfo);
    if (rc < 0) {
        LOGED(ERROR, domid, "Getting domain info list");
        return ERROR_FAIL;
    }
    if (rc != 1 || domaininfo.domain != domid)
        return ERROR_INVAL;

    rc = xc_sched_credit_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGED(ERROR, domid, "Getting domain sched credit");
        return ERROR_FAIL;
    }

    if (scinfo->weight != LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT) {
        if (scinfo->weight < 1 || scinfo->weight > 65535) {
            LOGD(ERROR, domid, "Cpu weight out of range, "
                 "valid values are within range from 1 to 65535");
            return ERROR_INVAL;
        }
        sdom.weight = scinfo->weight;
    }

    if (scinfo->cap != LIBXL_DOMAIN_SCHED_PARAM_CAP_DEFAULT) {
        if (scinfo->cap < 0
            || scinfo->cap > (domaininfo.max_vcpu_id + 1) * 100) {
            LOGD(ERROR, domid, "Cpu cap out of range, "
                 "valid range is from 0 to %d for specified number of vcpus",
                 ((domaininfo.max_vcpu_id + 1) * 100));
            return ERROR_INVAL;
        }
        sdom.cap = scinfo->cap;
    }

    rc = xc_sched_credit_domain_set(CTX->xch, domid, &sdom);
    if ( rc < 0 ) {
        LOGED(ERROR, domid, "Setting domain sched credit");
        return ERROR_FAIL;
    }

    return 0;
}

static int sched_ratelimit_check(libxl__gc *gc, int ratelimit)
{
    if (ratelimit != 0 &&
        (ratelimit <  XEN_SYSCTL_SCHED_RATELIMIT_MIN ||
         ratelimit > XEN_SYSCTL_SCHED_RATELIMIT_MAX)) {
        LOG(ERROR, "Ratelimit out of range, valid range is from %d to %d",
            XEN_SYSCTL_SCHED_RATELIMIT_MIN, XEN_SYSCTL_SCHED_RATELIMIT_MAX);
        return ERROR_INVAL;
    }

    return 0;
}

int libxl_sched_credit_params_get(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo)
{
    struct xen_sysctl_credit_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    r = xc_sched_credit_params_get(ctx->xch, poolid, &sparam);
    if (r < 0) {
        LOGE(ERROR, "getting Credit scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->tslice_ms = sparam.tslice_ms;
    scinfo->ratelimit_us = sparam.ratelimit_us;
    scinfo->vcpu_migr_delay_us = sparam.vcpu_migr_delay_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

int libxl_sched_credit_params_set(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo)
{
    struct xen_sysctl_credit_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    if (scinfo->tslice_ms <  XEN_SYSCTL_CSCHED_TSLICE_MIN
        || scinfo->tslice_ms > XEN_SYSCTL_CSCHED_TSLICE_MAX) {
        LOG(ERROR, "Time slice out of range, valid range is from %d to %d",
            XEN_SYSCTL_CSCHED_TSLICE_MIN, XEN_SYSCTL_CSCHED_TSLICE_MAX);
        rc = ERROR_INVAL;
        goto out;
    }
    rc = sched_ratelimit_check(gc, scinfo->ratelimit_us);
    if (rc) {
        goto out;
    }
    if (scinfo->ratelimit_us > scinfo->tslice_ms*1000) {
        LOG(ERROR, "Ratelimit cannot be greater than timeslice");
        rc = ERROR_INVAL;
        goto out;
    }
    if (scinfo->vcpu_migr_delay_us > XEN_SYSCTL_CSCHED_MGR_DLY_MAX_US) {
        LOG(ERROR, "vcpu migration delay should be >= 0 and <= %dus",
            XEN_SYSCTL_CSCHED_MGR_DLY_MAX_US);
        rc = ERROR_INVAL;
        goto out;
    }

    sparam.tslice_ms = scinfo->tslice_ms;
    sparam.ratelimit_us = scinfo->ratelimit_us;
    sparam.vcpu_migr_delay_us = scinfo->vcpu_migr_delay_us;

    r = xc_sched_credit_params_set(ctx->xch, poolid, &sparam);
    if ( r < 0 ) {
        LOGE(ERROR, "Setting Credit scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->tslice_ms = sparam.tslice_ms;
    scinfo->ratelimit_us = sparam.ratelimit_us;
    scinfo->vcpu_migr_delay_us = sparam.vcpu_migr_delay_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

int libxl_sched_credit2_params_get(libxl_ctx *ctx, uint32_t poolid,
                                   libxl_sched_credit2_params *scinfo)
{
    struct xen_sysctl_credit2_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    r = xc_sched_credit2_params_get(ctx->xch, poolid, &sparam);
    if (r < 0) {
        LOGE(ERROR, "getting Credit2 scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->ratelimit_us = sparam.ratelimit_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

int libxl_sched_credit2_params_set(libxl_ctx *ctx, uint32_t poolid,
                                   libxl_sched_credit2_params *scinfo)
{
    struct xen_sysctl_credit2_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    rc = sched_ratelimit_check(gc, scinfo->ratelimit_us);
    if (rc) goto out;

    sparam.ratelimit_us = scinfo->ratelimit_us;

    r = xc_sched_credit2_params_set(ctx->xch, poolid, &sparam);
    if (r < 0) {
        LOGE(ERROR, "Setting Credit2 scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->ratelimit_us = sparam.ratelimit_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

static int sched_credit2_domain_get(libxl__gc *gc, uint32_t domid,
                                    libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit2 sdom;
    int rc;

    rc = xc_sched_credit2_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGED(ERROR, domid, "Getting domain sched credit2");
        return ERROR_FAIL;
    }

    libxl_domain_sched_params_init(scinfo);
    scinfo->sched = LIBXL_SCHEDULER_CREDIT2;
    scinfo->weight = sdom.weight;
    scinfo->cap = sdom.cap;

    return 0;
}

static int sched_credit2_domain_set(libxl__gc *gc, uint32_t domid,
                                    const libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit2 sdom;
    xc_domaininfo_t info;
    int rc;

    rc = xc_domain_getinfolist(CTX->xch, domid, 1, &info);
    if (rc < 0) {
        LOGED(ERROR, domid, "Getting domain info");
        return ERROR_FAIL;
    }
    if (rc != 1 || info.domain != domid)
        return ERROR_INVAL;

    rc = xc_sched_credit2_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGED(ERROR, domid, "Getting domain sched credit2");
        return ERROR_FAIL;
    }

    if (scinfo->weight != LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT) {
        if (scinfo->weight < 1 || scinfo->weight > 65535) {
            LOGD(ERROR, domid, "Cpu weight out of range, "
                        "valid values are within range from 1 to 65535");
            return ERROR_INVAL;
        }
        sdom.weight = scinfo->weight;
    }

    if (scinfo->cap != LIBXL_DOMAIN_SCHED_PARAM_CAP_DEFAULT) {
        if (scinfo->cap < 0
            || scinfo->cap > (info.max_vcpu_id + 1) * 100) {
            LOGD(ERROR, domid, "Cpu cap out of range, "
                 "valid range is from 0 to %d for specified number of vcpus",
                 ((info.max_vcpu_id + 1) * 100));
            return ERROR_INVAL;
        }
        sdom.cap = scinfo->cap;
    }

    rc = xc_sched_credit2_domain_set(CTX->xch, domid, &sdom);
    if ( rc < 0 ) {
        LOGED(ERROR, domid, "Setting domain sched credit2");
        return ERROR_FAIL;
    }

    return 0;
}

static int sched_rtds_validate_params(libxl__gc *gc, int period, int budget)
{
    int rc;

    if (period < 1) {
        LOG(ERROR, "Invalid VCPU period of %d (it should be >= 1)", period);
        rc = ERROR_INVAL;
        goto out;
    }

    if (budget < 1) {
        LOG(ERROR, "Invalid VCPU budget of %d (it should be >= 1)", budget);
        rc = ERROR_INVAL;
        goto out;
    }

    if (budget > period) {
        LOG(ERROR, "VCPU budget must be smaller than or equal to period, "
                   "but %d > %d", budget, period);
        rc = ERROR_INVAL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

/* Get the RTDS scheduling parameters of vcpu(s) */
static int sched_rtds_vcpu_get(libxl__gc *gc, uint32_t domid,
                               libxl_vcpu_sched_params *scinfo)
{
    uint32_t num_vcpus;
    int i, r, rc;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }

    if (scinfo->num_vcpus <= 0) {
        rc = ERROR_INVAL;
        goto out;
    } else {
        num_vcpus = scinfo->num_vcpus;
        GCNEW_ARRAY(vcpus, num_vcpus);
        for (i = 0; i < num_vcpus; i++) {
            if (scinfo->vcpus[i].vcpuid < 0 ||
                scinfo->vcpus[i].vcpuid > info.max_vcpu_id) {
                LOGD(ERROR, domid, "VCPU index is out of range, "
                            "valid values are within range from 0 to %d",
                            info.max_vcpu_id);
                rc = ERROR_INVAL;
                goto out;
            }
            vcpus[i].vcpuid = scinfo->vcpus[i].vcpuid;
        }
    }

    r = xc_sched_rtds_vcpu_get(CTX->xch, domid, vcpus, num_vcpus);
    if (r != 0) {
        LOGED(ERROR, domid, "Getting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    scinfo->sched = LIBXL_SCHEDULER_RTDS;
    for (i = 0; i < num_vcpus; i++) {
        scinfo->vcpus[i].period = vcpus[i].u.rtds.period;
        scinfo->vcpus[i].budget = vcpus[i].u.rtds.budget;
        scinfo->vcpus[i].extratime =
                !!(vcpus[i].u.rtds.flags & XEN_DOMCTL_SCHEDRT_extra);
        scinfo->vcpus[i].vcpuid = vcpus[i].vcpuid;
    }
    rc = 0;
out:
    return rc;
}

/* Get the RTDS scheduling parameters of all vcpus of a domain */
static int sched_rtds_vcpu_get_all(libxl__gc *gc, uint32_t domid,
                                   libxl_vcpu_sched_params *scinfo)
{
    uint32_t num_vcpus;
    int i, r, rc;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }

    if (scinfo->num_vcpus > 0) {
        rc = ERROR_INVAL;
        goto out;
    } else {
        num_vcpus = info.max_vcpu_id + 1;
        GCNEW_ARRAY(vcpus, num_vcpus);
        for (i = 0; i < num_vcpus; i++)
            vcpus[i].vcpuid = i;
    }

    r = xc_sched_rtds_vcpu_get(CTX->xch, domid, vcpus, num_vcpus);
    if (r != 0) {
        LOGED(ERROR, domid, "Getting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    scinfo->sched = LIBXL_SCHEDULER_RTDS;
    scinfo->num_vcpus = num_vcpus;
    scinfo->vcpus = libxl__calloc(NOGC, num_vcpus,
                                  sizeof(libxl_sched_params));

    for (i = 0; i < num_vcpus; i++) {
        scinfo->vcpus[i].period = vcpus[i].u.rtds.period;
        scinfo->vcpus[i].budget = vcpus[i].u.rtds.budget;
        scinfo->vcpus[i].extratime =
                !!(vcpus[i].u.rtds.flags & XEN_DOMCTL_SCHEDRT_extra);
        scinfo->vcpus[i].vcpuid = vcpus[i].vcpuid;
    }
    rc = 0;
out:
    return rc;
}

/* Set the RTDS scheduling parameters of vcpu(s) */
static int sched_rtds_vcpu_set(libxl__gc *gc, uint32_t domid,
                               const libxl_vcpu_sched_params *scinfo)
{
    int r, rc;
    int i;
    uint16_t max_vcpuid;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }
    max_vcpuid = info.max_vcpu_id;

    if (scinfo->num_vcpus <= 0) {
        rc = ERROR_INVAL;
        goto out;
    }
    for (i = 0; i < scinfo->num_vcpus; i++) {
        if (scinfo->vcpus[i].vcpuid < 0 ||
            scinfo->vcpus[i].vcpuid > max_vcpuid) {
            LOGD(ERROR, domid, "Invalid VCPU %d: valid range is [0, %d]",
                        scinfo->vcpus[i].vcpuid, max_vcpuid);
            rc = ERROR_INVAL;
            goto out;
        }
        rc = sched_rtds_validate_params(gc, scinfo->vcpus[i].period,
                                        scinfo->vcpus[i].budget);
        if (rc) {
            rc = ERROR_INVAL;
            goto out;
        }
    }
    GCNEW_ARRAY(vcpus, scinfo->num_vcpus);
    for (i = 0; i < scinfo->num_vcpus; i++) {
        vcpus[i].vcpuid = scinfo->vcpus[i].vcpuid;
        vcpus[i].u.rtds.period = scinfo->vcpus[i].period;
        vcpus[i].u.rtds.budget = scinfo->vcpus[i].budget;
        if (scinfo->vcpus[i].extratime)
            vcpus[i].u.rtds.flags |= XEN_DOMCTL_SCHEDRT_extra;
        else
            vcpus[i].u.rtds.flags &= ~XEN_DOMCTL_SCHEDRT_extra;
    }

    r = xc_sched_rtds_vcpu_set(CTX->xch, domid,
                               vcpus, scinfo->num_vcpus);
    if (r != 0) {
        LOGED(ERROR, domid, "Setting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

/* Set the RTDS scheduling parameters of all vcpus of a domain */
static int sched_rtds_vcpu_set_all(libxl__gc *gc, uint32_t domid,
                                   const libxl_vcpu_sched_params *scinfo)
{
    int r, rc;
    int i;
    uint16_t max_vcpuid;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;
    uint32_t num_vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }
    max_vcpuid = info.max_vcpu_id;

    if (scinfo->num_vcpus != 1) {
        rc = ERROR_INVAL;
        goto out;
    }
    if (sched_rtds_validate_params(gc, scinfo->vcpus[0].period,
                                   scinfo->vcpus[0].budget)) {
        rc = ERROR_INVAL;
        goto out;
    }
    num_vcpus = max_vcpuid + 1;
    GCNEW_ARRAY(vcpus, num_vcpus);
    for (i = 0; i < num_vcpus; i++) {
        vcpus[i].vcpuid = i;
        vcpus[i].u.rtds.period = scinfo->vcpus[0].period;
        vcpus[i].u.rtds.budget = scinfo->vcpus[0].budget;
        if (scinfo->vcpus[0].extratime)
            vcpus[i].u.rtds.flags |= XEN_DOMCTL_SCHEDRT_extra;
        else
            vcpus[i].u.rtds.flags &= ~XEN_DOMCTL_SCHEDRT_extra;
    }

    r = xc_sched_rtds_vcpu_set(CTX->xch, domid,
                               vcpus, num_vcpus);
    if (r != 0) {
        LOGED(ERROR, domid, "Setting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

static int sched_rtds_domain_get(libxl__gc *gc, uint32_t domid,
                               libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_rtds sdom;
    int rc;

    rc = xc_sched_rtds_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGED(ERROR, domid, "Getting domain sched rtds");
        return ERROR_FAIL;
    }

    libxl_domain_sched_params_init(scinfo);

    scinfo->sched = LIBXL_SCHEDULER_RTDS;
    scinfo->period = sdom.period;
    scinfo->budget = sdom.budget;

    return 0;
}

static int sched_rtds_domain_set(libxl__gc *gc, uint32_t domid,
                               const libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_rtds sdom;
    int rc;

    rc = xc_sched_rtds_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGED(ERROR, domid, "Getting domain sched rtds");
        return ERROR_FAIL;
    }
    if (scinfo->period != LIBXL_DOMAIN_SCHED_PARAM_PERIOD_DEFAULT)
        sdom.period = scinfo->period;
    if (scinfo->budget != LIBXL_DOMAIN_SCHED_PARAM_BUDGET_DEFAULT)
        sdom.budget = scinfo->budget;
    /* Set extratime by default */
    if (scinfo->extratime)
        sdom.flags |= XEN_DOMCTL_SCHEDRT_extra;
    else
        sdom.flags &= ~XEN_DOMCTL_SCHEDRT_extra;
    if (sched_rtds_validate_params(gc, sdom.period, sdom.budget))
        return ERROR_INVAL;

    rc = xc_sched_rtds_domain_set(CTX->xch, domid, &sdom);
    if (rc < 0) {
        LOGED(ERROR, domid, "Setting domain sched rtds");
        return ERROR_FAIL;
    }

    return 0;
}

int libxl_domain_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                  const libxl_domain_sched_params *scinfo)
{
    GC_INIT(ctx);
    libxl_scheduler sched = scinfo->sched;
    int ret;

    if (sched == LIBXL_SCHEDULER_UNKNOWN)
        sched = libxl__domain_scheduler(gc, domid);

    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOGD(ERROR, domid, "SEDF scheduler no longer available");
        ret=ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
        ret=sched_credit_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_CREDIT2:
        ret=sched_credit2_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_ARINC653:
        ret=sched_arinc653_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_RTDS:
        ret=sched_rtds_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_NULL:
        ret=sched_null_domain_set(gc, domid, scinfo);
        break;
    default:
        LOGD(ERROR, domid, "Unknown scheduler");
        ret=ERROR_INVAL;
        break;
    }

    GC_FREE;
    return ret;
}

int libxl_vcpu_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                const libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    libxl_scheduler sched = scinfo->sched;
    int rc;

    if (sched == LIBXL_SCHEDULER_UNKNOWN)
        sched = libxl__domain_scheduler(gc, domid);

    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOGD(ERROR, domid, "SEDF scheduler no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
    case LIBXL_SCHEDULER_NULL:
        LOGD(ERROR, domid, "per-VCPU parameter setting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_set(gc, domid, scinfo);
        break;
    default:
        LOGD(ERROR, domid, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

int libxl_vcpu_sched_params_set_all(libxl_ctx *ctx, uint32_t domid,
                                    const libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    libxl_scheduler sched = scinfo->sched;
    int rc;

    if (sched == LIBXL_SCHEDULER_UNKNOWN)
        sched = libxl__domain_scheduler(gc, domid);

    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOGD(ERROR, domid, "SEDF scheduler no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
    case LIBXL_SCHEDULER_NULL:
        LOGD(ERROR, domid, "per-VCPU parameter setting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_set_all(gc, domid, scinfo);
        break;
    default:
        LOGD(ERROR, domid, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

int libxl_domain_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                  libxl_domain_sched_params *scinfo)
{
    GC_INIT(ctx);
    int ret;

    libxl_domain_sched_params_init(scinfo);

    scinfo->sched = libxl__domain_scheduler(gc, domid);

    switch (scinfo->sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOGD(ERROR, domid, "SEDF scheduler no longer available");
        ret=ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
        ret=sched_credit_domain_get(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_CREDIT2:
        ret=sched_credit2_domain_get(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_RTDS:
        ret=sched_rtds_domain_get(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_NULL:
        ret=sched_null_domain_get(gc, domid, scinfo);
        break;
    default:
        LOGD(ERROR, domid, "Unknown scheduler");
        ret=ERROR_INVAL;
        break;
    }

    GC_FREE;
    return ret;
}

int libxl_vcpu_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    int rc;

    scinfo->sched = libxl__domain_scheduler(gc, domid);

    switch (scinfo->sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOGD(ERROR, domid, "SEDF scheduler is no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
    case LIBXL_SCHEDULER_NULL:
        LOGD(ERROR, domid, "per-VCPU parameter getting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_get(gc, domid, scinfo);
        break;
    default:
        LOGD(ERROR, domid, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

int libxl_vcpu_sched_params_get_all(libxl_ctx *ctx, uint32_t domid,
                                    libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    int rc;

    scinfo->sched = libxl__domain_scheduler(gc, domid);

    switch (scinfo->sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOGD(ERROR, domid, "SEDF scheduler is no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
    case LIBXL_SCHEDULER_NULL:
        LOGD(ERROR, domid, "per-VCPU parameter getting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_get_all(gc, domid, scinfo);
        break;
    default:
        LOGD(ERROR, domid, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

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
