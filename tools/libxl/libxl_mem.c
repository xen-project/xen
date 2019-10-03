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
#include "libxl_arch.h"

/*
 * Set the maximum memory size of the domain in the hypervisor. There is no
 * change of the current memory size involved. The specified memory size can
 * even be above the configured maxmem size of the domain, but the related
 * Xenstore entry memory/static-max isn't modified!
 */
int libxl_domain_setmaxmem(libxl_ctx *ctx, uint32_t domid, uint64_t max_memkb)
{
    GC_INIT(ctx);
    char *mem, *endptr;
    uint64_t memorykb, size;
    char *dompath = libxl__xs_get_dompath(gc, domid);
    int rc = 1;
    libxl__domain_userdata_lock *lock = NULL;
    libxl_domain_config d_config;

    libxl_domain_config_init(&d_config);

    CTX_LOCK;

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    mem = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/memory/target", dompath));
    if (!mem) {
        LOGED(ERROR, domid, "Cannot get memory info from %s/memory/target",
              dompath);
        goto out;
    }
    memorykb = strtoull(mem, &endptr, 10);
    if (*endptr != '\0') {
        LOGED(ERROR, domid, "Invalid memory %s from %s/memory/target\n",
              mem, dompath);
        goto out;
    }

    if (max_memkb < memorykb) {
        LOGED(ERROR, domid,
              "memory_static_max must be greater than or or equal to memory_dynamic_max");
        goto out;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc < 0) {
        LOGE(ERROR, "unable to retrieve domain configuration");
        goto out;
    }

    rc = libxl__arch_extra_memory(gc, &d_config.b_info, &size);
    if (rc < 0) {
        LOGE(ERROR, "Couldn't get arch extra constant memory size");
        goto out;
    }

    rc = xc_domain_setmaxmem(ctx->xch, domid, max_memkb + size);
    if (rc != 0) {
        LOGED(ERROR, domid,
              "xc_domain_setmaxmem domid=%d memkb=%"PRIu64" failed ""rc=%d\n",
              domid, max_memkb + size, rc);
        goto out;
    }

    rc = 0;
out:
    libxl_domain_config_dispose(&d_config);
    if (lock) libxl__unlock_domain_userdata(lock);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

static int libxl__fill_dom0_memory_info(libxl__gc *gc, uint64_t *target_memkb,
                                        uint64_t *max_memkb)
{
    int rc;
    libxl_dominfo info;
    libxl_physinfo physinfo;
    char *target = NULL, *staticmax = NULL, *endptr = NULL;
    char *target_path = "/local/domain/0/memory/target";
    char *max_path = "/local/domain/0/memory/static-max";
    xs_transaction_t t;
    libxl_ctx *ctx = libxl__gc_owner(gc);

    libxl_dominfo_init(&info);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    target = libxl__xs_read(gc, t, target_path);
    staticmax = libxl__xs_read(gc, t, max_path);
    if (target && staticmax) {
        rc = 0;
        goto out;
    }

    if (target) {
        *target_memkb = strtoull(target, &endptr, 10);
        if (*endptr != '\0') {
            LOGED(ERROR, 0, "Invalid memory target %s from %s\n", target,
                 target_path);
            rc = ERROR_FAIL;
            goto out;
        }
    }

    if (staticmax) {
        *max_memkb = strtoull(staticmax, &endptr, 10);
        if (*endptr != '\0') {
            LOGED(ERROR, 0, "Invalid memory static-max %s from %s\n",
                 staticmax,
                 max_path);
            rc = ERROR_FAIL;
            goto out;
        }
    }

    libxl_dominfo_dispose(&info);
    libxl_dominfo_init(&info);
    rc = libxl_domain_info(ctx, &info, 0);
    if (rc < 0)
        goto out;

    rc = libxl_get_physinfo(ctx, &physinfo);
    if (rc < 0)
        goto out;

    if (target == NULL) {
        libxl__xs_printf(gc, t, target_path, "%"PRIu64, info.current_memkb);
        *target_memkb = info.current_memkb;
    }
    if (staticmax == NULL) {
        libxl__xs_printf(gc, t, max_path, "%"PRIu64, info.max_memkb);
        *max_memkb = info.max_memkb;
    }

    rc = 0;

out:
    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else
            rc = ERROR_FAIL;
    }

    libxl_dominfo_dispose(&info);
    return rc;
}

int libxl_set_memory_target(libxl_ctx *ctx, uint32_t domid,
        int64_t target_memkb, int relative, int enforce)
{
    GC_INIT(ctx);
    int rc, r, lrc, abort_transaction = 0;
    uint64_t memorykb, size;
    uint64_t videoram = 0;
    uint64_t current_target_memkb = 0, new_target_memkb = 0;
    uint64_t current_max_memkb = 0;
    char *memmax, *endptr, *videoram_s = NULL, *target = NULL;
    char *dompath = libxl__xs_get_dompath(gc, domid);
    xc_domaininfo_t info;
    libxl_dominfo ptr;
    char *uuid;
    xs_transaction_t t;
    libxl__domain_userdata_lock *lock;
    libxl_domain_config d_config;

    libxl_domain_config_init(&d_config);

    CTX_LOCK;

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out_no_transaction;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc < 0) {
        LOGE(ERROR, "unable to retrieve domain configuration");
        goto out_no_transaction;
    }

    rc = libxl__arch_extra_memory(gc, &d_config.b_info, &size);
    if (rc < 0) {
        LOGE(ERROR, "Couldn't get arch extra constant memory size");
        goto out_no_transaction;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    target = libxl__xs_read(gc, t, GCSPRINTF("%s/memory/target", dompath));
    if (!target && !domid) {
        if (!xs_transaction_end(ctx->xsh, t, 1)) {
            rc = ERROR_FAIL;
            goto out_no_transaction;
        }
        lrc = libxl__fill_dom0_memory_info(gc, &current_target_memkb,
                                           &current_max_memkb);
        if (lrc < 0) { rc = ERROR_FAIL; goto out_no_transaction; }
        goto retry_transaction;
    } else if (!target) {
        LOGED(ERROR, domid, "Cannot get target memory info from %s/memory/target",
              dompath);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    } else {
        current_target_memkb = strtoull(target, &endptr, 10);
        if (*endptr != '\0') {
            LOGED(ERROR, domid, "Invalid memory target %s from %s/memory/target\n",
                  target, dompath);
            abort_transaction = 1;
            rc = ERROR_FAIL;
            goto out;
        }
    }
    memmax = libxl__xs_read(gc, t, GCSPRINTF("%s/memory/static-max", dompath));
    if (!memmax) {
        LOGED(ERROR, domid, "Cannot get memory info from %s/memory/static-max",
              dompath);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }
    memorykb = strtoull(memmax, &endptr, 10);
    if (*endptr != '\0') {
        LOGED(ERROR, domid, "Invalid max memory %s from %s/memory/static-max\n",
             memmax, dompath);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }

    videoram_s = libxl__xs_read(gc, t, GCSPRINTF("%s/memory/videoram",
                                                 dompath));
    videoram = videoram_s ? atoi(videoram_s) : 0;

    if (relative) {
        if (target_memkb < 0 && llabs(target_memkb) > current_target_memkb)
            new_target_memkb = 0;
        else
            new_target_memkb = current_target_memkb + target_memkb;
    } else
        new_target_memkb = target_memkb - videoram;
    if (new_target_memkb > memorykb) {
        LOGD(ERROR, domid,
             "memory_dynamic_max must be less than or equal to"
             " memory_static_max\n");
        abort_transaction = 1;
        rc = ERROR_INVAL;
        goto out;
    }

    if (!domid && new_target_memkb < LIBXL_MIN_DOM0_MEM) {
        LOGD(ERROR, domid,
             "New target %"PRIu64" for dom0 is below the minimum threshold",
             new_target_memkb);
        abort_transaction = 1;
        rc = ERROR_INVAL;
        goto out;
    }

    if (enforce) {
        memorykb = new_target_memkb + videoram;
        r = xc_domain_setmaxmem(ctx->xch, domid, memorykb + size);
        if (r != 0) {
            LOGED(ERROR, domid,
                  "xc_domain_setmaxmem memkb=%"PRIu64" failed ""rc=%d\n",
                  memorykb + size,
                  r);
            abort_transaction = 1;
            rc = ERROR_FAIL;
            goto out;
        }
    }

    if (d_config.c_info.type != LIBXL_DOMAIN_TYPE_PV) {
        r = xc_domain_set_pod_target(ctx->xch, domid,
                (new_target_memkb + size) / 4, NULL, NULL, NULL);
        if (r != 0) {
            LOGED(ERROR, domid,
                  "xc_domain_set_pod_target memkb=%"PRIu64" failed rc=%d\n",
                  (new_target_memkb + size) / 4,
                  r);
            abort_transaction = 1;
            rc = ERROR_FAIL;
            goto out;
        }
    }

    libxl__xs_printf(gc, t, GCSPRINTF("%s/memory/target", dompath),
                     "%"PRIu64, new_target_memkb);

    r = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (r != 1 || info.domain != domid) {
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_dominfo_init(&ptr);
    libxl__xcinfo2xlinfo(ctx, &info, &ptr);
    uuid = libxl__uuid2string(gc, ptr.uuid);
    libxl__xs_printf(gc, t, GCSPRINTF("/vm/%s/memory", uuid),
                     "%"PRIu64, new_target_memkb / 1024);
    libxl_dominfo_dispose(&ptr);

    rc = 0;
out:
    if (!xs_transaction_end(ctx->xsh, t, abort_transaction)
        && !abort_transaction)
        if (errno == EAGAIN)
            goto retry_transaction;

out_no_transaction:
    libxl_domain_config_dispose(&d_config);
    if (lock) libxl__unlock_domain_userdata(lock);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

/* out_target_memkb and out_max_memkb can be NULL */
int libxl__get_memory_target(libxl__gc *gc, uint32_t domid,
                             uint64_t *out_target_memkb,
                             uint64_t *out_max_memkb)
{
    int rc;
    char *target = NULL, *static_max = NULL, *endptr = NULL;
    char *dompath = libxl__xs_get_dompath(gc, domid);
    uint64_t target_memkb, max_memkb;

    target = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/memory/target",
                                                    dompath));
    static_max = libxl__xs_read(gc, XBT_NULL,
                    GCSPRINTF("%s/memory/static-max", dompath));

    rc = ERROR_FAIL;
    if ((!target || !static_max) && !domid) {
        rc = libxl__fill_dom0_memory_info(gc, &target_memkb,
                                          &max_memkb);
        if (rc < 0)
            goto out;
    } else if (!target) {
        LOGED(ERROR, domid, "Cannot get target memory info from %s/memory/target",
              dompath);
        goto out;
    } else if (!static_max) {
        LOGED(ERROR, domid,
              "Cannot get target memory info from %s/memory/static-max",
               dompath);
        goto out;
    } else {
        target_memkb = strtoull(target, &endptr, 10);
        if (*endptr != '\0') {
            LOGED(ERROR, domid, "Invalid memory target %s from %s/memory/target\n",
                  target, dompath);
            goto out;
        }
        max_memkb = strtoull(static_max, &endptr, 10);
        if (*endptr != '\0') {
            LOGED(ERROR, domid,
                  "Invalid memory target %s from %s/memory/static-max\n",
                  static_max,
                  dompath);
            goto out;
        }

    }

    if (out_target_memkb)
        *out_target_memkb = target_memkb;

    if (out_max_memkb)
        *out_max_memkb = max_memkb;

    rc = 0;

out:
    return rc;
}

static int libxl__memkb_64to32(libxl_ctx *ctx, int rc,
                               uint64_t val64, uint32_t *ptr32)
{
    GC_INIT(ctx);

    if (rc)
        goto out;

    *ptr32 = val64;
    if (*ptr32 == val64)
        goto out;

    LOGE(ERROR, "memory size %"PRIu64" too large for 32 bit value\n", val64);
    rc = ERROR_FAIL;

out:
    GC_FREE;
    return rc;
}

int libxl_get_memory_target(libxl_ctx *ctx, uint32_t domid,
                            uint64_t *out_target)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__get_memory_target(gc, domid, out_target, NULL);

    GC_FREE;
    return rc;
}

int libxl_get_memory_target_0x040700(
    libxl_ctx *ctx, uint32_t domid, uint32_t *out_target)
{
    uint64_t my_out_target;
    int rc;

    rc = libxl_get_memory_target(ctx, domid, &my_out_target);
    return libxl__memkb_64to32(ctx, rc, my_out_target, out_target);
}

int libxl__domain_need_memory_calculate(libxl__gc *gc,
                              libxl_domain_build_info *b_info,
                              uint64_t *need_memkb)
{
    int rc;

    *need_memkb = b_info->target_memkb;
    *need_memkb += b_info->shadow_memkb + b_info->iommu_memkb;

    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_HVM:
        *need_memkb += LIBXL_HVM_EXTRA_MEMORY;
        if (libxl_defbool_val(b_info->device_model_stubdomain))
            *need_memkb += 32 * 1024;
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        *need_memkb += LIBXL_PV_EXTRA_MEMORY;
        break;
    default:
        rc = ERROR_INVAL;
        goto out;
    }
    if (*need_memkb % (2 * 1024))
        *need_memkb += (2 * 1024) - (*need_memkb % (2 * 1024));
    rc = 0;
out:
    return rc;
}

int libxl_domain_need_memory(libxl_ctx *ctx,
                             libxl_domain_config *d_config,
                             uint32_t domid_for_logging,
                             uint64_t *need_memkb)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__domain_config_setdefault(gc,
                                         d_config,
                                         domid_for_logging);
    if (rc) goto out;

    rc = libxl__domain_need_memory_calculate(gc,
                                   &d_config->b_info,
                                   need_memkb);
    if (rc) goto out;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

int libxl_domain_need_memory_0x041200(libxl_ctx *ctx,
                                      const libxl_domain_build_info *b_info_in,
                                      uint64_t *need_memkb)
{
    GC_INIT(ctx);
    int rc;

    libxl_domain_build_info b_info[1];
    libxl_domain_build_info_init(b_info);
    libxl_domain_build_info_copy(ctx, b_info, b_info_in);

    rc = libxl__domain_build_info_setdefault(gc, b_info);
    if (rc) goto out;

    rc = libxl__domain_need_memory_calculate(gc,
                                   b_info,
                                   need_memkb);
    if (rc) goto out;

    rc = 0;
 out:
    libxl_domain_build_info_dispose(b_info);
    GC_FREE;
    return rc;
}

int libxl_domain_need_memory_0x040700(libxl_ctx *ctx,
                                      const libxl_domain_build_info *b_info_in,
                                      uint32_t *need_memkb)
{
    uint64_t my_need_memkb;
    int rc;

    rc = libxl_domain_need_memory_0x041200(ctx, b_info_in, &my_need_memkb);
    return libxl__memkb_64to32(ctx, rc, my_need_memkb, need_memkb);
}

int libxl_get_free_memory(libxl_ctx *ctx, uint64_t *memkb)
{
    int rc = 0;
    libxl_physinfo info;
    GC_INIT(ctx);

    rc = libxl_get_physinfo(ctx, &info);
    if (rc < 0)
        goto out;

    *memkb = (info.free_pages + info.scrub_pages) * 4;

out:
    GC_FREE;
    return rc;
}

int libxl_get_free_memory_0x040700(libxl_ctx *ctx, uint32_t *memkb)
{
    uint64_t my_memkb;
    int rc;

    rc = libxl_get_free_memory(ctx, &my_memkb);
    return libxl__memkb_64to32(ctx, rc, my_memkb, memkb);
}

int libxl_wait_for_free_memory(libxl_ctx *ctx, uint32_t domid,
                               uint64_t memory_kb, int wait_secs)
{
    int rc = 0;
    libxl_physinfo info;
    GC_INIT(ctx);

    while (wait_secs > 0) {
        rc = libxl_get_physinfo(ctx, &info);
        if (rc < 0)
            goto out;
        if (info.free_pages * 4 >= memory_kb) {
            rc = 0;
            goto out;
        }
        wait_secs--;
        sleep(1);
    }
    rc = ERROR_NOMEM;

out:
    GC_FREE;
    return rc;
}

int libxl_wait_for_memory_target(libxl_ctx *ctx, uint32_t domid, int wait_secs)
{
    int rc = 0;
    uint64_t target_memkb = 0;
    uint64_t current_memkb, prev_memkb;
    libxl_dominfo info;

    rc = libxl_get_memory_target(ctx, domid, &target_memkb);
    if (rc < 0)
        return rc;

    libxl_dominfo_init(&info);
    prev_memkb = UINT64_MAX;

    do {
        sleep(2);

        libxl_dominfo_dispose(&info);
        libxl_dominfo_init(&info);
        rc = libxl_domain_info(ctx, &info, domid);
        if (rc < 0)
            goto out;

        current_memkb = info.current_memkb + info.outstanding_memkb;

        if (current_memkb > prev_memkb)
        {
            rc = ERROR_FAIL;
            goto out;
        }
        else if (current_memkb == prev_memkb)
            wait_secs -= 2;
        /* if current_memkb < prev_memkb loop for free as progress has
         * been made */

        prev_memkb = current_memkb;
    } while (wait_secs > 0 && current_memkb > target_memkb);

    if (current_memkb <= target_memkb)
        rc = 0;
    else
        rc = ERROR_FAIL;

out:
    libxl_dominfo_dispose(&info);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
