/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <glob.h>

#include "libxl_internal.h"
#include "libxl_arch.h"

#include <xc_dom.h>
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/hvm_xs_strings.h>
#include <xen/hvm/e820.h>
#include <xen/errno.h>

libxl_domain_type libxl__domain_type(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (ret != 1 || info.domain != domid) {
        LOG(ERROR, "unable to get domain type for domid=%"PRIu32, domid);
        return LIBXL_DOMAIN_TYPE_INVALID;
    }
    if (info.flags & XEN_DOMINF_hvm_guest)
        return LIBXL_DOMAIN_TYPE_HVM;
    else
        return LIBXL_DOMAIN_TYPE_PV;
}

int libxl__domain_cpupool(libxl__gc *gc, uint32_t domid)
{
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(CTX->xch, domid, 1, &info);
    if (ret != 1)
    {
        LOGE(ERROR, "getinfolist failed %d", ret);
        return ERROR_FAIL;
    }
    if (info.domain != domid)
    {
        LOGE(ERROR, "got info for dom%d, wanted dom%d\n", info.domain, domid);
        return ERROR_FAIL;
    }
    return info.cpupool;
}

libxl_scheduler libxl__domain_scheduler(libxl__gc *gc, uint32_t domid)
{
    int cpupool = libxl__domain_cpupool(gc, domid);
    libxl_cpupoolinfo poolinfo;
    libxl_scheduler sched = LIBXL_SCHEDULER_UNKNOWN;
    int rc;

    if (cpupool < 0)
        return sched;

    libxl_cpupoolinfo_init(&poolinfo);
    rc = libxl_cpupool_info(CTX, &poolinfo, cpupool);
    if (rc < 0)
        goto out;

    sched = poolinfo.sched;

out:
    libxl_cpupoolinfo_dispose(&poolinfo);
    return sched;
}

/*
 * Two NUMA placement candidates are compared by means of the following
 * heuristics:

 *  - the number of vcpus runnable on the candidates is considered, and
 *    candidates with fewer of them are preferred. If two candidate have
 *    the same number of runnable vcpus,
 *  - the amount of free memory in the candidates is considered, and the
 *    candidate with greater amount of it is preferred.
 *
 * In fact, leaving larger memory holes, maximizes the probability of being
 * able to put other domains on the node. That hopefully means many domains
 * will benefit from local memory accesses, but also introduces the risk of
 * overloading large (from a memory POV) nodes. That's right the effect
 * that counting the vcpus able to run on the nodes tries to prevent.
 *
 * Note that this completely ignore the number of nodes each candidate span,
 * as the fact that fewer nodes is better is already accounted for in the
 * algorithm.
 */
static int numa_cmpf(const libxl__numa_candidate *c1,
                     const libxl__numa_candidate *c2)
{
    if (c1->nr_vcpus != c2->nr_vcpus)
        return c1->nr_vcpus - c2->nr_vcpus;

    return c2->free_memkb - c1->free_memkb;
}

/* The actual automatic NUMA placement routine */
static int numa_place_domain(libxl__gc *gc, uint32_t domid,
                             libxl_domain_build_info *info)
{
    int found;
    libxl__numa_candidate candidate;
    libxl_bitmap cpupool_nodemap;
    libxl_cpupoolinfo cpupool_info;
    int i, cpupool, rc = 0;
    uint32_t memkb;

    libxl__numa_candidate_init(&candidate);
    libxl_bitmap_init(&cpupool_nodemap);
    libxl_cpupoolinfo_init(&cpupool_info);

    /*
     * Extract the cpumap from the cpupool the domain belong to. In fact,
     * it only makes sense to consider the cpus/nodes that are in there
     * for placement.
     */
    rc = cpupool = libxl__domain_cpupool(gc, domid);
    if (rc < 0)
        goto out;
    rc = libxl_cpupool_info(CTX, &cpupool_info, cpupool);
    if (rc)
        goto out;

    rc = libxl_domain_need_memory(CTX, info, &memkb);
    if (rc)
        goto out;
    if (libxl_node_bitmap_alloc(CTX, &cpupool_nodemap, 0)) {
        rc = ERROR_FAIL;
        goto out;
    }

    /* Find the best candidate with enough free memory and at least
     * as much pcpus as the domain has vcpus.  */
    rc = libxl__get_numa_candidate(gc, memkb, info->max_vcpus,
                                   0, 0, &cpupool_info.cpumap,
                                   numa_cmpf, &candidate, &found);
    if (rc)
        goto out;

    /* Not even a suitable placement candidate! Let's just don't touch the
     * domain's info->cpumap. It will have affinity with all nodes/cpus. */
    if (found == 0)
        goto out;

    /* Map the candidate's node map to the domain's info->nodemap */
    libxl__numa_candidate_get_nodemap(gc, &candidate, &info->nodemap);

    /* Avoid trying to set the affinity to nodes that might be in the
     * candidate's nodemap but out of our cpupool. */
    rc = libxl_cpumap_to_nodemap(CTX, &cpupool_info.cpumap,
                                 &cpupool_nodemap);
    if (rc)
        goto out;

    libxl_for_each_set_bit(i, info->nodemap) {
        if (!libxl_bitmap_test(&cpupool_nodemap, i))
            libxl_bitmap_reset(&info->nodemap, i);
    }

    LOG(DETAIL, "NUMA placement candidate with %d nodes, %d cpus and "
                "%"PRIu32" KB free selected", candidate.nr_nodes,
                candidate.nr_cpus, candidate.free_memkb / 1024);

 out:
    libxl__numa_candidate_dispose(&candidate);
    libxl_bitmap_dispose(&cpupool_nodemap);
    libxl_cpupoolinfo_dispose(&cpupool_info);
    return rc;
}

static unsigned long timer_mode(const libxl_domain_build_info *info)
{
    const libxl_timer_mode mode = info->u.hvm.timer_mode;
    assert(mode >= LIBXL_TIMER_MODE_DELAY_FOR_MISSED_TICKS &&
           mode <= LIBXL_TIMER_MODE_ONE_MISSED_TICK_PENDING);
    return ((unsigned long)mode);
}

#if defined(__i386__) || defined(__x86_64__)
static int hvm_set_viridian_features(libxl__gc *gc, uint32_t domid,
                                     libxl_domain_build_info *const info)
{
    libxl_bitmap enlightenments;
    libxl_viridian_enlightenment v;
    uint64_t mask = 0;

    libxl_bitmap_init(&enlightenments);
    libxl_bitmap_alloc(CTX, &enlightenments,
                       LIBXL_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE_WIDTH);

    if (libxl_defbool_val(info->u.hvm.viridian)) {
        /* Enable defaults */
        libxl_bitmap_set(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_BASE);
        libxl_bitmap_set(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_FREQ);
        libxl_bitmap_set(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_TIME_REF_COUNT);
    }

    libxl_for_each_set_bit(v, info->u.hvm.viridian_enable) {
        if (libxl_bitmap_test(&info->u.hvm.viridian_disable, v)) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR, "%s group both enabled and disabled",
                       libxl_viridian_enlightenment_to_string(v));
            goto err;
        }
        if (libxl_viridian_enlightenment_to_string(v)) /* check validity */
            libxl_bitmap_set(&enlightenments, v);
    }

    libxl_for_each_set_bit(v, info->u.hvm.viridian_disable)
        if (libxl_viridian_enlightenment_to_string(v)) /* check validity */
            libxl_bitmap_reset(&enlightenments, v);

    /* The base set is a pre-requisite for all others */
    if (!libxl_bitmap_is_empty(&enlightenments) &&
        !libxl_bitmap_test(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_BASE)) {
        LIBXL__LOG(CTX, LIBXL__LOG_ERROR, "base group not enabled");
        goto err;
    }

    libxl_for_each_set_bit(v, enlightenments)
        LOG(DETAIL, "%s group enabled", libxl_viridian_enlightenment_to_string(v));

    if (libxl_bitmap_test(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_BASE)) {
        mask |= HVMPV_base_freq;

        if (!libxl_bitmap_test(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_FREQ))
            mask |= HVMPV_no_freq;
    }

    if (libxl_bitmap_test(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_TIME_REF_COUNT))
        mask |= HVMPV_time_ref_count;

    if (libxl_bitmap_test(&enlightenments, LIBXL_VIRIDIAN_ENLIGHTENMENT_REFERENCE_TSC))
        mask |= HVMPV_reference_tsc;

    if (mask != 0 &&
        xc_hvm_param_set(CTX->xch,
                         domid,
                         HVM_PARAM_VIRIDIAN,
                         mask) != 0) {
        LIBXL__LOG_ERRNO(CTX, LIBXL__LOG_ERROR,
                         "Couldn't set viridian feature mask (0x%"PRIx64")",
                         mask);
        goto err;
    }

    libxl_bitmap_dispose(&enlightenments);
    return 0;

err:
    libxl_bitmap_dispose(&enlightenments);
    return ERROR_FAIL;
}
#endif

static void hvm_set_conf_params(xc_interface *handle, uint32_t domid,
                                libxl_domain_build_info *const info)
{
    xc_hvm_param_set(handle, domid, HVM_PARAM_PAE_ENABLED,
                    libxl_defbool_val(info->u.hvm.pae));
#if defined(__i386__) || defined(__x86_64__)
    xc_hvm_param_set(handle, domid, HVM_PARAM_HPET_ENABLED,
                    libxl_defbool_val(info->u.hvm.hpet));
#endif
    xc_hvm_param_set(handle, domid, HVM_PARAM_TIMER_MODE, timer_mode(info));
    xc_hvm_param_set(handle, domid, HVM_PARAM_VPT_ALIGN,
                    libxl_defbool_val(info->u.hvm.vpt_align));
    xc_hvm_param_set(handle, domid, HVM_PARAM_NESTEDHVM,
                    libxl_defbool_val(info->u.hvm.nested_hvm));
    xc_hvm_param_set(handle, domid, HVM_PARAM_ALTP2M,
                    libxl_defbool_val(info->u.hvm.altp2m));
}

int libxl__build_pre(libxl__gc *gc, uint32_t domid,
              libxl_domain_config *d_config, libxl__domain_build_state *state)
{
    libxl_domain_build_info *const info = &d_config->b_info;
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *xs_domid, *con_domid;
    int rc;

    if (xc_domain_max_vcpus(ctx->xch, domid, info->max_vcpus) != 0) {
        LOG(ERROR, "Couldn't set max vcpu count");
        return ERROR_FAIL;
    }

    /*
     * Check if the domain has any CPU or node affinity already. If not, try
     * to build up the latter via automatic NUMA placement. In fact, in case
     * numa_place_domain() manage to find a placement, in info->nodemap is
     * updated accordingly; if it does not manage, info->nodemap is just left
     * alone. It is then the the subsequent call to
     * libxl_domain_set_nodeaffinity() that enacts the actual placement.
     *
     * As far as scheduling is concerned, we achieve NUMA-aware scheduling
     * by having the results of placement affect the soft affinity of all
     * the vcpus of the domain. Of course, we want that iff placement is
     * enabled and actually happens, so we only change info->cpumap_soft to
     * reflect the placement result if that is the case
     */
    if (libxl_defbool_val(info->numa_placement)) {
        if (info->cpumap.size || info->num_vcpu_hard_affinity ||
            info->num_vcpu_soft_affinity)
            LOG(WARN, "Can't run NUMA placement, as an (hard or soft) "
                      "affinity has been specified explicitly");
        else if (info->nodemap.size)
            LOG(WARN, "Can't run NUMA placement, as the domain has "
                      "NUMA node affinity set already");
        else {
            libxl_bitmap cpumap_soft;

            rc = libxl_node_bitmap_alloc(ctx, &info->nodemap, 0);
            if (rc)
                return rc;
            libxl_bitmap_set_any(&info->nodemap);

            rc = libxl_cpu_bitmap_alloc(ctx, &cpumap_soft, 0);
            if (rc)
                return rc;

            rc = numa_place_domain(gc, domid, info);
            if (rc) {
                libxl_bitmap_dispose(&cpumap_soft);
                return rc;
            }

            /*
             * All we need to do now is converting the result of automatic
             * placement from nodemap to cpumap, and then use such cpumap
             * as the soft affinity for all the vcpus of the domain.
             *
             * When calling libxl_set_vcpuaffinity_all(), it is ok to use
             * NULL as hard affinity, as we know we don't have one, or we
             * won't be here.
             */
            libxl_nodemap_to_cpumap(ctx, &info->nodemap, &cpumap_soft);
            libxl_set_vcpuaffinity_all(ctx, domid, info->max_vcpus,
                                       NULL, &cpumap_soft);

            libxl_bitmap_dispose(&cpumap_soft);

            /*
             * Placement has run, so avoid for it to be re-run, if this
             * same config we are using and building here is ever re-used.
             * This means that people re-using configs will get the same
             * results, consistently, across every re-use, which is what
             * we expect most people to want.
             */
            libxl_defbool_set(&info->numa_placement, false);
        }
    }

    if (info->nodemap.size)
        libxl_domain_set_nodeaffinity(ctx, domid, &info->nodemap);

    if (info->num_vcpu_hard_affinity || info->num_vcpu_soft_affinity) {
        libxl_bitmap *hard_affinity, *soft_affinity;
        int i, n_vcpus;

        n_vcpus = info->num_vcpu_hard_affinity > info->num_vcpu_soft_affinity ?
            info->num_vcpu_hard_affinity : info->num_vcpu_soft_affinity;

        for (i = 0; i < n_vcpus; i++) {
            /*
             * Prepare hard and soft affinity pointers in a way that allows
             * us to issue only one call to libxl_set_vcpuaffinity(), setting,
             * for each vcpu, both hard and soft affinity "atomically".
             */
            hard_affinity = NULL;
            if (info->num_vcpu_hard_affinity &&
                i < info->num_vcpu_hard_affinity)
                hard_affinity = &info->vcpu_hard_affinity[i];

            soft_affinity = NULL;
            if (info->num_vcpu_soft_affinity &&
                i < info->num_vcpu_soft_affinity)
                soft_affinity = &info->vcpu_soft_affinity[i];

            if (libxl_set_vcpuaffinity(ctx, domid, i,
                                       hard_affinity, soft_affinity)) {
                LOG(ERROR, "setting affinity failed on vcpu `%d'", i);
                return ERROR_FAIL;
            }
        }
    }

    if (xc_domain_setmaxmem(ctx->xch, domid, info->target_memkb +
        LIBXL_MAXMEM_CONSTANT) < 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't set max memory");
        return ERROR_FAIL;
    }

    xs_domid = xs_read(ctx->xsh, XBT_NULL, "/tool/xenstored/domid", NULL);
    state->store_domid = xs_domid ? atoi(xs_domid) : 0;
    free(xs_domid);

    con_domid = xs_read(ctx->xsh, XBT_NULL, "/tool/xenconsoled/domid", NULL);
    state->console_domid = con_domid ? atoi(con_domid) : 0;
    free(con_domid);

    state->store_port = xc_evtchn_alloc_unbound(ctx->xch, domid, state->store_domid);
    state->console_port = xc_evtchn_alloc_unbound(ctx->xch, domid, state->console_domid);

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        hvm_set_conf_params(ctx->xch, domid, info);
#if defined(__i386__) || defined(__x86_64__)
        rc = hvm_set_viridian_features(gc, domid, info);
        if (rc)
            return rc;
#endif
    }

    rc = libxl__arch_domain_create(gc, d_config, domid);

    return rc;
}

static int set_vnuma_affinity(libxl__gc *gc, uint32_t domid,
                              libxl_domain_build_info *info)
{
    libxl_bitmap cpumap;
    libxl_vnode_info *v;
    unsigned int i, j;
    int rc = 0;

    libxl_bitmap_init(&cpumap);

    rc = libxl_cpu_bitmap_alloc(CTX, &cpumap, 0);
    if (rc) {
        LOG(ERROR, "Can't allocate nodemap");
        goto out;
    }

    /*
     * For each vcpu in each vnode, set its soft affinity to
     * the pcpus belonging to the pnode the vnode is on
     */
    for (i = 0; i < info->num_vnuma_nodes; i++) {
        v = &info->vnuma_nodes[i];

        rc = libxl_node_to_cpumap(CTX, v->pnode, &cpumap);
        if (rc) {
            LOG(ERROR, "Can't get cpumap for vnode %d", i);
            goto out;
        }

        libxl_for_each_set_bit(j, v->vcpus) {
            rc = libxl_set_vcpuaffinity(CTX, domid, j, NULL, &cpumap);
            if (rc) {
                LOG(ERROR, "Can't set cpu affinity for %d", j);
                goto out;
            }
        }
    }

out:
    libxl_bitmap_dispose(&cpumap);
    return rc;
}

int libxl__build_post(libxl__gc *gc, uint32_t domid,
                      libxl_domain_build_info *info,
                      libxl__domain_build_state *state,
                      char **vms_ents, char **local_ents)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *dom_path, *vm_path;
    xs_transaction_t t;
    char **ents;
    int i, rc;

    if (info->num_vnuma_nodes && !info->num_vcpu_soft_affinity) {
        rc = set_vnuma_affinity(gc, domid, info);
        if (rc)
            return rc;
    }

    rc = libxl_domain_sched_params_set(CTX, domid, &info->sched_params);
    if (rc)
        return rc;

    rc = xc_domain_set_max_evtchn(ctx->xch, domid, info->event_channels);
    if (rc) {
        LOG(ERROR, "Failed to set event channel limit to %d (%d)",
            info->event_channels, rc);
        return ERROR_FAIL;
    }

    libxl_cpuid_apply_policy(ctx, domid);
    if (info->cpuid != NULL)
        libxl_cpuid_set(ctx, domid, info->cpuid);

    if (info->type == LIBXL_DOMAIN_TYPE_HVM
        && !libxl_ms_vm_genid_is_zero(&info->u.hvm.ms_vm_genid)) {
        rc = libxl__ms_vm_genid_set(gc, domid,
                                    &info->u.hvm.ms_vm_genid);
        if (rc) {
            LOG(ERROR, "Failed to set VM Generation ID");
            return rc;
        }
    }

    ents = libxl__calloc(gc, 12 + (info->max_vcpus * 2) + 2, sizeof(char *));
    ents[0] = "memory/static-max";
    ents[1] = GCSPRINTF("%"PRId64, info->max_memkb);
    ents[2] = "memory/target";
    ents[3] = GCSPRINTF("%"PRId64, info->target_memkb - info->video_memkb);
    ents[4] = "memory/videoram";
    ents[5] = GCSPRINTF("%"PRId64, info->video_memkb);
    ents[6] = "domid";
    ents[7] = GCSPRINTF("%d", domid);
    ents[8] = "store/port";
    ents[9] = GCSPRINTF("%"PRIu32, state->store_port);
    ents[10] = "store/ring-ref";
    ents[11] = GCSPRINTF("%lu", state->store_mfn);
    for (i = 0; i < info->max_vcpus; i++) {
        ents[12+(i*2)]   = GCSPRINTF("cpu/%d/availability", i);
        ents[12+(i*2)+1] = libxl_bitmap_test(&info->avail_vcpus, i)
                            ? "online" : "offline";
    }

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        return ERROR_FAIL;
    }

    vm_path = xs_read(ctx->xsh, XBT_NULL, GCSPRINTF("%s/vm", dom_path), NULL);
retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    libxl__xs_writev(gc, t, dom_path, ents);
    libxl__xs_writev(gc, t, dom_path, local_ents);
    libxl__xs_writev(gc, t, vm_path, vms_ents);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    xs_introduce_domain(ctx->xsh, domid, state->store_mfn, state->store_port);
    free(vm_path);
    return 0;
}

static int set_vnuma_info(libxl__gc *gc, uint32_t domid,
                          const libxl_domain_build_info *info,
                          const libxl__domain_build_state *state)
{
    int rc = 0;
    unsigned int i, nr_vdistance;
    unsigned int *vcpu_to_vnode, *vnode_to_pnode, *vdistance = NULL;

    vcpu_to_vnode = libxl__calloc(gc, info->max_vcpus,
                                  sizeof(unsigned int));
    vnode_to_pnode = libxl__calloc(gc, info->num_vnuma_nodes,
                                   sizeof(unsigned int));

    nr_vdistance = info->num_vnuma_nodes * info->num_vnuma_nodes;
    vdistance = libxl__calloc(gc, nr_vdistance, sizeof(unsigned int));

    for (i = 0; i < info->num_vnuma_nodes; i++) {
        libxl_vnode_info *v = &info->vnuma_nodes[i];
        int j;

        /* vnode to pnode mapping */
        vnode_to_pnode[i] = v->pnode;

        /* vcpu to vnode mapping */
        libxl_for_each_set_bit(j, v->vcpus)
            vcpu_to_vnode[j] = i;

        /* node distances */
        assert(info->num_vnuma_nodes == v->num_distances);
        memcpy(vdistance + (i * info->num_vnuma_nodes),
               v->distances,
               v->num_distances * sizeof(unsigned int));
    }

    if (xc_domain_setvnuma(CTX->xch, domid, info->num_vnuma_nodes,
                           state->num_vmemranges, info->max_vcpus,
                           state->vmemranges, vdistance,
                           vcpu_to_vnode, vnode_to_pnode) < 0) {
        LOGE(ERROR, "xc_domain_setvnuma failed");
        rc = ERROR_FAIL;
    }

    return rc;
}

int libxl__build_pv(libxl__gc *gc, uint32_t domid,
             libxl_domain_build_info *info, libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    struct xc_dom_image *dom;
    int ret;
    int flags = 0;

    xc_dom_loginit(ctx->xch);

    dom = xc_dom_allocate(ctx->xch, state->pv_cmdline, info->u.pv.features);
    if (!dom) {
        LOGE(ERROR, "xc_dom_allocate failed");
        return ERROR_FAIL;
    }

    dom->pvh_enabled = state->pvh_enabled;

    LOG(DEBUG, "pv kernel mapped %d path %s", state->pv_kernel.mapped, state->pv_kernel.path);

    if (state->pv_kernel.mapped) {
        ret = xc_dom_kernel_mem(dom,
                                state->pv_kernel.data,
                                state->pv_kernel.size);
        if ( ret != 0) {
            LOGE(ERROR, "xc_dom_kernel_mem failed");
            goto out;
        }
    } else {
        ret = xc_dom_kernel_file(dom, state->pv_kernel.path);
        if ( ret != 0) {
            LOGE(ERROR, "xc_dom_kernel_file failed");
            goto out;
        }
    }

    if ( state->pv_ramdisk.path && strlen(state->pv_ramdisk.path) ) {
        if (state->pv_ramdisk.mapped) {
            if ( (ret = xc_dom_ramdisk_mem(dom, state->pv_ramdisk.data, state->pv_ramdisk.size)) != 0 ) {
                LOGE(ERROR, "xc_dom_ramdisk_mem failed");
                goto out;
            }
        } else {
            if ( (ret = xc_dom_ramdisk_file(dom, state->pv_ramdisk.path)) != 0 ) {
                LOGE(ERROR, "xc_dom_ramdisk_file failed");
                goto out;
            }
        }
    }

    dom->flags = flags;
    dom->console_evtchn = state->console_port;
    dom->console_domid = state->console_domid;
    dom->xenstore_evtchn = state->store_port;
    dom->xenstore_domid = state->store_domid;
    dom->claim_enabled = libxl_defbool_val(info->claim_mode);

    if (info->num_vnuma_nodes != 0) {
        unsigned int i;

        ret = libxl__vnuma_build_vmemrange_pv(gc, domid, info, state);
        if (ret) {
            LOGE(ERROR, "cannot build vmemranges");
            goto out;
        }
        ret = libxl__vnuma_config_check(gc, info, state);
        if (ret) goto out;

        ret = set_vnuma_info(gc, domid, info, state);
        if (ret) goto out;

        dom->nr_vmemranges = state->num_vmemranges;
        dom->vmemranges = xc_dom_malloc(dom, sizeof(*dom->vmemranges) *
                                        dom->nr_vmemranges);

        for (i = 0; i < dom->nr_vmemranges; i++) {
            dom->vmemranges[i].start = state->vmemranges[i].start;
            dom->vmemranges[i].end   = state->vmemranges[i].end;
            dom->vmemranges[i].flags = state->vmemranges[i].flags;
            dom->vmemranges[i].nid   = state->vmemranges[i].nid;
        }

        dom->nr_vnodes = info->num_vnuma_nodes;
        dom->vnode_to_pnode = xc_dom_malloc(dom, sizeof(*dom->vnode_to_pnode) *
                                            dom->nr_vnodes);
        for (i = 0; i < info->num_vnuma_nodes; i++)
            dom->vnode_to_pnode[i] = info->vnuma_nodes[i].pnode;
    }

    if ( (ret = xc_dom_boot_xen_init(dom, ctx->xch, domid)) != 0 ) {
        LOGE(ERROR, "xc_dom_boot_xen_init failed");
        goto out;
    }
#ifdef GUEST_RAM_BASE
    if ( (ret = xc_dom_rambase_init(dom, GUEST_RAM_BASE)) != 0 ) {
        LOGE(ERROR, "xc_dom_rambase failed");
        goto out;
    }
#endif
    if ( (ret = xc_dom_parse_image(dom)) != 0 ) {
        LOGE(ERROR, "xc_dom_parse_image failed");
        goto out;
    }
    if ( (ret = libxl__arch_domain_init_hw_description(gc, info, state, dom)) != 0 ) {
        LOGE(ERROR, "libxl__arch_domain_init_hw_description failed");
        goto out;
    }
    if ( (ret = xc_dom_mem_init(dom, info->target_memkb / 1024)) != 0 ) {
        LOGE(ERROR, "xc_dom_mem_init failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_mem_init(dom)) != 0 ) {
        LOGE(ERROR, "xc_dom_boot_mem_init failed");
        goto out;
    }
    if ( (ret = libxl__arch_domain_finalise_hw_description(gc, info, dom)) != 0 ) {
        LOGE(ERROR, "libxl__arch_domain_finalise_hw_description failed");
        goto out;
    }
    if ( (ret = xc_dom_build_image(dom)) != 0 ) {
        LOGE(ERROR, "xc_dom_build_image failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_image(dom)) != 0 ) {
        LOGE(ERROR, "xc_dom_boot_image failed");
        goto out;
    }
    if ( (ret = xc_dom_gnttab_init(dom)) != 0 ) {
        LOGE(ERROR, "xc_dom_gnttab_init failed");
        goto out;
    }

    if (xc_dom_feature_translated(dom)) {
        state->console_mfn = dom->console_pfn;
        state->store_mfn = dom->xenstore_pfn;
    } else {
        state->console_mfn = xc_dom_p2m_host(dom, dom->console_pfn);
        state->store_mfn = xc_dom_p2m_host(dom, dom->xenstore_pfn);
    }

    libxl__file_reference_unmap(&state->pv_kernel);
    libxl__file_reference_unmap(&state->pv_ramdisk);

    ret = 0;
out:
    xc_dom_release(dom);
    return ret == 0 ? 0 : ERROR_FAIL;
}

static int hvm_build_set_params(xc_interface *handle, uint32_t domid,
                                libxl_domain_build_info *info,
                                int store_evtchn, unsigned long *store_mfn,
                                int console_evtchn, unsigned long *console_mfn,
                                domid_t store_domid, domid_t console_domid)
{
    struct hvm_info_table *va_hvm;
    uint8_t *va_map, sum;
    uint64_t str_mfn, cons_mfn;
    int i;

    va_map = xc_map_foreign_range(handle, domid,
                                  XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                  HVM_INFO_PFN);
    if (va_map == NULL)
        return ERROR_FAIL;

    va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
    va_hvm->apic_mode = libxl_defbool_val(info->u.hvm.apic);
    va_hvm->nr_vcpus = info->max_vcpus;
    memset(va_hvm->vcpu_online, 0, sizeof(va_hvm->vcpu_online));
    memcpy(va_hvm->vcpu_online, info->avail_vcpus.map, info->avail_vcpus.size);
    for (i = 0, sum = 0; i < va_hvm->length; i++)
        sum += ((uint8_t *) va_hvm)[i];
    va_hvm->checksum -= sum;
    munmap(va_map, XC_PAGE_SIZE);

    xc_hvm_param_get(handle, domid, HVM_PARAM_STORE_PFN, &str_mfn);
    xc_hvm_param_get(handle, domid, HVM_PARAM_CONSOLE_PFN, &cons_mfn);
    xc_hvm_param_set(handle, domid, HVM_PARAM_STORE_EVTCHN, store_evtchn);
    xc_hvm_param_set(handle, domid, HVM_PARAM_CONSOLE_EVTCHN, console_evtchn);

    *store_mfn = str_mfn;
    *console_mfn = cons_mfn;

    xc_dom_gnttab_hvm_seed(handle, domid, *console_mfn, *store_mfn, console_domid, store_domid);
    return 0;
}

static int hvm_build_set_xs_values(libxl__gc *gc,
                                   uint32_t domid,
                                   struct xc_hvm_build_args *args)
{
    char *path = NULL;
    int ret = 0;

    if (args->smbios_module.guest_addr_out) {
        path = GCSPRINTF("/local/domain/%d/"HVM_XS_SMBIOS_PT_ADDRESS, domid);

        ret = libxl__xs_write(gc, XBT_NULL, path, "0x%"PRIx64,
                              args->smbios_module.guest_addr_out);
        if (ret)
            goto err;

        path = GCSPRINTF("/local/domain/%d/"HVM_XS_SMBIOS_PT_LENGTH, domid);

        ret = libxl__xs_write(gc, XBT_NULL, path, "0x%x",
                              args->smbios_module.length);
        if (ret)
            goto err;
    }

    if (args->acpi_module.guest_addr_out) {
        path = GCSPRINTF("/local/domain/%d/"HVM_XS_ACPI_PT_ADDRESS, domid);

        ret = libxl__xs_write(gc, XBT_NULL, path, "0x%"PRIx64,
                              args->acpi_module.guest_addr_out);
        if (ret)
            goto err;

        path = GCSPRINTF("/local/domain/%d/"HVM_XS_ACPI_PT_LENGTH, domid);

        ret = libxl__xs_write(gc, XBT_NULL, path, "0x%x",
                              args->acpi_module.length);
        if (ret)
            goto err;
    }

    return 0;

err:
    LOG(ERROR, "failed to write firmware xenstore value, err: %d", ret);
    return ret;
}

static int libxl__domain_firmware(libxl__gc *gc,
                                  libxl_domain_build_info *info,
                                  struct xc_hvm_build_args *args)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *firmware;
    int e, rc = ERROR_FAIL;
    int datalen = 0;
    void *data;

    if (info->u.hvm.firmware)
        firmware = info->u.hvm.firmware;
    else {
        switch (info->device_model_version)
        {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            firmware = "hvmloader";
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            firmware = "hvmloader";
            break;
        default:
            LOG(ERROR, "invalid device model version %d",
                info->device_model_version);
            return ERROR_FAIL;
            break;
        }
    }
    args->image_file_name = libxl__abs_path(gc, firmware,
                                            libxl__xenfirmwaredir_path());

    if (info->u.hvm.smbios_firmware) {
        data = NULL;
        e = libxl_read_file_contents(ctx, info->u.hvm.smbios_firmware,
                                     &data, &datalen);
        if (e) {
            LOGEV(ERROR, e, "failed to read SMBIOS firmware file %s",
                info->u.hvm.smbios_firmware);
            goto out;
        }
        libxl__ptr_add(gc, data);
        if (datalen) {
            /* Only accept non-empty files */
            args->smbios_module.data = data;
            args->smbios_module.length = (uint32_t)datalen;
        }
    }

    if (info->u.hvm.acpi_firmware) {
        data = NULL;
        e = libxl_read_file_contents(ctx, info->u.hvm.acpi_firmware,
                                     &data, &datalen);
        if (e) {
            LOGEV(ERROR, e, "failed to read ACPI firmware file %s",
                info->u.hvm.acpi_firmware);
            goto out;
        }
        libxl__ptr_add(gc, data);
        if (datalen) {
            /* Only accept non-empty files */
            args->acpi_module.data = data;
            args->acpi_module.length = (uint32_t)datalen;
        }
    }

    return 0;
out:
    return rc;
}

int libxl__build_hvm(libxl__gc *gc, uint32_t domid,
              libxl_domain_config *d_config,
              libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    struct xc_hvm_build_args args = {};
    int ret, rc;
    uint64_t mmio_start, lowmem_end, highmem_end;
    libxl_domain_build_info *const info = &d_config->b_info;

    memset(&args, 0, sizeof(struct xc_hvm_build_args));
    /* The params from the configuration file are in Mb, which are then
     * multiplied by 1 Kb. This was then divided off when calling
     * the old xc_hvm_build_target_mem() which then turned them to bytes.
     * Do all this in one step here...
     */
    args.mem_size = (uint64_t)(info->max_memkb - info->video_memkb) << 10;
    args.mem_target = (uint64_t)(info->target_memkb - info->video_memkb) << 10;
    args.claim_enabled = libxl_defbool_val(info->claim_mode);
    if (info->u.hvm.mmio_hole_memkb) {
        uint64_t max_ram_below_4g = (1ULL << 32) -
            (info->u.hvm.mmio_hole_memkb << 10);

        if (max_ram_below_4g < HVM_BELOW_4G_MMIO_START)
            args.mmio_size = info->u.hvm.mmio_hole_memkb << 10;
    }

    rc = libxl__domain_firmware(gc, info, &args);
    if (rc != 0) {
        LOG(ERROR, "initializing domain firmware failed");
        goto out;
    }
    if (args.mem_target == 0)
        args.mem_target = args.mem_size;
    if (args.mmio_size == 0)
        args.mmio_size = HVM_BELOW_4G_MMIO_LENGTH;
    lowmem_end = args.mem_size;
    highmem_end = 0;
    mmio_start = (1ull << 32) - args.mmio_size;
    if (lowmem_end > mmio_start)
    {
        highmem_end = (1ull << 32) + (lowmem_end - mmio_start);
        lowmem_end = mmio_start;
    }
    args.lowmem_end = lowmem_end;
    args.highmem_end = highmem_end;
    args.mmio_start = mmio_start;

    rc = libxl__domain_device_construct_rdm(gc, d_config,
                                            info->u.hvm.rdm_mem_boundary_memkb*1024,
                                            &args);
    if (rc) {
        LOG(ERROR, "checking reserved device memory failed");
        goto out;
    }

    if (info->num_vnuma_nodes != 0) {
        int i;

        rc = libxl__vnuma_build_vmemrange_hvm(gc, domid, info, state, &args);
        if (rc != 0) {
            LOG(ERROR, "hvm build vmemranges failed");
            goto out;
        }
        rc = libxl__vnuma_config_check(gc, info, state);
        if (rc != 0) goto out;
        rc = set_vnuma_info(gc, domid, info, state);
        if (rc != 0) goto out;

        args.nr_vmemranges = state->num_vmemranges;
        args.vmemranges = libxl__malloc(gc, sizeof(*args.vmemranges) *
                                        args.nr_vmemranges);

        for (i = 0; i < args.nr_vmemranges; i++) {
            args.vmemranges[i].start = state->vmemranges[i].start;
            args.vmemranges[i].end   = state->vmemranges[i].end;
            args.vmemranges[i].flags = state->vmemranges[i].flags;
            args.vmemranges[i].nid   = state->vmemranges[i].nid;
        }

        args.nr_vnodes = info->num_vnuma_nodes;
        args.vnode_to_pnode = libxl__malloc(gc, sizeof(*args.vnode_to_pnode) *
                                            args.nr_vnodes);
        for (i = 0; i < args.nr_vnodes; i++)
            args.vnode_to_pnode[i] = info->vnuma_nodes[i].pnode;
    }

    ret = xc_hvm_build(ctx->xch, domid, &args);
    if (ret) {
        LOGEV(ERROR, ret, "hvm building failed");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__arch_domain_construct_memmap(gc, d_config, domid, &args);
    if (rc != 0) {
        LOG(ERROR, "setting domain memory map failed");
        goto out;
    }

    rc = hvm_build_set_params(ctx->xch, domid, info, state->store_port,
                               &state->store_mfn, state->console_port,
                               &state->console_mfn, state->store_domid,
                               state->console_domid);
    if (rc != 0) {
        LOG(ERROR, "hvm build set params failed");
        goto out;
    }

    rc = hvm_build_set_xs_values(gc, domid, &args);
    if (rc != 0) {
        LOG(ERROR, "hvm build set xenstore values failed");
        goto out;
    }

    return 0;
out:
    assert(rc != 0);
    return rc;
}

int libxl__qemu_traditional_cmd(libxl__gc *gc, uint32_t domid,
                                const char *cmd)
{
    char *path = NULL;
    uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);
    path = libxl__device_model_xs_path(gc, dm_domid, domid, "/command");
    return libxl__xs_write(gc, XBT_NULL, path, "%s", cmd);
}

/*
 * Inspect the buffer between start and end, and return a pointer to the
 * character following the NUL terminator of start, or NULL if start is not
 * terminated before end.
 */
static const char *next_string(const char *start, const char *end)
{
    if (start >= end) return NULL;

    size_t total_len = end - start;
    size_t len = strnlen(start, total_len);

    if (len == total_len)
        return NULL;
    else
        return start + len + 1;
}

int libxl__restore_emulator_xenstore_data(libxl__domain_create_state *dcs,
                                          const char *ptr, uint32_t size)
{
    STATE_AO_GC(dcs->ao);
    const char *next = ptr, *end = ptr + size, *key, *val;
    int rc;

    const uint32_t domid = dcs->guest_domid;
    const uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);
    const char *xs_root = libxl__device_model_xs_path(gc, dm_domid, domid, "");

    while (next < end) {
        key = next;
        next = next_string(next, end);

        /* Sanitise 'key'. */
        if (!next) {
            rc = ERROR_FAIL;
            LOG(ERROR, "Key in xenstore data not NUL terminated");
            goto out;
        }
        if (key[0] == '\0') {
            rc = ERROR_FAIL;
            LOG(ERROR, "empty key found in xenstore data");
            goto out;
        }
        if (key[0] == '/') {
            rc = ERROR_FAIL;
            LOG(ERROR, "Key in xenstore data not relative");
            goto out;
        }

        val = next;
        next = next_string(next, end);

        /* Sanitise 'val'. */
        if (!next) {
            rc = ERROR_FAIL;
            LOG(ERROR, "Val in xenstore data not NUL terminated");
            goto out;
        }

        libxl__xs_write(gc, XBT_NULL,
                        GCSPRINTF("%s/%s", xs_root, key), "%s", val);
    }

    rc = 0;

 out:
    return rc;
}

/*==================== Domain suspend (save) ====================*/

static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *sws, int rc);
static void domain_save_done(libxl__egc *egc,
                             libxl__domain_suspend_state *dss, int rc);

/*----- complicated callback, called by xc_domain_save -----*/

/*
 * We implement the other end of protocol for controlling qemu-dm's
 * logdirty.  There is no documentation for this protocol, but our
 * counterparty's implementation is in
 * qemu-xen-traditional.git:xenstore.c in the function
 * xenstore_process_logdirty_event
 */

static void switch_logdirty_timeout(libxl__egc *egc, libxl__ev_time *ev,
                                    const struct timeval *requested_abs,
                                    int rc);
static void switch_logdirty_xswatch(libxl__egc *egc, libxl__ev_xswatch*,
                            const char *watch_path, const char *event_path);
static void switch_logdirty_done(libxl__egc *egc,
                                 libxl__domain_suspend_state *dss, int rc);

static void logdirty_init(libxl__logdirty_switch *lds)
{
    lds->cmd_path = 0;
    libxl__ev_xswatch_init(&lds->watch);
    libxl__ev_time_init(&lds->timeout);
}

static void domain_suspend_switch_qemu_xen_traditional_logdirty
                               (int domid, unsigned enable,
                                libxl__save_helper_state *shs)
{
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = shs->caller_state;
    libxl__logdirty_switch *lds = &dss->logdirty;
    STATE_AO_GC(dss->ao);
    int rc;
    xs_transaction_t t = 0;
    const char *got;

    if (!lds->cmd_path) {
        uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);
        lds->cmd_path = libxl__device_model_xs_path(gc, dm_domid, domid,
                                                    "/logdirty/cmd");
        lds->ret_path = libxl__device_model_xs_path(gc, dm_domid, domid,
                                                    "/logdirty/ret");
    }
    lds->cmd = enable ? "enable" : "disable";

    rc = libxl__ev_xswatch_register(gc, &lds->watch,
                                switch_logdirty_xswatch, lds->ret_path);
    if (rc) goto out;

    rc = libxl__ev_time_register_rel(ao, &lds->timeout,
                                switch_logdirty_timeout, 10*1000);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__xs_read_checked(gc, t, lds->cmd_path, &got);
        if (rc) goto out;

        if (got) {
            const char *got_ret;
            rc = libxl__xs_read_checked(gc, t, lds->ret_path, &got_ret);
            if (rc) goto out;

            if (!got_ret || strcmp(got, got_ret)) {
                LOG(ERROR,"controlling logdirty: qemu was already sent"
                    " command `%s' (xenstore path `%s') but result is `%s'",
                    got, lds->cmd_path, got_ret ? got_ret : "<none>");
                rc = ERROR_FAIL;
                goto out;
            }
            rc = libxl__xs_rm_checked(gc, t, lds->cmd_path);
            if (rc) goto out;
        }

        rc = libxl__xs_rm_checked(gc, t, lds->ret_path);
        if (rc) goto out;

        rc = libxl__xs_write_checked(gc, t, lds->cmd_path, lds->cmd);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc<0) goto out;
    }

    /* OK, wait for some callback */
    return;

 out:
    LOG(ERROR,"logdirty switch failed (rc=%d), abandoning suspend",rc);
    libxl__xs_transaction_abort(gc, &t);
    switch_logdirty_done(egc,dss,rc);
}

static void domain_suspend_switch_qemu_xen_logdirty
                               (int domid, unsigned enable,
                                libxl__save_helper_state *shs)
{
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = shs->caller_state;
    STATE_AO_GC(dss->ao);
    int rc;

    rc = libxl__qmp_set_global_dirty_log(gc, domid, enable);
    if (!rc) {
        libxl__xc_domain_saverestore_async_callback_done(egc, shs, 0);
    } else {
        LOG(ERROR,"logdirty switch failed (rc=%d), abandoning suspend",rc);
        dss->rc = rc;
        libxl__xc_domain_saverestore_async_callback_done(egc, shs, -1);
    }
}

void libxl__domain_suspend_common_switch_qemu_logdirty
                               (int domid, unsigned enable, void *user)
{
    libxl__save_helper_state *shs = user;
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = shs->caller_state;
    STATE_AO_GC(dss->ao);

    switch (libxl__device_model_version_running(gc, domid)) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        domain_suspend_switch_qemu_xen_traditional_logdirty(domid, enable, shs);
        break;
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        domain_suspend_switch_qemu_xen_logdirty(domid, enable, shs);
        break;
    default:
        LOG(ERROR,"logdirty switch failed"
            ", no valid device model version found, abandoning suspend");
        dss->rc = ERROR_FAIL;
        libxl__xc_domain_saverestore_async_callback_done(egc, shs, -1);
    }
}
static void switch_logdirty_timeout(libxl__egc *egc, libxl__ev_time *ev,
                                    const struct timeval *requested_abs,
                                    int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(ev, *dss, logdirty.timeout);
    STATE_AO_GC(dss->ao);
    LOG(ERROR,"logdirty switch: wait for device model timed out");
    switch_logdirty_done(egc,dss,ERROR_FAIL);
}

static void switch_logdirty_xswatch(libxl__egc *egc, libxl__ev_xswatch *watch,
                            const char *watch_path, const char *event_path)
{
    libxl__domain_suspend_state *dss =
        CONTAINER_OF(watch, *dss, logdirty.watch);
    libxl__logdirty_switch *lds = &dss->logdirty;
    STATE_AO_GC(dss->ao);
    const char *got;
    xs_transaction_t t = 0;
    int rc;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__xs_read_checked(gc, t, lds->ret_path, &got);
        if (rc) goto out;

        if (!got) {
            rc = +1;
            goto out;
        }

        if (strcmp(got, lds->cmd)) {
            LOG(ERROR,"logdirty switch: sent command `%s' but got reply `%s'"
                " (xenstore paths `%s' / `%s')", lds->cmd, got,
                lds->cmd_path, lds->ret_path);
            rc = ERROR_FAIL;
            goto out;
        }

        rc = libxl__xs_rm_checked(gc, t, lds->cmd_path);
        if (rc) goto out;

        rc = libxl__xs_rm_checked(gc, t, lds->ret_path);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc<0) goto out;
    }

 out:
    /* rc < 0: error
     * rc == 0: ok, we are done
     * rc == +1: need to keep waiting
     */
    libxl__xs_transaction_abort(gc, &t);

    if (rc <= 0) {
        if (rc < 0)
            LOG(ERROR,"logdirty switch: failed (rc=%d)",rc);
        switch_logdirty_done(egc,dss,rc);
    }
}

static void switch_logdirty_done(libxl__egc *egc,
                                 libxl__domain_suspend_state *dss,
                                 int rc)
{
    STATE_AO_GC(dss->ao);
    libxl__logdirty_switch *lds = &dss->logdirty;

    libxl__ev_xswatch_deregister(gc, &lds->watch);
    libxl__ev_time_deregister(gc, &lds->timeout);

    int broke;
    if (rc) {
        broke = -1;
        dss->rc = rc;
    } else {
        broke = 0;
    }
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, broke);
}

/*----- callbacks, called by xc_domain_save -----*/

/*
 * Expand the buffer 'buf' of length 'len', to append 'str' including its NUL
 * terminator.
 */
static void append_string(libxl__gc *gc, char **buf, uint32_t *len,
                          const char *str)
{
    size_t extralen = strlen(str) + 1;
    char *new = libxl__realloc(gc, *buf, *len + extralen);

    *buf = new;
    memcpy(new + *len, str, extralen);
    *len += extralen;
}

int libxl__save_emulator_xenstore_data(libxl__domain_suspend_state *dss,
                                       char **callee_buf,
                                       uint32_t *callee_len)
{
    STATE_AO_GC(dss->ao);
    const char *xs_root;
    char **entries, *buf = NULL;
    unsigned int nr_entries, i, j, len = 0;
    int rc;

    const uint32_t domid = dss->domid;
    const uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);

    xs_root = libxl__device_model_xs_path(gc, dm_domid, domid, "");

    entries = libxl__xs_directory(gc, 0, GCSPRINTF("%s/physmap", xs_root),
                                  &nr_entries);
    if (!entries || nr_entries == 0) { rc = 0; goto out; }

    for (i = 0; i < nr_entries; ++i) {
        static const char *const physmap_subkeys[] = {
            "start_addr", "size", "name"
        };

        for (j = 0; j < ARRAY_SIZE(physmap_subkeys); ++j) {
            const char *key = GCSPRINTF("physmap/%s/%s",
                                        entries[i], physmap_subkeys[j]);

            const char *val =
                libxl__xs_read(gc, XBT_NULL,
                               GCSPRINTF("%s/%s", xs_root, key));

            if (!val) { rc = ERROR_FAIL; goto out; }

            append_string(gc, &buf, &len, key);
            append_string(gc, &buf, &len, val);
        }
    }

    rc = 0;

 out:
    if (!rc) {
        *callee_buf = buf;
        *callee_len = len;
    }

    return rc;
}

/*----- remus callbacks -----*/
static void remus_domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state *dss, int ok);
static void remus_devices_postsuspend_cb(libxl__egc *egc,
                                         libxl__remus_devices_state *rds,
                                         int rc);
static void remus_devices_preresume_cb(libxl__egc *egc,
                                       libxl__remus_devices_state *rds,
                                       int rc);

static void libxl__remus_domain_suspend_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = shs->caller_state;

    dss->callback_common_done = remus_domain_suspend_callback_common_done;
    libxl__domain_suspend(egc, dss);
}

static void remus_domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state *dss, int rc)
{
    if (rc)
        goto out;

    libxl__remus_devices_state *const rds = &dss->rds;
    rds->callback = remus_devices_postsuspend_cb;
    libxl__remus_devices_postsuspend(egc, rds);
    return;

out:
    dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void remus_devices_postsuspend_cb(libxl__egc *egc,
                                         libxl__remus_devices_state *rds,
                                         int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(rds, *dss, rds);

    if (rc)
        goto out;

    rc = 0;

out:
    if (rc)
        dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void libxl__remus_domain_resume_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = shs->caller_state;
    STATE_AO_GC(dss->ao);

    libxl__remus_devices_state *const rds = &dss->rds;
    rds->callback = remus_devices_preresume_cb;
    libxl__remus_devices_preresume(egc, rds);
}

static void remus_devices_preresume_cb(libxl__egc *egc,
                                       libxl__remus_devices_state *rds,
                                       int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(rds, *dss, rds);
    STATE_AO_GC(dss->ao);

    if (rc)
        goto out;

    /* Resumes the domain and the device model */
    rc = libxl__domain_resume(gc, dss->domid, /* Fast Suspend */1);
    if (rc)
        goto out;

    rc = 0;

out:
    if (rc)
        dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

/*----- remus asynchronous checkpoint callback -----*/

static void remus_checkpoint_stream_written(
    libxl__egc *egc, libxl__stream_write_state *sws, int rc);
static void remus_devices_commit_cb(libxl__egc *egc,
                                    libxl__remus_devices_state *rds,
                                    int rc);
static void remus_next_checkpoint(libxl__egc *egc, libxl__ev_time *ev,
                                  const struct timeval *requested_abs,
                                  int rc);

static void libxl__remus_domain_save_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__domain_suspend_state *dss = shs->caller_state;
    libxl__egc *egc = shs->egc;
    STATE_AO_GC(dss->ao);

    libxl__stream_write_start_checkpoint(egc, &dss->sws);
}

static void remus_checkpoint_stream_written(
    libxl__egc *egc, libxl__stream_write_state *sws, int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(sws, *dss, sws);

    /* Convenience aliases */
    libxl__remus_devices_state *const rds = &dss->rds;

    STATE_AO_GC(dss->ao);

    if (rc) {
        LOG(ERROR, "Failed to save device model. Terminating Remus..");
        goto out;
    }

    rds->callback = remus_devices_commit_cb;
    libxl__remus_devices_commit(egc, rds);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void remus_devices_commit_cb(libxl__egc *egc,
                                    libxl__remus_devices_state *rds,
                                    int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(rds, *dss, rds);

    STATE_AO_GC(dss->ao);

    if (rc) {
        LOG(ERROR, "Failed to do device commit op."
            " Terminating Remus..");
        goto out;
    }

    /*
     * At this point, we have successfully checkpointed the guest and
     * committed it at the backup. We'll come back after the checkpoint
     * interval to checkpoint the guest again. Until then, let the guest
     * continue execution.
     */

    /* Set checkpoint interval timeout */
    rc = libxl__ev_time_register_rel(ao, &dss->checkpoint_timeout,
                                     remus_next_checkpoint,
                                     dss->interval);

    if (rc)
        goto out;

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void remus_next_checkpoint(libxl__egc *egc, libxl__ev_time *ev,
                                  const struct timeval *requested_abs,
                                  int rc)
{
    libxl__domain_suspend_state *dss =
                            CONTAINER_OF(ev, *dss, checkpoint_timeout);

    STATE_AO_GC(dss->ao);

    if (rc == ERROR_TIMEDOUT) /* As intended */
        rc = 0;

    /*
     * Time to checkpoint the guest again. We return 1 to libxc
     * (xc_domain_save.c). in order to continue executing the infinite loop
     * (suspend, checkpoint, resume) in xc_domain_save().
     */

    if (rc)
        dss->rc = rc;

    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

/*----- main code for saving, in order of execution -----*/

void libxl__domain_save(libxl__egc *egc, libxl__domain_suspend_state *dss)
{
    STATE_AO_GC(dss->ao);
    int port;
    int rc, ret;

    /* Convenience aliases */
    const uint32_t domid = dss->domid;
    const libxl_domain_type type = dss->type;
    const int live = dss->live;
    const int debug = dss->debug;
    const libxl_domain_remus_info *const r_info = dss->remus;
    libxl__srm_save_autogen_callbacks *const callbacks =
        &dss->sws.shs.callbacks.save.a;
    unsigned int nr_vnodes = 0, nr_vmemranges = 0, nr_vcpus = 0;

    dss->rc = 0;
    logdirty_init(&dss->logdirty);
    libxl__xswait_init(&dss->pvcontrol);
    libxl__ev_evtchn_init(&dss->guest_evtchn);
    libxl__ev_xswatch_init(&dss->guest_watch);
    libxl__ev_time_init(&dss->guest_timeout);

    switch (type) {
    case LIBXL_DOMAIN_TYPE_HVM: {
        dss->hvm = 1;
        break;
    }
    case LIBXL_DOMAIN_TYPE_PV:
        dss->hvm = 0;
        break;
    default:
        abort();
    }

    dss->xcflags = (live ? XCFLAGS_LIVE : 0)
          | (debug ? XCFLAGS_DEBUG : 0)
          | (dss->hvm ? XCFLAGS_HVM : 0);

    /* Disallow saving a guest with vNUMA configured because migration
     * stream does not preserve node information.
     *
     * Reject any domain which has vnuma enabled, even if the
     * configuration is empty. Only domains which have no vnuma
     * configuration at all are supported.
     */
    ret = xc_domain_getvnuma(CTX->xch, domid, &nr_vnodes, &nr_vmemranges,
                             &nr_vcpus, NULL, NULL, NULL);
    if (ret != -1 || errno != XEN_EOPNOTSUPP) {
        LOG(ERROR, "Cannot save a guest with vNUMA configured");
        rc = ERROR_FAIL;
        goto out;
    }

    dss->guest_evtchn.port = -1;
    dss->guest_evtchn_lockfd = -1;
    dss->guest_responded = 0;
    dss->dm_savefile = libxl__device_model_savefile(gc, domid);

    if (r_info != NULL) {
        dss->interval = r_info->interval;
        dss->xcflags |= XCFLAGS_CHECKPOINTED;
        if (libxl_defbool_val(r_info->compression))
            dss->xcflags |= XCFLAGS_CHECKPOINT_COMPRESS;
    }

    port = xs_suspend_evtchn_port(dss->domid);

    if (port >= 0) {
        rc = libxl__ctx_evtchn_init(gc);
        if (rc) goto out;

        dss->guest_evtchn.port =
            xc_suspend_evtchn_init_exclusive(CTX->xch, CTX->xce,
                                  dss->domid, port, &dss->guest_evtchn_lockfd);

        if (dss->guest_evtchn.port < 0) {
            LOG(WARN, "Suspend event channel initialization failed");
            rc = ERROR_FAIL;
            goto out;
        }
    }

    memset(callbacks, 0, sizeof(*callbacks));
    if (r_info != NULL) {
        callbacks->suspend = libxl__remus_domain_suspend_callback;
        callbacks->postcopy = libxl__remus_domain_resume_callback;
        callbacks->checkpoint = libxl__remus_domain_save_checkpoint_callback;
        dss->sws.checkpoint_callback = remus_checkpoint_stream_written;
    } else
        callbacks->suspend = libxl__domain_suspend_callback;

    callbacks->switch_qemu_logdirty = libxl__domain_suspend_common_switch_qemu_logdirty;

    dss->sws.ao  = dss->ao;
    dss->sws.dss = dss;
    dss->sws.fd  = dss->fd;
    dss->sws.completion_callback = stream_done;

    libxl__stream_write_start(egc, &dss->sws);
    return;

 out:
    domain_save_done(egc, dss, rc);
}

static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *sws, int rc)
{
    domain_save_done(egc, sws->dss, rc);
}

static void save_device_model_datacopier_done(libxl__egc *egc,
     libxl__datacopier_state *dc, int rc, int onwrite, int errnoval);

void libxl__domain_save_device_model(libxl__egc *egc,
                                     libxl__domain_suspend_state *dss,
                                     libxl__save_device_model_cb *callback)
{
    STATE_AO_GC(dss->ao);
    struct stat st;
    uint32_t qemu_state_len;
    int rc;

    dss->save_dm_callback = callback;

    /* Convenience aliases */
    const char *const filename = dss->dm_savefile;
    const int fd = dss->fd;

    libxl__datacopier_state *dc = &dss->save_dm_datacopier;
    memset(dc, 0, sizeof(*dc));
    dc->readwhat = GCSPRINTF("qemu save file %s", filename);
    dc->ao = ao;
    dc->readfd = -1;
    dc->writefd = fd;
    dc->maxsz = INT_MAX;
    dc->bytes_to_read = -1;
    dc->copywhat = GCSPRINTF("qemu save file for domain %"PRIu32, dss->domid);
    dc->writewhat = "save/migration stream";
    dc->callback = save_device_model_datacopier_done;

    dc->readfd = open(filename, O_RDONLY);
    if (dc->readfd < 0) {
        LOGE(ERROR, "unable to open %s", dc->readwhat);
        rc = ERROR_FAIL;
        goto out;
    }

    if (fstat(dc->readfd, &st))
    {
        LOGE(ERROR, "unable to fstat %s", dc->readwhat);
        rc = ERROR_FAIL;
        goto out;
    }

    if (!S_ISREG(st.st_mode)) {
        LOG(ERROR, "%s is not a plain file!", dc->readwhat);
        rc = ERROR_FAIL;
        goto out;
    }

    qemu_state_len = st.st_size;
    LOG(DEBUG, "%s is %d bytes", dc->readwhat, qemu_state_len);

    rc = libxl__datacopier_start(dc);
    if (rc) goto out;

    libxl__datacopier_prefixdata(egc, dc,
                                 QEMU_SIGNATURE, strlen(QEMU_SIGNATURE));

    libxl__datacopier_prefixdata(egc, dc,
                                 &qemu_state_len, sizeof(qemu_state_len));
    return;

 out:
    save_device_model_datacopier_done(egc, dc, rc, -1, EIO);
}

static void save_device_model_datacopier_done(libxl__egc *egc,
     libxl__datacopier_state *dc, int our_rc, int onwrite, int errnoval)
{
    libxl__domain_suspend_state *dss =
        CONTAINER_OF(dc, *dss, save_dm_datacopier);
    STATE_AO_GC(dss->ao);

    /* Convenience aliases */
    const char *const filename = dss->dm_savefile;
    int rc;

    libxl__datacopier_kill(dc);

    if (dc->readfd >= 0) {
        close(dc->readfd);
        dc->readfd = -1;
    }

    rc = libxl__remove_file(gc, filename);
    if (!our_rc) our_rc = rc;

    dss->save_dm_callback(egc, dss, our_rc);
}

static void libxl__remus_teardown(libxl__egc *egc,
                                  libxl__domain_suspend_state *dss,
                                  int rc);
static void remus_teardown_done(libxl__egc *egc,
                                       libxl__remus_devices_state *rds,
                                       int rc);

static void domain_save_done(libxl__egc *egc,
                             libxl__domain_suspend_state *dss, int rc)
{
    STATE_AO_GC(dss->ao);

    /* Convenience aliases */
    const uint32_t domid = dss->domid;

    libxl__ev_evtchn_cancel(gc, &dss->guest_evtchn);

    if (dss->guest_evtchn.port > 0)
        xc_suspend_evtchn_release(CTX->xch, CTX->xce, domid,
                           dss->guest_evtchn.port, &dss->guest_evtchn_lockfd);

    if (dss->remus) {
        /*
         * With Remus, if we reach this point, it means either
         * backup died or some network error occurred preventing us
         * from sending checkpoints. Teardown the network buffers and
         * release netlink resources.  This is an async op.
         */
        libxl__remus_teardown(egc, dss, rc);
        return;
    }

    dss->callback(egc, dss, rc);
}

static void libxl__remus_teardown(libxl__egc *egc,
                                  libxl__domain_suspend_state *dss,
                                  int rc)
{
    EGC_GC;

    LOG(WARN, "Remus: Domain suspend terminated with rc %d,"
        " teardown Remus devices...", rc);
    dss->rds.callback = remus_teardown_done;
    libxl__remus_devices_teardown(egc, &dss->rds);
}

static void remus_teardown_done(libxl__egc *egc,
                                       libxl__remus_devices_state *rds,
                                       int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(rds, *dss, rds);
    STATE_AO_GC(dss->ao);

    if (rc)
        LOG(ERROR, "Remus: failed to teardown device for guest with domid %u,"
            " rc %d", dss->domid, rc);

    dss->callback(egc, dss, rc);
}

/*==================== Miscellaneous ====================*/

char *libxl__uuid2string(libxl__gc *gc, const libxl_uuid uuid)
{
    return GCSPRINTF(LIBXL_UUID_FMT, LIBXL_UUID_BYTES(uuid));
}

const char *libxl__userdata_path(libxl__gc *gc, uint32_t domid,
                                 const char *userdata_userid,
                                 const char *wh)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *uuid_string, *path;
    libxl_dominfo info;
    int rc;

    libxl_dominfo_init(&info);

    rc = libxl_domain_info(ctx, &info, domid);
    if (rc) {
        LOGE(ERROR, "unable to find domain info for domain %"PRIu32, domid);
        path = NULL;
        goto out;
    }
    uuid_string = GCSPRINTF(LIBXL_UUID_FMT, LIBXL_UUID_BYTES(info.uuid));
    path = GCSPRINTF("/var/lib/xen/userdata-%s.%u.%s.%s",
                     wh, domid, uuid_string, userdata_userid);

 out:
    libxl_dominfo_dispose(&info);
    return path;
}

static int userdata_delete(libxl__gc *gc, const char *path)
{
    int r;
    r = unlink(path);
    if (r) {
        LOGE(ERROR, "remove failed for %s", path);
        return errno;
    }
    return 0;
}

void libxl__userdata_destroyall(libxl__gc *gc, uint32_t domid)
{
    const char *pattern;
    glob_t gl;
    int r, i;

    pattern = libxl__userdata_path(gc, domid, "*", "?");
    if (!pattern)
        goto out;

    gl.gl_pathc = 0;
    gl.gl_pathv = 0;
    gl.gl_offs = 0;
    r = glob(pattern, GLOB_ERR|GLOB_NOSORT|GLOB_MARK, 0, &gl);
    if (r == GLOB_NOMATCH)
        goto out;
    if (r)
        LOGE(ERROR, "glob failed for %s", pattern);

    /* Note: don't delete domain-userdata-lock, it will be handled by
     * unlock function.
     */
    for (i=0; i<gl.gl_pathc; i++) {
        if (!strstr(gl.gl_pathv[i], "domain-userdata-lock"))
            userdata_delete(gc, gl.gl_pathv[i]);
    }
    globfree(&gl);
out:
    return;
}

int libxl__userdata_store(libxl__gc *gc, uint32_t domid,
                          const char *userdata_userid,
                          const uint8_t *data, int datalen)
{
    const char *filename;
    const char *newfilename;
    int e, rc;
    int fd = -1;

    filename = libxl__userdata_path(gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    if (!datalen) {
        rc = userdata_delete(gc, filename);
        goto out;
    }

    newfilename = libxl__userdata_path(gc, domid, userdata_userid, "n");
    if (!newfilename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    rc = ERROR_FAIL;

    fd = open(newfilename, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        goto err;

    if (libxl_write_exactly(CTX, fd, data, datalen, "userdata", newfilename))
        goto err;

    if (close(fd) < 0) {
        fd = -1;
        goto err;
    }
    fd = -1;

    if (rename(newfilename, filename))
        goto err;

    rc = 0;

err:
    if (fd >= 0) {
        e = errno;
        close(fd);
        errno = e;
    }

    if (rc)
        LIBXL__LOG_ERRNO(CTX, LIBXL__LOG_ERROR, "cannot write/rename %s for %s",
                 newfilename, filename);
out:
    return rc;
}

int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen)
{
    GC_INIT(ctx);
    int rc;
    libxl__domain_userdata_lock *lock;

    CTX_LOCK;
    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__userdata_store(gc, domid, userdata_userid,
                               data, datalen);

    libxl__unlock_domain_userdata(lock);

out:
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

int libxl__userdata_retrieve(libxl__gc *gc, uint32_t domid,
                             const char *userdata_userid,
                             uint8_t **data_r, int *datalen_r)
{
    const char *filename;
    int e, rc;
    int datalen = 0;
    void *data = 0;

    filename = libxl__userdata_path(gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    e = libxl_read_file_contents(CTX, filename, data_r ? &data : 0, &datalen);
    if (e && errno != ENOENT) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (!e && !datalen) {
        LIBXL__LOG(CTX, LIBXL__LOG_ERROR, "userdata file %s is empty", filename);
        if (data_r) assert(!*data_r);
        rc = ERROR_FAIL;
        goto out;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;
    rc = 0;

out:
    return rc;
}

int libxl_userdata_retrieve(libxl_ctx *ctx, uint32_t domid,
                                 const char *userdata_userid,
                                 uint8_t **data_r, int *datalen_r)
{
    GC_INIT(ctx);
    int rc;
    libxl__domain_userdata_lock *lock;

    CTX_LOCK;
    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__userdata_retrieve(gc, domid, userdata_userid,
                                  data_r, datalen_r);


    libxl__unlock_domain_userdata(lock);
out:
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

int libxl_userdata_unlink(libxl_ctx *ctx, uint32_t domid,
                          const char *userdata_userid)
{
    GC_INIT(ctx);
    CTX_LOCK;

    int rc;
    libxl__domain_userdata_lock *lock = NULL;
    const char *filename;

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    filename = libxl__userdata_path(gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (unlink(filename)) {
        LOGE(ERROR, "error deleting userdata file: %s", filename);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    if (lock)
        libxl__unlock_domain_userdata(lock);
    CTX_UNLOCK;
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
