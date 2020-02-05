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

#include "_paths.h"

//#define DEBUG 1

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
    if (info.flags & XEN_DOMINF_hvm_guest) {
        const char *type_path = GCSPRINTF("%s/type",
                                          libxl__xs_libxl_path(gc, domid));
        const char *type;
        libxl_domain_type t;
        int rc;

        rc = libxl__xs_read_mandatory(gc, XBT_NULL, type_path, &type);
        if (rc) {
            LOG(WARN,
            "unable to get domain type for domid=%"PRIu32", assuming HVM",
                domid);
            return LIBXL_DOMAIN_TYPE_HVM;
        }

        rc = libxl_domain_type_from_string(type, &t);
        if (rc) {
            LOG(WARN,
            "unable to get domain type for domid=%"PRIu32", assuming HVM",
                domid);
            return LIBXL_DOMAIN_TYPE_HVM;
        }

        return t;
    } else
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
                             libxl_domain_config *d_config)
{
    libxl_domain_build_info *info = &d_config->b_info;
    int found;
    libxl__numa_candidate candidate;
    libxl_bitmap cpumap, cpupool_nodemap, *map;
    libxl_cpupoolinfo cpupool_info;
    int i, cpupool, rc = 0;
    uint64_t memkb;

    libxl__numa_candidate_init(&candidate);
    libxl_bitmap_init(&cpumap);
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
    map = &cpupool_info.cpumap;

    /*
     * If there's a well defined hard affinity mask (i.e., the same one for all
     * the vcpus), we can try to run the placement considering only the pcpus
     * within such mask.
     */
    if (info->num_vcpu_hard_affinity)
    {
#ifdef DEBUG
        int j;

        for (j = 0; j < info->num_vcpu_hard_affinity; j++)
            assert(libxl_bitmap_equal(&info->vcpu_hard_affinity[0],
                                      &info->vcpu_hard_affinity[j], 0));
#endif /* DEBUG */

        rc = libxl_bitmap_and(CTX, &cpumap, &info->vcpu_hard_affinity[0],
                              &cpupool_info.cpumap);
        if (rc)
            goto out;

        /* Hard affinity must contain at least one cpu of our cpupool */
        if (libxl_bitmap_is_empty(&cpumap)) {
            LOG(ERROR, "Hard affinity completely outside of domain's cpupool!");
            rc = ERROR_INVAL;
            goto out;
        }
    }

    rc = libxl__domain_need_memory_calculate(gc, info, &memkb);
    if (rc)
        goto out;
    if (libxl_node_bitmap_alloc(CTX, &cpupool_nodemap, 0)) {
        rc = ERROR_FAIL;
        goto out;
    }

    /* Find the best candidate with enough free memory and at least
     * as much pcpus as the domain has vcpus.  */
    rc = libxl__get_numa_candidate(gc, memkb, info->max_vcpus,
                                   0, 0, map, numa_cmpf, &candidate, &found);
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
                "%"PRIu64" KB free selected", candidate.nr_nodes,
                candidate.nr_cpus, candidate.free_memkb / 1024);

 out:
    libxl__numa_candidate_dispose(&candidate);
    libxl_bitmap_dispose(&cpupool_nodemap);
    libxl_bitmap_dispose(&cpumap);
    libxl_cpupoolinfo_dispose(&cpupool_info);
    return rc;
}

int libxl__build_pre(libxl__gc *gc, uint32_t domid,
              libxl_domain_config *d_config, libxl__domain_build_state *state)
{
    libxl_domain_build_info *const info = &d_config->b_info;
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *xs_domid, *con_domid;
    int rc;
    uint64_t size;

    if (xc_domain_max_vcpus(ctx->xch, domid, info->max_vcpus) != 0) {
        LOG(ERROR, "Couldn't set max vcpu count");
        return ERROR_FAIL;
    }

    if (libxl_defbool_val(d_config->b_info.disable_migrate) &&
        xc_domain_disable_migrate(ctx->xch, domid) != 0) {
        LOG(ERROR, "Couldn't set nomigrate");
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
        if (info->cpumap.size || info->num_vcpu_soft_affinity)
            LOG(WARN, "Can't run NUMA placement, as a soft "
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

            rc = numa_place_domain(gc, domid, d_config);
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


    rc = libxl__arch_extra_memory(gc, info, &size);
    if (rc < 0) {
        LOGE(ERROR, "Couldn't get arch extra constant memory size");
        return ERROR_FAIL;
    }

    if (xc_domain_setmaxmem(ctx->xch, domid, info->target_memkb + size) < 0) {
        LOGE(ERROR, "Couldn't set max memory");
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

    libxl__cpuid_legacy(ctx, domid, info);

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
    ents[3] = GCSPRINTF("%"PRId64, info->target_memkb -
                        libxl__get_targetmem_fudge(gc, info));
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

static int libxl__build_dom(libxl__gc *gc, uint32_t domid,
             libxl_domain_config *d_config, libxl__domain_build_state *state,
             struct xc_dom_image *dom)
{
    libxl_domain_build_info *const info = &d_config->b_info;
    uint64_t mem_kb;
    int ret;

    if ( (ret = xc_dom_boot_xen_init(dom, CTX->xch, domid)) != 0 ) {
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
        LOG(ERROR, "xc_dom_parse_image failed");
        goto out;
    }
    if ( (ret = libxl__arch_domain_init_hw_description(gc, info, state, dom)) != 0 ) {
        LOGE(ERROR, "libxl__arch_domain_init_hw_description failed");
        goto out;
    }

    mem_kb = dom->container_type == XC_DOM_HVM_CONTAINER ?
             (info->max_memkb - info->video_memkb) : info->target_memkb;
    if ( (ret = xc_dom_mem_init(dom, mem_kb / 1024)) != 0 ) {
        LOGE(ERROR, "xc_dom_mem_init failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_mem_init(dom)) != 0 ) {
        LOGE(ERROR, "xc_dom_boot_mem_init failed");
        goto out;
    }
    if ( (ret = libxl__arch_domain_finalise_hw_description(gc, domid, d_config, dom)) != 0 ) {
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
    if ((ret = libxl__arch_build_dom_finish(gc, info, dom, state)) != 0) {
        LOGE(ERROR, "libxl__arch_build_dom_finish failed");
        goto out;
    }

out:
    return ret != 0 ? ERROR_FAIL : 0;
}

int libxl__build_pv(libxl__gc *gc, uint32_t domid,
             libxl_domain_config *d_config, libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_domain_build_info *const info = &d_config->b_info;
    struct xc_dom_image *dom;
    int ret;
    int flags = 0;

    xc_dom_loginit(ctx->xch);

    dom = xc_dom_allocate(ctx->xch, state->pv_cmdline, info->u.pv.features);
    if (!dom) {
        LOGE(ERROR, "xc_dom_allocate failed");
        return ERROR_FAIL;
    }

    dom->container_type = XC_DOM_PV_CONTAINER;

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
            if ( (ret = xc_dom_module_mem(dom, state->pv_ramdisk.data, state->pv_ramdisk.size, NULL)) != 0 ) {
                LOGE(ERROR, "xc_dom_ramdisk_mem failed");
                goto out;
            }
        } else {
            if ( (ret = xc_dom_module_file(dom, state->pv_ramdisk.path, NULL)) != 0 ) {
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
    dom->max_vcpus = info->max_vcpus;

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

    ret = libxl__build_dom(gc, domid, d_config, state, dom);
    if (ret != 0)
        goto out;

    if (xc_dom_translated(dom)) {
        state->console_mfn = dom->console_pfn;
        state->store_mfn = dom->xenstore_pfn;
        state->vuart_gfn = dom->vuart_gfn;
    } else {
        state->console_mfn = xc_dom_p2m(dom, dom->console_pfn);
        state->store_mfn = xc_dom_p2m(dom, dom->xenstore_pfn);
    }

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

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        va_map = xc_map_foreign_range(handle, domid,
                                      XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                      HVM_INFO_PFN);
        if (va_map == NULL)
            return ERROR_FAIL;

        va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
        va_hvm->apic_mode = libxl_defbool_val(info->apic);
        va_hvm->nr_vcpus = info->max_vcpus;
        memset(va_hvm->vcpu_online, 0, sizeof(va_hvm->vcpu_online));
        memcpy(va_hvm->vcpu_online, info->avail_vcpus.map, info->avail_vcpus.size);
        for (i = 0, sum = 0; i < va_hvm->length; i++)
            sum += ((uint8_t *) va_hvm)[i];
        va_hvm->checksum -= sum;
        munmap(va_map, XC_PAGE_SIZE);
    }

    xc_hvm_param_get(handle, domid, HVM_PARAM_STORE_PFN, &str_mfn);
    xc_hvm_param_get(handle, domid, HVM_PARAM_CONSOLE_PFN, &cons_mfn);
    xc_hvm_param_set(handle, domid, HVM_PARAM_STORE_EVTCHN, store_evtchn);
    xc_hvm_param_set(handle, domid, HVM_PARAM_CONSOLE_EVTCHN, console_evtchn);

    *store_mfn = str_mfn;
    *console_mfn = cons_mfn;

    return 0;
}

static int hvm_build_set_xs_values(libxl__gc *gc,
                                   uint32_t domid,
                                   struct xc_dom_image *dom,
                                   const libxl_domain_build_info *info)
{
    char *path = NULL;
    int ret = 0;

    if (dom->smbios_module.guest_addr_out) {
        path = GCSPRINTF("/local/domain/%d/"HVM_XS_SMBIOS_PT_ADDRESS, domid);

        ret = libxl__xs_printf(gc, XBT_NULL, path, "0x%"PRIx64,
                               dom->smbios_module.guest_addr_out);
        if (ret)
            goto err;

        path = GCSPRINTF("/local/domain/%d/"HVM_XS_SMBIOS_PT_LENGTH, domid);

        ret = libxl__xs_printf(gc, XBT_NULL, path, "0x%x",
                               dom->smbios_module.length);
        if (ret)
            goto err;
    }

    /* Only one module can be passed. PVHv2 guests do not support this. */
    if (dom->acpi_modules[0].guest_addr_out && 
        info->type == LIBXL_DOMAIN_TYPE_HVM) {
        path = GCSPRINTF("/local/domain/%d/"HVM_XS_ACPI_PT_ADDRESS, domid);

        ret = libxl__xs_printf(gc, XBT_NULL, path, "0x%"PRIx64,
                               dom->acpi_modules[0].guest_addr_out);
        if (ret)
            goto err;

        path = GCSPRINTF("/local/domain/%d/"HVM_XS_ACPI_PT_LENGTH, domid);

        ret = libxl__xs_printf(gc, XBT_NULL, path, "0x%x",
                               dom->acpi_modules[0].length);
        if (ret)
            goto err;
    }

    return 0;

err:
    LOG(ERROR, "failed to write firmware xenstore value, err: %d", ret);
    return ret;
}

static int libxl__load_hvm_firmware_module(libxl__gc *gc,
                                           const char *filename,
                                           const char *what,
                                           struct xc_hvm_firmware_module *m)
{
    int datalen = 0;
    void *data = NULL;
    int r, rc;

    LOG(DEBUG, "Loading %s: %s", what, filename);
    r = libxl_read_file_contents(CTX, filename, &data, &datalen);
    if (r) {
        /*
         * Print a message only on ENOENT, other errors are logged by the
         * function libxl_read_file_contents().
         */
        if (r == ENOENT)
            LOGEV(ERROR, r, "failed to read %s file", what);
        rc =  ERROR_FAIL;
        goto out;
    }
    libxl__ptr_add(gc, data);
    if (datalen) {
        /* Only accept non-empty files */
        m->data = data;
        m->length = datalen;
    } else {
        LOG(ERROR, "file %s for %s is empty", filename, what);
        rc = ERROR_INVAL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

static int libxl__domain_firmware(libxl__gc *gc,
                                  libxl_domain_build_info *info,
                                  libxl__domain_build_state *state,
                                  struct xc_dom_image *dom)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *firmware = NULL;
    int e, rc;
    int datalen = 0;
    void *data;
    const char *bios_filename = NULL;

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        if (info->u.hvm.firmware) {
            firmware = info->u.hvm.firmware;
        } else {
            switch (info->device_model_version)
            {
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
                firmware = "hvmloader";
                break;
            default:
                LOG(ERROR, "invalid device model version %d",
                    info->device_model_version);
                rc = ERROR_FAIL;
                goto out;
            }
        }
    }

    if (state->pv_kernel.path != NULL &&
        info->type == LIBXL_DOMAIN_TYPE_PVH) {

        if (state->shim_path) {
            rc = xc_dom_kernel_file(dom, state->shim_path);
            if (rc) {
                LOGE(ERROR, "xc_dom_kernel_file failed");
                goto out;
            }

            /* We've loaded the shim, so load the kernel as a secondary module */
            if (state->pv_kernel.mapped) {
                LOG(DEBUG, "xc_dom_module_mem, cmdline %s",
                    state->pv_cmdline);
                rc = xc_dom_module_mem(dom, state->pv_kernel.data,
                                       state->pv_kernel.size, state->pv_cmdline);
                if (rc) {
                    LOGE(ERROR, "xc_dom_kernel_mem failed");
                    goto out;
                }
            } else {
                LOG(DEBUG, "xc_dom_module_file, path %s cmdline %s",
                    state->pv_kernel.path, state->pv_cmdline);
                rc = xc_dom_module_file(dom, state->pv_kernel.path, state->pv_cmdline);
                if (rc) {
                    LOGE(ERROR, "xc_dom_kernel_file failed");
                    goto out;
                }
            }
        } else {
            /* No shim, so load the kernel directly */
            if (state->pv_kernel.mapped) {
                rc = xc_dom_kernel_mem(dom, state->pv_kernel.data,
                                       state->pv_kernel.size);
                if (rc) {
                    LOGE(ERROR, "xc_dom_kernel_mem failed");
                    goto out;
                }
            } else {
                rc = xc_dom_kernel_file(dom, state->pv_kernel.path);
                if (rc) {
                    LOGE(ERROR, "xc_dom_kernel_file failed");
                    goto out;
                }
            }
        }

        if (state->pv_ramdisk.path && strlen(state->pv_ramdisk.path)) {
            if (state->pv_ramdisk.mapped) {
                rc = xc_dom_module_mem(dom, state->pv_ramdisk.data,
                                       state->pv_ramdisk.size, NULL);
                if (rc) {
                    LOGE(ERROR, "xc_dom_ramdisk_mem failed");
                    goto out;
                }
            } else {
                rc = xc_dom_module_file(dom, state->pv_ramdisk.path, NULL);
                if (rc) {
                    LOGE(ERROR, "xc_dom_ramdisk_file failed");
                    goto out;
                }
            }
        }
    } else {
        /*
         * Only HVM guests should get here, PVH should always have a set
         * kernel at this point.
         */
        assert(info->type == LIBXL_DOMAIN_TYPE_HVM);
        rc = xc_dom_kernel_file(dom, libxl__abs_path(gc, firmware,
                                                 libxl__xenfirmwaredir_path()));
    }

    if (rc != 0) {
        LOGE(ERROR, "xc_dom_{kernel_file/ramdisk_file} failed");
        goto out;
    }

    if (info->type == LIBXL_DOMAIN_TYPE_HVM &&
        info->device_model_version == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
        if (info->u.hvm.system_firmware) {
            bios_filename = info->u.hvm.system_firmware;
        } else {
            switch (info->u.hvm.bios) {
            case LIBXL_BIOS_TYPE_SEABIOS:
                bios_filename = libxl__seabios_path();
                break;
            case LIBXL_BIOS_TYPE_OVMF:
                bios_filename = libxl__ovmf_path();
                break;
            case LIBXL_BIOS_TYPE_ROMBIOS:
            default:
                abort();
            }
        }
    }

    if (bios_filename) {
        rc = libxl__load_hvm_firmware_module(gc, bios_filename, "BIOS",
                                             &dom->system_firmware_module);
        if (rc) goto out;
    }

    if (info->type == LIBXL_DOMAIN_TYPE_HVM &&
        info->u.hvm.bios == LIBXL_BIOS_TYPE_ROMBIOS &&
        libxl__ipxe_path()) {
        const char *fp = libxl__ipxe_path();
        rc = xc_dom_module_file(dom, fp, "ipxe");

        if (rc) {
            LOGE(ERROR, "failed to load IPXE %s (%d)", fp, rc);
            rc = ERROR_FAIL;
            goto out;
        }
    }

    if (info->type == LIBXL_DOMAIN_TYPE_HVM &&
        info->u.hvm.smbios_firmware) {
        data = NULL;
        e = libxl_read_file_contents(ctx, info->u.hvm.smbios_firmware,
                                     &data, &datalen);
        if (e) {
            LOGEV(ERROR, e, "failed to read SMBIOS firmware file %s",
                info->u.hvm.smbios_firmware);
            rc = ERROR_FAIL;
            goto out;
        }
        libxl__ptr_add(gc, data);
        if (datalen) {
            /* Only accept non-empty files */
            dom->smbios_module.data = data;
            dom->smbios_module.length = (uint32_t)datalen;
        }
    }

    if (info->type == LIBXL_DOMAIN_TYPE_HVM &&
        info->u.hvm.acpi_firmware) {
        data = NULL;
        e = libxl_read_file_contents(ctx, info->u.hvm.acpi_firmware,
                                     &data, &datalen);
        if (e) {
            LOGEV(ERROR, e, "failed to read ACPI firmware file %s",
                info->u.hvm.acpi_firmware);
            rc = ERROR_FAIL;
            goto out;
        }
        libxl__ptr_add(gc, data);
        if (datalen) {
            /* Only accept a non-empty file */
            dom->acpi_modules[0].data = data;
            dom->acpi_modules[0].length = (uint32_t)datalen;
        }
    }

    return 0;
out:
    assert(rc != 0);
    return rc;
}

int libxl__build_hvm(libxl__gc *gc, uint32_t domid,
              libxl_domain_config *d_config,
              libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc;
    uint64_t mmio_start, lowmem_end, highmem_end, mem_size;
    libxl_domain_build_info *const info = &d_config->b_info;
    struct xc_dom_image *dom = NULL;
    bool device_model = info->type == LIBXL_DOMAIN_TYPE_HVM ? true : false;

    xc_dom_loginit(ctx->xch);

    /*
     * If PVH and we have a shim override, use the shim cmdline.
     * If PVH and no shim override, use the pv cmdline.
     * If not PVH, use info->cmdline.
     */
    dom = xc_dom_allocate(ctx->xch, info->type == LIBXL_DOMAIN_TYPE_PVH ?
                          (state->shim_path ? state->shim_cmdline : state->pv_cmdline) :
                          info->cmdline, NULL);
    if (!dom) {
        LOGE(ERROR, "xc_dom_allocate failed");
        rc = ERROR_NOMEM;
        goto out;
    }

    dom->container_type = XC_DOM_HVM_CONTAINER;

    /* The params from the configuration file are in Mb, which are then
     * multiplied by 1 Kb. This was then divided off when calling
     * the old xc_hvm_build_target_mem() which then turned them to bytes.
     * Do all this in one step here...
     */
    mem_size = (uint64_t)(info->max_memkb - info->video_memkb) << 10;
    dom->target_pages = (uint64_t)(info->target_memkb - info->video_memkb) >> 2;
    dom->claim_enabled = libxl_defbool_val(info->claim_mode);
    if (info->u.hvm.mmio_hole_memkb) {
        uint64_t max_ram_below_4g = (1ULL << 32) -
            (info->u.hvm.mmio_hole_memkb << 10);

        if (max_ram_below_4g < HVM_BELOW_4G_MMIO_START)
            dom->mmio_size = info->u.hvm.mmio_hole_memkb << 10;
    }

    rc = libxl__domain_firmware(gc, info, state, dom);
    if (rc != 0) {
        LOG(ERROR, "initializing domain firmware failed");
        goto out;
    }

    if (dom->target_pages == 0)
        dom->target_pages = mem_size >> XC_PAGE_SHIFT;
    if (dom->mmio_size == 0 && device_model)
        dom->mmio_size = HVM_BELOW_4G_MMIO_LENGTH;
    else if (dom->mmio_size == 0 && !device_model) {
#if defined(__i386__) || defined(__x86_64__)
        /*
         * Make sure the local APIC page, the ACPI tables and the special pages
         * are inside the MMIO hole.
         */
        xen_paddr_t start =
            (X86_HVM_END_SPECIAL_REGION - X86_HVM_NR_SPECIAL_PAGES) <<
            XC_PAGE_SHIFT;

        start = min_t(xen_paddr_t, start, LAPIC_BASE_ADDRESS);
        start = min_t(xen_paddr_t, start, ACPI_INFO_PHYSICAL_ADDRESS);
        dom->mmio_size = GB(4) - start;
#else
        assert(1);
#endif
    }
    lowmem_end = mem_size;
    highmem_end = 0;
    mmio_start = (1ull << 32) - dom->mmio_size;
    if (lowmem_end > mmio_start)
    {
        highmem_end = (1ull << 32) + (lowmem_end - mmio_start);
        lowmem_end = mmio_start;
    }
    dom->lowmem_end = lowmem_end;
    dom->highmem_end = highmem_end;
    dom->mmio_start = mmio_start;
    dom->vga_hole_size = device_model ? LIBXL_VGA_HOLE_SIZE : 0;
    dom->device_model = device_model;
    dom->max_vcpus = info->max_vcpus;
    dom->console_domid = state->console_domid;
    dom->xenstore_domid = state->store_domid;

    rc = libxl__domain_device_construct_rdm(gc, d_config,
                                            info->u.hvm.rdm_mem_boundary_memkb*1024,
                                            dom);
    if (rc) {
        LOG(ERROR, "checking reserved device memory failed");
        goto out;
    }

    if (info->num_vnuma_nodes != 0) {
        int i;

        rc = libxl__vnuma_build_vmemrange_hvm(gc, domid, info, state, dom);
        if (rc != 0) {
            LOG(ERROR, "hvm build vmemranges failed");
            goto out;
        }
        rc = libxl__vnuma_config_check(gc, info, state);
        if (rc != 0) goto out;
        rc = set_vnuma_info(gc, domid, info, state);
        if (rc != 0) goto out;

        dom->nr_vmemranges = state->num_vmemranges;
        dom->vmemranges = libxl__malloc(gc, sizeof(*dom->vmemranges) *
                                        dom->nr_vmemranges);

        for (i = 0; i < dom->nr_vmemranges; i++) {
            dom->vmemranges[i].start = state->vmemranges[i].start;
            dom->vmemranges[i].end   = state->vmemranges[i].end;
            dom->vmemranges[i].flags = state->vmemranges[i].flags;
            dom->vmemranges[i].nid   = state->vmemranges[i].nid;
        }

        dom->nr_vnodes = info->num_vnuma_nodes;
        dom->vnode_to_pnode = libxl__malloc(gc, sizeof(*dom->vnode_to_pnode) *
                                            dom->nr_vnodes);
        for (i = 0; i < dom->nr_vnodes; i++)
            dom->vnode_to_pnode[i] = info->vnuma_nodes[i].pnode;
    }

    rc = libxl__build_dom(gc, domid, d_config, state, dom);
    if (rc != 0)
        goto out;

    rc = hvm_build_set_params(ctx->xch, domid, info, state->store_port,
                               &state->store_mfn, state->console_port,
                               &state->console_mfn, state->store_domid,
                               state->console_domid);
    if (rc != 0) {
        LOG(ERROR, "hvm build set params failed");
        goto out;
    }

    rc = hvm_build_set_xs_values(gc, domid, dom, info);
    if (rc != 0) {
        LOG(ERROR, "hvm build set xenstore values failed");
        goto out;
    }

    xc_dom_release(dom);
    return 0;

out:
    assert(rc != 0);
    if (dom != NULL) xc_dom_release(dom);
    return rc;
}

int libxl__qemu_traditional_cmd(libxl__gc *gc, uint32_t domid,
                                const char *cmd)
{
    char *path = NULL;
    uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/command");
    return libxl__xs_printf(gc, XBT_NULL, path, "%s", cmd);
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
    path = GCSPRINTF(XEN_LIB_DIR "/userdata-%s.%u.%s.%s",
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
        LOGE(ERROR, "cannot write/rename %s for %s", newfilename, filename);
out:
    return rc;
}

int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen)
{
    GC_INIT(ctx);
    int rc;
    libxl__flock *lock;

    CTX_LOCK;
    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__userdata_store(gc, domid, userdata_userid,
                               data, datalen);

    libxl__unlock_file(lock);

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
        LOG(ERROR, "userdata file %s is empty", filename);
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
    libxl__flock *lock;

    CTX_LOCK;
    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__userdata_retrieve(gc, domid, userdata_userid,
                                  data_r, datalen_r);


    libxl__unlock_file(lock);
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
    libxl__flock *lock = NULL;
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
        libxl__unlock_file(lock);
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
