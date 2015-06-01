/*
 * Copyright (C) 2014      Citrix Ltd.
 * Author Wei Liu <wei.liu2@citrix.com>
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
#include "libxl_arch.h"
#include <stdlib.h>

bool libxl__vnuma_configured(const libxl_domain_build_info *b_info)
{
    return b_info->num_vnuma_nodes != 0;
}

/* Sort vmemranges in ascending order with "start" */
static int compare_vmemrange(const void *a, const void *b)
{
    const xen_vmemrange_t *x = a, *y = b;
    if (x->start < y->start)
        return -1;
    if (x->start > y->start)
        return 1;
    return 0;
}

/* Check if a vcpu has an hard (or soft) affinity set in such
 * a way that it does not match the pnode to which the vcpu itself
 * is assigned to.
 */
static int check_vnuma_affinity(libxl__gc *gc,
                                 unsigned int vcpu,
                                 unsigned int pnode,
                                 unsigned int num_affinity,
                                 const libxl_bitmap *affinity,
                                 const char *kind)
{
    libxl_bitmap nodemap;
    int rc = 0;

    libxl_bitmap_init(&nodemap);

    rc = libxl_node_bitmap_alloc(CTX, &nodemap, 0);
    if (rc) {
        LOG(ERROR, "Can't allocate nodemap");
        goto out;
    }

    rc = libxl_cpumap_to_nodemap(CTX, affinity, &nodemap);
    if (rc) {
        LOG(ERROR, "Can't convert Vcpu %d affinity to nodemap", vcpu);
        goto out;
    }

    if (libxl_bitmap_count_set(&nodemap) != 1 ||
        !libxl_bitmap_test(&nodemap, pnode))
        LOG(WARN, "Vcpu %d %s affinity and vnuma info mismatch", vcpu, kind);

out:
    libxl_bitmap_dispose(&nodemap);
    return rc;
}

/* Check if vNUMA configuration is valid:
 *  1. all pnodes inside vnode_to_pnode array are valid
 *  2. each vcpu belongs to one and only one vnode
 *  3. each vmemrange is valid and doesn't overlap with any other
 *  4. local distance cannot be larger than remote distance
 *
 * Check also, if any hard or soft affinity is specified, whether
 * they match with the vNUMA related bits (namely vcpus to vnodes
 * mappings and vnodes to pnodes association). If that does not
 * hold, however, just print a warning, as that has "only"
 * performance implications.
 */
int libxl__vnuma_config_check(libxl__gc *gc,
                              const libxl_domain_build_info *b_info,
                              const libxl__domain_build_state *state)
{
    int nr_nodes = 0, rc = ERROR_VNUMA_CONFIG_INVALID;
    unsigned int i, j;
    libxl_numainfo *ninfo = NULL;
    uint64_t total_memkb = 0;
    libxl_bitmap cpumap;
    libxl_vnode_info *v;

    libxl_bitmap_init(&cpumap);

    /* Check pnode specified is valid */
    ninfo = libxl_get_numainfo(CTX, &nr_nodes);
    if (!ninfo) {
        LOG(ERROR, "libxl_get_numainfo failed");
        goto out;
    }

    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        uint32_t pnode;

        v = &b_info->vnuma_nodes[i];
        pnode = v->pnode;

        /* The pnode specified is not valid? */
        if (pnode >= nr_nodes) {
            LOG(ERROR, "Invalid pnode %"PRIu32" specified", pnode);
            goto out;
        }

        total_memkb += v->memkb;
    }

    if (total_memkb != b_info->max_memkb) {
        LOG(ERROR, "Amount of memory mismatch (0x%"PRIx64" != 0x%"PRIx64")",
            total_memkb, b_info->max_memkb);
        goto out;
    }

    /* Check vcpu mapping */
    libxl_cpu_bitmap_alloc(CTX, &cpumap, b_info->max_vcpus);
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        v = &b_info->vnuma_nodes[i];
        libxl_for_each_set_bit(j, v->vcpus) {
            if (!libxl_bitmap_test(&cpumap, j))
                libxl_bitmap_set(&cpumap, j);
            else {
                LOG(ERROR, "Vcpu %d assigned more than once", j);
                goto out;
            }
        }
    }

    for (i = 0; i < b_info->max_vcpus; i++) {
        if (!libxl_bitmap_test(&cpumap, i)) {
            LOG(ERROR, "Vcpu %d is not assigned to any vnode", i);
            goto out;
        }
    }

    /* Check whether vcpu affinity (if any) matches vnuma configuration */
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        v = &b_info->vnuma_nodes[i];
        libxl_for_each_set_bit(j, v->vcpus) {
            if (b_info->num_vcpu_hard_affinity > j)
                check_vnuma_affinity(gc, j, v->pnode,
                                     b_info->num_vcpu_hard_affinity,
                                     &b_info->vcpu_hard_affinity[j],
                                     "hard");
            if (b_info->num_vcpu_soft_affinity > j)
                check_vnuma_affinity(gc, j, v->pnode,
                                     b_info->num_vcpu_soft_affinity,
                                     &b_info->vcpu_soft_affinity[j],
                                     "soft");
        }
    }

    /* Check vmemranges */
    qsort(state->vmemranges, state->num_vmemranges, sizeof(xen_vmemrange_t),
          compare_vmemrange);

    for (i = 0; i < state->num_vmemranges; i++) {
        if (state->vmemranges[i].end < state->vmemranges[i].start) {
                LOG(ERROR, "Vmemrange end < start");
                goto out;
        }
    }

    for (i = 0; i < state->num_vmemranges - 1; i++) {
        if (state->vmemranges[i].end > state->vmemranges[i+1].start) {
            LOG(ERROR,
                "Vmemranges overlapped, 0x%"PRIx64"-0x%"PRIx64", 0x%"PRIx64"-0x%"PRIx64,
                state->vmemranges[i].start, state->vmemranges[i].end,
                state->vmemranges[i+1].start, state->vmemranges[i+1].end);
            goto out;
        }
    }

    /* Check vdistances */
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        uint32_t local_distance, remote_distance;

        v = &b_info->vnuma_nodes[i];
        local_distance = v->distances[i];

        for (j = 0; j < v->num_distances; j++) {
            if (i == j) continue;
            remote_distance = v->distances[j];
            if (local_distance > remote_distance) {
                LOG(ERROR,
                    "Distance from %u to %u smaller than %u's local distance",
                    i, j, i);
                goto out;
            }
        }
    }

    rc = 0;
out:
    libxl_numainfo_list_free(ninfo, nr_nodes);
    libxl_bitmap_dispose(&cpumap);
    return rc;
}

int libxl__vnuma_build_vmemrange_pv_generic(libxl__gc *gc,
                                            uint32_t domid,
                                            libxl_domain_build_info *b_info,
                                            libxl__domain_build_state *state)
{
    int i;
    uint64_t next;
    xen_vmemrange_t *v = NULL;

    /* Generate one vmemrange for each virtual node. */
    GCREALLOC_ARRAY(v, b_info->num_vnuma_nodes);
    next = 0;
    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[i];

        v[i].start = next;
        v[i].end = next + (p->memkb << 10);
        v[i].flags = 0;
        v[i].nid = i;

        next = v[i].end;
    }

    state->vmemranges = v;
    state->num_vmemranges = i;

    return 0;
}

/* Build vmemranges for PV guest */
int libxl__vnuma_build_vmemrange_pv(libxl__gc *gc,
                                    uint32_t domid,
                                    libxl_domain_build_info *b_info,
                                    libxl__domain_build_state *state)
{
    assert(state->vmemranges == NULL);
    return libxl__arch_vnuma_build_vmemrange(gc, domid, b_info, state);
}

/* Build vmemranges for HVM guest */
int libxl__vnuma_build_vmemrange_hvm(libxl__gc *gc,
                                     uint32_t domid,
                                     libxl_domain_build_info *b_info,
                                     libxl__domain_build_state *state,
                                     struct xc_hvm_build_args *args)
{
    uint64_t hole_start, hole_end, next;
    int nid, nr_vmemrange;
    xen_vmemrange_t *vmemranges;
    int rc;

    /* Derive vmemranges from vnode size and memory hole.
     *
     * Guest physical address space layout:
     * [0, hole_start) [hole_start, hole_end) [hole_end, highmem_end)
     */
    hole_start = args->lowmem_end < args->mmio_start ?
        args->lowmem_end : args->mmio_start;
    hole_end = (args->mmio_start + args->mmio_size) > (1ULL << 32) ?
        (args->mmio_start + args->mmio_size) : (1ULL << 32);

    assert(state->vmemranges == NULL);

    next = 0;
    nr_vmemrange = 0;
    vmemranges = NULL;
    for (nid = 0; nid < b_info->num_vnuma_nodes; nid++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[nid];
        uint64_t remaining_bytes = p->memkb << 10;

        /* Consider video ram belongs to vnode 0 */
        if (nid == 0) {
            if (p->memkb < b_info->video_memkb) {
                LOG(ERROR, "vnode 0 too small to contain video ram");
                rc = ERROR_INVAL;
                goto out;
            }
            remaining_bytes -= (b_info->video_memkb << 10);
        }

        while (remaining_bytes > 0) {
            uint64_t count = remaining_bytes;

            if (next >= hole_start && next < hole_end)
                next = hole_end;
            if ((next < hole_start) && (next + remaining_bytes >= hole_start))
                count = hole_start - next;

            GCREALLOC_ARRAY(vmemranges, nr_vmemrange+1);
            vmemranges[nr_vmemrange].start = next;
            vmemranges[nr_vmemrange].end = next + count;
            vmemranges[nr_vmemrange].flags = 0;
            vmemranges[nr_vmemrange].nid = nid;

            nr_vmemrange++;
            remaining_bytes -= count;
            next += count;
        }
    }

    state->vmemranges = vmemranges;
    state->num_vmemranges = nr_vmemrange;

    rc = 0;
out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
