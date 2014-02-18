/*
 * Copyright (C) 2012      Citrix Ltd.
 * Author Dario Faggioli <dario.faggioli@citrix.com>
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

/*
 * What follows are helpers for generating all the k-combinations
 * without repetitions of a set S with n elements in it. Formally
 * speaking, they are subsets of k distinct elements of S and, if
 * S is n elements big, the number of k-combinations is equal to the
 * binomial coefficient C(n k)=n!/(k! * (n - k)!).
 *
 * The various subset are generated one after the other by calling
 * comb_init() first, and, after that, comb_next()
 * C(n k)-1 times. An iterator is used to store the current status
 * of the whole generation operation (i.e., basically, the last
 * combination that has been generated). As soon as all combinations
 * have been generated, comb_next() will start returning 0 instead of
 * 1. The same instance of the iterator and the same values for
 * n and k _must_ be used for each call (if that doesn't happen, the
 * result is unspecified).
 *
 * The algorithm is a well known one (see, for example, D. Knuth's "The
 * Art of Computer Programming - Volume 4, Fascicle 3" and it produces
 * the combinations in such a way that they (well, more precisely, their
 * indexes it the array/map representing the set) come with lexicographic
 * ordering.
 *
 * For example, with n = 5 and k = 3, calling comb_init()
 * will generate { 0, 1, 2 }, while subsequent valid calls to
 * comb_next() will produce the following:
 * { { 0, 1, 3 }, { 0, 1, 4 },
 *   { 0, 2, 3 }, { 0, 2, 4 }, { 0, 3, 4 },
 *   { 1, 2, 3 }, { 1, 2, 4 }, { 1, 3, 4 },
 *   { 2, 3, 4 } }
 *
 * This is used by the automatic NUMA placement logic below.
 */
typedef int* comb_iter_t;

static int comb_init(libxl__gc *gc, comb_iter_t *it, int n, int k)
{
    comb_iter_t new_iter;
    int i;

    if (n < k)
        return 0;

    /* First set is always { 0, 1, 2, ..., k-1 } */
    GCNEW_ARRAY(new_iter, k);
    for (i = 0; i < k; i++)
        new_iter[i] = i;

    *it = new_iter;
    return 1;
}

static int comb_next(comb_iter_t it, int n, int k)
{
    int i;

    /*
     * The idea here is to find the leftmost element from where
     * we should start incrementing the indexes of the iterator.
     * This means looking for the highest index that can be increased
     * while still producing value smaller than n-1. In the example
     * above, when dealing with { 0, 1, 4 }, such an element is the
     * second one, as the third is already equal to 4 (which actually
     * is n-1).
     * Once we found from where to start, we increment that element
     * and override the right-hand rest of the iterator with its
     * successors, thus achieving lexicographic ordering.
     *
     * Regarding the termination of the generation process, when we
     * manage in bringing n-k at the very first position of the iterator,
     * we know that is the last valid combination ( { 2, 3, 4 }, with
     * n - k = 5 - 2 = 2, in the example above), and thus we start
     * returning 0 as soon as we cross that border.
     */
    for (i = k - 1; it[i] == n - k + i; i--) {
        if (i <= 0)
            return 0;
    }
    for (it[i]++, i++; i < k; i++)
        it[i] = it[i - 1] + 1;
    return 1;
}

/* NUMA automatic placement (see libxl_internal.h for details) */

/*
 * This function turns a k-combination iterator into a node map,
 * given another map, telling us which nodes should be considered.
 *
 * This means the bits that are set in suitable_nodemap and that
 * corresponds to the indexes of the given combination are the ones
 * that will be set in nodemap.
 *
 * For example, given a fully set suitable_nodemap, if the iterator
 * represents the combination { 0, 2, 4}, nodmeap will have bits #0,
 * #2 and #4 set.
 * On the other hand, if, say,  suitable_nodemap=01011011, the same
 * iterator will cause bits #1, #4 and #7 of nodemap to be set.
 */
static void comb_get_nodemap(comb_iter_t it, libxl_bitmap *suitable_nodemap,
                             libxl_bitmap *nodemap, int k)
{
    int i, m = 0, n = 0;

    libxl_bitmap_set_none(nodemap);
    libxl_for_each_set_bit(i, *suitable_nodemap) {
        /* Check wether the n-th set bit of suitable_nodemap
         * matches with the m-th element of the iterator (and,
         * only if it does, advance to the next one) */
        if (m < k && n == it[m]) {
            libxl_bitmap_set(nodemap, i);
            m++;
        }
        n++;
    }
}

/* Retrieve the number of cpus that the nodes that are part of the nodemap
 * span and are also set in suitable_cpumap. */
static int nodemap_to_nr_cpus(libxl_cputopology *tinfo, int nr_cpus,
                              const libxl_bitmap *suitable_cpumap,
                              const libxl_bitmap *nodemap)
{
    int i, nodes_cpus = 0;

    for (i = 0; i < nr_cpus; i++) {
        if (libxl_bitmap_test(suitable_cpumap, i) &&
            libxl_bitmap_test(nodemap, tinfo[i].node))
            nodes_cpus++;
    }
    return nodes_cpus;
}

/* Retrieve the amount of free memory within the nodemap */
static uint32_t nodemap_to_free_memkb(libxl_numainfo *ninfo,
                                      libxl_bitmap *nodemap)
{
    uint32_t free_memkb = 0;
    int i;

    libxl_for_each_set_bit(i, *nodemap)
        free_memkb += ninfo[i].free / 1024;

    return free_memkb;
}

/* Retrieve the number of vcpus able to run on the nodes in nodemap */
static int nodemap_to_nr_vcpus(libxl__gc *gc, int vcpus_on_node[],
                               const libxl_bitmap *nodemap)
{
    int i, nr_vcpus = 0;

    libxl_for_each_set_bit(i, *nodemap)
        nr_vcpus += vcpus_on_node[i];

    return nr_vcpus;
}

/* Number of vcpus able to run on the cpus of the various nodes
 * (reported by filling the array vcpus_on_node[]). */
static int nr_vcpus_on_nodes(libxl__gc *gc, libxl_cputopology *tinfo,
                             size_t tinfo_elements,
                             const libxl_bitmap *suitable_cpumap,
                             int vcpus_on_node[])
{
    libxl_dominfo *dinfo = NULL;
    libxl_bitmap dom_nodemap, nodes_counted;
    int nr_doms, nr_cpus;
    int i, j, k;

    dinfo = libxl_list_domain(CTX, &nr_doms);
    if (dinfo == NULL)
        return ERROR_FAIL;

    if (libxl_node_bitmap_alloc(CTX, &nodes_counted, 0) < 0) {
        libxl_dominfo_list_free(dinfo, nr_doms);
        return ERROR_FAIL;
    }

    if (libxl_node_bitmap_alloc(CTX, &dom_nodemap, 0) < 0) {
        libxl_bitmap_dispose(&nodes_counted);
        libxl_dominfo_list_free(dinfo, nr_doms);
        return ERROR_FAIL;
    }

    for (i = 0; i < nr_doms; i++) {
        libxl_vcpuinfo *vinfo;
        int nr_dom_vcpus;

        vinfo = libxl_list_vcpu(CTX, dinfo[i].domid, &nr_dom_vcpus, &nr_cpus);
        if (vinfo == NULL)
            continue;

        /* Retrieve the domain's node-affinity map */
        libxl_domain_get_nodeaffinity(CTX, dinfo[i].domid, &dom_nodemap);

        for (j = 0; j < nr_dom_vcpus; j++) {
            /*
             * For each vcpu of each domain, it must have both vcpu-affinity
             * and node-affinity to (a pcpu belonging to) a certain node to
             * cause an increment in the corresponding element of the array.
             */
            libxl_bitmap_set_none(&nodes_counted);
            libxl_for_each_set_bit(k, vinfo[j].cpumap) {
                if (k >= tinfo_elements)
                    break;
                int node = tinfo[k].node;

                if (libxl_bitmap_test(suitable_cpumap, k) &&
                    libxl_bitmap_test(&dom_nodemap, node) &&
                    !libxl_bitmap_test(&nodes_counted, node)) {
                    libxl_bitmap_set(&nodes_counted, node);
                    vcpus_on_node[node]++;
                }
            }
        }

        libxl_vcpuinfo_list_free(vinfo, nr_dom_vcpus);
    }

    libxl_bitmap_dispose(&dom_nodemap);
    libxl_bitmap_dispose(&nodes_counted);
    libxl_dominfo_list_free(dinfo, nr_doms);
    return 0;
}

/*
 * This function tries to figure out if the host has a consistent number
 * of cpus along all its NUMA nodes. In fact, if that is the case, we can
 * calculate the minimum number of nodes needed for a domain by just
 * dividing its total number of vcpus by this value computed here.
 * However, we are not allowed to assume that all the nodes have the
 * same number of cpus. Therefore, in case discrepancies among different
 * nodes are found, this function just returns 0, for the caller to know
 * it shouldn't rely on this 'optimization', and sort out things in some
 * other way (by doing something basic, like starting trying with
 * candidates with just one node).
 */
static int count_cpus_per_node(libxl_cputopology *tinfo, int nr_cpus,
                               int nr_nodes)
{
    int cpus_per_node = 0;
    int j, i;

    /* This makes sense iff # of PCPUs is the same for all nodes */
    for (j = 0; j < nr_nodes; j++) {
        int curr_cpus = 0;

        for (i = 0; i < nr_cpus; i++) {
            if (tinfo[i].node == j)
                curr_cpus++;
        }
        /* So, if the above does not hold, turn the whole thing off! */
        cpus_per_node = cpus_per_node == 0 ? curr_cpus : cpus_per_node;
        if (cpus_per_node != curr_cpus)
            return 0;
    }
    return cpus_per_node;
}

/*
 * Looks for the placement candidates that satisfyies some specific
 * conditions and return the best one according to the provided
 * comparison function.
 */
int libxl__get_numa_candidate(libxl__gc *gc,
                              uint32_t min_free_memkb, int min_cpus,
                              int min_nodes, int max_nodes,
                              const libxl_bitmap *suitable_cpumap,
                              libxl__numa_candidate_cmpf numa_cmpf,
                              libxl__numa_candidate *cndt_out,
                              int *cndt_found)
{
    libxl__numa_candidate new_cndt;
    libxl_cputopology *tinfo = NULL;
    libxl_numainfo *ninfo = NULL;
    int nr_nodes = 0, nr_suit_nodes, nr_cpus = 0;
    libxl_bitmap suitable_nodemap, nodemap;
    int *vcpus_on_node, rc = 0;

    libxl_bitmap_init(&nodemap);
    libxl_bitmap_init(&suitable_nodemap);
    libxl__numa_candidate_init(&new_cndt);

    /* Get platform info and prepare the map for testing the combinations */
    ninfo = libxl_get_numainfo(CTX, &nr_nodes);
    if (ninfo == NULL)
        return ERROR_FAIL;

    GCNEW_ARRAY(vcpus_on_node, nr_nodes);

    /*
     * The good thing about this solution is that it is based on heuristics
     * (implemented in numa_cmpf() ), but we at least can evaluate it on
     * all the possible placement candidates. That can happen because the
     * number of nodes present in current NUMA systems is quite small.
     * In fact, even if a sum of binomials is involved, if the system has
     * up to 16 nodes it "only" takes 65535 steps. This is fine, as the
     * number of nodes the biggest NUMA systems provide at the time of this
     * writing is 8 (and it will probably continue to be so for a while).
     * However, computanional complexity would explode on systems bigger
     * than that, and it's really important we avoid trying to run this
     * on monsters with 32, 64 or more nodes (if they ever pop into being).
     * Therefore, here it comes a safety catch that disables the algorithm
     * for the cases when it wouldn't work well.
     */
    if (nr_nodes > 16) {
        /* Log we did nothing and return 0, as no real error occurred */
        LOG(WARN, "System has %d NUMA nodes, which is too big for the "
                  "placement algorithm to work effectively: skipping it. "
                  "Consider manually pinning the vCPUs and/or looking at "
                  "cpupools for manually partitioning the system.",
                  nr_nodes);
        *cndt_found = 0;
        goto out;
    }

    tinfo = libxl_get_cpu_topology(CTX, &nr_cpus);
    if (tinfo == NULL) {
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl_node_bitmap_alloc(CTX, &nodemap, 0);
    if (rc)
        goto out;
    rc = libxl__numa_candidate_alloc(gc, &new_cndt);
    if (rc)
        goto out;

    /* Allocate and prepare the map of the node that can be utilized for
     * placement, basing on the map of suitable cpus. */
    rc = libxl_node_bitmap_alloc(CTX, &suitable_nodemap, 0);
    if (rc)
        goto out;
    rc = libxl_cpumap_to_nodemap(CTX, suitable_cpumap, &suitable_nodemap);
    if (rc)
        goto out;

    /*
     * Later on, we will try to figure out how many vcpus are runnable on
     * each candidate (as a part of choosing the best one of them). That
     * requires going through all the vcpus of all the domains and check
     * their affinities. So, instead of doing that for each candidate,
     * let's count here the number of vcpus runnable on each node, so that
     * all we have to do later is summing up the right elements of the
     * vcpus_on_node array.
     */
    rc = nr_vcpus_on_nodes(gc, tinfo, nr_cpus, suitable_cpumap, vcpus_on_node);
    if (rc)
        goto out;

    /*
     * If the minimum number of NUMA nodes is not explicitly specified
     * (i.e., min_nodes == 0), we try to figure out a sensible number of nodes
     * from where to start generating candidates, if possible (or just start
     * from 1 otherwise). The maximum number of nodes should not exceed the
     * number of existent NUMA nodes on the host, or the candidate generation
     * won't work properly.
     */
    if (!min_nodes) {
        int cpus_per_node;

        cpus_per_node = count_cpus_per_node(tinfo, nr_cpus, nr_nodes);
        if (cpus_per_node == 0)
            min_nodes = 1;
        else
            min_nodes = (min_cpus + cpus_per_node - 1) / cpus_per_node;
    }
    /* We also need to be sure we do not exceed the number of
     * nodes we are allowed to use. */
    nr_suit_nodes = libxl_bitmap_count_set(&suitable_nodemap);

    if (min_nodes > nr_suit_nodes)
        min_nodes = nr_suit_nodes;
    if (!max_nodes || max_nodes > nr_suit_nodes)
        max_nodes = nr_suit_nodes;
    if (min_nodes > max_nodes) {
        LOG(ERROR, "Inconsistent minimum or maximum number of guest nodes");
        rc = ERROR_INVAL;
        goto out;
    }

    /* This is up to the caller to be disposed */
    rc = libxl__numa_candidate_alloc(gc, cndt_out);
    if (rc)
        goto out;

    /*
     * Consider all the combinations with sizes in [min_nodes, max_nodes]
     * (see comb_init() and comb_next()). Note that, since the fewer the
     * number of nodes the better, it is guaranteed that any candidate
     * found during the i-eth step will be better than any other one we
     * could find during the (i+1)-eth and all the subsequent steps (they
     * all will have more nodes). It's thus pointless to keep going if
     * we already found something.
     */
    *cndt_found = 0;
    while (min_nodes <= max_nodes && *cndt_found == 0) {
        comb_iter_t comb_iter;
        int comb_ok;

        /*
         * And here it is. Each step of this cycle generates a combination of
         * nodes as big as min_nodes mandates.  Each of these combinations is
         * checked against the constraints provided by the caller (namely,
         * amount of free memory and number of cpus) and it can concur to
         * become our best placement iff it passes the check.
         */
        for (comb_ok = comb_init(gc, &comb_iter, nr_suit_nodes, min_nodes);
             comb_ok;
             comb_ok = comb_next(comb_iter, nr_suit_nodes, min_nodes)) {
            uint32_t nodes_free_memkb;
            int nodes_cpus;

            /* Get the nodemap for the combination, only considering
             * suitable nodes. */
            comb_get_nodemap(comb_iter, &suitable_nodemap,
                             &nodemap, min_nodes);

            /* If there is not enough memory in this combination, skip it
             * and go generating the next one... */
            nodes_free_memkb = nodemap_to_free_memkb(ninfo, &nodemap);
            if (min_free_memkb && nodes_free_memkb < min_free_memkb)
                continue;

            /* And the same applies if this combination is short in cpus */
            nodes_cpus = nodemap_to_nr_cpus(tinfo, nr_cpus, suitable_cpumap,
                                            &nodemap);
            if (min_cpus && nodes_cpus < min_cpus)
                continue;

            /*
             * Conditions are met, we can compare this candidate with the
             * current best one (if any).
             */
            libxl__numa_candidate_put_nodemap(gc, &new_cndt, &nodemap);
            new_cndt.nr_vcpus = nodemap_to_nr_vcpus(gc, vcpus_on_node,
                                                    &nodemap);
            new_cndt.free_memkb = nodes_free_memkb;
            new_cndt.nr_nodes = libxl_bitmap_count_set(&nodemap);
            new_cndt.nr_cpus = nodes_cpus;

            /*
             * Check if the new candidate we is better the what we found up
             * to now by means of the comparison function. If no comparison
             * function is provided, just return as soon as we find our first
             * candidate.
             */
            if (*cndt_found == 0 || numa_cmpf(&new_cndt, cndt_out) < 0) {
                *cndt_found = 1;

                LOG(DEBUG, "New best NUMA placement candidate found: "
                           "nr_nodes=%d, nr_cpus=%d, nr_vcpus=%d, "
                           "free_memkb=%"PRIu32"", new_cndt.nr_nodes,
                           new_cndt.nr_cpus, new_cndt.nr_vcpus,
                           new_cndt.free_memkb / 1024);

                libxl__numa_candidate_put_nodemap(gc, cndt_out, &nodemap);
                cndt_out->nr_vcpus = new_cndt.nr_vcpus;
                cndt_out->free_memkb = new_cndt.free_memkb;
                cndt_out->nr_nodes = new_cndt.nr_nodes;
                cndt_out->nr_cpus = new_cndt.nr_cpus;

                if (numa_cmpf == NULL)
                    break;
            }
        }
        min_nodes++;
    }

    if (*cndt_found == 0)
        LOG(NOTICE, "NUMA placement failed, performance might be affected");

 out:
    libxl_bitmap_dispose(&nodemap);
    libxl_bitmap_dispose(&suitable_nodemap);
    libxl__numa_candidate_dispose(&new_cndt);
    libxl_numainfo_list_free(ninfo, nr_nodes);
    libxl_cputopology_list_free(tinfo, nr_cpus);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
