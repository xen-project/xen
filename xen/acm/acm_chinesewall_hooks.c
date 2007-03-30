/****************************************************************
 * acm_chinesewall_hooks.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributions:
 * Stefan Berger <stefanb@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype Chinese Wall Policy for Xen
 *    This code implements the hooks that are called
 *    throughout Xen operations and decides authorization
 *    based on domain types and Chinese Wall conflict type 
 *    sets. The CHWALL policy decides if a new domain can be started
 *    based on the types of running domains and the type of the
 *    new domain to be started. If the new domain's type is in
 *    conflict with types of running domains, then this new domain
 *    is not allowed to be created. A domain can have multiple types,
 *    in which case all types of a new domain must be conflict-free
 *    with all types of already running domains.
 *
 * indent -i4 -kr -nut
 *
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <public/acm.h>
#include <asm/atomic.h>
#include <acm/acm_core.h>
#include <acm/acm_hooks.h>
#include <acm/acm_endian.h>
#include <acm/acm_core.h>

ssidref_t dom0_chwall_ssidref = 0x0001;

/* local cache structures for chinese wall policy */
struct chwall_binary_policy chwall_bin_pol;

/*
 * Initializing chinese wall policy (will be filled by policy partition
 * using setpolicy command)
 */
int acm_init_chwall_policy(void)
{
    /* minimal startup policy; policy write-locked already */
    chwall_bin_pol.max_types = 1;
    chwall_bin_pol.max_ssidrefs = 1 + dom0_chwall_ssidref;
    chwall_bin_pol.max_conflictsets = 1;
    chwall_bin_pol.ssidrefs =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_ssidrefs *
                                       chwall_bin_pol.max_types);
    chwall_bin_pol.conflict_sets =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_conflictsets *
                                       chwall_bin_pol.max_types);
    chwall_bin_pol.running_types =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_types);
    chwall_bin_pol.conflict_aggregate_set =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_types);

    if ((chwall_bin_pol.conflict_sets == NULL)
        || (chwall_bin_pol.running_types == NULL)
        || (chwall_bin_pol.ssidrefs == NULL)
        || (chwall_bin_pol.conflict_aggregate_set == NULL))
        return ACM_INIT_SSID_ERROR;

    /* initialize state */
    memset((void *) chwall_bin_pol.ssidrefs, 0,
           chwall_bin_pol.max_ssidrefs * chwall_bin_pol.max_types *
           sizeof(domaintype_t));
    memset((void *) chwall_bin_pol.conflict_sets, 0,
           chwall_bin_pol.max_conflictsets * chwall_bin_pol.max_types *
           sizeof(domaintype_t));
    memset((void *) chwall_bin_pol.running_types, 0,
           chwall_bin_pol.max_types * sizeof(domaintype_t));
    memset((void *) chwall_bin_pol.conflict_aggregate_set, 0,
           chwall_bin_pol.max_types * sizeof(domaintype_t));
    return ACM_OK;
}

static int chwall_init_domain_ssid(void **chwall_ssid, ssidref_t ssidref)
{
    struct chwall_ssid *chwall_ssidp = xmalloc(struct chwall_ssid);
    traceprintk("%s.\n", __func__);
    if (chwall_ssidp == NULL)
        return ACM_INIT_SSID_ERROR;

    chwall_ssidp->chwall_ssidref =
        GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);

    if ((chwall_ssidp->chwall_ssidref >= chwall_bin_pol.max_ssidrefs)
        || (chwall_ssidp->chwall_ssidref == ACM_DEFAULT_LOCAL_SSID))
    {
        printkd("%s: ERROR chwall_ssidref(%x) undefined (>max) or unset (0).\n",
                __func__, chwall_ssidp->chwall_ssidref);
        xfree(chwall_ssidp);
        return ACM_INIT_SSID_ERROR;
    }
    (*chwall_ssid) = chwall_ssidp;
    printkd("%s: determined chwall_ssidref to %x.\n",
            __func__, chwall_ssidp->chwall_ssidref);
    return ACM_OK;
}

static void chwall_free_domain_ssid(void *chwall_ssid)
{
    traceprintk("%s.\n", __func__);
    xfree(chwall_ssid);
    return;
}


/* dump chinese wall cache; policy read-locked already */
static int chwall_dump_policy(u8 * buf, u32 buf_size)
{
    struct acm_chwall_policy_buffer *chwall_buf =
        (struct acm_chwall_policy_buffer *) buf;
    int ret = 0;

    if (buf_size < sizeof(struct acm_chwall_policy_buffer))
        return -EINVAL;

    chwall_buf->chwall_max_types = cpu_to_be32(chwall_bin_pol.max_types);
    chwall_buf->chwall_max_ssidrefs = cpu_to_be32(chwall_bin_pol.max_ssidrefs);
    chwall_buf->policy_code = cpu_to_be32(ACM_CHINESE_WALL_POLICY);
    chwall_buf->chwall_ssid_offset =
        cpu_to_be32(sizeof(struct acm_chwall_policy_buffer));
    chwall_buf->chwall_max_conflictsets =
        cpu_to_be32(chwall_bin_pol.max_conflictsets);
    chwall_buf->chwall_conflict_sets_offset =
        cpu_to_be32(be32_to_cpu(chwall_buf->chwall_ssid_offset) +
              sizeof(domaintype_t) * chwall_bin_pol.max_ssidrefs *
              chwall_bin_pol.max_types);
    chwall_buf->chwall_running_types_offset =
        cpu_to_be32(be32_to_cpu(chwall_buf->chwall_conflict_sets_offset) +
              sizeof(domaintype_t) * chwall_bin_pol.max_conflictsets *
              chwall_bin_pol.max_types);
    chwall_buf->chwall_conflict_aggregate_offset =
        cpu_to_be32(be32_to_cpu(chwall_buf->chwall_running_types_offset) +
              sizeof(domaintype_t) * chwall_bin_pol.max_types);

    ret = be32_to_cpu(chwall_buf->chwall_conflict_aggregate_offset) +
        sizeof(domaintype_t) * chwall_bin_pol.max_types;

    ret = (ret + 7) & ~7;

    if (buf_size < ret)
        return -EINVAL;

    /* now copy buffers over */
    arrcpy16((u16 *) (buf + be32_to_cpu(chwall_buf->chwall_ssid_offset)),
             chwall_bin_pol.ssidrefs,
             chwall_bin_pol.max_ssidrefs * chwall_bin_pol.max_types);

    arrcpy16((u16 *) (buf +
                      be32_to_cpu(chwall_buf->chwall_conflict_sets_offset)),
             chwall_bin_pol.conflict_sets,
             chwall_bin_pol.max_conflictsets * chwall_bin_pol.max_types);

    arrcpy16((u16 *) (buf +
                      be32_to_cpu(chwall_buf->chwall_running_types_offset)),
             chwall_bin_pol.running_types, chwall_bin_pol.max_types);

    arrcpy16((u16 *) (buf +
                      be32_to_cpu(chwall_buf->chwall_conflict_aggregate_offset)),
             chwall_bin_pol.conflict_aggregate_set,
             chwall_bin_pol.max_types);
    return ret;
}

/* adapt security state (running_types and conflict_aggregate_set) to all running
 * domains; chwall_init_state is called when a policy is changed to bring the security
 * information into a consistent state and to detect violations (return != 0).
 * from a security point of view, we simulate that all running domains are re-started
 */
static int
chwall_init_state(struct acm_chwall_policy_buffer *chwall_buf,
                  domaintype_t * ssidrefs, domaintype_t * conflict_sets,
                  domaintype_t * running_types,
                  domaintype_t * conflict_aggregate_set)
{
    int violation = 0, i, j;
    struct chwall_ssid *chwall_ssid;
    ssidref_t chwall_ssidref;
    struct domain *d;

    spin_lock(&domlist_update_lock);
    /* go through all domains and adjust policy as if this domain was started now */
    for_each_domain ( d )
    {
        chwall_ssid =
            GET_SSIDP(ACM_CHINESE_WALL_POLICY,
                      (struct acm_ssid_domain *)d->ssid);
        chwall_ssidref = chwall_ssid->chwall_ssidref;
        traceprintk("%s: validating policy for domain %x (chwall-REF=%x).\n",
                    __func__, d->domain_id, chwall_ssidref);
        /* a) adjust types ref-count for running domains */
        for (i = 0; i < chwall_buf->chwall_max_types; i++)
            running_types[i] +=
                ssidrefs[chwall_ssidref * chwall_buf->chwall_max_types + i];

        /* b) check for conflict */
        for (i = 0; i < chwall_buf->chwall_max_types; i++)
            if (conflict_aggregate_set[i] &&
                ssidrefs[chwall_ssidref * chwall_buf->chwall_max_types + i])
            {
                printk("%s: CHINESE WALL CONFLICT in type %02x.\n",
                       __func__, i);
                violation = 1;
                goto out;
            }
        /* set violation and break out of the loop */
        /* c) adapt conflict aggregate set for this domain (notice conflicts) */
        for (i = 0; i < chwall_buf->chwall_max_conflictsets; i++)
        {
            int common = 0;
            /* check if conflict_set_i and ssidref have common types */
            for (j = 0; j < chwall_buf->chwall_max_types; j++)
                if (conflict_sets[i * chwall_buf->chwall_max_types + j] &&
                    ssidrefs[chwall_ssidref *
                            chwall_buf->chwall_max_types + j])
                {
                    common = 1;
                    break;
                }
            if (common == 0)
                continue;       /* try next conflict set */
            /* now add types of the conflict set to conflict_aggregate_set (except types in chwall_ssidref) */
            for (j = 0; j < chwall_buf->chwall_max_types; j++)
                if (conflict_sets[i * chwall_buf->chwall_max_types + j] &&
                    !ssidrefs[chwall_ssidref *
                             chwall_buf->chwall_max_types + j])
                    conflict_aggregate_set[j]++;
        }
    }
 out:
    spin_unlock(&domlist_update_lock);
    return violation;
    /* returning "violation != 0" means that the currently running set of domains would
     * not be possible if the new policy had been enforced before starting them; for chinese
     * wall, this means that the new policy includes at least one conflict set of which
     * more than one type is currently running */
}

static int chwall_set_policy(u8 * buf, u32 buf_size, int is_bootpolicy)
{
    /* policy write-locked already */
    struct acm_chwall_policy_buffer *chwall_buf =
        (struct acm_chwall_policy_buffer *) buf;
    void *ssids = NULL, *conflict_sets = NULL, *running_types =
        NULL, *conflict_aggregate_set = NULL;

    if (buf_size < sizeof(struct acm_chwall_policy_buffer))
        return -EINVAL;

    /* rewrite the policy due to endianess */
    chwall_buf->policy_code = be32_to_cpu(chwall_buf->policy_code);
    chwall_buf->policy_version = be32_to_cpu(chwall_buf->policy_version);
    chwall_buf->chwall_max_types = be32_to_cpu(chwall_buf->chwall_max_types);
    chwall_buf->chwall_max_ssidrefs =
        be32_to_cpu(chwall_buf->chwall_max_ssidrefs);
    chwall_buf->chwall_max_conflictsets =
        be32_to_cpu(chwall_buf->chwall_max_conflictsets);
    chwall_buf->chwall_ssid_offset = be32_to_cpu(chwall_buf->chwall_ssid_offset);
    chwall_buf->chwall_conflict_sets_offset =
        be32_to_cpu(chwall_buf->chwall_conflict_sets_offset);
    chwall_buf->chwall_running_types_offset =
        be32_to_cpu(chwall_buf->chwall_running_types_offset);
    chwall_buf->chwall_conflict_aggregate_offset =
        be32_to_cpu(chwall_buf->chwall_conflict_aggregate_offset);

    /* policy type and version checks */
    if ((chwall_buf->policy_code != ACM_CHINESE_WALL_POLICY) ||
        (chwall_buf->policy_version != ACM_CHWALL_VERSION))
        return -EINVAL;

    /* during boot dom0_chwall_ssidref is set */
    if (is_bootpolicy &&
        (dom0_chwall_ssidref >= chwall_buf->chwall_max_ssidrefs)) {
        goto error_free;
    }

    /* 1. allocate new buffers */
    ssids =
        xmalloc_array(domaintype_t,
                      chwall_buf->chwall_max_types *
                      chwall_buf->chwall_max_ssidrefs);
    conflict_sets =
        xmalloc_array(domaintype_t,
                      chwall_buf->chwall_max_conflictsets *
                      chwall_buf->chwall_max_types);
    running_types =
        xmalloc_array(domaintype_t, chwall_buf->chwall_max_types);
    conflict_aggregate_set =
        xmalloc_array(domaintype_t, chwall_buf->chwall_max_types);

    if ((ssids == NULL) || (conflict_sets == NULL)
        || (running_types == NULL) || (conflict_aggregate_set == NULL))
        goto error_free;

    /* 2. set new policy */
    if (chwall_buf->chwall_ssid_offset + sizeof(domaintype_t) *
        chwall_buf->chwall_max_types * chwall_buf->chwall_max_ssidrefs >
        buf_size)
        goto error_free;

    arrcpy(ssids, buf + chwall_buf->chwall_ssid_offset,
           sizeof(domaintype_t),
           chwall_buf->chwall_max_types * chwall_buf->chwall_max_ssidrefs);

    if (chwall_buf->chwall_conflict_sets_offset + sizeof(domaintype_t) *
        chwall_buf->chwall_max_types *
        chwall_buf->chwall_max_conflictsets > buf_size)
        goto error_free;

    arrcpy(conflict_sets, buf + chwall_buf->chwall_conflict_sets_offset,
           sizeof(domaintype_t),
           chwall_buf->chwall_max_types *
           chwall_buf->chwall_max_conflictsets);

    /* we also use new state buffers since max_types can change */
    memset(running_types, 0,
           sizeof(domaintype_t) * chwall_buf->chwall_max_types);
    memset(conflict_aggregate_set, 0,
           sizeof(domaintype_t) * chwall_buf->chwall_max_types);

    /* 3. now re-calculate the state for the new policy based on running domains;
     *    this can fail if new policy is conflicting with running domains */
    if (chwall_init_state(chwall_buf, ssids,
                          conflict_sets, running_types,
                          conflict_aggregate_set))
    {
        printk("%s: New policy conflicts with running domains. Policy load aborted.\n",
               __func__);
        goto error_free;        /* new policy conflicts with running domains */
    }
    /* 4. free old policy buffers, replace with new ones */
    chwall_bin_pol.max_types = chwall_buf->chwall_max_types;
    chwall_bin_pol.max_ssidrefs = chwall_buf->chwall_max_ssidrefs;
    chwall_bin_pol.max_conflictsets = chwall_buf->chwall_max_conflictsets;
    xfree(chwall_bin_pol.ssidrefs);
    xfree(chwall_bin_pol.conflict_aggregate_set);
    xfree(chwall_bin_pol.running_types);
    xfree(chwall_bin_pol.conflict_sets);
    chwall_bin_pol.ssidrefs = ssids;
    chwall_bin_pol.conflict_aggregate_set = conflict_aggregate_set;
    chwall_bin_pol.running_types = running_types;
    chwall_bin_pol.conflict_sets = conflict_sets;
    return ACM_OK;

 error_free:
    printk("%s: ERROR setting policy.\n", __func__);
    xfree(ssids);
    xfree(conflict_sets);
    xfree(running_types);
    xfree(conflict_aggregate_set);
    return -EFAULT;
}

static int chwall_dump_stats(u8 * buf, u16 len)
{
    /* no stats for Chinese Wall Policy */
    return 0;
}

static int chwall_dump_ssid_types(ssidref_t ssidref, u8 * buf, u16 len)
{
    int i;

    /* fill in buffer */
    if (chwall_bin_pol.max_types > len)
        return -EFAULT;

    if (ssidref >= chwall_bin_pol.max_ssidrefs)
        return -EFAULT;

    /* read types for chwall ssidref */
    for (i = 0; i < chwall_bin_pol.max_types; i++)
    {
        if (chwall_bin_pol.
            ssidrefs[ssidref * chwall_bin_pol.max_types + i])
            buf[i] = 1;
        else
            buf[i] = 0;
    }
    return chwall_bin_pol.max_types;
}

/***************************
 * Authorization functions
 ***************************/

/* -------- DOMAIN OPERATION HOOKS -----------*/

static int chwall_pre_domain_create(void *subject_ssid, ssidref_t ssidref)
{
    ssidref_t chwall_ssidref;
    int i, j;
    traceprintk("%s.\n", __func__);

    read_lock(&acm_bin_pol_rwlock);
    chwall_ssidref = GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);
    if (chwall_ssidref == ACM_DEFAULT_LOCAL_SSID)
    {
        printk("%s: ERROR CHWALL SSID is NOT SET but policy enforced.\n",
               __func__);
        read_unlock(&acm_bin_pol_rwlock);
        return ACM_ACCESS_DENIED;       /* catching and indicating config error */
    }
    if (chwall_ssidref >= chwall_bin_pol.max_ssidrefs)
    {
        printk("%s: ERROR chwall_ssidref > max(%x).\n",
               __func__, chwall_bin_pol.max_ssidrefs - 1);
        read_unlock(&acm_bin_pol_rwlock);
        return ACM_ACCESS_DENIED;
    }
    /* A: chinese wall check for conflicts */
    for (i = 0; i < chwall_bin_pol.max_types; i++)
        if (chwall_bin_pol.conflict_aggregate_set[i] &&
            chwall_bin_pol.ssidrefs[chwall_ssidref *
                                   chwall_bin_pol.max_types + i])
        {
            printk("%s: CHINESE WALL CONFLICT in type %02x.\n", __func__, i);
            read_unlock(&acm_bin_pol_rwlock);
            return ACM_ACCESS_DENIED;
        }

    /* B: chinese wall conflict set adjustment (so that other
     *      other domains simultaneously created are evaluated against this new set)*/
    for (i = 0; i < chwall_bin_pol.max_conflictsets; i++)
    {
        int common = 0;
        /* check if conflict_set_i and ssidref have common types */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && chwall_bin_pol.ssidrefs[chwall_ssidref *
                                          chwall_bin_pol.max_types + j])
            {
                common = 1;
                break;
            }
        if (common == 0)
            continue;           /* try next conflict set */
        /* now add types of the conflict set to conflict_aggregate_set (except types in chwall_ssidref) */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && !chwall_bin_pol.ssidrefs[chwall_ssidref *
                                           chwall_bin_pol.max_types + j])
                chwall_bin_pol.conflict_aggregate_set[j]++;
    }
    read_unlock(&acm_bin_pol_rwlock);
    return ACM_ACCESS_PERMITTED;
}

static void chwall_post_domain_create(domid_t domid, ssidref_t ssidref)
{
    int i, j;
    ssidref_t chwall_ssidref;
    traceprintk("%s.\n", __func__);

    read_lock(&acm_bin_pol_rwlock);
    chwall_ssidref = GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);
    /* adjust types ref-count for running domains */
    for (i = 0; i < chwall_bin_pol.max_types; i++)
        chwall_bin_pol.running_types[i] +=
            chwall_bin_pol.ssidrefs[chwall_ssidref *
                                   chwall_bin_pol.max_types + i];
    if (domid)
    {
        read_unlock(&acm_bin_pol_rwlock);
        return;
    }
    /* Xen does not call pre-create hook for DOM0;
     * to consider type conflicts of any domain with DOM0, we need
     * to adjust the conflict_aggregate for DOM0 here the same way it
     * is done for non-DOM0 domains in the pre-hook */
    printkd("%s: adjusting security state for DOM0 (ssidref=%x, chwall_ssidref=%x).\n",
            __func__, ssidref, chwall_ssidref);

    /* chinese wall conflict set adjustment (so that other
     *      other domains simultaneously created are evaluated against this new set)*/
    for (i = 0; i < chwall_bin_pol.max_conflictsets; i++)
    {
        int common = 0;
        /* check if conflict_set_i and ssidref have common types */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && chwall_bin_pol.ssidrefs[chwall_ssidref *
                                          chwall_bin_pol.max_types + j])
            {
                common = 1;
                break;
            }
        if (common == 0)
            continue;           /* try next conflict set */
        /* now add types of the conflict set to conflict_aggregate_set (except types in chwall_ssidref) */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && !chwall_bin_pol.ssidrefs[chwall_ssidref *
                                           chwall_bin_pol.max_types + j])
                chwall_bin_pol.conflict_aggregate_set[j]++;
    }
    read_unlock(&acm_bin_pol_rwlock);
    return;
}

static void
chwall_fail_domain_create(void *subject_ssid, ssidref_t ssidref)
{
    int i, j;
    ssidref_t chwall_ssidref;
    traceprintk("%s.\n", __func__);

    read_lock(&acm_bin_pol_rwlock);
    chwall_ssidref = GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);
    /* roll-back: re-adjust conflicting types aggregate */
    for (i = 0; i < chwall_bin_pol.max_conflictsets; i++)
    {
        int common = 0;
        /* check if conflict_set_i and ssidref have common types */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && chwall_bin_pol.ssidrefs[chwall_ssidref *
                                          chwall_bin_pol.max_types + j])
            {
                common = 1;
                break;
            }
        if (common == 0)
            continue;           /* try next conflict set, this one does not include any type of chwall_ssidref */
        /* now add types of the conflict set to conflict_aggregate_set (except types in chwall_ssidref) */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && !chwall_bin_pol.ssidrefs[chwall_ssidref *
                                           chwall_bin_pol.max_types + j])
                chwall_bin_pol.conflict_aggregate_set[j]--;
    }
    read_unlock(&acm_bin_pol_rwlock);
}


static void chwall_post_domain_destroy(void *object_ssid, domid_t id)
{
    int i, j;
    struct chwall_ssid *chwall_ssidp = GET_SSIDP(ACM_CHINESE_WALL_POLICY,
                                                 (struct acm_ssid_domain *)
                                                 object_ssid);
    ssidref_t chwall_ssidref = chwall_ssidp->chwall_ssidref;

    traceprintk("%s.\n", __func__);

    read_lock(&acm_bin_pol_rwlock);
    /* adjust running types set */
    for (i = 0; i < chwall_bin_pol.max_types; i++)
        chwall_bin_pol.running_types[i] -=
            chwall_bin_pol.ssidrefs[chwall_ssidref *
                                   chwall_bin_pol.max_types + i];

    /* roll-back: re-adjust conflicting types aggregate */
    for (i = 0; i < chwall_bin_pol.max_conflictsets; i++)
    {
        int common = 0;
        /* check if conflict_set_i and ssidref have common types */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && chwall_bin_pol.ssidrefs[chwall_ssidref *
                                          chwall_bin_pol.max_types + j])
            {
                common = 1;
                break;
            }
        if (common == 0)
            continue;           /* try next conflict set, this one does not include any type of chwall_ssidref */
        /* now add types of the conflict set to conflict_aggregate_set (except types in chwall_ssidref) */
        for (j = 0; j < chwall_bin_pol.max_types; j++)
            if (chwall_bin_pol.
                conflict_sets[i * chwall_bin_pol.max_types + j]
                && !chwall_bin_pol.ssidrefs[chwall_ssidref *
                                           chwall_bin_pol.max_types + j])
                chwall_bin_pol.conflict_aggregate_set[j]--;
    }
    read_unlock(&acm_bin_pol_rwlock);
    return;
}

struct acm_operations acm_chinesewall_ops = {
    /* policy management services */
    .init_domain_ssid = chwall_init_domain_ssid,
    .free_domain_ssid = chwall_free_domain_ssid,
    .dump_binary_policy = chwall_dump_policy,
    .set_binary_policy = chwall_set_policy,
    .dump_statistics = chwall_dump_stats,
    .dump_ssid_types = chwall_dump_ssid_types,
    /* domain management control hooks */
    .pre_domain_create = chwall_pre_domain_create,
    .post_domain_create = chwall_post_domain_create,
    .fail_domain_create = chwall_fail_domain_create,
    .post_domain_destroy = chwall_post_domain_destroy,
    /* event channel control hooks */
    .pre_eventchannel_unbound = NULL,
    .fail_eventchannel_unbound = NULL,
    .pre_eventchannel_interdomain = NULL,
    .fail_eventchannel_interdomain = NULL,
    /* grant table control hooks */
    .pre_grant_map_ref = NULL,
    .fail_grant_map_ref = NULL,
    .pre_grant_setup = NULL,
    .fail_grant_setup = NULL,
    /* generic domain-requested decision hooks */
    .sharing = NULL,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
