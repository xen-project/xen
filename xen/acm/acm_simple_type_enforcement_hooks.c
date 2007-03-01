/****************************************************************
 * acm_simple_type_enforcement_hooks.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributors:
 * Stefan Berger <stefanb@watson.ibm.com>
 *         support for network order binary policies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype Simple Type Enforcement for Xen
 *     STE allows to control which domains can setup sharing
 *     (eventchannels right now) with which other domains. Hooks
 *     are defined and called throughout Xen when domains bind to
 *     shared resources (setup eventchannels) and a domain is allowed
 *     to setup sharing with another domain if and only if both domains
 *     share at least on common type.
 *
 */

#include <xen/lib.h>
#include <asm/types.h>
#include <asm/current.h>
#include <acm/acm_hooks.h>
#include <asm/atomic.h>
#include <acm/acm_endian.h>

/* local cache structures for STE policy */
struct ste_binary_policy ste_bin_pol;

static inline int have_common_type (ssidref_t ref1, ssidref_t ref2) {
    int i;
    for(i=0; i< ste_bin_pol.max_types; i++)
        if ( ste_bin_pol.ssidrefs[ref1*ste_bin_pol.max_types + i] && 
             ste_bin_pol.ssidrefs[ref2*ste_bin_pol.max_types + i]) {
            printkd("%s: common type #%02x.\n", __func__, i);
            return 1;
        }
    return 0;
}

/* Helper function: return = (subj and obj share a common type) */
static int share_common_type(struct domain *subj, struct domain *obj)
{
    ssidref_t ref_s, ref_o;
    int ret;

    if ((subj == NULL) || (obj == NULL) || (subj->ssid == NULL) || (obj->ssid == NULL))
        return 0;
    read_lock(&acm_bin_pol_rwlock);
    /* lookup the policy-local ssids */
    ref_s = ((struct ste_ssid *)(GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                                           (struct acm_ssid_domain *)subj->ssid)))->ste_ssidref;
    ref_o = ((struct ste_ssid *)(GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                                           (struct acm_ssid_domain *)obj->ssid)))->ste_ssidref;
    /* check whether subj and obj share a common ste type */
    ret = have_common_type(ref_s, ref_o);
    read_unlock(&acm_bin_pol_rwlock);
    return ret;
}

/*
 * Initializing STE policy (will be filled by policy partition
 * using setpolicy command)
 */
int acm_init_ste_policy(void)
{
    /* minimal startup policy; policy write-locked already */
    ste_bin_pol.max_types = 1;
    ste_bin_pol.max_ssidrefs = 2;
    ste_bin_pol.ssidrefs = (domaintype_t *)xmalloc_array(domaintype_t, 2);
    memset(ste_bin_pol.ssidrefs, 0, 2);

    if (ste_bin_pol.ssidrefs == NULL)
        return ACM_INIT_SSID_ERROR;

 /* initialize state so that dom0 can start up and communicate with itself */
    ste_bin_pol.ssidrefs[1] = 1;

    /* init stats */
    atomic_set(&(ste_bin_pol.ec_eval_count), 0);
    atomic_set(&(ste_bin_pol.ec_denied_count), 0);
    atomic_set(&(ste_bin_pol.ec_cachehit_count), 0);
    atomic_set(&(ste_bin_pol.gt_eval_count), 0);
    atomic_set(&(ste_bin_pol.gt_denied_count), 0);
    atomic_set(&(ste_bin_pol.gt_cachehit_count), 0);
    return ACM_OK;
}


/* ste initialization function hooks */
static int
ste_init_domain_ssid(void **ste_ssid, ssidref_t ssidref)
{
    int i;
    struct ste_ssid *ste_ssidp = xmalloc(struct ste_ssid);
    traceprintk("%s.\n", __func__);

    if (ste_ssidp == NULL)
        return ACM_INIT_SSID_ERROR;

    /* get policy-local ssid reference */
    ste_ssidp->ste_ssidref = GET_SSIDREF(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, ssidref);
    if ((ste_ssidp->ste_ssidref >= ste_bin_pol.max_ssidrefs) ||
        (ste_ssidp->ste_ssidref == ACM_DEFAULT_LOCAL_SSID)) {
        printkd("%s: ERROR ste_ssidref (%x) undefined or unset (0).\n",
                __func__, ste_ssidp->ste_ssidref);
        xfree(ste_ssidp);
        return ACM_INIT_SSID_ERROR;
    }
    /* clean ste cache */
    for (i=0; i<ACM_TE_CACHE_SIZE; i++)
        ste_ssidp->ste_cache[i].valid = ACM_STE_free;

    (*ste_ssid) = ste_ssidp;
    printkd("%s: determined ste_ssidref to %x.\n", 
            __func__, ste_ssidp->ste_ssidref);
    return ACM_OK;
}


static void
ste_free_domain_ssid(void *ste_ssid)
{
    traceprintk("%s.\n", __func__);
    xfree(ste_ssid);
    return;
}

/* dump type enforcement cache; policy read-locked already */
static int 
ste_dump_policy(u8 *buf, u32 buf_size) {
    struct acm_ste_policy_buffer *ste_buf = (struct acm_ste_policy_buffer *)buf;
    int ret = 0;

    if (buf_size < sizeof(struct acm_ste_policy_buffer))
        return -EINVAL;

    ste_buf->ste_max_types = cpu_to_be32(ste_bin_pol.max_types);
    ste_buf->ste_max_ssidrefs = cpu_to_be32(ste_bin_pol.max_ssidrefs);
    ste_buf->policy_code = cpu_to_be32(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY);
    ste_buf->ste_ssid_offset = cpu_to_be32(sizeof(struct acm_ste_policy_buffer));
    ret = be32_to_cpu(ste_buf->ste_ssid_offset) +
        sizeof(domaintype_t)*ste_bin_pol.max_ssidrefs*ste_bin_pol.max_types;

    ret = (ret + 7) & ~7;

    if (buf_size < ret)
        return -EINVAL;

    /* now copy buffer over */
    arrcpy(buf + be32_to_cpu(ste_buf->ste_ssid_offset),
           ste_bin_pol.ssidrefs,
           sizeof(domaintype_t),
           ste_bin_pol.max_ssidrefs*ste_bin_pol.max_types);

    return ret;
}

/* ste_init_state is called when a policy is changed to detect violations (return != 0).
 * from a security point of view, we simulate that all running domains are re-started and
 * all sharing decisions are replayed to detect violations or current sharing behavior
 * (right now: event_channels, future: also grant_tables)
 */ 
static int
ste_init_state(struct acm_ste_policy_buffer *ste_buf, domaintype_t *ssidrefs)
{
    int violation = 1;
    struct ste_ssid *ste_ssid, *ste_rssid;
    ssidref_t ste_ssidref, ste_rssidref;
    struct domain *d, *rdom;
    domid_t rdomid;
    struct grant_entry sha_copy;
    int port, i;

    rcu_read_lock(&domlist_read_lock);
    /* go by domain? or directly by global? event/grant list */
    /* go through all domains and adjust policy as if this domain was started now */
    for_each_domain ( d )
    {
        ste_ssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                             (struct acm_ssid_domain *)d->ssid);
        ste_ssidref = ste_ssid->ste_ssidref;
        traceprintk("%s: validating policy for eventch domain %x (ste-Ref=%x).\n",
                    __func__, d->domain_id, ste_ssidref);
        /* a) check for event channel conflicts */
        for (port=0; port < NR_EVTCHN_BUCKETS; port++) {
            spin_lock(&d->evtchn_lock);
            if (d->evtchn[port] == NULL ||
                d->evtchn[port]->state == ECS_UNBOUND) {
                spin_unlock(&d->evtchn_lock);
                continue;
            }
            if (d->evtchn[port]->state == ECS_INTERDOMAIN) {
                rdom = d->evtchn[port]->u.interdomain.remote_dom;
                rdomid = rdom->domain_id;
            } else {
                spin_unlock(&d->evtchn_lock);
                continue; /* port unused */
            }
            spin_unlock(&d->evtchn_lock);

            /* rdom now has remote domain */
            ste_rssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                                  (struct acm_ssid_domain *)(rdom->ssid));
            ste_rssidref = ste_rssid->ste_ssidref;
            traceprintk("%s: eventch: domain %x (ssidref %x) --> domain %x (rssidref %x) used (port %x).\n", 
                        __func__, d->domain_id, ste_ssidref, rdom->domain_id, ste_rssidref, port);  
            /* check whether on subj->ssid, obj->ssid share a common type*/
            if (!have_common_type(ste_ssidref, ste_rssidref)) {
                printkd("%s: Policy violation in event channel domain %x -> domain %x.\n",
                        __func__, d->domain_id, rdomid);
                goto out;
            }
        } 
        /* b) check for grant table conflicts on shared pages */
        spin_lock(&d->grant_table->lock);
        for ( i = 0; i < nr_grant_entries(d->grant_table); i++ ) {
#define SPP (PAGE_SIZE / sizeof(struct grant_entry))
            sha_copy = d->grant_table->shared[i/SPP][i%SPP];
            if ( sha_copy.flags ) {
                printkd("%s: grant dom (%hu) SHARED (%d) flags:(%hx) dom:(%hu) frame:(%lx)\n",
                        __func__, d->domain_id, i, sha_copy.flags, sha_copy.domid, 
                        (unsigned long)sha_copy.frame);
                rdomid = sha_copy.domid;
                if ((rdom = rcu_lock_domain_by_id(rdomid)) == NULL) {
                    spin_unlock(&d->grant_table->lock);
                    printkd("%s: domain not found ERROR!\n", __func__);
                    goto out;
                };
                /* rdom now has remote domain */
                ste_rssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                                      (struct acm_ssid_domain *)(rdom->ssid));
                ste_rssidref = ste_rssid->ste_ssidref;
                rcu_unlock_domain(rdom);
                if (!have_common_type(ste_ssidref, ste_rssidref)) {
                    spin_unlock(&d->grant_table->lock);
                    printkd("%s: Policy violation in grant table sharing domain %x -> domain %x.\n",
                            __func__, d->domain_id, rdomid);
                    goto out;
                }
            }
        }
        spin_unlock(&d->grant_table->lock);
    }
    violation = 0;
 out:
    rcu_read_unlock(&domlist_read_lock);
    return violation;
    /* returning "violation != 0" means that existing sharing between domains would not 
     * have been allowed if the new policy had been enforced before the sharing; for ste, 
     * this means that there are at least 2 domains that have established sharing through 
     * event-channels or grant-tables but these two domains don't have no longer a common 
     * type in their typesets referenced by their ssidrefs */
}

/* set new policy; policy write-locked already */
static int
ste_set_policy(u8 *buf, u32 buf_size)
{
    struct acm_ste_policy_buffer *ste_buf = (struct acm_ste_policy_buffer *)buf;
    void *ssidrefsbuf;
    struct ste_ssid *ste_ssid;
    struct domain *d;
    int i;

    if (buf_size < sizeof(struct acm_ste_policy_buffer))
        return -EINVAL;

    /* Convert endianess of policy */
    ste_buf->policy_code = be32_to_cpu(ste_buf->policy_code);
    ste_buf->policy_version = be32_to_cpu(ste_buf->policy_version);
    ste_buf->ste_max_types = be32_to_cpu(ste_buf->ste_max_types);
    ste_buf->ste_max_ssidrefs = be32_to_cpu(ste_buf->ste_max_ssidrefs);
    ste_buf->ste_ssid_offset = be32_to_cpu(ste_buf->ste_ssid_offset);

    /* policy type and version checks */
    if ((ste_buf->policy_code != ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY) ||
        (ste_buf->policy_version != ACM_STE_VERSION))
        return -EINVAL;

    /* 1. create and copy-in new ssidrefs buffer */
    ssidrefsbuf = xmalloc_array(u8, sizeof(domaintype_t)*ste_buf->ste_max_types*ste_buf->ste_max_ssidrefs);
    if (ssidrefsbuf == NULL) {
        return -ENOMEM;
    }
    if (ste_buf->ste_ssid_offset + sizeof(domaintype_t) * ste_buf->ste_max_ssidrefs*ste_buf->ste_max_types > buf_size)
        goto error_free;

    arrcpy(ssidrefsbuf, 
           buf + ste_buf->ste_ssid_offset,
           sizeof(domaintype_t),
           ste_buf->ste_max_ssidrefs*ste_buf->ste_max_types);

    /* 2. now re-calculate sharing decisions based on running domains;
     *    this can fail if new policy is conflicting with sharing of running domains 
     *    now: reject violating new policy; future: adjust sharing through revoking sharing */
    if (ste_init_state(ste_buf, (domaintype_t *)ssidrefsbuf)) {
        printk("%s: New policy conflicts with running domains. Policy load aborted.\n", __func__);
        goto error_free; /* new policy conflicts with sharing of running domains */
    }
    /* 3. replace old policy (activate new policy) */
    ste_bin_pol.max_types = ste_buf->ste_max_types;
    ste_bin_pol.max_ssidrefs = ste_buf->ste_max_ssidrefs;
    xfree(ste_bin_pol.ssidrefs);
    ste_bin_pol.ssidrefs = (domaintype_t *)ssidrefsbuf;

    /* clear all ste caches */
    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d ) {
        ste_ssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                             (struct acm_ssid_domain *)(d)->ssid);
        for (i=0; i<ACM_TE_CACHE_SIZE; i++)
            ste_ssid->ste_cache[i].valid = ACM_STE_free;
    }
    rcu_read_unlock(&domlist_read_lock);
    return ACM_OK;

 error_free:
    printk("%s: ERROR setting policy.\n", __func__);
    xfree(ssidrefsbuf);
    return -EFAULT;
}

static int 
ste_dump_stats(u8 *buf, u16 buf_len)
{
    struct acm_ste_stats_buffer stats;

    /* now send the hook counts to user space */
    stats.ec_eval_count = cpu_to_be32(atomic_read(&ste_bin_pol.ec_eval_count));
    stats.gt_eval_count = cpu_to_be32(atomic_read(&ste_bin_pol.gt_eval_count));
    stats.ec_denied_count = cpu_to_be32(atomic_read(&ste_bin_pol.ec_denied_count));
    stats.gt_denied_count = cpu_to_be32(atomic_read(&ste_bin_pol.gt_denied_count));
    stats.ec_cachehit_count = cpu_to_be32(atomic_read(&ste_bin_pol.ec_cachehit_count));
    stats.gt_cachehit_count = cpu_to_be32(atomic_read(&ste_bin_pol.gt_cachehit_count));

    if (buf_len < sizeof(struct acm_ste_stats_buffer))
        return -ENOMEM;

    memcpy(buf, &stats, sizeof(struct acm_ste_stats_buffer));
    return sizeof(struct acm_ste_stats_buffer);
}

static int
ste_dump_ssid_types(ssidref_t ssidref, u8 *buf, u16 len)
{
    int i;

    /* fill in buffer */
    if (ste_bin_pol.max_types > len)
        return -EFAULT;

    if (ssidref >= ste_bin_pol.max_ssidrefs)
        return -EFAULT;

    /* read types for chwall ssidref */
    for(i=0; i< ste_bin_pol.max_types; i++) {
        if (ste_bin_pol.ssidrefs[ssidref * ste_bin_pol.max_types + i])
            buf[i] = 1;
        else
            buf[i] = 0;
    }
    return ste_bin_pol.max_types;
}

/* we need to go through this before calling the hooks,
 * returns 1 == cache hit */
static int inline
check_cache(struct domain *dom, domid_t rdom) {
    struct ste_ssid *ste_ssid;
    int i;

    printkd("checking cache: %x --> %x.\n", dom->domain_id, rdom);

    if (dom->ssid == NULL)
        return 0;
    ste_ssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                         (struct acm_ssid_domain *)(dom->ssid));

    for(i=0; i< ACM_TE_CACHE_SIZE; i++) {
        if ((ste_ssid->ste_cache[i].valid == ACM_STE_valid) &&
            (ste_ssid->ste_cache[i].id == rdom)) {
            printkd("cache hit (entry %x, id= %x!\n", i, ste_ssid->ste_cache[i].id);
            return 1;
        }
    }
    return 0;
}


/* we only get here if there is NO entry yet; no duplication check! */
static void inline
cache_result(struct domain *subj, struct domain *obj) {
    struct ste_ssid *ste_ssid;
    int i;
    printkd("caching from doms: %x --> %x.\n", subj->domain_id, obj->domain_id);
    if (subj->ssid == NULL)
        return;
    ste_ssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, 
                         (struct acm_ssid_domain *)(subj)->ssid);
    for(i=0; i< ACM_TE_CACHE_SIZE; i++)
        if (ste_ssid->ste_cache[i].valid == ACM_STE_free)
            break;
    if (i< ACM_TE_CACHE_SIZE) {
        ste_ssid->ste_cache[i].valid = ACM_STE_valid;
        ste_ssid->ste_cache[i].id = obj->domain_id;
    } else
        printk ("Cache of dom %x is full!\n", subj->domain_id);
}

/* deletes entries for domain 'id' from all caches (re-use) */
static void inline
clean_id_from_cache(domid_t id) 
{
    struct ste_ssid *ste_ssid;
    int i;
    struct domain *d;
    struct acm_ssid_domain *ssid;

    printkd("deleting cache for dom %x.\n", id);
    rcu_read_lock(&domlist_read_lock);
    /* look through caches of all domains */
    for_each_domain ( d ) {
        ssid = (struct acm_ssid_domain *)(d->ssid);

        if (ssid == NULL)
            continue; /* hanging domain structure, no ssid any more ... */
        ste_ssid = GET_SSIDP(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, ssid);
        if (!ste_ssid) {
            printk("%s: deleting ID from cache ERROR (no ste_ssid)!\n",
                   __func__);
            goto out;
        }
        for (i=0; i<ACM_TE_CACHE_SIZE; i++)
            if ((ste_ssid->ste_cache[i].valid == ACM_STE_valid) &&
                (ste_ssid->ste_cache[i].id == id))
                ste_ssid->ste_cache[i].valid = ACM_STE_free;
    }
 out:
    rcu_read_unlock(&domlist_read_lock);
}

/***************************
 * Authorization functions
 **************************/
static int 
ste_pre_domain_create(void *subject_ssid, ssidref_t ssidref)
{      
    /* check for ssidref in range for policy */
    ssidref_t ste_ssidref;
    traceprintk("%s.\n", __func__);

    read_lock(&acm_bin_pol_rwlock);
    ste_ssidref = GET_SSIDREF(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, ssidref);
    if (ste_ssidref == ACM_DEFAULT_LOCAL_SSID) {
        printk("%s: ERROR STE SSID is NOT SET but policy enforced.\n", __func__);
        read_unlock(&acm_bin_pol_rwlock);
        return ACM_ACCESS_DENIED; /* catching and indicating config error */
    }
    if (ste_ssidref >= ste_bin_pol.max_ssidrefs) {
        printk("%s: ERROR ste_ssidref > max(%x).\n", 
               __func__, ste_bin_pol.max_ssidrefs-1);
        read_unlock(&acm_bin_pol_rwlock);
        return ACM_ACCESS_DENIED;
    }
    read_unlock(&acm_bin_pol_rwlock);
    return ACM_ACCESS_PERMITTED;
}

static void 
ste_post_domain_destroy(void *subject_ssid, domid_t id)
{
    /* clean all cache entries for destroyed domain (might be re-used) */
    clean_id_from_cache(id);
}

/* -------- EVENTCHANNEL OPERATIONS -----------*/
static int
ste_pre_eventchannel_unbound(domid_t id1, domid_t id2) {
    struct domain *subj, *obj;
    int ret;
    traceprintk("%s: dom%x-->dom%x.\n", __func__,
                (id1 == DOMID_SELF) ? current->domain->domain_id : id1,
                (id2 == DOMID_SELF) ? current->domain->domain_id : id2);

    if (id1 == DOMID_SELF) id1 = current->domain->domain_id;
    if (id2 == DOMID_SELF) id2 = current->domain->domain_id;

    subj = rcu_lock_domain_by_id(id1);
    obj  = rcu_lock_domain_by_id(id2);
    if ((subj == NULL) || (obj == NULL)) {
        ret = ACM_ACCESS_DENIED;
        goto out;
    }
    /* cache check late */
    if (check_cache(subj, obj->domain_id)) {
        atomic_inc(&ste_bin_pol.ec_cachehit_count);
        ret = ACM_ACCESS_PERMITTED;
        goto out;
    }
    atomic_inc(&ste_bin_pol.ec_eval_count);

    if (share_common_type(subj, obj)) {
        cache_result(subj, obj);
        ret = ACM_ACCESS_PERMITTED;
    } else {
        atomic_inc(&ste_bin_pol.ec_denied_count);
        ret = ACM_ACCESS_DENIED;
    }
  out:
    if (obj != NULL)
        rcu_unlock_domain(obj);
    if (subj != NULL)
        rcu_unlock_domain(subj);
    return ret;
}

static int
ste_pre_eventchannel_interdomain(domid_t id)
{
    struct domain *subj=NULL, *obj=NULL;
    int ret;

    traceprintk("%s: dom%x-->dom%x.\n", __func__,
                current->domain->domain_id,
                (id == DOMID_SELF) ? current->domain->domain_id : id);

    /* following is a bit longer but ensures that we
     * "put" only domains that we where "find"-ing 
     */
    if (id == DOMID_SELF) id = current->domain->domain_id;

    subj = current->domain;
    obj  = rcu_lock_domain_by_id(id);
    if (obj == NULL) {
        ret = ACM_ACCESS_DENIED;
        goto out;
    }

    /* cache check late, but evtchn is not on performance critical path */
    if (check_cache(subj, obj->domain_id)) {
        atomic_inc(&ste_bin_pol.ec_cachehit_count);
        ret = ACM_ACCESS_PERMITTED;
        goto out;
    }

    atomic_inc(&ste_bin_pol.ec_eval_count);

    if (share_common_type(subj, obj)) {
        cache_result(subj, obj);
        ret = ACM_ACCESS_PERMITTED;
    } else {
        atomic_inc(&ste_bin_pol.ec_denied_count);
        ret = ACM_ACCESS_DENIED;
    }
 out:
    if (obj != NULL)
        rcu_unlock_domain(obj);
    return ret;
}

/* -------- SHARED MEMORY OPERATIONS -----------*/

static int
ste_pre_grant_map_ref (domid_t id) {
    struct domain *obj, *subj;
    int ret;
    traceprintk("%s: dom%x-->dom%x.\n", __func__,
                current->domain->domain_id, id);

    if (check_cache(current->domain, id)) {
        atomic_inc(&ste_bin_pol.gt_cachehit_count);
        return ACM_ACCESS_PERMITTED;
    }
    atomic_inc(&ste_bin_pol.gt_eval_count);
    subj = current->domain;
    obj = rcu_lock_domain_by_id(id);

    if (share_common_type(subj, obj)) {
        cache_result(subj, obj);
        ret = ACM_ACCESS_PERMITTED;
    } else {
        atomic_inc(&ste_bin_pol.gt_denied_count);
        printkd("%s: ACCESS DENIED!\n", __func__);
        ret = ACM_ACCESS_DENIED;
    }
    if (obj != NULL)
        rcu_unlock_domain(obj);
    return ret;
}


/* since setting up grant tables involves some implicit information
   flow from the creating domain to the domain that is setup, we 
   check types in addition to the general authorization */
static int
ste_pre_grant_setup (domid_t id) {
    struct domain *obj, *subj;
    int ret;
    traceprintk("%s: dom%x-->dom%x.\n", __func__,
                current->domain->domain_id, id);

    if (check_cache(current->domain, id)) {
        atomic_inc(&ste_bin_pol.gt_cachehit_count);
        return ACM_ACCESS_PERMITTED;
    }
    atomic_inc(&ste_bin_pol.gt_eval_count);
    /* a) check authorization (eventually use specific capabilities) */
    if (!IS_PRIV(current->domain)) {
        printk("%s: Grant table management authorization denied ERROR!\n", __func__);
        return ACM_ACCESS_DENIED;
    }
    /* b) check types */
    subj = current->domain;
    obj = rcu_lock_domain_by_id(id);

    if (share_common_type(subj, obj)) {
        cache_result(subj, obj);
        ret = ACM_ACCESS_PERMITTED;
    } else {
        atomic_inc(&ste_bin_pol.gt_denied_count);
        ret = ACM_ACCESS_DENIED;
    }
    if (obj != NULL)
        rcu_unlock_domain(obj);
    return ret;
}

/* -------- DOMAIN-Requested Decision hooks -----------*/

static int
ste_sharing(ssidref_t ssidref1, ssidref_t ssidref2) {
    if (have_common_type (
        GET_SSIDREF(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, ssidref1),
        GET_SSIDREF(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY, ssidref2)
        ))
        return ACM_ACCESS_PERMITTED;
    else
        return ACM_ACCESS_DENIED;
}


/* now define the hook structure similarly to LSM */
struct acm_operations acm_simple_type_enforcement_ops = {

    /* policy management services */
    .init_domain_ssid  = ste_init_domain_ssid,
    .free_domain_ssid  = ste_free_domain_ssid,
    .dump_binary_policy     = ste_dump_policy,
    .set_binary_policy      = ste_set_policy,
    .dump_statistics  = ste_dump_stats,
    .dump_ssid_types        = ste_dump_ssid_types,

    /* domain management control hooks */
    .pre_domain_create       = ste_pre_domain_create,
    .post_domain_create     = NULL,
    .fail_domain_create     = NULL,
    .post_domain_destroy    = ste_post_domain_destroy,

    /* event channel control hooks */
    .pre_eventchannel_unbound   = ste_pre_eventchannel_unbound,
    .fail_eventchannel_unbound = NULL,
    .pre_eventchannel_interdomain = ste_pre_eventchannel_interdomain,
    .fail_eventchannel_interdomain  = NULL,

    /* grant table control hooks */
    .pre_grant_map_ref      = ste_pre_grant_map_ref,
    .fail_grant_map_ref     = NULL,
    .pre_grant_setup        = ste_pre_grant_setup,
    .fail_grant_setup       = NULL,
    .sharing                = ste_sharing,
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
