/****************************************************************
 * acm_policy.c
 * 
 * Copyright (C) 2005-2007 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributors:
 * Stefan Berger <stefanb@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype access control policy management for Xen.
 *       This interface allows policy tools in authorized
 *       domains to interact with the Xen access control module
 * 
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <public/xen.h>
#include <acm/acm_core.h>
#include <public/acm_ops.h>
#include <acm/acm_hooks.h>
#include <acm/acm_endian.h>
#include <asm/current.h>

static int acm_check_deleted_ssidrefs(struct acm_sized_buffer *dels,
                                      struct acm_sized_buffer *errors);
static void acm_doms_change_ssidref(ssidref_t (*translator)
                                     (const struct acm_ssid_domain *,
                                      const struct acm_sized_buffer *),
                                      struct acm_sized_buffer *translation_map);
static void acm_doms_restore_ssidref(void);
static ssidref_t oldssid_to_newssid(const struct acm_ssid_domain *,
                                    const struct acm_sized_buffer *map);


int
acm_set_policy(XEN_GUEST_HANDLE_64(void) buf, u32 buf_size)
{
    u8 *policy_buffer = NULL;
    int ret = -EFAULT;
 
    if (buf_size < sizeof(struct acm_policy_buffer))
        return -EFAULT;

    /* copy buffer from guest domain */
    if ((policy_buffer = xmalloc_array(u8, buf_size)) == NULL)
        return -ENOMEM;

    if (copy_from_guest(policy_buffer, buf, buf_size))
    {
        printk("%s: Error copying!\n",__func__);
        goto error_free;
    }
    ret = do_acm_set_policy(policy_buffer, buf_size, 0,
                            NULL, NULL, NULL);

 error_free:
    xfree(policy_buffer);
    return ret;
}


/*
 * Update the policy of the running system by:
 * - deleting ssidrefs that are not in the new policy anymore
 *   -> no running domain may use such an ssidref
 * - assign new ssidrefs to domains based on their old ssidrefs
 *
 */
static int
_acm_update_policy(void *buf, u32 buf_size, int is_bootpolicy,
                   struct acm_policy_buffer *pol,
                   struct acm_sized_buffer *deletions,
                   struct acm_sized_buffer *ssidchanges,
                   struct acm_sized_buffer *errors)
{
    uint32_t offset, length;

    write_lock(&acm_bin_pol_rwlock);

    /*
       first some tests to check compatibility of new policy with
       current state of system/domains
     */

    /* if ssidrefs are to be deleted, make sure no domain is using them */
    if (deletions != NULL) {
        if (acm_check_deleted_ssidrefs(deletions, errors))
            goto error_lock_free;
    }

    if ((ssidchanges != NULL) && (ssidchanges->num_items > 0)) {
        /* assign all running domains new ssidrefs as requested */
        acm_doms_change_ssidref(oldssid_to_newssid, ssidchanges);
    }

    /* test primary policy data with the new ssidrefs */
    offset = be32_to_cpu(pol->primary_buffer_offset);
    length = be32_to_cpu(pol->secondary_buffer_offset) - offset;

    if ( (offset + length) > buf_size ||
         acm_primary_ops->test_binary_policy(buf + offset, length,
                                             is_bootpolicy,
                                             errors))
        goto error_lock_free;

    /* test secondary policy data with the new ssidrefs */
    offset = be32_to_cpu(pol->secondary_buffer_offset);
    length = be32_to_cpu(pol->len) - offset;
    if ( (offset + length) > buf_size ||
         acm_secondary_ops->test_binary_policy(buf + offset, length,
                                               is_bootpolicy,
                                               errors)) {
        goto error_lock_free;
    }

    /* end of testing --- now real updates */

    offset = be32_to_cpu(pol->policy_reference_offset);
    length = be32_to_cpu(pol->primary_buffer_offset) - offset;

    /* set label reference name */
    if ( (offset + length) > buf_size ||
        acm_set_policy_reference(buf + offset, length) )
        goto error_lock_free;

    /* set primary policy data */
    offset = be32_to_cpu(pol->primary_buffer_offset);
    length = be32_to_cpu(pol->secondary_buffer_offset) - offset;

    if ( acm_primary_ops->set_binary_policy(buf + offset, length) )
        goto error_lock_free;

    /* set secondary policy data */
    offset = be32_to_cpu(pol->secondary_buffer_offset);
    length = be32_to_cpu(pol->len) - offset;
    if ( acm_secondary_ops->set_binary_policy(buf + offset, length) )
        goto error_lock_free;

    memcpy(&acm_bin_pol.xml_pol_version,
           &pol->xml_pol_version,
           sizeof(acm_bin_pol.xml_pol_version));

    write_unlock(&acm_bin_pol_rwlock);
    return ACM_OK;

error_lock_free:
    if ((ssidchanges != NULL) && (ssidchanges->num_items > 0)) {
        acm_doms_restore_ssidref();
    }
    do_chwall_init_state_curr(NULL);
    write_unlock(&acm_bin_pol_rwlock);

    return -EFAULT;
}


int
do_acm_set_policy(void *buf, u32 buf_size, int is_bootpolicy,
                  struct acm_sized_buffer *deletions,
                  struct acm_sized_buffer *ssidchanges,
                  struct acm_sized_buffer *errors)
{
    struct acm_policy_buffer *pol = (struct acm_policy_buffer *)buf;

    /* some sanity checking */
    if ((be32_to_cpu(pol->magic) != ACM_MAGIC) ||
        (buf_size != be32_to_cpu(pol->len)) ||
        (be32_to_cpu(pol->policy_version) != ACM_POLICY_VERSION))
    {
        printk("%s: ERROR in Magic, Version, or buf size.\n", __func__);
        goto error_free;
    }

    if (acm_active_security_policy == ACM_POLICY_UNDEFINED) {
        /* setup the policy with the boot policy */
        if (acm_init_binary_policy((be32_to_cpu(pol->secondary_policy_code) << 4) |
                                   be32_to_cpu(pol->primary_policy_code))) {
            goto error_free;
        }
        acm_active_security_policy = (acm_bin_pol.secondary_policy_code << 4) |
                                      acm_bin_pol.primary_policy_code;
    }

    /* once acm_active_security_policy is set, it cannot be changed */
    if ((be32_to_cpu(pol->primary_policy_code) != acm_bin_pol.primary_policy_code) ||
        (be32_to_cpu(pol->secondary_policy_code) != acm_bin_pol.secondary_policy_code))
    {
        printkd("%s: Wrong policy type in boot policy!\n", __func__);
        goto error_free;
    }

    return _acm_update_policy(buf, buf_size, is_bootpolicy,
                              pol,
                              deletions, ssidchanges,
                              errors);

 error_free:
    printk("%s: Error setting policy.\n", __func__);
    return -EFAULT;
}

int
acm_get_policy(XEN_GUEST_HANDLE_64(void) buf, u32 buf_size)
{ 
    u8 *policy_buffer;
    int ret;
    struct acm_policy_buffer *bin_pol;

    if (buf_size < sizeof(struct acm_policy_buffer))
        return -EFAULT;

    if ((policy_buffer = xmalloc_array(u8, buf_size)) == NULL)
        return -ENOMEM;

    read_lock(&acm_bin_pol_rwlock);

    bin_pol = (struct acm_policy_buffer *)policy_buffer;
    bin_pol->magic = cpu_to_be32(ACM_MAGIC);
    bin_pol->primary_policy_code = cpu_to_be32(acm_bin_pol.primary_policy_code);
    bin_pol->secondary_policy_code = cpu_to_be32(acm_bin_pol.secondary_policy_code);

    bin_pol->len = cpu_to_be32(sizeof(struct acm_policy_buffer));
    bin_pol->policy_reference_offset = cpu_to_be32(be32_to_cpu(bin_pol->len));
    bin_pol->primary_buffer_offset = cpu_to_be32(be32_to_cpu(bin_pol->len));
    bin_pol->secondary_buffer_offset = cpu_to_be32(be32_to_cpu(bin_pol->len));

    memcpy(&bin_pol->xml_pol_version,
           &acm_bin_pol.xml_pol_version,
           sizeof(struct acm_policy_version));

    ret = acm_dump_policy_reference(policy_buffer + be32_to_cpu(bin_pol->policy_reference_offset),
                                    buf_size - be32_to_cpu(bin_pol->policy_reference_offset));
    if (ret < 0)
        goto error_free_unlock;

    bin_pol->len = cpu_to_be32(be32_to_cpu(bin_pol->len) + ret);
    bin_pol->primary_buffer_offset = cpu_to_be32(be32_to_cpu(bin_pol->len));

    ret = acm_primary_ops->dump_binary_policy (policy_buffer + be32_to_cpu(bin_pol->primary_buffer_offset),
                                               buf_size - be32_to_cpu(bin_pol->primary_buffer_offset));
    if (ret < 0)
        goto error_free_unlock;

    bin_pol->len = cpu_to_be32(be32_to_cpu(bin_pol->len) + ret);
    bin_pol->secondary_buffer_offset = cpu_to_be32(be32_to_cpu(bin_pol->len));

    ret = acm_secondary_ops->dump_binary_policy(policy_buffer + be32_to_cpu(bin_pol->secondary_buffer_offset),
                                                buf_size - be32_to_cpu(bin_pol->secondary_buffer_offset));
    if (ret < 0)
        goto error_free_unlock;

    bin_pol->len = cpu_to_be32(be32_to_cpu(bin_pol->len) + ret);
    if (copy_to_guest(buf, policy_buffer, be32_to_cpu(bin_pol->len)))
        goto error_free_unlock;

    read_unlock(&acm_bin_pol_rwlock);
    xfree(policy_buffer);
    return ACM_OK;

 error_free_unlock:
    read_unlock(&acm_bin_pol_rwlock);
    printk("%s: Error getting policy.\n", __func__);
    xfree(policy_buffer);
    return -EFAULT;
}

int
acm_dump_statistics(XEN_GUEST_HANDLE_64(void) buf, u16 buf_size)
{ 
    /* send stats to user space */
    u8 *stats_buffer;
    int len1, len2;
    struct acm_stats_buffer acm_stats;

    if ((stats_buffer = xmalloc_array(u8, buf_size)) == NULL)
        return -ENOMEM;

    read_lock(&acm_bin_pol_rwlock);
     
    len1 = acm_primary_ops->dump_statistics(stats_buffer + sizeof(struct acm_stats_buffer),
                                            buf_size - sizeof(struct acm_stats_buffer));
    if (len1 < 0)
        goto error_lock_free;
      
    len2 = acm_secondary_ops->dump_statistics(stats_buffer + sizeof(struct acm_stats_buffer) + len1,
                                              buf_size - sizeof(struct acm_stats_buffer) - len1);
    if (len2 < 0)
        goto error_lock_free;

    acm_stats.magic = cpu_to_be32(ACM_MAGIC);
    acm_stats.primary_policy_code = cpu_to_be32(acm_bin_pol.primary_policy_code);
    acm_stats.secondary_policy_code = cpu_to_be32(acm_bin_pol.secondary_policy_code);
    acm_stats.primary_stats_offset = cpu_to_be32(sizeof(struct acm_stats_buffer));
    acm_stats.secondary_stats_offset = cpu_to_be32(sizeof(struct acm_stats_buffer) + len1);
    acm_stats.len = cpu_to_be32(sizeof(struct acm_stats_buffer) + len1 + len2);

    memcpy(stats_buffer, &acm_stats, sizeof(struct acm_stats_buffer));

    if (copy_to_guest(buf, stats_buffer, sizeof(struct acm_stats_buffer) + len1 + len2))
        goto error_lock_free;

    read_unlock(&acm_bin_pol_rwlock);
    xfree(stats_buffer);
    return ACM_OK;

 error_lock_free:
    read_unlock(&acm_bin_pol_rwlock);
    xfree(stats_buffer);
    return -EFAULT;
}


int
acm_get_ssid(ssidref_t ssidref, XEN_GUEST_HANDLE_64(void) buf, u16 buf_size)
{
    /* send stats to user space */
    u8 *ssid_buffer;
    int ret;
    struct acm_ssid_buffer *acm_ssid;
    if (buf_size < sizeof(struct acm_ssid_buffer))
        return -EFAULT;

    if ((ssid_buffer = xmalloc_array(u8, buf_size)) == NULL)
        return -ENOMEM;

    read_lock(&acm_bin_pol_rwlock);

    acm_ssid = (struct acm_ssid_buffer *)ssid_buffer;
    acm_ssid->len = sizeof(struct acm_ssid_buffer);
    acm_ssid->ssidref = ssidref;
    acm_ssid->primary_policy_code = acm_bin_pol.primary_policy_code;
    acm_ssid->secondary_policy_code = acm_bin_pol.secondary_policy_code;

    acm_ssid->policy_reference_offset = acm_ssid->len;
    ret = acm_dump_policy_reference(ssid_buffer + acm_ssid->policy_reference_offset,
                                    buf_size - acm_ssid->policy_reference_offset);
    if (ret < 0)
        goto error_free_unlock;

    acm_ssid->len += ret;
    acm_ssid->primary_types_offset = acm_ssid->len;

    /* ret >= 0 --> ret == max_types */
    ret = acm_primary_ops->dump_ssid_types(ACM_PRIMARY(ssidref),
                                           ssid_buffer + acm_ssid->primary_types_offset,
                                           buf_size - acm_ssid->primary_types_offset);
    if (ret < 0)
        goto error_free_unlock;

    acm_ssid->len += ret;
    acm_ssid->primary_max_types = ret;
    acm_ssid->secondary_types_offset = acm_ssid->len;

    ret = acm_secondary_ops->dump_ssid_types(ACM_SECONDARY(ssidref),
                                             ssid_buffer + acm_ssid->secondary_types_offset,
                                             buf_size - acm_ssid->secondary_types_offset);
    if (ret < 0)
        goto error_free_unlock;

    acm_ssid->len += ret;
    acm_ssid->secondary_max_types = ret;

    if (copy_to_guest(buf, ssid_buffer, acm_ssid->len))
        goto error_free_unlock;

    read_unlock(&acm_bin_pol_rwlock);
    xfree(ssid_buffer);
    return ACM_OK;

 error_free_unlock:
    read_unlock(&acm_bin_pol_rwlock);
    printk("%s: Error getting ssid.\n", __func__);
    xfree(ssid_buffer);
    return -ENOMEM;
}

int
acm_get_decision(ssidref_t ssidref1, ssidref_t ssidref2, u32 hook)
{
    int ret = ACM_ACCESS_DENIED;
    switch (hook) {

    case ACMHOOK_sharing:
        /* Sharing hook restricts access in STE policy only */
        ret = acm_sharing(ssidref1, ssidref2);
        break;

    default:
        /* deny */
        break;
    }

    printkd("%s: ssid1=%x, ssid2=%x, decision=%s.\n",
            __func__, ssidref1, ssidref2,
            (ret == ACM_ACCESS_PERMITTED) ? "GRANTED" : "DENIED");

    return ret;
}



/*
   Check if an ssidref of the current policy type is being used by any
   domain.
 */
static int
acm_check_used_ssidref(uint32_t policy_type, uint32_t search_ssidref,
                       struct acm_sized_buffer *errors)
{
    int rc = 0;
    struct acm_ssid_domain *rawssid;

    read_lock(&ssid_list_rwlock);

    for_each_acmssid( rawssid ) {
        ssidref_t ssidref;
        void *s = GET_SSIDP(policy_type, rawssid);

        if (policy_type == ACM_CHINESE_WALL_POLICY) {
            ssidref = ((struct chwall_ssid *)s)->chwall_ssidref;
        } else {
            ssidref = ((struct ste_ssid *)s)->ste_ssidref;
        }
        gdprintk(XENLOG_INFO,"domid=%d: search ssidref=%d, ssidref=%d\n",
                 rawssid->domainid,search_ssidref,ssidref);
        if (ssidref == search_ssidref) {
            /* one is enough */
            acm_array_append_tuple(errors, ACM_SSIDREF_IN_USE, search_ssidref);
            rc = 1;
            break;
        }
    }

    read_unlock(&ssid_list_rwlock);

    return rc;
}


/*
 * Translate a current ssidref into its future representation under
 * the new policy.
 * The map provides translation of ssidrefs from old to new in tuples
 * of (old ssidref, new ssidref).
 */
static ssidref_t
oldssid_to_newssid(const struct acm_ssid_domain *rawssid,
                   const struct acm_sized_buffer *map)
{
    uint i;

    if (rawssid != NULL) {
        ssidref_t ssid = rawssid->ssidref & 0xffff;
        for (i = 0; i+1 < map->num_items; i += 2) {
            if (map->array[i] == ssid) {
                return (map->array[i+1] << 16 | map->array[i+1]);
            }
        }
    }
    return ACM_INVALID_SSIDREF;
}


/*
 * Assign an ssidref to the CHWALL policy component of the domain
 */
static void
acm_pri_policy_assign_ssidref(struct acm_ssid_domain *rawssid, ssidref_t new_ssid)
{
    struct chwall_ssid *chwall = (struct chwall_ssid *)rawssid->primary_ssid;
    chwall->chwall_ssidref = new_ssid;
}


/*
 * Assign an ssidref to the STE policy component of the domain
 */
static void
acm_sec_policy_assign_ssidref(struct acm_ssid_domain *rawssid, ssidref_t new_ssid)
{
    struct ste_ssid *ste = (struct ste_ssid *)rawssid->secondary_ssid;
    ste->ste_ssidref = new_ssid;
}

/*
   Change the ssidrefs on each domain using a passed translation function;
 */
static void
acm_doms_change_ssidref(ssidref_t (*translator_fn)
                          (const struct acm_ssid_domain *,
                           const struct acm_sized_buffer *),
                        struct acm_sized_buffer *translation_map)
{
    struct acm_ssid_domain *rawssid;

    write_lock(&ssid_list_rwlock);

    for_each_acmssid( rawssid ) {
        ssidref_t new_ssid;

        rawssid->old_ssidref = rawssid->ssidref;

        new_ssid = translator_fn(rawssid, translation_map);
        if (new_ssid == ACM_INVALID_SSIDREF) {
            /* means no mapping found, so no change -- old = new */
            continue;
        }

        acm_pri_policy_assign_ssidref(rawssid, ACM_PRIMARY  (new_ssid) );
        acm_sec_policy_assign_ssidref(rawssid, ACM_SECONDARY(new_ssid) );

        rawssid->ssidref = new_ssid;
    }

    write_unlock(&ssid_list_rwlock);
}

/*
 * Restore the previous ssidref values on all domains
 */
static void
acm_doms_restore_ssidref(void)
{
    struct acm_ssid_domain *rawssid;

    write_lock(&ssid_list_rwlock);

    for_each_acmssid( rawssid ) {
        ssidref_t old_ssid;

        if (rawssid->old_ssidref == rawssid->ssidref)
            continue;

        old_ssid = rawssid->old_ssidref & 0xffff;
        rawssid->ssidref = rawssid->old_ssidref;

        acm_pri_policy_assign_ssidref(rawssid, old_ssid);
        acm_sec_policy_assign_ssidref(rawssid, old_ssid);
    }

    write_unlock(&ssid_list_rwlock);
}


/*
   Check the list of domains whether either one of them uses a
   to-be-deleted ssidref.
 */
static int
acm_check_deleted_ssidrefs(struct acm_sized_buffer *dels,
                           struct acm_sized_buffer *errors)
{
    int rc = 0;
    uint idx;
    /* check for running domains that should not be there anymore */
    for (idx = 0; idx < dels->num_items; idx++) {
        if (acm_check_used_ssidref(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY,
                                   dels->array[idx],
                                   errors) > 0 ||
            acm_check_used_ssidref(ACM_CHINESE_WALL_POLICY,
                                   dels->array[idx],
                                   errors) > 0) {
            rc = ACM_ERROR;
            break;
        }
    }
    return rc;
}


/*
 * Change the policy of the system.
 */
int
acm_change_policy(struct acm_change_policy *chgpolicy)
{
    int rc = 0;
    u8 *binpolicy = NULL;
    struct acm_sized_buffer dels = {
        .array = NULL,
    };
    struct acm_sized_buffer ssidmap = {
        .array = NULL,
    };
    struct acm_sized_buffer errors = {
        .array = NULL,
    };

    gdprintk(XENLOG_INFO, "change policy operation\n");

    if ((chgpolicy->delarray_size > 4096) ||
        (chgpolicy->chgarray_size > 4096) ||
        (chgpolicy->errarray_size > 4096)) {
        return ACM_ERROR;
    }

    dels.num_items = chgpolicy->delarray_size / sizeof(uint32_t);
    if (dels.num_items > 0) {
        dels.array = xmalloc_array(uint32_t, dels.num_items);
        if (dels.array == NULL) {
            rc = -ENOMEM;
            goto acm_chg_policy_exit;
        }
    }

    ssidmap.num_items = chgpolicy->chgarray_size / sizeof(uint32_t);
    if (ssidmap.num_items > 0) {
        ssidmap.array = xmalloc_array(uint32_t, ssidmap.num_items);
        if (ssidmap.array == NULL) {
            rc = -ENOMEM;
            goto acm_chg_policy_exit;
        }
    }

    errors.num_items = chgpolicy->errarray_size / sizeof(uint32_t);
    if (errors.num_items > 0) {
        errors.array = xmalloc_array(uint32_t, errors.num_items);
        if (errors.array == NULL) {
            rc = -ENOMEM;
            goto acm_chg_policy_exit;
        }
        memset(errors.array, 0x0, sizeof(uint32_t) * errors.num_items);
    }

    binpolicy = xmalloc_array(u8,
                              chgpolicy->policy_pushcache_size);
    if (binpolicy == NULL) {
        rc = -ENOMEM;
        goto acm_chg_policy_exit;
    }

    if ( copy_from_guest(dels.array,
                         chgpolicy->del_array,
                         chgpolicy->delarray_size) ||
         copy_from_guest(ssidmap.array,
                         chgpolicy->chg_array,
                         chgpolicy->chgarray_size) ||
         copy_from_guest(binpolicy,
                         chgpolicy->policy_pushcache,
                         chgpolicy->policy_pushcache_size )) {
        rc = -EFAULT;
        goto acm_chg_policy_exit;
    }

    rc = do_acm_set_policy(binpolicy,
                           chgpolicy->policy_pushcache_size,
                           0,
                           &dels, &ssidmap, &errors);

    if ( (errors.num_items > 0) &&
         copy_to_guest(chgpolicy->err_array,
                       errors.array,
                       errors.num_items ) ) {
        rc = -EFAULT;
        goto acm_chg_policy_exit;
    }


acm_chg_policy_exit:
    xfree(dels.array);
    xfree(ssidmap.array);
    xfree(errors.array);
    xfree(binpolicy);

    return rc;
}


/*
 * Lookup the new ssidref given the domain's id.
 * The translation map provides a list of tuples in the format
 * (domid, new ssidref).
 */
static ssidref_t
domid_to_newssid(const struct acm_ssid_domain *rawssid,
                 const struct acm_sized_buffer *map)
{
    domid_t domid = rawssid->domainid;
    uint i;
    for (i = 0; (i+1) < map->num_items; i += 2) {
        if (map->array[i] == domid) {
            return (ssidref_t)map->array[i+1];
        }
    }
    return ACM_INVALID_SSIDREF;
}


int
do_acm_relabel_doms(struct acm_sized_buffer *relabel_map,
                    struct acm_sized_buffer *errors)
{
    int rc = 0, irc;

    write_lock(&acm_bin_pol_rwlock);

    acm_doms_change_ssidref(domid_to_newssid, relabel_map);

    /* run tests; collect as much error info as possible */
    irc =  do_chwall_init_state_curr(errors);
    irc += do_ste_init_state_curr(errors);
    if (irc != 0) {
        rc = -EFAULT;
        goto acm_relabel_doms_lock_err_exit;
    }

    write_unlock(&acm_bin_pol_rwlock);

    return rc;

acm_relabel_doms_lock_err_exit:
    /* revert the new ssidref assignment */
    acm_doms_restore_ssidref();
    do_chwall_init_state_curr(NULL);

    write_unlock(&acm_bin_pol_rwlock);

    return rc;
}


int
acm_relabel_domains(struct acm_relabel_doms *relabel)
{
    int rc = ACM_OK;
    struct acm_sized_buffer relabels = {
        .array = NULL,
    };
    struct acm_sized_buffer errors = {
        .array = NULL,
    };

    if (relabel->relabel_map_size > 4096) {
        return ACM_ERROR;
    }

    relabels.num_items = relabel->relabel_map_size / sizeof(uint32_t);
    if (relabels.num_items > 0) {
        relabels.array = xmalloc_array(uint32_t, relabels.num_items);
        if (relabels.array == NULL) {
            rc = -ENOMEM;
            goto acm_relabel_doms_exit;
        }
    }

    errors.num_items = relabel->errarray_size / sizeof(uint32_t);
    if (errors.num_items > 0) {
        errors.array = xmalloc_array(uint32_t, errors.num_items);
        if (errors.array == NULL) {
            rc = -ENOMEM;
            goto acm_relabel_doms_exit;
        }
        memset(errors.array, 0x0, sizeof(uint32_t) * errors.num_items);
    }

    if ( copy_from_guest(relabels.array,
                         relabel->relabel_map,
                         relabel->relabel_map_size) ) {
        rc = -EFAULT;
        goto acm_relabel_doms_exit;
    }

    rc = do_acm_relabel_doms(&relabels, &errors);

    if ( copy_to_guest(relabel->err_array,
                       errors.array,
                       errors.num_items ) ) {
        rc = -EFAULT;
        goto acm_relabel_doms_exit;
    }

acm_relabel_doms_exit:
    xfree(relabels.array);
    xfree(errors.array);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
