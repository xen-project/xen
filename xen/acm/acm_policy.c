/****************************************************************
 * acm_policy.c
 * 
 * Copyright (C) 2005 IBM Corporation
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
#include <acm/acm_core.h>
#include <public/acm_ops.h>
#include <acm/acm_hooks.h>
#include <acm/acm_endian.h>

int
acm_set_policy(XEN_GUEST_HANDLE(void) buf, u32 buf_size)
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
    ret = do_acm_set_policy(policy_buffer, buf_size);

 error_free:
    xfree(policy_buffer);
    return ret;
}


int
do_acm_set_policy(void *buf, u32 buf_size)
{
    struct acm_policy_buffer *pol = (struct acm_policy_buffer *)buf;
    uint32_t offset, length;
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
        acm_active_security_policy =
            (acm_bin_pol.secondary_policy_code << 4) | acm_bin_pol.primary_policy_code;
    }

    /* once acm_active_security_policy is set, it cannot be changed */
    if ((be32_to_cpu(pol->primary_policy_code) != acm_bin_pol.primary_policy_code) ||
        (be32_to_cpu(pol->secondary_policy_code) != acm_bin_pol.secondary_policy_code))
    {
        printkd("%s: Wrong policy type in boot policy!\n", __func__);
        goto error_free;
    }

    /* get bin_policy lock and rewrite policy (release old one) */
    write_lock(&acm_bin_pol_rwlock);

    offset = be32_to_cpu(pol->policy_reference_offset);
    length = be32_to_cpu(pol->primary_buffer_offset) - offset;

    /* set label reference name */
    if ( (offset + length) > buf_size ||
         acm_set_policy_reference(buf + offset, length))
        goto error_lock_free;

    /* set primary policy data */
    offset = be32_to_cpu(pol->primary_buffer_offset);
    length = be32_to_cpu(pol->secondary_buffer_offset) - offset;

    if ( (offset + length) > buf_size ||
         acm_primary_ops->set_binary_policy(buf + offset, length))
        goto error_lock_free;

    /* set secondary policy data */
    offset = be32_to_cpu(pol->secondary_buffer_offset);
    length = be32_to_cpu(pol->len) - offset;
    if ( (offset + length) > buf_size ||
         acm_secondary_ops->set_binary_policy(buf + offset, length))
        goto error_lock_free;

    memcpy(&acm_bin_pol.xml_pol_version,
           &pol->xml_pol_version,
           sizeof(acm_bin_pol.xml_pol_version));

    write_unlock(&acm_bin_pol_rwlock);
    return ACM_OK;

 error_lock_free:
    write_unlock(&acm_bin_pol_rwlock);
 error_free:
    printk("%s: Error setting policy.\n", __func__);
    return -EFAULT;
}

int
acm_get_policy(XEN_GUEST_HANDLE(void) buf, u32 buf_size)
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
acm_dump_statistics(XEN_GUEST_HANDLE(void) buf, u16 buf_size)
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
acm_get_ssid(ssidref_t ssidref, XEN_GUEST_HANDLE(void) buf, u16 buf_size)
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
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
