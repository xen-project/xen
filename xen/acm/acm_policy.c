/****************************************************************
 * acm_policy.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributions:
 * Stefan Berger <stefanb@watson.ibm.com>
 *	support for network-byte-order binary policies
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
#include <public/policy_ops.h>
#include <acm/acm_core.h>
#include <acm/acm_hooks.h>
#include <acm/acm_endian.h>

int
acm_set_policy(void *buf, u16 buf_size, u16 policy)
{
	u8 *policy_buffer = NULL;
	struct acm_policy_buffer *pol;
	
	if (policy != ACM_USE_SECURITY_POLICY) {
		printk("%s: Loading incompatible policy (running: %s).\n", __func__,
		       ACM_POLICY_NAME(ACM_USE_SECURITY_POLICY));
		return -EFAULT;
	}
	/* now check correct buffer sizes for policy combinations */
	if (policy == ACM_NULL_POLICY) {
		printkd("%s: NULL Policy, no policy needed.\n", __func__);
		goto out;
	}
     	if (buf_size < sizeof(struct acm_policy_buffer))
		return -EFAULT;
	/* 1. copy buffer from domain */
	if ((policy_buffer = xmalloc_array(u8, buf_size)) == NULL)
	    goto error_free;
        if (copy_from_user(policy_buffer, buf, buf_size)) {
		printk("%s: Error copying!\n",__func__);
		goto error_free;
	}
	/* 2. some sanity checking */
	pol = (struct acm_policy_buffer *)policy_buffer;

	if ((ntohl(pol->magic) != ACM_MAGIC) || 
	    (ntohs(pol->primary_policy_code) != acm_bin_pol.primary_policy_code) ||
	    (ntohs(pol->secondary_policy_code) != acm_bin_pol.secondary_policy_code)) {
		printkd("%s: Wrong policy magics!\n", __func__);
		goto error_free;
	}
	if (buf_size != ntohl(pol->len)) {
		printk("%s: ERROR in buf size.\n", __func__);
		goto error_free;
	}

	/* get bin_policy lock and rewrite policy (release old one) */
	write_lock(&acm_bin_pol_rwlock);

	/* 3. now get/set primary policy data */
	if (acm_primary_ops->set_binary_policy(buf + ntohs(pol->primary_buffer_offset), 
                                               ntohs(pol->secondary_buffer_offset) -
					       ntohs(pol->primary_buffer_offset))) {
		goto error_lock_free;
	}
	/* 4. now get/set secondary policy data */
	if (acm_secondary_ops->set_binary_policy(buf + ntohs(pol->secondary_buffer_offset),
						 ntohl(pol->len) - 
						 ntohs(pol->secondary_buffer_offset))) {
		goto error_lock_free;
	}
	write_unlock(&acm_bin_pol_rwlock);
 out:
	printk("%s: Done .\n", __func__);
	if (policy_buffer != NULL)
		xfree(policy_buffer);
	return ACM_OK;

 error_lock_free:
	write_unlock(&acm_bin_pol_rwlock);
 error_free:
	printk("%s: Error setting policy.\n", __func__);
	if (policy_buffer != NULL)
		xfree(policy_buffer);
	return -ENOMEM;
}

int
acm_get_policy(void *buf, u16 buf_size)
{	
     u8 *policy_buffer;
     int ret;
     struct acm_policy_buffer *bin_pol;
	
     if ((policy_buffer = xmalloc_array(u8, buf_size)) == NULL)
	    return -ENOMEM;

     read_lock(&acm_bin_pol_rwlock);
     /* future: read policy from file and set it */
     bin_pol = (struct acm_policy_buffer *)policy_buffer;
     bin_pol->magic = htonl(ACM_MAGIC);
     bin_pol->policyversion = htonl(POLICY_INTERFACE_VERSION);
     bin_pol->primary_policy_code = htons(acm_bin_pol.primary_policy_code);
     bin_pol->secondary_policy_code = htons(acm_bin_pol.secondary_policy_code);

     bin_pol->len = htonl(sizeof(struct acm_policy_buffer));
     bin_pol->primary_buffer_offset = htons(ntohl(bin_pol->len));
     bin_pol->secondary_buffer_offset = htons(ntohl(bin_pol->len));
     
     ret = acm_primary_ops->dump_binary_policy (policy_buffer + ntohs(bin_pol->primary_buffer_offset),
				       buf_size - ntohs(bin_pol->primary_buffer_offset));
     if (ret < 0) {
	     printk("%s: ERROR creating chwallpolicy buffer.\n", __func__);
	     read_unlock(&acm_bin_pol_rwlock);
	     return -1;
     }
     bin_pol->len = htonl(ntohl(bin_pol->len) + ret);
     bin_pol->secondary_buffer_offset = htons(ntohl(bin_pol->len));

     ret = acm_secondary_ops->dump_binary_policy(policy_buffer + ntohs(bin_pol->secondary_buffer_offset), 
				    buf_size - ntohs(bin_pol->secondary_buffer_offset));
     if (ret < 0) {
	     printk("%s: ERROR creating chwallpolicy buffer.\n", __func__);
	     read_unlock(&acm_bin_pol_rwlock);
	     return -1;
     }
     bin_pol->len = htonl(ntohl(bin_pol->len) + ret);
     read_unlock(&acm_bin_pol_rwlock);
     if (copy_to_user(buf, policy_buffer, ntohl(bin_pol->len)))
	     return -EFAULT;
     xfree(policy_buffer);
     return ACM_OK;
}

int
acm_dump_statistics(void *buf, u16 buf_size)
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

     acm_stats.magic = htonl(ACM_MAGIC);
     acm_stats.policyversion = htonl(POLICY_INTERFACE_VERSION);
     acm_stats.primary_policy_code = htons(acm_bin_pol.primary_policy_code);
     acm_stats.secondary_policy_code = htons(acm_bin_pol.secondary_policy_code);
     acm_stats.primary_stats_offset = htons(sizeof(struct acm_stats_buffer));
     acm_stats.secondary_stats_offset = htons(sizeof(struct acm_stats_buffer) + len1);
     acm_stats.len = htonl(sizeof(struct acm_stats_buffer) + len1 + len2);
     memcpy(stats_buffer, &acm_stats, sizeof(struct acm_stats_buffer));

     if (copy_to_user(buf, stats_buffer, sizeof(struct acm_stats_buffer) + len1 + len2))
	     goto error_lock_free;

     read_unlock(&acm_bin_pol_rwlock);
     xfree(stats_buffer);
     return ACM_OK;

 error_lock_free:
     read_unlock(&acm_bin_pol_rwlock);
     xfree(stats_buffer);
     return -EFAULT;
}

/*eof*/
