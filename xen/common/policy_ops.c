/******************************************************************************
 *policy_ops.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * Process policy command requests from guest OS.
 *
 */
#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/policy_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>
#include <acm/acm_hooks.h>

/* function prototypes defined in acm/acm_policy.c */
int acm_set_policy(void *buf, u16 buf_size, u16 policy);
int acm_get_policy(void *buf, u16 buf_size);
int acm_dump_statistics(void *buf, u16 buf_size);

typedef enum policyoperation {
	POLICY,     /* access to policy interface (early drop) */
	GETPOLICY,  /* dump policy cache */
	SETPOLICY,  /* set policy cache (controls security) */
	DUMPSTATS   /* dump policy statistics */
} policyoperation_t;

int
acm_authorize_policyops(struct domain *d, policyoperation_t pops)
{
	/* currently, all policy management functions are restricted to privileged domains,
	 * soon we will introduce finer-grained privileges for policy operations 
	 */
	if (!IS_PRIV(d)) {
		printk("%s: Policy management authorization denied ERROR!\n", __func__);
		return ACM_ACCESS_DENIED;
	}
	return ACM_ACCESS_PERMITTED;
}

long do_policy_op(policy_op_t *u_policy_op)
{
    long ret = 0;
    policy_op_t curop, *op = &curop;

    /* check here policy decision for policy commands */
    /* for now allow DOM0 only, later indepedently    */
    if (acm_authorize_policyops(current->domain, POLICY))
	    return -EACCES;

    if ( copy_from_user(op, u_policy_op, sizeof(*op)) )
        return -EFAULT;

    if ( op->interface_version != POLICY_INTERFACE_VERSION )
        return -EACCES;

    switch ( op->cmd )
    {
    case POLICY_SETPOLICY:
    {
        if (acm_authorize_policyops(current->domain, SETPOLICY))
		return -EACCES;
	printkd("%s: setting policy.\n", __func__);
	ret = acm_set_policy(op->u.setpolicy.pushcache, op->u.setpolicy.pushcache_size, op->u.setpolicy.policy_type);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    case POLICY_GETPOLICY:
    {
        if (acm_authorize_policyops(current->domain, GETPOLICY))
		return -EACCES;
        printkd("%s: getting policy.\n", __func__);
	ret = acm_get_policy(op->u.getpolicy.pullcache, op->u.getpolicy.pullcache_size);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    case POLICY_DUMPSTATS:
    {
        if (acm_authorize_policyops(current->domain, DUMPSTATS))
		return -EACCES;
	printkd("%s: dumping statistics.\n", __func__);
	ret = acm_dump_statistics(op->u.dumpstats.pullcache, op->u.dumpstats.pullcache_size);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    default:
        ret = -ESRCH;

    }
    return ret;
}
