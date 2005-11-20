/******************************************************************************
 * acm_ops.c
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
 * Process acm command requests from guest OS.
 *
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/acm.h>
#include <public/acm_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>
#include <acm/acm_hooks.h>

#ifndef ACM_SECURITY

long do_acm_op(struct acm_op * u_acm_op)
{
    return -ENOSYS;
}

#else

enum acm_operation {
    POLICY,                     /* access to policy interface (early drop) */
    GETPOLICY,                  /* dump policy cache */
    SETPOLICY,                  /* set policy cache (controls security) */
    DUMPSTATS,                  /* dump policy statistics */
    GETSSID,                    /* retrieve ssidref for domain id (decide inside authorized domains) */
    GETDECISION                 /* retrieve ACM decision from authorized domains */
};

int acm_authorize_acm_ops(struct domain *d, enum acm_operation pops)
{
    /* all policy management functions are restricted to privileged domains,
     * soon we will introduce finer-grained privileges for policy operations
     */
    if (!IS_PRIV(d))
    {
        printk("%s: ACM management authorization denied ERROR!\n", __func__);
        return ACM_ACCESS_DENIED;
    }
    return ACM_ACCESS_PERMITTED;
}

long do_acm_op(struct acm_op * u_acm_op)
{
    long ret = 0;
    struct acm_op curop, *op = &curop;

    /* check here policy decision for policy commands */
    /* for now allow DOM0 only, later indepedently    */
    if (acm_authorize_acm_ops(current->domain, POLICY))
        return -EACCES;

    if (copy_from_user(op, u_acm_op, sizeof(*op)))
        return -EFAULT;

    if (op->interface_version != ACM_INTERFACE_VERSION)
        return -EACCES;

    switch (op->cmd)
    {
    case ACM_SETPOLICY:
    {
        if (acm_authorize_acm_ops(current->domain, SETPOLICY))
            return -EACCES;
        printkd("%s: setting policy.\n", __func__);
        ret = acm_set_policy(op->u.setpolicy.pushcache,
                             op->u.setpolicy.pushcache_size, 1);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    case ACM_GETPOLICY:
    {
        if (acm_authorize_acm_ops(current->domain, GETPOLICY))
            return -EACCES;
        printkd("%s: getting policy.\n", __func__);
        ret = acm_get_policy(op->u.getpolicy.pullcache,
                             op->u.getpolicy.pullcache_size);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    case ACM_DUMPSTATS:
    {
        if (acm_authorize_acm_ops(current->domain, DUMPSTATS))
            return -EACCES;
        printkd("%s: dumping statistics.\n", __func__);
        ret = acm_dump_statistics(op->u.dumpstats.pullcache,
                                  op->u.dumpstats.pullcache_size);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    case ACM_GETSSID:
    {
        ssidref_t ssidref;

        if (acm_authorize_acm_ops(current->domain, GETSSID))
            return -EACCES;
        printkd("%s: getting SSID.\n", __func__);
        if (op->u.getssid.get_ssid_by == SSIDREF)
            ssidref = op->u.getssid.id.ssidref;
        else if (op->u.getssid.get_ssid_by == DOMAINID) {
            struct domain *subj = find_domain_by_id(op->u.getssid.id.domainid);
            if (!subj)
                return -ESRCH; /* domain not found */
            if (subj->ssid == NULL) {
                put_domain(subj);
                return -ESRCH;
            }
            ssidref = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            put_domain(subj);
        } else
            return -ESRCH;

        ret = acm_get_ssid(ssidref,
                           op->u.getssid.ssidbuf,
                           op->u.getssid.ssidbuf_size);
        if (ret == ACM_OK)
            ret = 0;
        else
            ret = -ESRCH;
    }
    break;

    case ACM_GETDECISION:
    {
        ssidref_t ssidref1, ssidref2;

        if (acm_authorize_acm_ops(current->domain, GETDECISION)) {
            ret = -EACCES;
            goto out;
        }
        printkd("%s: getting access control decision.\n", __func__);
        if (op->u.getdecision.get_decision_by1 == SSIDREF) {
            ssidref1 = op->u.getdecision.id1.ssidref;
        }
        else if (op->u.getdecision.get_decision_by1 == DOMAINID) {
            struct domain *subj = find_domain_by_id(op->u.getdecision.id1.domainid);
            if (!subj) {
                ret = -ESRCH; /* domain not found */
                goto out;
            }
            if (subj->ssid == NULL) {
                put_domain(subj);
                ret = -ESRCH;
            }
            ssidref1 = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            put_domain(subj);
        } else {
            ret = -ESRCH;
            goto out;
        }
        if (op->u.getdecision.get_decision_by2 == SSIDREF) {
            ssidref2 = op->u.getdecision.id2.ssidref;
        }
        else if (op->u.getdecision.get_decision_by2 == DOMAINID) {
            struct domain *subj = find_domain_by_id(op->u.getdecision.id2.domainid);
            if (!subj) {
                ret = -ESRCH; /* domain not found */
                goto out;
            }
            if (subj->ssid == NULL) {
                put_domain(subj);
                return -ESRCH;
            }
            ssidref2 = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            put_domain(subj);
        } else {
            ret = -ESRCH;
            goto out;
        }
        ret = acm_get_decision(ssidref1, ssidref2, op->u.getdecision.hook);
    }
    break;

    default:
        ret = -ESRCH;
    }

 out:
    if (ret == ACM_ACCESS_PERMITTED) {
        op->u.getdecision.acm_decision = ACM_ACCESS_PERMITTED;
        ret = 0;
    } else if  (ret == ACM_ACCESS_DENIED) {
        op->u.getdecision.acm_decision = ACM_ACCESS_DENIED;
        ret = 0;
    } else {
        op->u.getdecision.acm_decision = ACM_ACCESS_DENIED;
        if (ret > 0)
            ret = -ret;
    }
    /* copy decision back to user space */
    copy_to_user(u_acm_op, op, sizeof(*op));
    return ret;
}

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
