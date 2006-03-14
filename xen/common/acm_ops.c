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
#include <xen/guest_access.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>
#include <acm/acm_hooks.h>

#ifndef ACM_SECURITY

long do_acm_op(GUEST_HANDLE(acm_op_t) u_acm_op)
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
    /* currently, policy management functions are restricted to privileged domains */
    if (!IS_PRIV(d))
        return -EPERM;

    return 0;
}

long do_acm_op(GUEST_HANDLE(acm_op_t) u_acm_op)
{
    long ret = 0;
    struct acm_op curop, *op = &curop;

    if (acm_authorize_acm_ops(current->domain, POLICY))
        return -EPERM;

    if (copy_from_guest(op, u_acm_op, 1))
        return -EFAULT;

    if (op->interface_version != ACM_INTERFACE_VERSION)
        return -EACCES;

    switch (op->cmd)
    {
    case ACM_SETPOLICY:
    {
        ret = acm_authorize_acm_ops(current->domain, SETPOLICY);
        if (!ret)
            ret = acm_set_policy(op->u.setpolicy.pushcache,
                                 op->u.setpolicy.pushcache_size, 1);
    }
    break;

    case ACM_GETPOLICY:
    {
        ret = acm_authorize_acm_ops(current->domain, GETPOLICY);
        if (!ret)
            ret = acm_get_policy(op->u.getpolicy.pullcache,
                                 op->u.getpolicy.pullcache_size);
        if (!ret)
            copy_to_guest(u_acm_op, op, 1);
    }
    break;

    case ACM_DUMPSTATS:
    {
        ret = acm_authorize_acm_ops(current->domain, DUMPSTATS);
        if (!ret)
            ret = acm_dump_statistics(op->u.dumpstats.pullcache,
                                      op->u.dumpstats.pullcache_size);
        if (!ret)
            copy_to_guest(u_acm_op, op, 1);
    }
    break;

    case ACM_GETSSID:
    {
        ssidref_t ssidref;

        ret = acm_authorize_acm_ops(current->domain, GETSSID);
        if (ret)
            break;

        if (op->u.getssid.get_ssid_by == SSIDREF)
            ssidref = op->u.getssid.id.ssidref;
        else if (op->u.getssid.get_ssid_by == DOMAINID)
        {
            struct domain *subj = find_domain_by_id(op->u.getssid.id.domainid);
            if (!subj)
            {
                ret = -ESRCH; /* domain not found */
                break;
            }
            if (subj->ssid == NULL)
            {
                put_domain(subj);
                ret = -ESRCH;
                break;
            }
            ssidref = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            put_domain(subj);
        }
        else
        {
            ret = -ESRCH;
            break;
        }
        ret = acm_get_ssid(ssidref,
                           op->u.getssid.ssidbuf,
                           op->u.getssid.ssidbuf_size);
        if (!ret)
            copy_to_guest(u_acm_op, op, 1);
    }
    break;

    case ACM_GETDECISION:
    {
        ssidref_t ssidref1, ssidref2;

        ret = acm_authorize_acm_ops(current->domain, GETDECISION);
        if (ret)
            break;

        if (op->u.getdecision.get_decision_by1 == SSIDREF)
            ssidref1 = op->u.getdecision.id1.ssidref;
        else if (op->u.getdecision.get_decision_by1 == DOMAINID)
        {
            struct domain *subj = find_domain_by_id(op->u.getdecision.id1.domainid);
            if (!subj)
            {
                ret = -ESRCH; /* domain not found */
                break;
            }
            if (subj->ssid == NULL)
            {
                put_domain(subj);
                ret = -ESRCH;
                break;
            }
            ssidref1 = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            put_domain(subj);
        }
        else
        {
            ret = -ESRCH;
            break;
        }
        if (op->u.getdecision.get_decision_by2 == SSIDREF)
            ssidref2 = op->u.getdecision.id2.ssidref;
        else if (op->u.getdecision.get_decision_by2 == DOMAINID)
        {
            struct domain *subj = find_domain_by_id(op->u.getdecision.id2.domainid);
            if (!subj)
            {
                ret = -ESRCH; /* domain not found */
                break;;
            }
            if (subj->ssid == NULL)
            {
                put_domain(subj);
                ret = -ESRCH;
                break;
            }
            ssidref2 = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            put_domain(subj);
        }
        else
        {
            ret = -ESRCH;
            break;
        }
        ret = acm_get_decision(ssidref1, ssidref2, op->u.getdecision.hook);

        if (ret == ACM_ACCESS_PERMITTED)
        {
            op->u.getdecision.acm_decision = ACM_ACCESS_PERMITTED;
            ret = 0;
        }
        else if  (ret == ACM_ACCESS_DENIED)
        {
            op->u.getdecision.acm_decision = ACM_ACCESS_DENIED;
            ret = 0;
        }
        else
            ret = -ESRCH;

        if (!ret)
            copy_to_guest(u_acm_op, op, 1);
    }
    break;

    default:
        ret = -ESRCH;
    }

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
