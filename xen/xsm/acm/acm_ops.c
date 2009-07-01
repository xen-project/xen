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
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/xsm/acm.h>
#include <public/xsm/acm_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/guest_access.h>
#include <xsm/acm/acm_hooks.h>

#ifndef ACM_SECURITY

long do_acm_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    return -ENOSYS;
}

#else

int acm_authorize_acm_ops(struct domain *d)
{
    /* currently, policy management functions are restricted to privileged domains */
    return (IS_PRIV(d) ? 0 : -EPERM);
}


long do_acm_op(XEN_GUEST_HANDLE(xen_acmctl_t) u_acmctl)
{
    long rc = -EFAULT;
    struct xen_acmctl curop, *op = &curop;

    if (acm_authorize_acm_ops(current->domain))
        return -EPERM;

    if ( copy_from_guest(op, u_acmctl, 1) )
        return -EFAULT;

    if (op->interface_version != ACM_INTERFACE_VERSION)
        return -EACCES;

    switch ( op->cmd )
    {

    case ACMOP_setpolicy: {
        rc = acm_set_policy(op->u.setpolicy.pushcache,
                            op->u.setpolicy.pushcache_size);
        break;
    }

    case ACMOP_getpolicy: {
        rc = acm_get_policy(op->u.getpolicy.pullcache,
                            op->u.getpolicy.pullcache_size);
        break;
    }

    case ACMOP_dumpstats: {
        rc = acm_dump_statistics(op->u.dumpstats.pullcache,
                                 op->u.dumpstats.pullcache_size);
        break;
    }

    case ACMOP_getssid: {
        ssidref_t ssidref;

        if (op->u.getssid.get_ssid_by == ACM_GETBY_ssidref)
            ssidref = op->u.getssid.id.ssidref;
        else if (op->u.getssid.get_ssid_by == ACM_GETBY_domainid)
        {
            struct domain *subj = rcu_lock_domain_by_id(op->u.getssid.id.domainid);
            if (!subj)
            {
                rc = -ESRCH; /* domain not found */
                break;
            }
            if (subj->ssid == NULL)
            {
                rcu_unlock_domain(subj);
                rc = -ESRCH;
                break;
            }
            ssidref = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            rcu_unlock_domain(subj);
        }
        else
        {
            rc = -ESRCH;
            break;
        }
        rc = acm_get_ssid(ssidref, op->u.getssid.ssidbuf,
                          op->u.getssid.ssidbuf_size);
        break;
    }

    case ACMOP_getdecision: {
        ssidref_t ssidref1, ssidref2;

        if (op->u.getdecision.get_decision_by1 == ACM_GETBY_ssidref)
            ssidref1 = op->u.getdecision.id1.ssidref;
        else if (op->u.getdecision.get_decision_by1 == ACM_GETBY_domainid)
        {
            struct domain *subj = rcu_lock_domain_by_id(op->u.getdecision.id1.domainid);
            if (!subj)
            {
                rc = -ESRCH; /* domain not found */
                break;
            }
            if (subj->ssid == NULL)
            {
                rcu_unlock_domain(subj);
                rc = -ESRCH;
                break;
            }
            ssidref1 = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            rcu_unlock_domain(subj);
        }
        else
        {
            rc = -ESRCH;
            break;
        }
        if (op->u.getdecision.get_decision_by2 == ACM_GETBY_ssidref)
            ssidref2 = op->u.getdecision.id2.ssidref;
        else if (op->u.getdecision.get_decision_by2 == ACM_GETBY_domainid)
        {
            struct domain *subj = rcu_lock_domain_by_id(op->u.getdecision.id2.domainid);
            if (!subj)
            {
                rc = -ESRCH; /* domain not found */
                break;
            }
            if (subj->ssid == NULL)
            {
                rcu_unlock_domain(subj);
                rc = -ESRCH;
                break;
            }
            ssidref2 = ((struct acm_ssid_domain *)(subj->ssid))->ssidref;
            rcu_unlock_domain(subj);
        }
        else
        {
            rc = -ESRCH;
            break;
        }
        rc = acm_get_decision(ssidref1, ssidref2, op->u.getdecision.hook);

        if (rc == ACM_ACCESS_PERMITTED)
        {
            op->u.getdecision.acm_decision = ACM_ACCESS_PERMITTED;
            rc = 0;
        }
        else if  (rc == ACM_ACCESS_DENIED)
        {
            op->u.getdecision.acm_decision = ACM_ACCESS_DENIED;
            rc = 0;
        }
        else
            rc = -ESRCH;

        if ( (rc == 0) && (copy_to_guest(u_acmctl, op, 1) != 0) )
            rc = -EFAULT;
        break;
    }

    case ACMOP_chgpolicy: {
        rc = acm_change_policy(&op->u.change_policy);
        break;
    }

    case ACMOP_relabeldoms: {
        rc = acm_relabel_domains(&op->u.relabel_doms);
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
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
