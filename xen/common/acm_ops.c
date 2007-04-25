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

#ifndef COMPAT
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
#include <acm/acm_hooks.h>

typedef long ret_t;

#endif /* !COMPAT */

#ifndef ACM_SECURITY


long do_acm_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    return -ENOSYS;
}


#else


#ifndef COMPAT
int acm_authorize_acm_ops(struct domain *d)
{
    /* currently, policy management functions are restricted to privileged domains */
    if (!IS_PRIV(d))
        return -EPERM;
    return 0;
}
#endif


ret_t do_acm_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    ret_t rc = -EFAULT;

    if (acm_authorize_acm_ops(current->domain))
        return -EPERM;

    switch ( cmd )
    {

    case ACMOP_setpolicy: {
        struct acm_setpolicy setpolicy;
        if (copy_from_guest(&setpolicy, arg, 1) != 0)
            return -EFAULT;
        if (setpolicy.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        rc = acm_set_policy(setpolicy.pushcache,
                            setpolicy.pushcache_size);
        break;
    }

    case ACMOP_getpolicy: {
        struct acm_getpolicy getpolicy;
        if (copy_from_guest(&getpolicy, arg, 1) != 0)
            return -EFAULT;
        if (getpolicy.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        rc = acm_get_policy(getpolicy.pullcache,
                            getpolicy.pullcache_size);
        break;
    }

    case ACMOP_dumpstats: {
        struct acm_dumpstats dumpstats;
        if (copy_from_guest(&dumpstats, arg, 1) != 0)
            return -EFAULT;
        if (dumpstats.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        rc = acm_dump_statistics(dumpstats.pullcache,
                                 dumpstats.pullcache_size);
        break;
    }

    case ACMOP_getssid: {
        struct acm_getssid getssid;
        ssidref_t ssidref;

        if (copy_from_guest(&getssid, arg, 1) != 0)
            return -EFAULT;
        if (getssid.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        if (getssid.get_ssid_by == ACM_GETBY_ssidref)
            ssidref = getssid.id.ssidref;
        else if (getssid.get_ssid_by == ACM_GETBY_domainid)
        {
            struct domain *subj = rcu_lock_domain_by_id(getssid.id.domainid);
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
        rc = acm_get_ssid(ssidref, getssid.ssidbuf, getssid.ssidbuf_size);
        break;
    }

    case ACMOP_getdecision: {
        struct acm_getdecision getdecision;
        ssidref_t ssidref1, ssidref2;

        if (copy_from_guest(&getdecision, arg, 1) != 0)
            return -EFAULT;
        if (getdecision.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        if (getdecision.get_decision_by1 == ACM_GETBY_ssidref)
            ssidref1 = getdecision.id1.ssidref;
        else if (getdecision.get_decision_by1 == ACM_GETBY_domainid)
        {
            struct domain *subj = rcu_lock_domain_by_id(getdecision.id1.domainid);
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
        if (getdecision.get_decision_by2 == ACM_GETBY_ssidref)
            ssidref2 = getdecision.id2.ssidref;
        else if (getdecision.get_decision_by2 == ACM_GETBY_domainid)
        {
            struct domain *subj = rcu_lock_domain_by_id(getdecision.id2.domainid);
            if (!subj)
            {
                rc = -ESRCH; /* domain not found */
                break;;
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
        rc = acm_get_decision(ssidref1, ssidref2, getdecision.hook);

        if (rc == ACM_ACCESS_PERMITTED)
        {
            getdecision.acm_decision = ACM_ACCESS_PERMITTED;
            rc = 0;
        }
        else if  (rc == ACM_ACCESS_DENIED)
        {
            getdecision.acm_decision = ACM_ACCESS_DENIED;
            rc = 0;
        }
        else
            rc = -ESRCH;

        if ( (rc == 0) && (copy_to_guest(arg, &getdecision, 1) != 0) )
            rc = -EFAULT;
        break;
    }

    case ACMOP_chgpolicy: {
        struct acm_change_policy chgpolicy;

        if (copy_from_guest(&chgpolicy, arg, 1) != 0)
            return -EFAULT;
        if (chgpolicy.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        rc = acm_change_policy(&chgpolicy);

        if (rc == 0) {
            if (copy_to_guest(arg, &chgpolicy, 1) != 0) {
                rc = -EFAULT;
            }
        }
        break;
    }

    case ACMOP_relabeldoms: {
        struct acm_relabel_doms relabeldoms;

        if (copy_from_guest(&relabeldoms, arg, 1) != 0)
            return -EFAULT;
        if (relabeldoms.interface_version != ACM_INTERFACE_VERSION)
            return -EACCES;

        rc = acm_relabel_domains(&relabeldoms);

        if (rc == 0) {
            if (copy_to_guest(arg, &relabeldoms, 1) != 0) {
                rc = -EFAULT;
            }
        }
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

#endif

#if defined(CONFIG_COMPAT) && !defined(COMPAT)
#include "compat/acm_ops.c"
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
