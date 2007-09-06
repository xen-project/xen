/****************************************************************
 * acm_xsm_hooks.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributors: 
 * Michael LeMay, <mdlemay@epoch.ncsc.mil>
 * George Coker, <gscoker@alpha.ncsc.mil>
 *
 * sHype hooks for XSM based on the original ACM hooks.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#include <xsm/xsm.h>
#include <xsm/acm/acm_hooks.h>
#include <public/xsm/acm.h>

static int acm_grant_mapref(
    struct domain *ld, struct domain *rd, uint32_t flags) 
{
    domid_t id = rd->domain_id;

    return acm_pre_grant_map_ref(id);
}

static int acm_evtchn_unbound(
    struct domain *d1, struct evtchn *chn1, domid_t id2) 
{
    domid_t id1 = d1->domain_id;
    
    return acm_pre_eventchannel_unbound(id1, id2);
}

static int acm_evtchn_interdomain(
    struct domain *d1, struct evtchn *chn1, 
    struct domain *d2, struct evtchn *chn2) 
{
    domid_t id2 = d2->domain_id;

    return acm_pre_eventchannel_interdomain(id2);
}

static void acm_security_domaininfo(
    struct domain *d, struct xen_domctl_getdomaininfo *info)
{
    if ( d->ssid != NULL )
        info->ssidref = ((struct acm_ssid_domain *)d->ssid)->ssidref;
    else    
        info->ssidref = ACM_DEFAULT_SSID;
}

extern long do_acm_op(XEN_GUEST_HANDLE(xsm_op_t) arg);

struct xsm_operations acm_xsm_ops = {
    .domain_create = acm_domain_create,
    .free_security_domain = acm_domain_destroy,

    .grant_mapref = acm_grant_mapref,

    .evtchn_unbound = acm_evtchn_unbound,
    .evtchn_interdomain = acm_evtchn_interdomain,

    .security_domaininfo = acm_security_domaininfo,

    .__do_xsm_op = do_acm_op,
};
