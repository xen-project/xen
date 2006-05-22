/*
 * acm_ops.h: Xen access control module hypervisor commands
 *
 * Reiner Sailer <sailer@watson.ibm.com>
 * Copyright (c) 2005,2006 International Business Machines Corporation.
 */

#ifndef __XEN_PUBLIC_ACM_OPS_H__
#define __XEN_PUBLIC_ACM_OPS_H__

#include "xen.h"
#include "sched_ctl.h"
#include "acm.h"

/*
 * Make sure you increment the interface version whenever you modify this file!
 * This makes sure that old versions of acm tools will stop working in a
 * well-defined way (rather than crashing the machine, for instance).
 */
#define ACM_INTERFACE_VERSION   0xAAAA0007

/************************************************************************/

/*
 * Prototype for this hypercall is:
 *  int acm_op(int cmd, void *args)
 * @cmd  == ACMOP_??? (access control module operation).
 * @args == Operation-specific extra arguments (NULL if none).
 */


#define ACMOP_setpolicy         1
struct acm_setpolicy {
    /* IN */
    uint32_t interface_version;
    void *pushcache;
    uint32_t pushcache_size;
};


#define ACMOP_getpolicy         2
struct acm_getpolicy {
    /* IN */
    uint32_t interface_version;
    void *pullcache;
    uint32_t pullcache_size;
};


#define ACMOP_dumpstats         3
struct acm_dumpstats {
    /* IN */
    uint32_t interface_version;
    void *pullcache;
    uint32_t pullcache_size;
};


#define ACMOP_getssid           4
enum get_type {UNSET=0, SSIDREF, DOMAINID};
struct acm_getssid {
    /* IN */
    uint32_t interface_version;
    enum get_type get_ssid_by;
    union {
        domaintype_t domainid;
        ssidref_t    ssidref;
    } id;
    void *ssidbuf;
    uint32_t ssidbuf_size;
};

#define ACMOP_getdecision      5
struct acm_getdecision {
    /* IN */
    uint32_t interface_version;
    enum get_type get_decision_by1;
    enum get_type get_decision_by2;
    union {
        domaintype_t domainid;
        ssidref_t    ssidref;
    } id1;
    union {
        domaintype_t domainid;
        ssidref_t    ssidref;
    } id2;
    enum acm_hook_type hook;
    /* OUT */
    int acm_decision;
};

#endif /* __XEN_PUBLIC_ACM_OPS_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
