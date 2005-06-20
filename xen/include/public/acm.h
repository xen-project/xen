/****************************************************************
 * acm.h
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributors:
 * Stefan Berger <stefanb@watson.ibm.com> 
 *	added network byte order support for binary policies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype general access control module header file.
 *     here are all definitions that are shared between
 *     xen-core, guest-kernels, and applications.
 *
 * todo: move from static policy choice to compile option.
 */

#ifndef _XEN_PUBLIC_SHYPE_H
#define _XEN_PUBLIC_SHYPE_H

#include "xen.h"
#include "sched_ctl.h"

/* if ACM_DEBUG defined, all hooks should
 * print a short trace message (comment it out
 * when not in testing mode )
 */
/* #define ACM_DEBUG */

#ifdef ACM_DEBUG
#  define printkd(fmt, args...) printk(fmt,## args)
#else
#  define printkd(fmt, args...)
#endif

/* default ssid reference value if not supplied */
#define ACM_DEFAULT_SSID 	0xffffffff
#define ACM_DEFAULT_LOCAL_SSID  0xffff

/* Internal ACM ERROR types */
#define ACM_OK				 0
#define ACM_UNDEF			-1
#define ACM_INIT_SSID_ERROR		-2
#define ACM_INIT_SOID_ERROR		-3
#define ACM_ERROR		        -4

/* External ACCESS DECISIONS */
#define ACM_ACCESS_PERMITTED		0
#define ACM_ACCESS_DENIED		-111
#define ACM_NULL_POINTER_ERROR		-200

#define ACM_MAX_POLICY  3

#define ACM_NULL_POLICY	0
#define ACM_CHINESE_WALL_POLICY	1
#define ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY 2
#define ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY 3

/* policy: */
#define ACM_POLICY_NAME(X) \
	(X == ACM_NULL_POLICY) ? "NULL policy" : \
	(X == ACM_CHINESE_WALL_POLICY) ? "CHINESE WALL policy" : \
	(X == ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY) ? "SIMPLE TYPE ENFORCEMENT policy" : \
	(X == ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY) ? "CHINESE WALL AND SIMPLE TYPE ENFORCEMENT policy" : \
	"UNDEFINED policy"

#ifndef ACM_USE_SECURITY_POLICY
#define ACM_USE_SECURITY_POLICY ACM_NULL_POLICY
#endif

/* defines a ssid reference used by xen */
typedef u32 ssidref_t;

/* -------security policy relevant type definitions-------- */

/* type identifier; compares to "equal" or "not equal" */
typedef u16 domaintype_t;

/* CHINESE WALL POLICY DATA STRUCTURES
 *
 * current accumulated conflict type set:
 * When a domain is started and has a type that is in
 * a conflict set, the conflicting types are incremented in
 * the aggregate set. When a domain is destroyed, the 
 * conflicting types to its type are decremented.
 * If a domain has multiple types, this procedure works over
 * all those types.
 *
 * conflict_aggregate_set[i] holds the number of
 *   running domains that have a conflict with type i.
 *
 * running_types[i] holds the number of running domains
 *        that include type i in their ssidref-referenced type set
 *
 * conflict_sets[i][j] is "0" if type j has no conflict
 *    with type i and is "1" otherwise.
 */
/* high-16 = version, low-16 = check magic */
#define ACM_MAGIC		0x0001debc

/* each offset in bytes from start of the struct they
 *   the are part of */
/* each buffer consists of all policy information for
 * the respective policy given in the policy code
 */
struct acm_policy_buffer {
        u32 magic;
	u32 policyversion;
	u32 len;
	u16 primary_policy_code;
	u16 primary_buffer_offset;
	u16 secondary_policy_code;
	u16 secondary_buffer_offset;
};

struct acm_chwall_policy_buffer {
	u16 policy_code;
	u16 chwall_max_types;
	u16 chwall_max_ssidrefs;
	u16 chwall_max_conflictsets;
	u16 chwall_ssid_offset;
	u16 chwall_conflict_sets_offset;
	u16 chwall_running_types_offset;
	u16 chwall_conflict_aggregate_offset;
};

struct acm_ste_policy_buffer {
	u16 policy_code;
	u16 ste_max_types;
	u16 ste_max_ssidrefs;
	u16 ste_ssid_offset;
};

struct acm_stats_buffer {
        u32 magic;
	u32 policyversion;
	u32 len;
	u16 primary_policy_code;
	u16 primary_stats_offset;
	u16 secondary_policy_code;
	u16 secondary_stats_offset;
};

struct acm_ste_stats_buffer {
	u32 ec_eval_count;
	u32 gt_eval_count;
	u32 ec_denied_count;
	u32 gt_denied_count; 
	u32 ec_cachehit_count;
	u32 gt_cachehit_count;
};


#endif
