/******************************************************************************
 * policy_ops.h
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
 * access checked by policy; not restricted to DOM0
 * 
 */


#ifndef __XEN_PUBLIC_POLICY_OPS_H__
#define __XEN_PUBLIC_POLICY_OPS_H__

#include "xen.h"
#include "sched_ctl.h"

/*
 * Make sure you increment the interface version whenever you modify this file!
 * This makes sure that old versions of policy tools will stop working in a
 * well-defined way (rather than crashing the machine, for instance).
 */
#define POLICY_INTERFACE_VERSION   0xAAAA0002

/************************************************************************/

#define POLICY_SETPOLICY        	4
typedef struct {
    /* IN variables. */
    u16           policy_type;
    u16		  padding1;
    /* OUT variables */
    void  	  *pushcache;
    u16           pushcache_size;
} PACKED policy_setpolicy_t;          


#define POLICY_GETPOLICY        	5
typedef struct {
    /* IN variables. */
    u16           policy_type;
    u16		  padding1;
    /* OUT variables */
    void  	  *pullcache;
    u16           pullcache_size;
} PACKED policy_getpolicy_t;       

#define POLICY_DUMPSTATS        	6
typedef struct {
    void  	  *pullcache;
    u16           pullcache_size;
} PACKED policy_dumpstats_t;            
 

typedef struct {
    u32 cmd;                          /* 0 */
    u32 interface_version;            /* 4 */ /* POLICY_INTERFACE_VERSION */
	union {			      /* 8 */
        u32	                 dummy[14];  /* 72bytes */
	policy_setpolicy_t       setpolicy;
        policy_getpolicy_t       getpolicy;
	policy_dumpstats_t	 dumpstats;
    } PACKED u;
} PACKED policy_op_t;            /* 80 bytes */

#endif /* __XEN_PUBLIC_POLICY_OPS_H__ */
