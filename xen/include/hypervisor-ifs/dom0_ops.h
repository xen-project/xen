/******************************************************************************
 * dom0_ops.h
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002-2003, K A Fraser, B Dragovic
 */


#ifndef __DOM0_OPS_H__
#define __DOM0_OPS_H__

#include "hypervisor-if.h"

/*
 * Make sure you increment the interface version whenever you modify this file!
 * This makes sure that old versions of dom0 tools will stop working in a
 * well-defined way (rather than crashing the machine, for instance).
 */
#define DOM0_INTERFACE_VERSION   0xAAAA0008

#define MAX_CMD_LEN       256
#define MAX_DOMAIN_NAME    16

#define DOM0_CREATEDOMAIN      8
typedef struct dom0_createdomain_st 
{
    /* IN parameters. */
    unsigned int memory_kb; 
    char         name[MAX_DOMAIN_NAME];
    /* OUT parameters. */
    domid_t      domain; 
} dom0_createdomain_t;

#define DOM0_STARTDOMAIN      10
typedef struct dom0_startdomain_st
{
    /* IN parameters. */
    domid_t domain;
} dom0_startdomain_t;

#define DOM0_STOPDOMAIN       11
typedef struct dom0_stopdomain_st
{
    /* IN parameters. */
    domid_t domain;
} dom0_stopdomain_t;

#define DOM0_DESTROYDOMAIN     9
typedef struct dom0_destroydomain_st
{
    /* IN variables. */
    domid_t      domain;
    int          force;
} dom0_destroydomain_t;

#define DOM0_GETMEMLIST        2
typedef struct dom0_getmemlist_st
{
    /* IN variables. */
    domid_t       domain;
    unsigned long max_pfns;
    void         *buffer;
    /* OUT variables. */
    unsigned long num_pfns;
} dom0_getmemlist_t;

#define DOM0_BUILDDOMAIN      13
typedef struct dom0_builddomain_st
{
    /* IN variables. */
    domid_t                  domain;
    unsigned int             num_vifs;
    full_execution_context_t ctxt;
} dom0_builddomain_t;

#define DOM0_BVTCTL            6
typedef struct dom0_bvtctl_st
{
    /* IN variables. */
    unsigned long ctx_allow;  /* context switch allowance */
} dom0_bvtctl_t;

#define DOM0_ADJUSTDOM         7
typedef struct dom0_adjustdom_st
{
    /* IN variables. */
    domid_t       domain;     /* domain id */
    unsigned long mcu_adv;    /* mcu advance: inverse of weight */
    unsigned long warp;       /* time warp */
    unsigned long warpl;      /* warp limit */
    unsigned long warpu;      /* unwarp time requirement */
} dom0_adjustdom_t;

#define DOM0_GETDOMAININFO    12
typedef struct dom0_getdomaininfo_st
{
    /* IN variables. */
    domid_t domain;
    /* OUT variables. */
    char name[MAX_DOMAIN_NAME];
    int processor;
    int has_cpu;
#define DOMSTATE_ACTIVE              0
#define DOMSTATE_STOPPED             1
    int state;
    int hyp_events;
    unsigned long mcu_advance;
    unsigned int tot_pages;
    long long cpu_time;
    unsigned long shared_info_frame;  /* MFN of shared_info struct */
    full_execution_context_t ctxt;
} dom0_getdomaininfo_t;

#define DOM0_GETPAGEFRAMEINFO 18
typedef struct dom0_getpageframeinfo_st
{
    /* IN variables. */
    unsigned long pfn;          /* Machine page frame number to query.       */
    domid_t domain;        /* To which domain does the frame belong?    */
    /* OUT variables. */
    enum { NONE, L1TAB, L2TAB } type; /* Is the page PINNED to a type?       */
} dom0_getpageframeinfo_t;

#define DOM0_IOPL             14
typedef struct dom0_iopl_st
{
    domid_t domain;
    unsigned int iopl;
} dom0_iopl_t;

#define DOM0_MSR              15
typedef struct dom0_msr_st
{
    /* IN variables. */
    int write, cpu_mask, msr;
    unsigned int in1, in2;
    /* OUT variables. */
    unsigned int out1, out2;
} dom0_msr_t;

#define DOM0_DEBUG            16
typedef struct dom0_debug_st
{
    /* IN variables. */
    char opcode;
    domid_t domain;
    int in1, in2, in3, in4;
    /* OUT variables. */
    unsigned int status;
    int out1, out2;
} dom0_debug_t;

/*
 * Set clock such that it would read <secs,usecs> after 00:00:00 UTC,
 * 1 January, 1970 if the current system time was <system_time>.
 */
#define DOM0_SETTIME          17
typedef struct dom0_settime_st
{
    /* IN variables. */
    unsigned long secs, usecs;
    u64 system_time;
} dom0_settime_t;

/*
 * Read console content from Xen buffer ring.
 */

#define DOM0_READCONSOLE      19
typedef struct dom0_readconsole_st
{
    unsigned long str;
    unsigned int count;
    unsigned int cmd;
} dom0_readconsole_t;

/* 
 * Pin Domain to a particular CPU  (use -1 to unpin)
 */
#define DOM0_PINCPUDOMAIN     20
typedef struct dom0_pincpudomain_st
{
    /* IN variables. */
    domid_t      domain;
    int          cpu;  /* -1 implies unpin */
} dom0_pincpudomain_t;

/* Get trace buffers physical base pointer */
#define DOM0_GETTBUFS         21
typedef struct dom0_gettbufs_st
{
  /* OUT variables */
  unsigned long phys_addr; /* location of the trace buffers       */
  unsigned long size;      /* size of each trace buffer, in bytes */
} dom0_gettbufs_t;

/*
 * Get physical information about the host machine
 */
#define DOM0_PHYSINFO         22
typedef struct dom0_physinfo_st
{
    int ht_per_core;
    int cores;
    unsigned long cpu_khz;
    unsigned long total_pages;
    unsigned long free_pages;
} dom0_physinfo_t;

/* 
 * Allow a domain access to a physical PCI device
 */
#define DOM0_PCIDEV_ACCESS    23
typedef struct dom0_pcidev_access_st
{
    /* IN variables. */
    domid_t      domain;
    int          bus; 
    int          dev;
    int          func; 
    int          enable;
} dom0_pcidev_access_t;

typedef struct dom0_op_st
{
    unsigned long cmd;
    unsigned long interface_version; /* DOM0_INTERFACE_VERSION */
    union
    {
        dom0_createdomain_t     createdomain;
        dom0_startdomain_t      startdomain;
        dom0_stopdomain_t       stopdomain;
        dom0_destroydomain_t    destroydomain;
        dom0_getmemlist_t       getmemlist;
        dom0_bvtctl_t           bvtctl;
        dom0_adjustdom_t        adjustdom;
        dom0_builddomain_t      builddomain;
        dom0_getdomaininfo_t    getdomaininfo;
        dom0_getpageframeinfo_t getpageframeinfo;
        dom0_iopl_t             iopl;
	dom0_msr_t              msr;
	dom0_debug_t            debug;
	dom0_settime_t          settime;
	dom0_readconsole_t	readconsole;
	dom0_pincpudomain_t     pincpudomain;
        dom0_gettbufs_t         gettbufs;
        dom0_physinfo_t         physinfo;
        dom0_pcidev_access_t    pcidev_access;
    } u;
} dom0_op_t;

#endif /* __DOM0_OPS_H__ */
