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
#define DOM0_INTERFACE_VERSION   0xAAAA0001


/*
 * The following is all CPU context. Note that the i387_ctxt block is filled 
 * in by FXSAVE if the CPU has feature FXSR; otherwise FSAVE is used.
 */
typedef struct full_execution_context_st
{
    execution_context_t i386_ctxt;          /* User-level CPU registers     */
    char          i387_ctxt[256];           /* User-level FPU registers     */
    trap_info_t   trap_ctxt[256];           /* Virtual IDT                  */
    unsigned int  fast_trap_idx;            /* "Fast trap" vector offset    */
    unsigned long ldt_base, ldt_ents;       /* LDT (linear address, # ents) */
    unsigned long gdt_frames[16], gdt_ents; /* GDT (machine frames, # ents) */
    unsigned long ring1_ss, ring1_esp;      /* Virtual TSS (only SS1/ESP1)  */
    unsigned long pt_base;                  /* CR3 (pagetable base)         */
    unsigned long debugreg[8];              /* DB0-DB7 (debug registers)    */
} full_execution_context_t;

#define MAX_CMD_LEN       256
#define MAX_DOMAIN_NAME    16

#define DOM0_CREATEDOMAIN      8
typedef struct dom0_createdomain_st 
{
    /* IN parameters. */
    unsigned int memory_kb; 
    char name[MAX_DOMAIN_NAME];
    /* OUT parameters. */
    unsigned int domain; 
} dom0_createdomain_t;

#define DOM0_STARTDOMAIN      10
typedef struct dom0_startdomain_st
{
    /* IN parameters. */
    unsigned int domain;
} dom0_startdomain_t;

#define DOM0_STOPDOMAIN       11
typedef struct dom0_stopdomain_st
{
    /* IN parameters. */
    unsigned int domain;
} dom0_stopdomain_t;

#define DOM0_DESTROYDOMAIN     9
typedef struct dom0_destroydomain_st
{
    /* IN variables. */
    unsigned int domain;
    int          force;
} dom0_destroydomain_t;

#define DOM0_GETMEMLIST        2
typedef struct dom0_getmemlist_st
{
    /* IN variables. */
    unsigned int  domain;
    unsigned long max_pfns;
    void         *buffer;
    /* OUT variables. */
    unsigned long num_pfns;
} dom0_getmemlist_t;

#define DOM0_BUILDDOMAIN      13
typedef struct dom0_builddomain_st
{
    /* IN variables. */
    unsigned int  domain;
    unsigned long l2_pgt_addr;
    unsigned long virt_load_addr;
    unsigned long virt_startinfo_addr;
    unsigned int num_vifs;
    char cmd_line[MAX_CMD_LEN];
    unsigned long virt_mod_addr;
    unsigned long virt_mod_len;
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
    unsigned int  domain;     /* domain id */
    unsigned long mcu_adv;    /* mcu advance: inverse of weight */
    unsigned long warp;       /* time warp */
    unsigned long warpl;      /* warp limit */
    unsigned long warpu;      /* unwarp time requirement */
} dom0_adjustdom_t;

#define DOM0_GETDOMAININFO    12
typedef struct dom0_getdomaininfo_st
{
    /* IN variables. */
    unsigned int domain;
    /* OUT variables. */
    char name[MAX_DOMAIN_NAME];
    int processor;
    int has_cpu;
    int state;
    int hyp_events;
    unsigned long mcu_advance;
    unsigned int tot_pages;
    long long cpu_time;
    full_execution_context_t ctxt;
} dom0_getdomaininfo_t;

#define DOM0_GETPAGEFRAMEINFO 18
typedef struct dom0_getpageframeinfo_st
{
    /* IN variables. */
    unsigned long pfn;          /* Machine page frame number to query.       */
    /* OUT variables. */
    unsigned int domain;        /* To which domain does the frame belong?    */
    enum { NONE, L1TAB, L2TAB } type; /* Is the page PINNED to a type?       */
} dom0_getpageframeinfo_t;

#define DOM0_IOPL             14
typedef struct dom0_iopl_st
{
    unsigned int domain;
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
    int domain, in1, in2;
    /* OUT variables. */
    int status, out1, out2;
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
    } u;
} dom0_op_t;

#endif
