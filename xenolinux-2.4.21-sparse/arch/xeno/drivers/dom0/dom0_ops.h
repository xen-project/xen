/******************************************************************************
 * dom0_ops.h
 * 
 * Process command requests from domain-0 guest OS.
 * This file includes the Xen part of the interface, plus the extra stuff
 * that is dealt with by Xenolinux without being handed down to Xen.
 * 
 * Copyright (c) 2002-2003, K A Fraser, B Dragovic
 */

#ifndef __DOM0_DOM0_OPS_H__
#define __DOM0_DOM0_OPS_H__

/* External users of this header file will include Xen's version separately. */
#ifdef __KERNEL__
#define NO_DOM0_OP_T
#include <asm/hypervisor-ifs/dom0_ops.h>
#endif

/* Extra commands dealt with by Xenolinux. */
#define MAP_DOM_MEM        14
#define DO_PGUPDATES       15
#define MAX_CMD            16

typedef struct dom_mem 
{
    unsigned int domain;
    unsigned long vaddr;
    unsigned long start_pfn;
    int tot_pages;
} dom_mem_t;

typedef struct dom_pgupdate
{
    unsigned long pgt_update_arr;
    unsigned long num_pgt_updates;
} dom_pgupdate_t;

typedef struct dom0_op_st
{
    unsigned long cmd;
    union
    {
        dom0_newdomain_t newdomain;
        dom0_killdomain_t killdomain;
        dom0_getmemlist_t getmemlist;
        dom0_bvtctl_t bvtctl;
        dom0_adjustdom_t adjustdom;
        dom_mem_t dommem;
        dom_pgupdate_t pgupdate;
        dom_meminfo_t meminfo;
        dom0_getdominfo_t getdominfo;
   }
    u;
} dom0_op_t;

#endif /* __DOM0_DOM0_OPS_H__ */
