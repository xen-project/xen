/******************************************************************************
 * dom0_ops.h
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __DOM0_OPS_H__
#define __DOM0_OPS_H__

#define DOM0_NEWDOMAIN   0
#define DOM0_KILLDOMAIN  1

typedef struct dom0_newdomain_st
{
    unsigned int memory_kb;
    unsigned int num_vifs;
} dom0_newdomain_t;

typedef struct dom0_killdomain_st
{
    unsigned int domain;
} dom0_killdomain_t;

typedef struct dom0_op_st
{
    unsigned long cmd;
    union
    {
        dom0_newdomain_t newdomain;
        dom0_killdomain_t killdomain;
    }
    u;
} dom0_op_t;

#endif
