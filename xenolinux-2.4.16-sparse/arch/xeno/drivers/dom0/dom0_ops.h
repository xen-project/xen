/******************************************************************************
 * dom0_ops.h
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser, B Dragovic
 */

#define DOM0_NEWDOMAIN   0
#define DOM0_KILLDOMAIN  1
#define DOM0_GETMEMLIST  2
#define MAP_DOM_MEM      3
#define DOM0_STARTDOM    4
#define MAX_CMD          4

#define MAX_CMD_LEN     256

typedef struct dom0_newdomain_st
{
    unsigned int domain;
    unsigned int memory_kb;
    unsigned int num_vifs;  // temporary
    unsigned long pg_head;  // return parameter
} dom0_newdomain_t;

typedef struct dom0_killdomain_st
{
    unsigned int domain;
} dom0_killdomain_t;

typedef struct dom0_getmemlist_st
{
    unsigned long start_pfn;
    unsigned long num_pfns;
    void *buffer;
} dom0_getmemlist_t;

typedef struct dom_mem 
{
    unsigned int domain;
    unsigned long vaddr;
    unsigned long start_pfn;
    int tot_pages;
} dom_mem_t;

typedef struct domain_launch
{
    unsigned int domain;
    unsigned long l2_pgt_addr;
    unsigned long virt_load_addr;
    unsigned long virt_shinfo_addr;
    unsigned long virt_startinfo_addr;
    unsigned long pgt_update_arr;
    unsigned long num_pgt_updates;
    unsigned int num_vifs;
    char cmd_line[MAX_CMD_LEN];
} dom_meminfo_t;

typedef struct dom0_op_st
{
    unsigned long cmd;
    union
    {
        dom0_newdomain_t newdomain;
        dom0_killdomain_t killdomain;
        dom0_getmemlist_t getmemlist;
        dom_mem_t dommem;
        dom_meminfo_t meminfo;
    }
    u;
} dom0_op_t;

