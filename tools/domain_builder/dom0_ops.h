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
#define DOM0_STARTDOM    4
#define MAP_DOM_MEM      6 /* Not passed down to Xen */
#define DO_PGUPDATES     7 /* Not passed down to Xen */
#define MAX_CMD          8

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
    int          force;
} dom0_killdomain_t;

typedef struct dom0_getmemlist_st
{
    unsigned long start_pfn;
    unsigned long num_pfns;
    void *buffer;
} dom0_getmemlist_t;

/* This is entirely processed by XenoLinux */
typedef struct dom_mem 
{
    unsigned int domain;
    unsigned long vaddr;
    unsigned long start_pfn;
    int tot_pages;
} dom_mem_t;

/* This is entirely processed by XenoLinux */
typedef struct dom_pgupdate
{
    unsigned long pgt_update_arr;
    unsigned long num_pgt_updates;
} dom_pgupdate_t;

typedef struct domain_launch
{
    unsigned int domain;
    unsigned long l2_pgt_addr;
    unsigned long virt_load_addr;
    unsigned long virt_shinfo_addr;
    unsigned long virt_startinfo_addr;
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
        dom_pgupdate_t pgupdate;
        dom_meminfo_t meminfo;
    }
    u;
} dom0_op_t;

