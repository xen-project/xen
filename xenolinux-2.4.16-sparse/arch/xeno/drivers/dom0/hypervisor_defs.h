
/******************************************************************************
 * dom0_ops.h
 * 
 * Data structures defined in hypervisor code but needed in DOM0 as well. 
 * Contents of this file should be kept in sync with the hypervisor ones
 * unless you do not want something terrible :) to happen. 
 * 
 * Copyright (c) 2002, Keir Fraser & Boris Dragovic 
 */


/* original version: xen-2.4.16/include/xeno/mm.h */
typedef struct pfn_info {
    struct list_head list;      /* ->mapping has some page lists. */
    unsigned long next;         /* used for threading pages belonging */
    unsigned long prev;         /* to same domain */
    unsigned long flags;        /* atomic flags. */
    unsigned long tot_count;    /* Total domain usage count. */
    unsigned long type_count;   /* pagetable/dir, or domain-writeable refs. */
} frame_table_t;

extern frame_table_t * frame_table;

typedef struct proc_data {
    unsigned int domain;
    unsigned long map_size;
} dom_procdata_t;

typedef struct proc_mem_data {
    unsigned long pfn;
    int tot_pages;
} proc_memdata_t;
