
/******************************************************************************
 * dom0_ops.h
 * 
 * Data structures defined in hypervisor code but needed in DOM0 as well. 
 * Contents of this file should be kept in sync with the hypervisor ones
 * unless you do not want something terrible :) to happen. 
 * 
 * Copyright (c) 2002, Keir Fraser & Boris Dragovic 
 */


typedef struct proc_data {
    unsigned int domain;
    unsigned long map_size;
} dom_procdata_t;

typedef struct proc_mem_data {
    unsigned long pfn;
    int tot_pages;
} proc_memdata_t;
