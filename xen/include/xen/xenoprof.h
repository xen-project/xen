/******************************************************************************
 * xenoprof.h
 * 
 * Xenoprof: Xenoprof enables performance profiling in Xen
 * 
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 */

#ifndef __XEN_XENOPROF_H__
#define __XEN_XENOPROF_H__

#include <public/xenoprof.h>

#define XENOPROF_DOMAIN_IGNORED    0
#define XENOPROF_DOMAIN_ACTIVE     1

#define XENOPROF_IDLE              0
#define XENOPROF_COUNTERS_RESERVED 1
#define XENOPROF_READY             2
#define XENOPROF_PROFILING         3


typedef struct xenoprof_vcpu {
    int event_size;
    xenoprof_buf_t *buffer;
} xenoprof_vcpu_t;

typedef struct xenoprof {
    char* rawbuf;
    int npages;
    int nbuf;
    int bufsize;
    int domain_type;
    int domain_ready;
    int is_primary;
    xenoprof_vcpu_t vcpu [MAX_VIRT_CPUS];
} xenoprof_t;

#endif  /* __XEN__XENOPROF_H__ */
