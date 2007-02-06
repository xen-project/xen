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

#include <xen/config.h>
#include <public/xenoprof.h>
#include <asm/xenoprof.h>

#define XENOPROF_DOMAIN_IGNORED    0
#define XENOPROF_DOMAIN_ACTIVE     1
#define XENOPROF_DOMAIN_PASSIVE    2

#define XENOPROF_IDLE              0
#define XENOPROF_COUNTERS_RESERVED 1
#define XENOPROF_READY             2
#define XENOPROF_PROFILING         3

#ifndef CONFIG_COMPAT
typedef struct xenoprof_buf xenoprof_buf_t;
#else
#include <compat/xenoprof.h>
typedef union {
	struct xenoprof_buf native;
	struct compat_oprof_buf compat;
} xenoprof_buf_t;
#endif

struct xenoprof_vcpu {
    int event_size;
    xenoprof_buf_t *buffer;
};

struct xenoprof {
    char *rawbuf;
    int npages;
    int nbuf;
    int bufsize;
    int domain_type;
    int domain_ready;
    int is_primary;
#ifdef CONFIG_COMPAT
    int is_compat;
#endif
    struct xenoprof_vcpu vcpu [MAX_VIRT_CPUS];
};

#ifndef CONFIG_COMPAT
#define XENOPROF_COMPAT(x) 0
#define xenoprof_buf(d, b, field) ((b)->field)
#else
#define XENOPROF_COMPAT(x) ((x)->is_compat)
#define xenoprof_buf(d, b, field) (*(!(d)->xenoprof->is_compat ? \
                                       &(b)->native.field : \
                                       &(b)->compat.field))
#endif

struct domain;
void free_xenoprof_pages(struct domain *d);

int do_xenoprof_op(int op, XEN_GUEST_HANDLE(void) arg);

extern struct domain *xenoprof_primary_profiler;

#endif  /* __XEN__XENOPROF_H__ */
