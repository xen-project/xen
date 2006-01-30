/******************************************************************************
 * version.h
 * 
 * Xen version, type, and compile information.
 * 
 * Copyright (c) 2005, Nguyen Anh Quynh <aquynh@gmail.com>
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_PUBLIC_VERSION_H__
#define __XEN_PUBLIC_VERSION_H__

/* NB. All ops return zero on success, except XENVER_version. */

/* arg == NULL; returns major:minor (16:16). */
#define XENVER_version      0

/* arg == xen_extraversion_t. */
#define XENVER_extraversion 1
typedef char xen_extraversion_t[16];

/* arg == xen_compile_info_t. */
#define XENVER_compile_info 2
typedef struct xen_compile_info {
    char compiler[64];
    char compile_by[16];
    char compile_domain[32];
    char compile_date[32];
} xen_compile_info_t;

#define XENVER_capabilities 3
typedef char xen_capabilities_info_t[1024];

#define XENVER_changeset 4
typedef char xen_changeset_info_t[64];

#define XENVER_platform_parameters 5
typedef struct xen_platform_parameters {
    unsigned long virt_start;
} xen_platform_parameters_t;

#define XENVER_get_features 6
typedef struct xen_feature_info {
    unsigned int submap_idx;    /* IN: which 32-bit submap to return */
    uint32_t     submap;        /* OUT: 32-bit submap */
} xen_feature_info_t;

#define XENFEAT_writable_page_tables       0
#define XENFEAT_writable_descriptor_tables 1

#define XENFEAT_NR_SUBMAPS 1

#endif /* __XEN_PUBLIC_VERSION_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
