/******************************************************************************
 * version.h
 * 
 * Xen version, type, and compile information.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2005, Nguyen Anh Quynh <aquynh@gmail.com>
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_PUBLIC_VERSION_H__
#define __XEN_PUBLIC_VERSION_H__

#include "xen.h"

/*
 * There are two hypercalls mentioned in here. The XENVER_ are for
 * HYPERCALL_xen_version (17), while VERSION_ are for the
 * HYPERCALL_version_op (41).
 *
 * The subops are very similar except that the later hypercall has a
 * sane interface.
 *
 * NB. All XENVER_ ops return zero on success, except XENVER_{version,pagesize}
 */

/* arg == NULL; returns major:minor (16:16). */
#define XENVER_version      0

/* arg == xen_extraversion_t. */
#define XENVER_extraversion 1
typedef char xen_extraversion_t[16];
#define XEN_EXTRAVERSION_LEN (sizeof(xen_extraversion_t))

/* arg == xen_compile_info_t. */
#define XENVER_compile_info 2
struct xen_compile_info {
    char compiler[64];
    char compile_by[16];
    char compile_domain[32];
    char compile_date[32];
};
typedef struct xen_compile_info xen_compile_info_t;

#define XENVER_capabilities 3
typedef char xen_capabilities_info_t[1024];
#define XEN_CAPABILITIES_INFO_LEN (sizeof(xen_capabilities_info_t))

#define XENVER_changeset 4
typedef char xen_changeset_info_t[64];
#define XEN_CHANGESET_INFO_LEN (sizeof(xen_changeset_info_t))

#define XENVER_platform_parameters 5
struct xen_platform_parameters {
    xen_ulong_t virt_start;
};
typedef struct xen_platform_parameters xen_platform_parameters_t;

#define XENVER_get_features 6
struct xen_feature_info {
    unsigned int submap_idx;    /* IN: which 32-bit submap to return */
    uint32_t     submap;        /* OUT: 32-bit submap */
};
typedef struct xen_feature_info xen_feature_info_t;

/* Declares the features reported by XENVER_get_features. */
#include "features.h"

/* arg == NULL; returns host memory page size. */
#define XENVER_pagesize 7

/* arg == xen_domain_handle_t.
 *
 * The toolstack fills it out for guest consumption. It is intended to hold
 * the UUID of the guest.
 */
#define XENVER_guest_handle 8

#define XENVER_commandline 9
typedef char xen_commandline_t[1024];

/*
 * The HYPERCALL_version_op has a set of sub-ops which mirror the
 * sub-ops of HYPERCALL_xen_version. However this hypercall differs
 * radically from the former:
 *  - It returns the amount of bytes copied, or
 *  - It will return -XEN_EPERM if the sub-op is denied to the guest.
 *    (Albeit XEN_VERSION_version, XEN_VERSION_platform_parameters, and
 *    XEN_VERSION_get_features will always return an value as guest cannot
 *    survive without this information).
 *  - It will return the requested data in arg.
 *  - It requires an third argument (len) for the length of the
 *    arg. Naturally the arg has to fit the requested data otherwise
 *    -XEN_ENOBUFS is returned.
 *
 * It also offers a mechanism to probe for the amount of bytes an
 * sub-op will require. Having the arg have a NULL handle will
 * return the number of bytes requested for the operation.
 * Or a negative value if an error is encountered.
 */

typedef uint64_t xen_version_op_val_t;
DEFINE_XEN_GUEST_HANDLE(xen_version_op_val_t);

/*
 * arg == xen_version_op_val_t. Encoded as major:minor (31..16:15..0), while
 * 63..32 are zero.
 */
#define XEN_VERSION_version             0

/* arg == char[]. Contains NUL terminated utf-8 string. */
#define XEN_VERSION_extraversion        1

/* arg == char[]. Contains NUL terminated utf-8 string. */
#define XEN_VERSION_capabilities        3

/* arg == char[]. Contains NUL terminated utf-8 string. */
#define XEN_VERSION_changeset           4

/* arg == xen_version_op_val_t. */
#define XEN_VERSION_platform_parameters 5

/*
 * arg = xen_feature_info_t - shares the same structure
 * as the XENVER_get_features.
 */
#define XEN_VERSION_get_features        6

/* arg == xen_version_op_val_t. */
#define XEN_VERSION_pagesize            7

/*
 * arg == void.
 *
 * The toolstack fills it out for guest consumption. It is intended to hold
 * the UUID of the guest.
 */
#define XEN_VERSION_guest_handle        8

/* arg = char[]. Contains NUL terminated utf-8 string. */
#define XEN_VERSION_commandline         9

#endif /* __XEN_PUBLIC_VERSION_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
