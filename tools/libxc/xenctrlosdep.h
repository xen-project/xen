/******************************************************************************
 *
 * Interface to OS specific low-level operations
 *
 * Copyright (c) 2010, Citrix Systems Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * This interface defines the interactions between the Xen control
 * libraries and the OS facilities used to communicate with the
 * hypervisor.
 *
 * It is possible to override the default (native) implementation by
 * setting the XENCTRL_OSDEP environment variable to point to a
 * plugin library. Userspace can use this facility to intercept
 * hypervisor operations. This can be used e.g. to implement a
 * userspace simulator for Xen hypercalls.
 *
 * The plugin must contain a data structure:
 *  xc_osdep_info_t xc_osdep_info;
 *
 * xc_osdep_init:
 *   Must return a suitable struct xc_osdep_ops pointer or NULL on failure.
 */

#ifndef XC_OSDEP_H
#define XC_OSDEP_H

/* Tell the Xen public headers we are a user-space tools build. */
#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__ 1
#endif

#include <sys/mman.h>
#include <sys/types.h>

#include <xen/sys/privcmd.h>

enum xc_osdep_type {
    XC_OSDEP_PRIVCMD,
    XC_OSDEP_EVTCHN,
    XC_OSDEP_GNTTAB,
    XC_OSDEP_GNTSHR,
};

/* Opaque handle internal to the backend */
typedef unsigned long xc_osdep_handle;

#define XC_OSDEP_OPEN_ERROR ((xc_osdep_handle)-1)

struct xc_osdep_ops
{
    /* Opens an interface.
     *
     * Must return an opaque handle on success or
     * XC_OSDEP_OPEN_ERROR on failure
     */
    xc_osdep_handle (*open)(xc_interface *xch);

    int (*close)(xc_interface *xch, xc_osdep_handle h);

    union {
        struct {
            void *(*alloc_hypercall_buffer)(xc_interface *xch, xc_osdep_handle h, int npages);
            void (*free_hypercall_buffer)(xc_interface *xch, xc_osdep_handle h, void *ptr, int npages);

            int (*hypercall)(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall);

            void *(*map_foreign_batch)(xc_interface *xch, xc_osdep_handle h, uint32_t dom, int prot,
                                       xen_pfn_t *arr, int num);
            void *(*map_foreign_bulk)(xc_interface *xch, xc_osdep_handle h, uint32_t dom, int prot,
                                      const xen_pfn_t *arr, int *err, unsigned int num);
            void *(*map_foreign_range)(xc_interface *xch, xc_osdep_handle h, uint32_t dom, int size, int prot,
                                       unsigned long mfn);
            void *(*map_foreign_ranges)(xc_interface *xch, xc_osdep_handle h, uint32_t dom, size_t size, int prot,
                                        size_t chunksize, privcmd_mmap_entry_t entries[],
                                        int nentries);
        } privcmd;
        struct {
            int (*fd)(xc_evtchn *xce, xc_osdep_handle h);

            int (*notify)(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port);

            evtchn_port_or_error_t (*bind_unbound_port)(xc_evtchn *xce, xc_osdep_handle h, int domid);
            evtchn_port_or_error_t (*bind_interdomain)(xc_evtchn *xce, xc_osdep_handle h, int domid,
                                                       evtchn_port_t remote_port);
            evtchn_port_or_error_t (*bind_virq)(xc_evtchn *xce, xc_osdep_handle h, unsigned int virq);

            int (*unbind)(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port);

            evtchn_port_or_error_t (*pending)(xc_evtchn *xce, xc_osdep_handle h);
            int (*unmask)(xc_evtchn *xce, xc_osdep_handle h, evtchn_port_t port);
        } evtchn;
        struct {
#define XC_GRANT_MAP_SINGLE_DOMAIN 0x1
            void *(*grant_map)(xc_gnttab *xcg, xc_osdep_handle h,
                               uint32_t count, int flags, int prot,
                               uint32_t *domids, uint32_t *refs,
                               uint32_t notify_offset,
                               evtchn_port_t notify_port);
            int (*munmap)(xc_gnttab *xcg, xc_osdep_handle h,
                          void *start_address,
                          uint32_t count);
            int (*set_max_grants)(xc_gnttab *xcg, xc_osdep_handle h, uint32_t count);
        } gnttab;
        struct {
            void *(*share_pages)(xc_gntshr *xcg, xc_osdep_handle h,
                                 uint32_t domid, int count,
                                 uint32_t *refs, int writable,
                                 uint32_t notify_offset,
                                 evtchn_port_t notify_port);
            int (*munmap)(xc_gntshr *xcg, xc_osdep_handle h,
                          void *start_address, uint32_t count);
        } gntshr;
    } u;
};
typedef struct xc_osdep_ops xc_osdep_ops;

typedef xc_osdep_ops *(*xc_osdep_init_fn)(xc_interface *xch, enum xc_osdep_type);

struct xc_osdep_info
{
    /* Describes this backend. */
    const char *name;

    /* Returns ops function. */
    xc_osdep_init_fn init;

    /* True if this interface backs onto a fake Xen. */
    int fake;

    /* For internal use by loader. */
    void *dl_handle;
};
typedef struct xc_osdep_info xc_osdep_info_t;

/* All backends, including the builtin backend, must supply this structure. */
extern xc_osdep_info_t xc_osdep_info;

/* Stub for not yet converted OSes */
void *xc_map_foreign_bulk_compat(xc_interface *xch, xc_osdep_handle h,
                                 uint32_t dom, int prot,
                                 const xen_pfn_t *arr, int *err, unsigned int num);

/* Report errors through xc_interface */
void xc_osdep_log(xc_interface *xch, xentoollog_level level, int code, const char *fmt, ...);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
