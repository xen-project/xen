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
};
typedef struct xc_osdep_info xc_osdep_info_t;

/* All backends, including the builtin backend, must supply this structure. */
extern xc_osdep_info_t xc_osdep_info;

/* Stub for not yet converted OSes */
void *xc_map_foreign_bulk_compat(xc_interface *xch, xc_osdep_handle h,
                                 uint32_t dom, int prot,
                                 const xen_pfn_t *arr, int *err, unsigned int num);

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
