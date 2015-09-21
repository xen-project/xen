/*
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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Split off from:
 * xenctrl.h
 *
 * A library for low-level access to the Xen control interfaces.
 *
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 */
#ifndef XENGNTTAB_H
#define XENGNTTAB_H

#include <stdint.h>

#include <xen/grant_table.h>
#include <xen/event_channel.h>

/* Callers who don't care don't need to #include <xentoollog.h> */
typedef struct xentoollog_logger xentoollog_logger;

/*
 * Grant Table Interface (making use of grants from other domains)
 */

typedef struct xengntdev_handle xengnttab_handle;

/*
 * Note:
 * After fork a child process must not use any opened xc gnttab
 * handle inherited from their parent. They must open a new handle if
 * they want to interact with xc.
 *
 * Return an fd onto the grant table driver.  Logs errors.
 */
xengnttab_handle *xengnttab_open(xentoollog_logger *logger, unsigned open_flags);

/*
 * Close a handle previously allocated with xengnttab_open().
 * Never logs errors.
 */
int xengnttab_close(xengnttab_handle *xgt);

/*
 * Memory maps a grant reference from one domain to a local address range.
 * Mappings should be unmapped with xengnttab_unmap.  Logs errors.
 *
 * @parm xgt a handle on an open grant table interface
 * @parm domid the domain to map memory from
 * @parm ref the grant reference ID to map
 * @parm prot same flag as in mmap()
 */
void *xengnttab_map_grant_ref(xengnttab_handle *xgt,
                              uint32_t domid,
                              uint32_t ref,
                              int prot);

/**
 * Memory maps one or more grant references from one or more domains to a
 * contiguous local address range. Mappings should be unmapped with
 * xengnttab_unmap.  Logs errors.
 *
 * @parm xgt a handle on an open grant table interface
 * @parm count the number of grant references to be mapped
 * @parm domids an array of @count domain IDs by which the corresponding @refs
 *              were granted
 * @parm refs an array of @count grant references to be mapped
 * @parm prot same flag as in mmap()
 */
void *xengnttab_map_grant_refs(xengnttab_handle *xgt,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot);

/**
 * Memory maps one or more grant references from one domain to a
 * contiguous local address range. Mappings should be unmapped with
 * xengnttab_unmap.  Logs errors.
 *
 * @parm xgt a handle on an open grant table interface
 * @parm count the number of grant references to be mapped
 * @parm domid the domain to map memory from
 * @parm refs an array of @count grant references to be mapped
 * @parm prot same flag as in mmap()
 */
void *xengnttab_map_domain_grant_refs(xengnttab_handle *xgt,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot);

/**
 * Memory maps a grant reference from one domain to a local address range.
 * Mappings should be unmapped with xengnttab_unmap. If notify_offset or
 * notify_port are not -1, this version will attempt to set up an unmap
 * notification at the given offset and event channel. When the page is
 * unmapped, the byte at the given offset will be zeroed and a wakeup will be
 * sent to the given event channel.  Logs errors.
 *
 * @parm xgt a handle on an open grant table interface
 * @parm domid the domain to map memory from
 * @parm ref the grant reference ID to map
 * @parm prot same flag as in mmap()
 * @parm notify_offset The byte offset in the page to use for unmap
 *                     notification; -1 for none.
 * @parm notify_port The event channel port to use for unmap notify, or -1
 */
void *xengnttab_map_grant_ref_notify(xengnttab_handle *xgt,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port);

/*
 * Unmaps the @count pages starting at @start_address, which were mapped by a
 * call to xengnttab_map_grant_ref or xengnttab_map_grant_refs. Never logs.
 */
int xengnttab_unmap(xengnttab_handle *xgt, void *start_address, uint32_t count);

/*
 * Sets the maximum number of grants that may be mapped by the given instance
 * to @count.  Never logs.
 *
 * N.B. This function must be called after opening the handle, and before any
 *      other functions are invoked on it.
 *
 * N.B. When variable-length grants are mapped, fragmentation may be observed,
 *      and it may not be possible to satisfy requests up to the maximum number
 *      of grants.
 */
int xengnttab_set_max_grants(xengnttab_handle *xgt,
                             uint32_t count);

/*
 * Grant Sharing Interface (allocating and granting pages)
 */

typedef struct xengntdev_handle xengntshr_handle;

/*
 * Return an fd onto the grant sharing driver.  Logs errors.
 *
 * Note:
 * After fork a child process must not use any opened xc gntshr
 * handle inherited from their parent. They must open a new handle if
 * they want to interact with xc.
 *
 */
xengntshr_handle *xengntshr_open(xentoollog_logger *logger,
                                 unsigned open_flags);

/*
 * Close a handle previously allocated with xengntshr_open().
 * Never logs errors.
 */
int xengntshr_close(xengntshr_handle *xgs);

/*
 * Creates and shares pages with another domain.
 *
 * @parm xgs a handle to an open grant sharing instance
 * @parm domid the domain to share memory with
 * @parm count the number of pages to share
 * @parm refs the grant references of the pages (output)
 * @parm writable true if the other domain can write to the pages
 * @return local mapping of the pages
 */
void *xengntshr_share_pages(xengntshr_handle *xgs, uint32_t domid,
                            int count, uint32_t *refs, int writable);

/*
 * Creates and shares a page with another domain, with unmap notification.
 *
 * @parm xgs a handle to an open grant sharing instance
 * @parm domid the domain to share memory with
 * @parm refs the grant reference of the pages (output)
 * @parm writable true if the other domain can write to the page
 * @parm notify_offset The byte offset in the page to use for unmap
 *                     notification; -1 for none.
 * @parm notify_port The event channel port to use for unmap notify, or -1
 * @return local mapping of the page
 */
void *xengntshr_share_page_notify(xengntshr_handle *xgs, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port);
/*
 * Unmaps the @count pages starting at @start_address, which were mapped by a
 * call to xengntshr_share_*. Never logs.
 */
int xengntshr_unshare(xengntshr_handle *xgs, void *start_address, uint32_t count);

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
