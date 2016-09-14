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
struct xentoollog_logger;

/*
 * PRODUCING AND CONSUMING GRANT REFERENCES
 * ========================================
 *
 * The xengnttab library contains two distinct interfaces, each with
 * their own distinct handle type and entry points. The represent the
 * two sides of the grant table interface, producer (gntshr) and
 * consumer (gnttab).
 *
 * The xengnttab_* interfaces take a xengnttab_handle and provide
 * mechanisms for consuming (i.e. mapping or copying to/from) grant
 * references provided by a peer.
 *
 * The xengntshr_* interfaces take a xengntshr_handle and provide a
 * mechanism to produce grantable memory and grant references to that
 * memory, which can be handed to some peer.
 *
 * UNMAP NOTIFICATION
 * ==================
 *
 * The xengnt{tab,shr}_*_notify interfaces implement a cooperative
 * interface which is intended to allow the underlying kernel
 * interfaces to attempt to notify the peer to perform graceful
 * teardown upon failure (i.e. crash or exit) of the process on their
 * end.
 *
 * These interfaces operate on a single page only and are intended for
 * use on the main shared-ring page of a protocol. It is assumed that
 * on teardown both ends would automatically teardown all grants
 * associated with the protocol in addition to the shared ring itself.
 *
 * Each end is able to optionally nominate a byte offset within the
 * shared page or an event channel or both. On exit of the process the
 * underlying kernel driver will zero the byte at the given offset and
 * signal the event channel.
 *
 * The event channel can be the same event channel used for regular
 * ring progress notifications, or may be a dedicated event channel.
 *
 * Both ends may share the same notification byte offset within the
 * shared page, or may have dedicated "client" and "server" status
 * bytes.
 *
 * Since the byte is cleared on shutdown the protocol must use 0 as
 * the "closed/dead" status, but is permitted to use any other non-0
 * values to indicate various other "live" states (waiting for
 * connection, connected, etc).
 *
 * Both ends are permitted to modify (including clear) their
 * respective status bytes and to signal the event channel themselves
 * from userspace.
 *
 * Depending on the mechanisms which have been registered an
 * the peer may receive a shutdown notification as:
 *
 *   - An event channel notification on a dedicated event channel
 *   - Observation of the other ends's status byte being cleared
 *     (whether in response to an explicit notification or in the
 *     course of normal operation).
 *
 * The mechanism should be defined as part of the specific ring
 * protocol.
 *
 * Upon receiving notification of the peer is expected to teardown any
 * resources (and in particular any grant mappings) in a timely
 * manner.
 *
 * NOTE: this protocol is intended to allow for better error behaviour
 * and recovery between two cooperating peers. It does not cover the
 * case of a malicious peer who may continue to hold resources open.
 */

/*
 * Grant Table Interface (making use of grants from other domains)
 */

typedef struct xengntdev_handle xengnttab_handle;

/*
 * Returns a handle onto the grant table driver.  Logs errors.
 *
 * Note: After fork(2) a child process must not use any opened gnttab
 * handle inherited from their parent, nor access any grant mapped
 * areas associated with that handle.
 *
 * The child must open a new handle if they want to interact with
 * gnttab.
 *
 * Calling exec(2) in a child will safely (and reliably) reclaim any
 * resources which were allocated via a xengnttab_handle in the parent.
 *
 * A child which does not call exec(2) may safely call
 * xengnttab_close() on a xengnttab_handle inherited from their
 * parent. This will attempt to reclaim any resources associated with
 * that handle. Note that in some implementations this reclamation may
 * not be completely effective, in this case any affected resources
 * remain allocated.
 *
 * Calling xengnttab_close() is the only safe operation on a
 * xengnttab_handle which has been inherited. xengnttab_unmap() must
 * not be called under such circumstances.
 */
xengnttab_handle *xengnttab_open(struct xentoollog_logger *logger,
                                 unsigned open_flags);

/*
 * Close a handle previously allocated with xengnttab_open(),
 * including unmaping any current grant maps.  Never logs errors.
 *
 * Under normal circumstances (i.e. not in the child after a fork)
 * xengnttab_unmap() should be used on all mappings allocated through
 * a xengnttab_handle prior to closing the handle in order to free up
 * resources associated with those mappings.
 *
 * This is the only function which may be safely called on a
 * xengnttab_handle in a child after a fork.
 */
int xengnttab_close(xengnttab_handle *xgt);

/**
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
 * On failure (including partial failure) sets errno and returns
 * NULL. On partial failure no mappings are established (any partial
 * work is undone).
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
 * This call is equivalent to calling @xengnttab_map_grant_refs with a
 * @domids array with every entry set to @domid.
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
 * On failure sets errno and returns NULL.
 *
 * If notify_offset or notify_port are requested and cannot be set up
 * an error will be returned and no mapping will be made.
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

/**
 * Unmaps the @count pages starting at @start_address, which were
 * mapped by a call to xengnttab_map_grant_ref,
 * xengnttab_map_grant_refs or xengnttab_map_grant_ref_notify. Never
 * logs.
 *
 * If the mapping was made using xengnttab_map_grant_ref_notify() with
 * either notify_offset or notify_port then the peer will be notified.
 */
int xengnttab_unmap(xengnttab_handle *xgt, void *start_address, uint32_t count);

/**
 * Sets the maximum number of grants that may be mapped by the given
 * instance to @count.  Never logs.
 *
 * N.B. This function must be called after opening the handle, and before any
 *      other functions are invoked on it.
 *
 * N.B. When variable-length grants are mapped, fragmentation may be observed,
 *      and it may not be possible to satisfy requests up to the maximum number
 *      of grants.
 */
int xengnttab_set_max_grants(xengnttab_handle *xgt,
                             uint32_t nr_grants);

struct xengnttab_grant_copy_segment {
    union xengnttab_copy_ptr {
        void *virt;
        struct {
            uint32_t ref;
            uint16_t offset;
            uint16_t domid;
        } foreign;
    } source, dest;
    uint16_t len;
    uint16_t flags;
    int16_t status;
};

typedef struct xengnttab_grant_copy_segment xengnttab_grant_copy_segment_t;

/**
 * Copy memory from or to grant references. The information of each operations
 * are contained in 'xengnttab_grant_copy_segment_t'. The @flag value indicate
 * the direction of an operation (GNTCOPY_source_gref\GNTCOPY_dest_gref).
 *
 * For each segment, @virt may cross a page boundary but @offset + @len
 * must not exceed XEN_PAGE_SIZE.
 */
int xengnttab_grant_copy(xengnttab_handle *xgt,
                         uint32_t count,
                         xengnttab_grant_copy_segment_t *segs);

/*
 * Grant Sharing Interface (allocating and granting pages to others)
 */

typedef struct xengntdev_handle xengntshr_handle;

/*
 * Returns a handle onto the grant sharing driver.  Logs errors.
 *
 * Note: After fork(2) a child process must not use any opened gntshr
 * handle inherited from their parent, nor access any grant mapped
 * areas associated with that handle.
 *
 * The child must open a new handle if they want to interact with
 * gntshr.
 *
 * Calling exec(2) in a child will safely (and reliably) reclaim any
 * resources which were allocated via a xengntshr_handle in the
 * parent.
 *
 * A child which does not call exec(2) may safely call
 * xengntshr_close() on a xengntshr_handle inherited from their
 * parent. This will attempt to reclaim any resources associated with
 * that handle. Note that in some implementations this reclamation may
 * not be completely effective, in this case any affected resources
 * remain allocated.
 *
 * Calling xengntshr_close() is the only safe operation on a
 * xengntshr_handle which has been inherited.
 */
xengntshr_handle *xengntshr_open(struct xentoollog_logger *logger,
                                 unsigned open_flags);

/*
 * Close a handle previously allocated with xengntshr_open().
 * Never logs errors.
 *
 * Under normal circumstances (i.e. not in the child after a fork)
 * xengntshr_unmap() should be used on all mappings allocated through
 * a xengnttab_handle prior to closing the handle in order to free up
 * resources associated with those mappings.
 *
 * xengntshr_close() is the only function which may be safely called
 * on a xengntshr_handle in a child after a fork. xengntshr_unshare()
 * must not be called under such circumstances.
 */
int xengntshr_close(xengntshr_handle *xgs);

/**
 * Allocates and shares pages with another domain.
 *
 * On failure sets errno and returns NULL. No allocations will be made.
 *
 * This library only provides functionality for sharing memory
 * allocated via this call, memory from elsewhere (malloc, mmap etc)
 * cannot be shared here.
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

/**
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

/**
 * Unmaps the @count pages starting at @start_address, which were
 * mapped by a call to xengntshr_share_*. Never logs.
 *
 * If the mapping was made using xengntshr_share_page_notify() with
 * either notify_offset or notify_port then the peer will be notified.
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
