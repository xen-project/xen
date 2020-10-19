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
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef XENEVTCHN_H
#define XENEVTCHN_H

#include <stdint.h>

#include <xen/event_channel.h>

/* A port identifier is guaranteed to fit in 31 bits. */
typedef int xenevtchn_port_or_error_t;

typedef struct xenevtchn_handle xenevtchn_handle;

/* Callers who don't care don't need to #include <xentoollog.h> */
struct xentoollog_logger;

/*
 * EVENT CHANNEL FUNCTIONS
 *
 * None of these do any logging.
 */

/*
 * Return a handle to the event channel driver, or NULL on failure, in
 * which case errno will be set appropriately.
 *
 * Note: After fork(2) a child process must not use any opened evtchn
 * handle inherited from their parent, nor access any grant mapped
 * areas associated with that handle.
 *
 * The child must open a new handle if they want to interact with
 * evtchn.
 *
 * Calling exec(2) in a child will safely (and reliably) reclaim any
 * allocated resources via a xenevtchn_handle in the parent.
 *
 * A child which does not call exec(2) may safely call
 * xenevtchn_close() on a xenevtchn_handle inherited from their
 * parent. This will attempt to reclaim any resources associated with
 * that handle. Note that in some implementations this reclamation may
 * not be completely effective, in this case any affected resources
 * remain allocated.
 *
 * Calling xenevtchn_close() is the only safe operation on a
 * xenevtchn_handle which has been inherited.
 */
/* Currently no flags are defined */
xenevtchn_handle *xenevtchn_open(struct xentoollog_logger *logger,
                                 unsigned open_flags);

/*
 * Close a handle previously allocated with xenevtchn_open().
 */
int xenevtchn_close(xenevtchn_handle *xce);

/*
 * Return an fd that can be select()ed on.
 *
 * Note that due to bugs, setting this fd to non blocking may not
 * work: you would hope that it would result in xenevtchn_pending
 * failing with EWOULDBLOCK if there are no events signaled, but in
 * fact it may block.  (Bug is present in at least Linux 3.12, and
 * perhaps on other platforms or later version.)
 *
 * To be safe, you must use poll() or select() before each call to
 * xenevtchn_pending.  If you have multiple threads (or processes)
 * sharing a single xce handle this will not work, and there is no
 * straightforward workaround.  Please design your program some other
 * way.
 */
int xenevtchn_fd(xenevtchn_handle *xce);

/*
 * Notify the given event channel. Returns -1 on failure, in which case
 * errno will be set appropriately.
 */
int xenevtchn_notify(xenevtchn_handle *xce, evtchn_port_t port);

/*
 * Returns a new event port awaiting interdomain connection from the given
 * domain ID, or -1 on failure, in which case errno will be set appropriately.
 */
xenevtchn_port_or_error_t
xenevtchn_bind_unbound_port(xenevtchn_handle *xce, uint32_t domid);

/*
 * Returns a new event port bound to the remote port for the given domain ID,
 * or -1 on failure, in which case errno will be set appropriately.
 */
xenevtchn_port_or_error_t
xenevtchn_bind_interdomain(xenevtchn_handle *xce, uint32_t domid,
                           evtchn_port_t remote_port);

/*
 * Bind an event channel to the given VIRQ. Returns the event channel bound to
 * the VIRQ, or -1 on failure, in which case errno will be set appropriately.
 */
xenevtchn_port_or_error_t
xenevtchn_bind_virq(xenevtchn_handle *xce, unsigned int virq);

/*
 * Unbind the given event channel. Returns -1 on failure, in which case errno
 * will be set appropriately.
 */
int xenevtchn_unbind(xenevtchn_handle *xce, evtchn_port_t port);

/*
 * Return the next event channel to become pending, or -1 on failure, in which
 * case errno will be set appropriately.
 *
 * At the hypervisor level the event channel will have been masked,
 * and then cleared, by the underlying machinery (evtchn kernel
 * driver, or equivalent).  So if the event channel is signaled again
 * after it is returned here, it will be queued up, and delivered
 * again after you unmask it.  (See the documentation in the Xen
 * public header event_channel.h.)
 *
 * On receiving the notification from xenevtchn_pending, you should
 * normally: check (by other means) what work needs doing; do the
 * necessary work (if any); unmask the event channel with
 * xenevtchn_unmask (if you want to receive any further
 * notifications).
 */
xenevtchn_port_or_error_t
xenevtchn_pending(xenevtchn_handle *xce);

/*
 * Unmask the given event channel. Returns -1 on failure, in which case errno
 * will be set appropriately.
 */
int xenevtchn_unmask(xenevtchn_handle *xce, evtchn_port_t port);

/**
 * This function restricts the use of this handle to the specified
 * domain.
 *
 * @parm xce handle to the open evtchn interface
 * @parm domid the domain id
 * @return 0 on success, -1 on failure with errno set appropriately.
 */
int xenevtchn_restrict(xenevtchn_handle *xce, domid_t domid);

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
