/**
 * @file
 * @section AUTHORS
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *
 *  Authors:
 *       Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *       Daniel De Graaf <dgdegra@tycho.nsa.gov>
 *
 * @section LICENSE
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * @section DESCRIPTION
 *
 *  Originally borrowed from the Qubes OS Project, http://www.qubes-os.org,
 *  this code has been substantially rewritten to use the gntdev and gntalloc
 *  devices instead of raw MFNs and map_foreign_range.
 *
 *  This is a library for inter-domain communication.  A standard Xen ring
 *  buffer is used, with a datagram-based interface built on top.  The grant
 *  reference and event channels are shared in XenStore under the path
 *  /local/domain/<srv-id>/data/vchan/<cli-id>/<port>/{ring-ref,event-channel}
 *
 *  The ring.h macros define an asymmetric interface to a shared data structure
 *  that assumes all rings reside in a single contiguous memory space. This is
 *  not suitable for vchan because the interface to the ring is symmetric except
 *  for the setup. Unlike the producer-consumer rings defined in ring.h, the
 *  size of the rings used in vchan are determined at execution time instead of
 *  compile time, so the macros in ring.h cannot be used to access the rings.
 */

#include <xen/io/libxenvchan.h>
#include <xen/sys/evtchn.h>
#include <xenevtchn.h>
#include <xengnttab.h>

/* Callers who don't care don't need to #include <xentoollog.h> */
struct xentoollog_logger;

struct libxenvchan_ring {
	/* Pointer into the shared page. Offsets into buffer. */
	struct ring_shared* shr;
	/* ring data; may be its own shared page(s) depending on order */
	void* buffer;
	/**
	 * The size of the ring is (1 << order); offsets wrap around when they
	 * exceed this. This copy is required because we can't trust the order
	 * in the shared page to remain constant.
	 */
	int order;
};

/**
 * struct libxenvchan: control structure passed to all library calls
 */
struct libxenvchan {
	/* Mapping handle for shared ring page */
	union {
		xengntshr_handle *gntshr; /* for server */
		xengnttab_handle *gnttab; /* for client */
	};
	/* Pointer to shared ring page */
	struct vchan_interface *ring;
	/* event channel interface */
	xenevtchn_handle *event;
	uint32_t event_port;
	/* informative flags: are we acting as server? */
	int is_server:1;
	/* true if server remains active when client closes (allows reconnection) */
	int server_persist:1;
	/* true if operations should block instead of returning 0 */
	int blocking:1;
	/* communication rings */
	struct libxenvchan_ring read, write;
};

/**
 * Set up a vchan, including granting pages
 * @param logger Logger for libxc errors
 * @param domain The peer domain that will be connecting
 * @param xs_path Base xenstore path for storing ring/event data
 * @param send_min The minimum size (in bytes) of the send ring (left)
 * @param recv_min The minimum size (in bytes) of the receive ring (right)
 * @return The structure, or NULL in case of an error
 */
struct libxenvchan *libxenvchan_server_init(struct xentoollog_logger *logger,
                                            int domain, const char* xs_path,
                                            size_t read_min, size_t write_min);
/**
 * Connect to an existing vchan. Note: you can reconnect to an existing vchan
 * safely, however no locking is performed, so you must prevent multiple clients
 * from connecting to a single server.
 *
 * @param logger Logger for libxc errors
 * @param domain The peer domain to connect to
 * @param xs_path Base xenstore path for storing ring/event data
 * @return The structure, or NULL in case of an error
 */
struct libxenvchan *libxenvchan_client_init(struct xentoollog_logger *logger,
                                            int domain, const char* xs_path);
/**
 * Close a vchan. This deallocates the vchan and attempts to free its
 * resources. The other side is notified of the close, but can still read any
 * data pending prior to the close.
 */
void libxenvchan_close(struct libxenvchan *ctrl);

/**
 * Packet-based receive: always reads exactly $size bytes.
 * @param ctrl The vchan control structure
 * @param data Buffer for data that was read
 * @param size Size of the buffer and amount of data to read
 * @return -1 on error, 0 if nonblocking and insufficient data is available, or $size
 */
int libxenvchan_recv(struct libxenvchan *ctrl, void *data, size_t size);
/**
 * Stream-based receive: reads as much data as possible.
 * @param ctrl The vchan control structure
 * @param data Buffer for data that was read
 * @param size Size of the buffer
 * @return -1 on error, otherwise the amount of data read (which may be zero if
 *         the vchan is nonblocking)
 */
int libxenvchan_read(struct libxenvchan *ctrl, void *data, size_t size);
/**
 * Packet-based send: send entire buffer if possible
 * @param ctrl The vchan control structure
 * @param data Buffer for data to send
 * @param size Size of the buffer and amount of data to send
 * @return -1 on error, 0 if nonblocking and insufficient space is available, or $size
 */
int libxenvchan_send(struct libxenvchan *ctrl, const void *data, size_t size);
/**
 * Stream-based send: send as much data as possible.
 * @param ctrl The vchan control structure
 * @param data Buffer for data to send
 * @param size Size of the buffer
 * @return -1 on error, otherwise the amount of data sent (which may be zero if
 *         the vchan is nonblocking)
 */
int libxenvchan_write(struct libxenvchan *ctrl, const void *data, size_t size);
/**
 * Waits for reads or writes to unblock, or for a close
 */
int libxenvchan_wait(struct libxenvchan *ctrl);
/**
 * Returns the event file descriptor for this vchan. When this FD is readable,
 * libxenvchan_wait() will not block, and the state of the vchan has changed since
 * the last invocation of libxenvchan_wait().
 */
int libxenvchan_fd_for_select(struct libxenvchan *ctrl);
/**
 * Query the state of the vchan shared page:
 *  return 0 when one side has called libxenvchan_close() or crashed
 *  return 1 when both sides are open
 *  return 2 [server only] when no client has yet connected
 */
int libxenvchan_is_open(struct libxenvchan* ctrl);
/** Amount of data ready to read, in bytes */
int libxenvchan_data_ready(struct libxenvchan *ctrl);
/** Amount of data it is possible to send without blocking */
int libxenvchan_buffer_space(struct libxenvchan *ctrl);
