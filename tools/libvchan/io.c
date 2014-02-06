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
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * @section DESCRIPTION
 *
 *  This file contains the communications interface built on the ring buffer.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <xenctrl.h>
#include <libxenvchan.h>

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif


static inline uint32_t rd_prod(struct libxenvchan *ctrl)
{
	return ctrl->read.shr->prod;
}

static inline uint32_t* _rd_cons(struct libxenvchan *ctrl)
{
	return &ctrl->read.shr->cons;
}
#define rd_cons(x) (*_rd_cons(x))

static inline uint32_t* _wr_prod(struct libxenvchan *ctrl)
{
	return &ctrl->write.shr->prod;
}
#define wr_prod(x) (*_wr_prod(x))

static inline uint32_t wr_cons(struct libxenvchan *ctrl)
{
	return ctrl->write.shr->cons;
}

static inline const void* rd_ring(struct libxenvchan *ctrl)
{
	return ctrl->read.buffer;
}

static inline void* wr_ring(struct libxenvchan *ctrl)
{
	return ctrl->write.buffer;
}

static inline uint32_t wr_ring_size(struct libxenvchan *ctrl)
{
	return (1 << ctrl->write.order);
}

static inline uint32_t rd_ring_size(struct libxenvchan *ctrl)
{
	return (1 << ctrl->read.order);
}

static inline void request_notify(struct libxenvchan *ctrl, uint8_t bit)
{
	uint8_t *notify = ctrl->is_server ? &ctrl->ring->cli_notify : &ctrl->ring->srv_notify;
	__sync_or_and_fetch(notify, bit);
	xen_mb(); /* post the request /before/ caller re-reads any indexes */
}

static inline int send_notify(struct libxenvchan *ctrl, uint8_t bit)
{
	uint8_t *notify, prev;
	xen_mb(); /* caller updates indexes /before/ we decode to notify */
	notify = ctrl->is_server ? &ctrl->ring->srv_notify : &ctrl->ring->cli_notify;
	prev = __sync_fetch_and_and(notify, ~bit);
	if (prev & bit)
		return xc_evtchn_notify(ctrl->event, ctrl->event_port);
	else
		return 0;
}

/*
 * Get the amount of buffer space available, and do nothing about
 * notifications.
 */
static inline int raw_get_data_ready(struct libxenvchan *ctrl)
{
	uint32_t ready = rd_prod(ctrl) - rd_cons(ctrl);
	if (ready >= rd_ring_size(ctrl))
		/* We have no way to return errors.  Locking up the ring is
		 * better than the alternatives. */
		return 0;
	return ready;
}

/**
 * Get the amount of buffer space available and enable notifications if needed.
 */
static inline int fast_get_data_ready(struct libxenvchan *ctrl, size_t request)
{
	int ready = raw_get_data_ready(ctrl);
	if (ready >= request)
		return ready;
	/* We plan to consume all data; please tell us if you send more */
	request_notify(ctrl, VCHAN_NOTIFY_WRITE);
	/*
	 * If the writer moved rd_prod after our read but before request, we
	 * will not get notified even though the actual amount of data ready is
	 * above request. Reread rd_prod to cover this case.
	 */
	return raw_get_data_ready(ctrl);
}

int libxenvchan_data_ready(struct libxenvchan *ctrl)
{
	/* Since this value is being used outside libxenvchan, request notification
	 * when it changes
	 */
	request_notify(ctrl, VCHAN_NOTIFY_WRITE);
	return raw_get_data_ready(ctrl);
}

/**
 * Get the amount of buffer space available, and do nothing
 * about notifications
 */
static inline int raw_get_buffer_space(struct libxenvchan *ctrl)
{
	uint32_t ready = wr_ring_size(ctrl) - (wr_prod(ctrl) - wr_cons(ctrl));
	if (ready > wr_ring_size(ctrl))
		/* We have no way to return errors.  Locking up the ring is
		 * better than the alternatives. */
		return 0;
	return ready;
}

/**
 * Get the amount of buffer space available and enable notifications if needed.
 */
static inline int fast_get_buffer_space(struct libxenvchan *ctrl, size_t request)
{
	int ready = raw_get_buffer_space(ctrl);
	if (ready >= request)
		return ready;
	/* We plan to fill the buffer; please tell us when you've read it */
	request_notify(ctrl, VCHAN_NOTIFY_READ);
	/*
	 * If the reader moved wr_cons after our read but before request, we
	 * will not get notified even though the actual amount of buffer space
	 * is above request. Reread wr_cons to cover this case.
	 */
	return raw_get_buffer_space(ctrl);
}

int libxenvchan_buffer_space(struct libxenvchan *ctrl)
{
	/* Since this value is being used outside libxenvchan, request notification
	 * when it changes
	 */
	request_notify(ctrl, VCHAN_NOTIFY_READ);
	return raw_get_buffer_space(ctrl);
}

int libxenvchan_wait(struct libxenvchan *ctrl)
{
	int ret = xc_evtchn_pending(ctrl->event);
	if (ret < 0)
		return -1;
	xc_evtchn_unmask(ctrl->event, ret);
	return 0;
}

/**
 * returns -1 on error, or size on success
 *
 * caller must have checked that enough space is available
 */
static int do_send(struct libxenvchan *ctrl, const void *data, size_t size)
{
	int real_idx = wr_prod(ctrl) & (wr_ring_size(ctrl) - 1);
	int avail_contig = wr_ring_size(ctrl) - real_idx;
	if (avail_contig > size)
		avail_contig = size;
	xen_mb(); /* read indexes /then/ write data */
	memcpy(wr_ring(ctrl) + real_idx, data, avail_contig);
	if (avail_contig < size)
	{
		// we rolled across the end of the ring
		memcpy(wr_ring(ctrl), data + avail_contig, size - avail_contig);
	}
	xen_wmb(); /* write data /then/ notify */
	wr_prod(ctrl) += size;
	if (send_notify(ctrl, VCHAN_NOTIFY_WRITE))
		return -1;
	return size;
}

/**
 * returns 0 if no buffer space is available, -1 on error, or size on success
 */
int libxenvchan_send(struct libxenvchan *ctrl, const void *data, size_t size)
{
	int avail;
	while (1) {
		if (!libxenvchan_is_open(ctrl))
			return -1;
		avail = fast_get_buffer_space(ctrl, size);
		if (size <= avail)
			return do_send(ctrl, data, size);
		if (!ctrl->blocking)
			return 0;
		if (size > wr_ring_size(ctrl))
			return -1;
		if (libxenvchan_wait(ctrl))
			return -1;
	}
}

int libxenvchan_write(struct libxenvchan *ctrl, const void *data, size_t size)
{
	int avail;
	if (!libxenvchan_is_open(ctrl))
		return -1;
	if (ctrl->blocking) {
		size_t pos = 0;
		while (1) {
			avail = fast_get_buffer_space(ctrl, size - pos);
			if (pos + avail > size)
				avail = size - pos;
			if (avail)
				pos += do_send(ctrl, data + pos, avail);
			if (pos == size)
				return pos;
			if (libxenvchan_wait(ctrl))
				return -1;
			if (!libxenvchan_is_open(ctrl))
				return -1;
		}
	} else {
		avail = fast_get_buffer_space(ctrl, size);
		if (size > avail)
			size = avail;
		if (size == 0)
			return 0;
		return do_send(ctrl, data, size);
	}
}

/**
 * returns -1 on error, or size on success
 *
 * caller must have checked that enough data is available
 */
static int do_recv(struct libxenvchan *ctrl, void *data, size_t size)
{
	int real_idx = rd_cons(ctrl) & (rd_ring_size(ctrl) - 1);
	int avail_contig = rd_ring_size(ctrl) - real_idx;
	if (avail_contig > size)
		avail_contig = size;
	xen_rmb(); /* data read must happen /after/ rd_cons read */
	memcpy(data, rd_ring(ctrl) + real_idx, avail_contig);
	if (avail_contig < size)
	{
		// we rolled across the end of the ring
		memcpy(data + avail_contig, rd_ring(ctrl), size - avail_contig);
	}
	xen_mb(); /* consume /then/ notify */
	rd_cons(ctrl) += size;
	if (send_notify(ctrl, VCHAN_NOTIFY_READ))
		return -1;
	return size;
}

/**
 * reads exactly size bytes from the vchan.
 * returns 0 if insufficient data is available, -1 on error, or size on success
 */
int libxenvchan_recv(struct libxenvchan *ctrl, void *data, size_t size)
{
	while (1) {
		int avail = fast_get_data_ready(ctrl, size);
		if (size <= avail)
			return do_recv(ctrl, data, size);
		if (!libxenvchan_is_open(ctrl))
			return -1;
		if (!ctrl->blocking)
			return 0;
		if (size > rd_ring_size(ctrl))
			return -1;
		if (libxenvchan_wait(ctrl))
			return -1;
	}
}

int libxenvchan_read(struct libxenvchan *ctrl, void *data, size_t size)
{
	while (1) {
		int avail = fast_get_data_ready(ctrl, size);
		if (avail && size > avail)
			size = avail;
		if (avail)
			return do_recv(ctrl, data, size);
		if (!libxenvchan_is_open(ctrl))
			return -1;
		if (!ctrl->blocking)
			return 0;
		if (libxenvchan_wait(ctrl))
			return -1;
	}
}

int libxenvchan_is_open(struct libxenvchan* ctrl)
{
	if (ctrl->is_server)
		return ctrl->server_persist ? 1 : ctrl->ring->cli_live;
	else
		return ctrl->ring->srv_live;
}

int libxenvchan_fd_for_select(struct libxenvchan *ctrl)
{
	return xc_evtchn_fd(ctrl->event);
}

void libxenvchan_close(struct libxenvchan *ctrl)
{
	if (!ctrl)
		return;
	if (ctrl->read.order >= PAGE_SHIFT)
		munmap(ctrl->read.buffer, 1 << ctrl->read.order);
	if (ctrl->write.order >= PAGE_SHIFT)
		munmap(ctrl->write.buffer, 1 << ctrl->write.order);
	if (ctrl->ring) {
		if (ctrl->is_server) {
			ctrl->ring->srv_live = 0;
			xc_gntshr_munmap(ctrl->gntshr, ctrl->ring, PAGE_SIZE);
		} else {
			ctrl->ring->cli_live = 0;
			xc_gnttab_munmap(ctrl->gnttab, ctrl->ring, PAGE_SIZE);
		}
	}
	if (ctrl->event) {
		if (ctrl->ring)
			xc_evtchn_notify(ctrl->event, ctrl->event_port);
		xc_evtchn_close(ctrl->event);
	}
	if (ctrl->is_server) {
		if (ctrl->gntshr)
			xc_gntshr_close(ctrl->gntshr);
	} else {
		if (ctrl->gnttab)
			xc_gnttab_close(ctrl->gnttab);
	}
	free(ctrl);
}
