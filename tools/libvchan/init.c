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
 *  This file contains the setup code used to establish the ring buffer.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/user.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <xenstore.h>
#include <xen/sys/evtchn.h>
#include <xen/sys/gntalloc.h>
#include <xen/sys/gntdev.h>
#include <libxenvchan.h>

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define SMALL_RING_SHIFT 10
#define LARGE_RING_SHIFT 11

#define MAX_SMALL_RING (1 << SMALL_RING_SHIFT)
#define SMALL_RING_OFFSET 1024
#define MAX_LARGE_RING (1 << LARGE_RING_SHIFT)
#define LARGE_RING_OFFSET 2048

// if you go over this size, you'll have too many grants to fit in the shared page.
#define MAX_RING_SHIFT 20
#define MAX_RING_SIZE (1 << MAX_RING_SHIFT)

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define max(a,b) ((a > b) ? a : b)

static int init_gnt_srv(struct libxenvchan *ctrl, int domain)
{
	int pages_left = ctrl->read.order >= PAGE_SHIFT ? 1 << (ctrl->read.order - PAGE_SHIFT) : 0;
	int pages_right = ctrl->write.order >= PAGE_SHIFT ? 1 << (ctrl->write.order - PAGE_SHIFT) : 0;
	uint32_t ring_ref = -1;
	void *ring;

	ring = xc_gntshr_share_page_notify(ctrl->gntshr, domain,
			&ring_ref, 1, offsetof(struct vchan_interface, srv_live),
			ctrl->event_port);

	if (!ring)
		goto out;

	memset(ring, 0, PAGE_SIZE);

	ctrl->ring = ring;
	ctrl->read.shr = &ctrl->ring->left;
	ctrl->write.shr = &ctrl->ring->right;
	ctrl->ring->left_order = ctrl->read.order;
	ctrl->ring->right_order = ctrl->write.order;
	ctrl->ring->cli_live = 2;
	ctrl->ring->srv_live = 1;
	ctrl->ring->cli_notify = VCHAN_NOTIFY_WRITE;

	switch (ctrl->read.order) {
	case SMALL_RING_SHIFT:
		ctrl->read.buffer = ((void*)ctrl->ring) + SMALL_RING_OFFSET;
		break;
	case LARGE_RING_SHIFT:
		ctrl->read.buffer = ((void*)ctrl->ring) + LARGE_RING_OFFSET;
		break;
	default:
		ctrl->read.buffer = xc_gntshr_share_pages(ctrl->gntshr, domain,
			pages_left, ctrl->ring->grants, 1);
		if (!ctrl->read.buffer)
			goto out_ring;
	}

	switch (ctrl->write.order) {
	case SMALL_RING_SHIFT:
		ctrl->write.buffer = ((void*)ctrl->ring) + SMALL_RING_OFFSET;
		break;
	case LARGE_RING_SHIFT:
		ctrl->write.buffer = ((void*)ctrl->ring) + LARGE_RING_OFFSET;
		break;
	default:
		ctrl->write.buffer = xc_gntshr_share_pages(ctrl->gntshr, domain,
			pages_right, ctrl->ring->grants + pages_left, 1);
		if (!ctrl->write.buffer)
			goto out_unmap_left;
	}

out:
	return ring_ref;
out_unmap_left:
	if (pages_left)
		xc_gntshr_munmap(ctrl->gntshr, ctrl->read.buffer, pages_left * PAGE_SIZE);
out_ring:
	xc_gntshr_munmap(ctrl->gntshr, ring, PAGE_SIZE);
	ring_ref = -1;
	ctrl->ring = NULL;
	ctrl->write.order = ctrl->read.order = 0;
	goto out;
}

static int init_gnt_cli(struct libxenvchan *ctrl, int domain, uint32_t ring_ref)
{
	int rv = -1;
	uint32_t *grants;

	ctrl->ring = xc_gnttab_map_grant_ref_notify(ctrl->gnttab,
		domain, ring_ref, PROT_READ|PROT_WRITE,
		offsetof(struct vchan_interface, cli_live), ctrl->event_port);

	if (!ctrl->ring)
		goto out;

	ctrl->write.order = ctrl->ring->left_order;
	ctrl->read.order = ctrl->ring->right_order;
	ctrl->write.shr = &ctrl->ring->left;
	ctrl->read.shr = &ctrl->ring->right;
	if (ctrl->write.order < SMALL_RING_SHIFT || ctrl->write.order > MAX_RING_SHIFT)
		goto out_unmap_ring;
	if (ctrl->read.order < SMALL_RING_SHIFT || ctrl->read.order > MAX_RING_SHIFT)
		goto out_unmap_ring;
	if (ctrl->read.order == ctrl->write.order && ctrl->read.order < PAGE_SHIFT)
		goto out_unmap_ring;

	grants = ctrl->ring->grants;

	switch (ctrl->write.order) {
	case SMALL_RING_SHIFT:
		ctrl->write.buffer = ((void*)ctrl->ring) + SMALL_RING_OFFSET;
		break;
	case LARGE_RING_SHIFT:
		ctrl->write.buffer = ((void*)ctrl->ring) + LARGE_RING_OFFSET;
		break;
	default:
		{
			int pages_left = 1 << (ctrl->write.order - PAGE_SHIFT);
			ctrl->write.buffer = xc_gnttab_map_domain_grant_refs(ctrl->gnttab,
				pages_left, domain, grants, PROT_READ|PROT_WRITE);
			if (!ctrl->write.buffer)
				goto out_unmap_ring;
			grants += pages_left;
		}
	}

	switch (ctrl->read.order) {
	case SMALL_RING_SHIFT:
		ctrl->read.buffer = ((void*)ctrl->ring) + SMALL_RING_OFFSET;
		break;
	case LARGE_RING_SHIFT:
		ctrl->read.buffer = ((void*)ctrl->ring) + LARGE_RING_OFFSET;
		break;
	default:
		{
			int pages_right = 1 << (ctrl->read.order - PAGE_SHIFT);
			ctrl->read.buffer = xc_gnttab_map_domain_grant_refs(ctrl->gnttab,
				pages_right, domain, grants, PROT_READ);
			if (!ctrl->read.buffer)
				goto out_unmap_left;
		}
	}

	rv = 0;
 out:
	return rv;
 out_unmap_left:
	if (ctrl->write.order >= PAGE_SHIFT)
		xc_gnttab_munmap(ctrl->gnttab, ctrl->write.buffer,
		                 1 << ctrl->write.order);
 out_unmap_ring:
	xc_gnttab_munmap(ctrl->gnttab, ctrl->ring, PAGE_SIZE);
	ctrl->ring = 0;
	ctrl->write.order = ctrl->read.order = 0;
	rv = -1;
	goto out;
}

static int init_evt_srv(struct libxenvchan *ctrl, int domain, xentoollog_logger *logger)
{
	evtchn_port_or_error_t port;

	ctrl->event = xc_evtchn_open(logger, 0);
	if (!ctrl->event)
		return -1;

	port = xc_evtchn_bind_unbound_port(ctrl->event, domain);
	if (port < 0)
		goto fail;
	ctrl->event_port = port;

	if (xc_evtchn_unmask(ctrl->event, ctrl->event_port))
		goto fail;

	return 0;

fail:
	if (port >= 0)
		xc_evtchn_unbind(ctrl->event, port);

	xc_evtchn_close(ctrl->event);
	ctrl->event = NULL;

	return -1;
}

static int init_xs_srv(struct libxenvchan *ctrl, int domain, const char* xs_base, int ring_ref)
{
	int ret = -1;
	struct xs_handle *xs;
	struct xs_permissions perms[2];
	char buf[64];
	char ref[16];
	char* domid_str = NULL;
	xs = xs_domain_open();
	if (!xs)
		goto fail;
	domid_str = xs_read(xs, 0, "domid", NULL);
	if (!domid_str)
		goto fail_xs_open;

	// owner domain is us
	perms[0].id = atoi(domid_str);
	// permissions for domains not listed = none
	perms[0].perms = XS_PERM_NONE;
	// other domains
	perms[1].id = domain;
	perms[1].perms = XS_PERM_READ;

	snprintf(ref, sizeof ref, "%d", ring_ref);
	snprintf(buf, sizeof buf, "%s/ring-ref", xs_base);
	if (!xs_write(xs, 0, buf, ref, strlen(ref)))
		goto fail_xs_open;
	if (!xs_set_permissions(xs, 0, buf, perms, 2))
		goto fail_xs_open;

	snprintf(ref, sizeof ref, "%d", ctrl->event_port);
	snprintf(buf, sizeof buf, "%s/event-channel", xs_base);
	if (!xs_write(xs, 0, buf, ref, strlen(ref)))
		goto fail_xs_open;
	if (!xs_set_permissions(xs, 0, buf, perms, 2))
		goto fail_xs_open;

	ret = 0;
 fail_xs_open:
	free(domid_str);
	xs_daemon_close(xs);
 fail:
	return ret;
}

static int min_order(size_t siz)
{
	int rv = PAGE_SHIFT;
	while (siz > (1 << rv))
		rv++;
	return rv;
}

struct libxenvchan *libxenvchan_server_init(xentoollog_logger *logger, int domain, const char* xs_path, size_t left_min, size_t right_min)
{
	struct libxenvchan *ctrl;
	int ring_ref;
	if (left_min > MAX_RING_SIZE || right_min > MAX_RING_SIZE)
		return 0;

	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl)
		return 0;

	ctrl->ring = NULL;
	ctrl->event = NULL;
	ctrl->is_server = 1;
	ctrl->server_persist = 0;

	ctrl->read.order = min_order(left_min);
	ctrl->write.order = min_order(right_min);

	// if we can avoid allocating extra pages by using in-page rings, do so
	if (left_min <= MAX_SMALL_RING && right_min <= MAX_LARGE_RING) {
		ctrl->read.order = SMALL_RING_SHIFT;
		ctrl->write.order = LARGE_RING_SHIFT;
	} else if (left_min <= MAX_LARGE_RING && right_min <= MAX_SMALL_RING) {
		ctrl->read.order = LARGE_RING_SHIFT;
		ctrl->write.order = SMALL_RING_SHIFT;
	} else if (left_min <= MAX_LARGE_RING) {
		ctrl->read.order = LARGE_RING_SHIFT;
	} else if (right_min <= MAX_LARGE_RING) {
		ctrl->write.order = LARGE_RING_SHIFT;
	}

	ctrl->gntshr = xc_gntshr_open(logger, 0);
	if (!ctrl->gntshr)
		goto out;

	if (init_evt_srv(ctrl, domain, logger))
		goto out;
	ring_ref = init_gnt_srv(ctrl, domain);
	if (ring_ref < 0)
		goto out;
	if (init_xs_srv(ctrl, domain, xs_path, ring_ref))
		goto out;
	return ctrl;
out:
	libxenvchan_close(ctrl);
	return 0;
}

static int init_evt_cli(struct libxenvchan *ctrl, int domain, xentoollog_logger *logger)
{
	evtchn_port_or_error_t port;

	ctrl->event = xc_evtchn_open(logger, 0);
	if (!ctrl->event)
		return -1;

	port = xc_evtchn_bind_interdomain(ctrl->event,
		domain, ctrl->event_port);
	if (port < 0)
		goto fail;
	ctrl->event_port = port;

	if (xc_evtchn_unmask(ctrl->event, ctrl->event_port))
		goto fail;

	return 0;

fail:
	if (port >= 0)
		xc_evtchn_unbind(ctrl->event, port);

	xc_evtchn_close(ctrl->event);
	ctrl->event = NULL;

	return -1;
}


struct libxenvchan *libxenvchan_client_init(xentoollog_logger *logger, int domain, const char* xs_path)
{
	struct libxenvchan *ctrl = malloc(sizeof(struct libxenvchan));
	struct xs_handle *xs = NULL;
	char buf[64];
	char *ref;
	int ring_ref;
	unsigned int len;

	if (!ctrl)
		return 0;
	ctrl->ring = NULL;
	ctrl->event = NULL;
	ctrl->gnttab = NULL;
	ctrl->write.order = ctrl->read.order = 0;
	ctrl->is_server = 0;

	xs = xs_daemon_open();
	if (!xs)
		xs = xs_domain_open();
	if (!xs)
		goto fail;

// find xenstore entry
	snprintf(buf, sizeof buf, "%s/ring-ref", xs_path);
	ref = xs_read(xs, 0, buf, &len);
	if (!ref)
		goto fail;
	ring_ref = atoi(ref);
	free(ref);
	if (!ring_ref)
		goto fail;
	snprintf(buf, sizeof buf, "%s/event-channel", xs_path);
	ref = xs_read(xs, 0, buf, &len);
	if (!ref)
		goto fail;
	ctrl->event_port = atoi(ref);
	free(ref);
	if (!ctrl->event_port)
		goto fail;

	ctrl->gnttab = xc_gnttab_open(logger, 0);
	if (!ctrl->gnttab)
		goto fail;

// set up event channel
	if (init_evt_cli(ctrl, domain, logger))
		goto fail;

// set up shared page(s)
	if (init_gnt_cli(ctrl, domain, ring_ref))
		goto fail;

	ctrl->ring->cli_live = 1;
	ctrl->ring->srv_notify = VCHAN_NOTIFY_WRITE;

 out:
	if (xs)
		xs_daemon_close(xs);
	return ctrl;
 fail:
	libxenvchan_close(ctrl);
	ctrl = NULL;
	goto out;
}
