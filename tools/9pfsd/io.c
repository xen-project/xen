/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * xen-9pfsd - Xen 9pfs daemon
 *
 * Copyright (C) 2024 Juergen Gross <jgross@suse.com>
 *
 * I/O thread handling.
 *
 * Only handle one request at a time, pushing out the complete response
 * before looking for the next request.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <xenctrl.h>           /* For cpu barriers. */
#include <xen-tools/common-macros.h>

#include "xen-9pfsd.h"

/*
 * Note that the ring names "in" and "out" are from the frontend's
 * perspective, so the "in" ring will be used for responses to the frontend,
 * while the "out" ring is used for requests from the frontend to the
 * backend.
 */
static unsigned int ring_in_free(struct ring *ring)
{
    unsigned int queued;

    queued = xen_9pfs_queued(ring->prod_pvt_in, ring->intf->in_cons,
                             ring->ring_size);
    xen_rmb();

    return ring->ring_size - queued;
}

static unsigned int ring_out_data(struct ring *ring)
{
    unsigned int queued;

    queued = xen_9pfs_queued(ring->intf->out_prod, ring->cons_pvt_out,
                             ring->ring_size);
    xen_rmb();

    return queued;
}

static unsigned int get_request_bytes(struct ring *ring, unsigned int off,
                                      unsigned int total_len)
{
    unsigned int size;
    unsigned int out_data = ring_out_data(ring);
    RING_IDX prod, cons;

    size = min(total_len - off, out_data);
    prod = xen_9pfs_mask(ring->intf->out_prod, ring->ring_size);
    cons = xen_9pfs_mask(ring->cons_pvt_out, ring->ring_size);
    xen_9pfs_read_packet(ring->buffer + off, ring->data.out, size,
                         prod, &cons, ring->ring_size);

    xen_rmb();           /* Read data out before setting visible consumer. */
    ring->cons_pvt_out += size;
    ring->intf->out_cons = ring->cons_pvt_out;

    /* Signal that more space is available now. */
    xenevtchn_notify(xe, ring->evtchn);

    return size;
}

static unsigned int put_response_bytes(struct ring *ring, unsigned int off,
                                       unsigned int total_len)
{
    unsigned int size;
    unsigned int in_data = ring_in_free(ring);
    RING_IDX prod, cons;

    size = min(total_len - off, in_data);
    prod = xen_9pfs_mask(ring->prod_pvt_in, ring->ring_size);
    cons = xen_9pfs_mask(ring->intf->in_cons, ring->ring_size);
    xen_9pfs_write_packet(ring->data.in, ring->buffer + off, size,
                          &prod, cons, ring->ring_size);

    xen_wmb();           /* Write data out before setting visible producer. */
    ring->prod_pvt_in += size;
    ring->intf->in_prod = ring->prod_pvt_in;

    return size;
}

static bool io_work_pending(struct ring *ring)
{
    if ( ring->stop_thread )
        return true;
    if ( ring->error )
        return false;
    return ring->handle_response ? ring_in_free(ring) : ring_out_data(ring);
}

void *io_thread(void *arg)
{
    struct ring *ring = arg;
    unsigned int count = 0;
    struct p9_header hdr = { .size = 0 };
    bool in_hdr = true;

    ring->max_size = ring->ring_size;
    ring->buffer = malloc(ring->max_size);
    if ( !ring->buffer )
    {
        syslog(LOG_CRIT, "memory allocation failure!");
        return NULL;
    }

    while ( !ring->stop_thread )
    {
        pthread_mutex_lock(&ring->mutex);
        if ( !io_work_pending(ring) )
        {
            if ( !ring->error && xenevtchn_unmask(xe, ring->evtchn) < 0 )
                syslog(LOG_WARNING, "xenevtchn_unmask() failed");
            pthread_cond_wait(&ring->cond, &ring->mutex);
        }
        pthread_mutex_unlock(&ring->mutex);

        if ( ring->stop_thread || ring->error )
            continue;

        if ( !ring->handle_response )
        {
            if ( in_hdr )
            {
                count += get_request_bytes(ring, count, sizeof(hdr));
                if ( count != sizeof(hdr) )
                    continue;
                hdr = *(struct p9_header *)ring->buffer;
                if ( hdr.size > ring->max_size || hdr.size < sizeof(hdr) )
                {
                    syslog(LOG_ERR, "%u.%u specified illegal request length %u",
                           ring->device->domid, ring->device->devid, hdr.size);
                    ring->error = true;
                    continue;
                }
                in_hdr = false;
            }

            count += get_request_bytes(ring, count, hdr.size);
            if ( count < hdr.size )
                continue;

            /* TODO: handle request (will rewrite hdr.size). */

            ring->handle_response = true;
            hdr.size = ((struct p9_header *)ring->buffer)->size;
            count = 0;
        }

        if ( ring->handle_response )
        {
            count += put_response_bytes(ring, count, hdr.size);

            if ( count == hdr.size )
            {
                /* Signal presence of response. */
                xenevtchn_notify(xe, ring->evtchn);

                ring->handle_response = false;
                in_hdr = true;
                count = 0;
            }
        }
    }

    free(ring->buffer);

    ring->thread_active = false;

    return NULL;
}
