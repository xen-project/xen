/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * xen-9pfsd - Xen 9pfs daemon
 *
 * Copyright (C) 2024 Juergen Gross <jgross@suse.com>
 *
 * I/O thread handling.
 */

#include <stdbool.h>
#include <string.h>
#include <syslog.h>

#include "xen-9pfsd.h"

static bool io_work_pending(struct ring *ring)
{
    if ( ring->stop_thread )
        return true;
    return false;
}

void *io_thread(void *arg)
{
    struct ring *ring = arg;

    while ( !ring->stop_thread )
    {
        pthread_mutex_lock(&ring->mutex);
        if ( !io_work_pending(ring) )
        {
            if ( xenevtchn_unmask(xe, ring->evtchn) < 0 )
                syslog(LOG_WARNING, "xenevtchn_unmask() failed");
            pthread_cond_wait(&ring->cond, &ring->mutex);
        }
        pthread_mutex_unlock(&ring->mutex);

        /* TODO: I/O handling. */
    }

    ring->thread_active = false;

    return NULL;
}
