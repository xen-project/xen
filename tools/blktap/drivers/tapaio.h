/*
 * Copyright (c) 2006 Andrew Warfield and Julian Chesterfield
 * Copyright (c) 2007 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __TAPAIO_H__
#define __TAPAIO_H__

#include <pthread.h>
#include <libaio.h>

struct tap_aio_context {
        io_context_t     aio_ctx;

        struct io_event *aio_events;
        int              max_aio_events;

        pthread_t        aio_thread;
        int              command_fd[2];
        int              completion_fd[2];
        int              pollfd;
        unsigned int     poll_in_thread : 1;
};

typedef struct tap_aio_context tap_aio_context_t;

int  tap_aio_setup      (tap_aio_context_t *ctx,
                         struct io_event *aio_events,
                         int max_aio_events);
void tap_aio_continue   (tap_aio_context_t *ctx);
int  tap_aio_get_events (tap_aio_context_t *ctx);
int  tap_aio_more_events(tap_aio_context_t *ctx);

#endif /* __TAPAIO_H__ */
