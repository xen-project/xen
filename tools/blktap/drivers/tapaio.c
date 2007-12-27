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

#include "tapaio.h"
#include "tapdisk.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

/**
 * We used a kernel patch to return an fd associated with the AIO context
 * so that we can concurrently poll on synchronous and async descriptors.
 * This is signalled by passing 1 as the io context to io_setup.
 */
#define REQUEST_ASYNC_FD 1

/*
 * If we don't have any way to do epoll on aio events in a normal kernel,
 * wait for aio events in a separate thread and return completion status
 * that via a pipe that can be waited on normally.
 *
 * To keep locking problems between the completion thread and the submit
 * thread to a minimum, there's a handshake which allows only one thread
 * to be doing work on the completion queue at a time:
 *
 * 1) main thread sends completion thread a command via the command pipe;
 * 2) completion thread waits for aio events and returns the number
 *    received on the completion pipe
 * 3) main thread processes the received ctx->aio_events events
 * 4) loop back to 1) to let the completion thread refill the aio_events
 *    buffer.
 *
 * This workaround needs to disappear once the kernel provides a single
 * mechanism for waiting on both aio and normal fd wakeups.
 */
static void *
tap_aio_completion_thread(void *arg)
{
	tap_aio_context_t *ctx = (tap_aio_context_t *) arg;
	int command;
	int nr_events;
	int rc;

	while (1) {
		rc = read(ctx->command_fd[0], &command, sizeof(command));

		do {
			rc = io_getevents(ctx->aio_ctx, 1,
					  ctx->max_aio_events, ctx->aio_events,
					  NULL);
			if (rc) {
				nr_events = rc;
				rc = write(ctx->completion_fd[1], &nr_events,
					   sizeof(nr_events));
			}
		} while (!rc);
	}
}

void
tap_aio_continue(tap_aio_context_t *ctx)
{
        int cmd = 0;

        if (!ctx->poll_in_thread)
                return;

        if (write(ctx->command_fd[1], &cmd, sizeof(cmd)) < 0)
                DPRINTF("Cannot write to command pipe\n");
}

int
tap_aio_setup(tap_aio_context_t *ctx,
              struct io_event *aio_events,
              int max_aio_events)
{
        int ret;

        ctx->aio_events = aio_events;
        ctx->max_aio_events = max_aio_events;
        ctx->poll_in_thread = 0;

        ctx->aio_ctx = (io_context_t) REQUEST_ASYNC_FD;
        ret = io_setup(ctx->max_aio_events, &ctx->aio_ctx);
        if (ret < 0 && ret != -EINVAL)
                return ret;
        else if (ret > 0) {
                ctx->pollfd = ret;
                return ctx->pollfd;
        }

        ctx->aio_ctx = (io_context_t) 0;
        ret = io_setup(ctx->max_aio_events, &ctx->aio_ctx);
        if (ret < 0)
                return ret;

        if ((ret = pipe(ctx->command_fd)) < 0) {
                DPRINTF("Unable to create command pipe\n");
                return -1;
        }
        if ((ret = pipe(ctx->completion_fd)) < 0) {
                DPRINTF("Unable to create completion pipe\n");
                return -1;
        }

        if ((ret = pthread_create(&ctx->aio_thread, NULL,
                                  tap_aio_completion_thread, ctx)) != 0) {
                DPRINTF("Unable to create completion thread\n");
                return -1;
        }

        ctx->pollfd = ctx->completion_fd[0];
        ctx->poll_in_thread = 1;

        tap_aio_continue(ctx);

        return 0;
}

int
tap_aio_get_events(tap_aio_context_t *ctx)
{
        int nr_events = 0;

        if (!ctx->poll_in_thread)
                nr_events = io_getevents(ctx->aio_ctx, 1,
                                         ctx->max_aio_events, ctx->aio_events, NULL);
        else {
		int r;
		r = read(ctx->completion_fd[0], &nr_events, sizeof(nr_events));
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			/* This is pretty bad, we'll probably spin */
			DPRINTF("Aargh, read completion_fd failed: %s",
				strerror(errno));
		} else if (r != sizeof(nr_events)) {
			/* Should never happen because sizeof(nr_events)
			 * fits in the guaranteed atomic pipe write size.
			 * Blundering on is slightly nicer than asserting */
			DPRINTF("Aargh, read completion_fd short read %d", r);
		}
	}

        return nr_events;
}

int tap_aio_more_events(tap_aio_context_t *ctx)
{
        return io_getevents(ctx->aio_ctx, 0,
                            ctx->max_aio_events, ctx->aio_events, NULL);
}


