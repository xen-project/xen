/* 
    Fake libxc which doesn't require hypervisor but talks to xs_test.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include "utils.h"
#include "xenstored_core.h"
#include "xenstored_domain.h"
#include "xenstored_test.h"
#include <xenctrl.h>

static int sigfd;
static int xs_test_pid;
static evtchn_port_t port;

/* The event channel maps to a signal, shared page to an mmapped file. */
void evtchn_notify(int local_port)
{
	assert(local_port == port);
	if (kill(xs_test_pid, SIGUSR2) != 0)
		barf_perror("fake event channel failed");
}

void *xc_map_foreign_range(int xc_handle, uint32_t dom __attribute__((unused)),
			   int size, int prot,
			   unsigned long mfn __attribute__((unused)))
{
	void *ret;

	ret = mmap(NULL, size, prot, MAP_SHARED, xc_handle, 0);
	if (ret == MAP_FAILED)
		return NULL;

	/* xs_test tells us pid and port by putting it in buffer, we reply. */
	xs_test_pid = *(int *)(ret + 32);
	port = *(int *)(ret + 36);
	*(int *)(ret + 32) = getpid();
	return ret;
}

int xc_interface_open(void)
{
	int fd;
	char page[getpagesize()];

	fd = open("/tmp/xcmap", O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (fd < 0)
		return fd;

	memset(page, 0, sizeof(page));
	if (!xs_write_all(fd, page, sizeof(page)))
		barf_perror("Failed to write /tmp/xcmap page");
	
	return fd;
}

int xc_interface_close(int xc_handle)
{
	close(xc_handle);
	return 0;
}

int xc_domain_getinfo(int xc_handle __attribute__((unused)),
		      uint32_t first_domid, unsigned int max_doms,
                      xc_dominfo_t *info)
{
	assert(max_doms == 1);
        info->domid = first_domid;

        info->dying    = 0;
        info->shutdown = 0;
        info->paused   = 0;
        info->blocked  = 0;
        info->running  = 1;

        info->shutdown_reason = 0;

        if ( info->shutdown && (info->shutdown_reason == SHUTDOWN_crash) )
        {
            info->shutdown = 0;
            info->crashed  = 1;
        }

	return 1;
}

static void send_to_fd(int signo __attribute__((unused)))
{
	int saved_errno = errno;
	write(sigfd, &port, sizeof(port));
	errno = saved_errno;
}

void fake_block_events(void)
{
	signal(SIGUSR2, SIG_IGN);
}

void fake_ack_event(void)
{
	signal(SIGUSR2, send_to_fd);
}

int fake_open_eventchn(void)
{
	int fds[2];

	if (pipe(fds) != 0)
		return -1;

	if (signal(SIGUSR2, send_to_fd) == SIG_ERR) {
		int saved_errno = errno;
		close(fds[0]);
		close(fds[1]);
		errno = saved_errno;
		return -1;
	}
	sigfd = fds[1];
	return fds[0];
}
