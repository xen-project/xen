/******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (C) 2005 Rusty Russell IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <xen/sys/xenbus.h>

#include "xenstored_core.h"

evtchn_port_t xenbus_evtchn(void)
{
	int fd;
	evtchn_port_t port; 

	fd = open("/dev/xen/xenbus", O_RDONLY); 
	if (fd == -1)
		return -1;

	port = ioctl(fd, IOCTL_XENBUS_XENSTORE_EVTCHN);

	close(fd); 
	return port;
}

void *xenbus_map(void)
{
	int fd;
	void *addr;

	fd = open("/dev/xen/xenbus", O_RDWR);
	if (fd == -1)
		return NULL;

	addr = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, 0);

	if (addr == MAP_FAILED)
		addr = NULL;

	close(fd);

	return addr;
}

void xenbus_notify_running(void)
{
	int fd;

	fd = open("/dev/xen/xenbus", O_RDONLY);

	(void) ioctl(fd, IOCTL_XENBUS_NOTIFY_UP);

	close(fd);
}
