/* 
    Simple prototype Xen Store Daemon providing simple tree-like database.
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
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/types.h>
#include <sys/mman.h>
#include "core.h"
#include "utils.h"
#include <xen/grant_table.h>
#include <mini-os/lib.h>

void finish_daemonize(void)
{
}

struct connection *add_socket_connection(int fd)
{
	barf("socket based connection without sockets");
}

evtchn_port_t get_xenbus_evtchn(void)
{
	return dom0_event;
}

void *xenbus_map(void)
{
	return xengnttab_map_grant_ref(*xgt_handle, xenbus_master_domid(),
			GNTTAB_RESERVED_XENSTORE, PROT_READ|PROT_WRITE);
}

void unmap_xenbus(void *interface)
{
	xengnttab_unmap(*xgt_handle, interface, 1);
}

void early_init(bool live_update, bool dofork, const char *pidfile)
{
	stub_domid = get_domid();
	if (stub_domid == DOMID_INVALID)
		barf("could not get own domid");
}

void late_init(bool live_update)
{
}

void set_special_fds(void)
{
}

void handle_special_fds(void)
{
}

int get_socket_fd(void)
{
	return -1;
}

void set_socket_fd(int fd)
{
}
