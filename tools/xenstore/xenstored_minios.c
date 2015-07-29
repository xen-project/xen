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
#include <xenctrl.h>
#include "xenstored_core.h"
#include <xen/grant_table.h>

void write_pidfile(const char *pidfile)
{
}

void daemonize(void)
{
}

void finish_daemonize(void)
{
}

void init_pipe(int reopen_log_pipe[2])
{
	reopen_log_pipe[0] = -1;
	reopen_log_pipe[1] = -1;
}

void xenbus_notify_running(void)
{
}

evtchn_port_t xenbus_evtchn(void)
{
	return dom0_event;
}

void *xenbus_map(void)
{
	return xc_gnttab_map_grant_ref(*xcg_handle, xenbus_master_domid(),
			GNTTAB_RESERVED_XENSTORE, PROT_READ|PROT_WRITE);
}

void unmap_xenbus(void *interface)
{
	xc_gnttab_munmap(*xcg_handle, interface, 1);
}

