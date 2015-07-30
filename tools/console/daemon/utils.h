/*\
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Xen Console Daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
\*/

#ifndef CONSOLED_UTILS_H
#define CONSOLED_UTILS_H

#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include <xenctrl.h>

#include <xenstore.h>

void daemonize(const char *pidfile);
bool xen_setup(void);

extern struct xs_handle *xs;
extern xc_interface *xc;

#if 1
#define dolog(val, fmt, ...) do {				\
	if ((val) == LOG_ERR)					\
		fprintf(stderr, fmt "\n", ## __VA_ARGS__);	\
	syslog(val, fmt, ## __VA_ARGS__);			\
} while (/* CONSTCOND */0)
#else
#define dolog(val, fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__)
#endif

#endif
