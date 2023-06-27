/* 
    Common routines between Xen store user library and daemon.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef XENSTORE_LIB_H
#define XENSTORE_LIB_H

#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <xen/io/xs_wire.h>

struct xs_permissions
{
	unsigned int id;
	unsigned int perms;	/* Bitmask of permissions. */
#define XS_PERM_NONE		0x00
#define XS_PERM_READ		0x01
#define XS_PERM_WRITE		0x02
	/* Internal use. */
#define XS_PERM_ENOENT_OK	0x04
#define XS_PERM_OWNER		0x08
#define XS_PERM_IGNORE		0x10
};

/* Each 10 bits takes ~ 3 digits, plus one, plus one for nul terminator. */
#define MAX_STRLEN(x) ((sizeof(x) * CHAR_BIT + CHAR_BIT-1) / 10 * 3 + 2)

/* Path for various daemon things: env vars can override. */
const char *xs_daemon_rundir(void);
const char *xs_daemon_socket(void);
const char *xs_daemon_socket_ro(void);

/* Convert strings to permissions.  False if a problem. */
bool xs_strings_to_perms(struct xs_permissions *perms, unsigned int num,
			 const char *strings);

#endif /* XENSTORE_LIB_H */
