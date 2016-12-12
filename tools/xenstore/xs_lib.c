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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "xenstore_lib.h"

/* Common routines for the Xen store daemon and client library. */

const char *xs_daemon_rootdir(void)
{
	char *s = getenv("XENSTORED_ROOTDIR");
	return (s ? s : XEN_LIB_STORED);
}

const char *xs_daemon_rundir(void)
{
	char *s = getenv("XENSTORED_RUNDIR");
	return (s ? s : XEN_RUN_STORED);
}

static const char *xs_daemon_path(void)
{
	static char buf[PATH_MAX];
	char *s = getenv("XENSTORED_PATH");
	if (s)
		return s;
	if (snprintf(buf, sizeof(buf), "%s/socket",
		     xs_daemon_rundir()) >= PATH_MAX)
		return NULL;
	return buf;
}

const char *xs_daemon_tdb(void)
{
	static char buf[PATH_MAX];
	snprintf(buf, sizeof(buf), "%s/tdb", xs_daemon_rootdir());
	return buf;
}

const char *xs_daemon_socket(void)
{
	return xs_daemon_path();
}

const char *xs_daemon_socket_ro(void)
{
	static char buf[PATH_MAX];
	const char *s = xs_daemon_path();
	if (s == NULL)
		return NULL;
	if (snprintf(buf, sizeof(buf), "%s_ro", s) >= PATH_MAX)
		return NULL;
	return buf;
}

const char *xs_domain_dev(void)
{
	char *s = getenv("XENSTORED_PATH");
	if (s)
		return s;
#if defined(__RUMPUSER_XEN__) || defined(__RUMPRUN__)
	return "/dev/xen/xenbus";
#elif defined(__linux__)
	if (access("/dev/xen/xenbus", F_OK) == 0)
		return "/dev/xen/xenbus";
	return "/proc/xen/xenbus";
#elif defined(__NetBSD__)
	return "/kern/xen/xenbus";
#elif defined(__FreeBSD__)
	return "/dev/xen/xenstore";
#else
	return "/dev/xen/xenbus";
#endif
}

/* Simple routines for writing to sockets, etc. */
bool xs_write_all(int fd, const void *data, unsigned int len)
{
	while (len) {
		int done;

		done = write(fd, data, len);
		if (done < 0 && errno == EINTR)
			continue;
		if (done <= 0)
			return false;
		data += done;
		len -= done;
	}

	return true;
}

/* Convert strings to permissions.  False if a problem. */
bool xs_strings_to_perms(struct xs_permissions *perms, unsigned int num,
			 const char *strings)
{
	const char *p;
	char *end;
	unsigned int i;

	for (p = strings, i = 0; i < num; i++) {
		/* "r", "w", or "b" for both. */
		switch (*p) {
		case 'r':
			perms[i].perms = XS_PERM_READ;
			break;
		case 'w':
			perms[i].perms = XS_PERM_WRITE;
			break;
		case 'b':
			perms[i].perms = XS_PERM_READ|XS_PERM_WRITE;
			break;
		case 'n':
			perms[i].perms = XS_PERM_NONE;
			break;
		default:
			errno = EINVAL;
			return false;
		} 
		p++;
		perms[i].id = strtol(p, &end, 0);
		if (*end || !*p) {
			errno = EINVAL;
			return false;
		}
		p = end + 1;
	}
	return true;
}

/* Convert permissions to a string (up to len MAX_STRLEN(unsigned int)+1). */
bool xs_perm_to_string(const struct xs_permissions *perm,
                       char *buffer, size_t buf_len)
{
	switch ((int)perm->perms) {
	case XS_PERM_WRITE:
		*buffer = 'w';
		break;
	case XS_PERM_READ:
		*buffer = 'r';
		break;
	case XS_PERM_READ|XS_PERM_WRITE:
		*buffer = 'b';
		break;
	case XS_PERM_NONE:
		*buffer = 'n';
		break;
	default:
		errno = EINVAL;
		return false;
	}
	snprintf(buffer+1, buf_len-1, "%i", (int)perm->id);
	return true;
}

/* Given a string and a length, count how many strings (nul terms). */
unsigned int xs_count_strings(const char *strings, unsigned int len)
{
	unsigned int num;
	const char *p;

	for (p = strings, num = 0; p < strings + len; p++)
		if (*p == '\0')
			num++;

	return num;
}
