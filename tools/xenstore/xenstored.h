/* 
    Simple prototyle Xen Store Daemon providing simple tree-like database.
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
#ifndef _XENSTORED_H
#define _XENSTORED_H

enum xsd_sockmsg_type
{
	XS_DEBUG,
	XS_SHUTDOWN,
	XS_DIRECTORY,
	XS_READ,
	XS_GET_PERMS,
	XS_WATCH,
	XS_WATCH_ACK,
	XS_UNWATCH,
	XS_TRANSACTION_START,
	XS_TRANSACTION_END,
	XS_OP_READ_ONLY = XS_TRANSACTION_END,
	XS_INTRODUCE,
	XS_RELEASE,
	XS_GETDOMAINPATH,
	XS_WRITE,
	XS_MKDIR,
	XS_RM,
	XS_SET_PERMS,
	XS_WATCH_EVENT,
	XS_ERROR,
};

#define XS_WRITE_NONE "NONE"
#define XS_WRITE_CREATE "CREATE"
#define XS_WRITE_CREATE_EXCL "CREATE|EXCL"

/* We hand errors as strings, for portability. */
struct xsd_errors
{
	int errnum;
	const char *errstring;
};
#define XSD_ERROR(x) { x, #x }
static struct xsd_errors xsd_errors[] __attribute__((unused)) = {
	XSD_ERROR(EINVAL),
	XSD_ERROR(EACCES),
	XSD_ERROR(EEXIST),
	XSD_ERROR(EISDIR),
	XSD_ERROR(ENOENT),
	XSD_ERROR(ENOMEM),
	XSD_ERROR(ENOSPC),
	XSD_ERROR(EIO),
	XSD_ERROR(ENOTEMPTY),
	XSD_ERROR(ENOSYS),
	XSD_ERROR(EROFS),
	XSD_ERROR(EBUSY),
	XSD_ERROR(ETIMEDOUT),
	XSD_ERROR(EISCONN),
};
struct xsd_sockmsg
{
	u32 type;
	u32 len; 		/* Length of data following this. */

	/* Generally followed by nul-terminated string(s). */
};

#endif /* _XENSTORED_H */
