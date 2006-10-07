/*
  Copyright (c) 2006 XenSource, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/

#ifndef XEN_COMMON_H
#define XEN_COMMON_H


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "xen_host_decl.h"


typedef bool (*xen_result_func)(const void *data, size_t len,
                                void *result_handle);


/**
 * len does not include a terminating \0.
 */
typedef int (*xen_call_func)(const void *, size_t len, void *user_handle,
                             void *result_handle,
                             xen_result_func result_func);


typedef struct
{
    xen_call_func call_func;
    void *handle;
    const char *session_id;
    bool ok;
    char **error_description;
    int error_description_count;
} xen_session;


struct xen_task_;
typedef struct xen_task_ * xen_task_id;


typedef struct
{
    int progress;
    long eta;
    /* !!! RESULT */
}  xen_task_status;


typedef struct
{
    int major;
    int minor;
    int patch;
    char *extraversion;
} xen_version;


/**
 * Free the given xen_version, and all referenced values.
 */
extern void xen_version_free(xen_version *version);


/**
 * Return the version of this client-side library.  This will be the major,
 * minor, and extraversion of the Xen release with which it was released,
 * plus the library's own version as the patch.
 */
extern xen_version *xen_get_client_side_version();


extern bool
xen_uuid_string_to_bytes(char *uuid, char **bytes);


extern bool
xen_uuid_bytes_to_string(char *bytes, char **uuid);


extern void
xen_uuid_free(char *uuid);


extern void
xen_uuid_bytes_free(char *bytes);


/**
 * Initialise this library.  Call this before starting to use this library.
 * Note that since this library depends upon libxml2, you should also call
 * xmlInitParser as appropriate for your program.
 */
extern
void xen_init(void);


/**
 * Clear up this library.  Call when you have finished using this library.
 * Note that since this library depends upon libxml2, you should also call
 * xmlCleanupParser as appropriate for your program.
 */
extern
void xen_fini(void);


/**
 * Log in at the server, and allocate a xen_session to represent this session.
 */
extern xen_session *
xen_session_login_with_password(xen_call_func call_func, void *handle,
                                const char *uname, const char *pwd);


/**
 * Log out at the server, and free the xen_session.
 */
extern void
xen_session_logout(xen_session *session);


/**
 * Set *result to be a handle to the host to which this session is connected.
 */
extern int
xen_session_get_this_host(xen_session *session, xen_host *result);


#endif
