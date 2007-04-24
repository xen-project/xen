/*
 * Copyright (c) 2006 XenSource, Inc.
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

#include "xen/api/xen_host_decl.h"


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


typedef struct xen_session_record
{
    char *uuid;
    struct xen_host_record_opt *this_host;
    char *this_user;
    time_t last_active;
} xen_session_record;


/**
 * Allocate a xen_session_record.
 */
extern xen_session_record *
xen_session_record_alloc(void);


/**
 * Free the given xen_session_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_session_record_free(xen_session_record *record);


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
 * Clear any error condition recorded on this session.
 */
void
xen_session_clear_error(xen_session *session);


/**
 * Get the UUID of the second given session.  Set *result to point at a
 * string, yours to free.
 */
extern bool
xen_session_get_uuid(xen_session *session, char **result,
                     xen_session *self_session);


/**
 * Get the this_host field of the second given session.  Set *result to be a
 * handle to that host.
 */
extern bool
xen_session_get_this_host(xen_session *session, xen_host *result,
                          xen_session *self_session);


/**
 * Get the this_user field of the second given session.  Set *result to point
 * at a string, yours to free.
 */
extern bool
xen_session_get_this_user(xen_session *session, char **result,
                          xen_session *self_session);


/**
 * Get the last_active field of the given session, and place it in *result.
 */
extern bool
xen_session_get_last_active(xen_session *session, time_t *result,
                            xen_session *self_session);

/**
 * Get a record containing the current state of the second given session.
 */
extern bool
xen_session_get_record(xen_session *session, xen_session_record **result,
                       xen_session *self_session);


#endif
