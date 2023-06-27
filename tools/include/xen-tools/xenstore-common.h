/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Common functions for libxenstore, xenstored and xenstore-clients. */

#ifndef __XEN_TOOLS_XENSTORE_COMMON__
#define __XEN_TOOLS_XENSTORE_COMMON__

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <xenstore_lib.h>

static inline const char *xenstore_daemon_rundir(void)
{
    char *s = getenv("XENSTORED_RUNDIR");

    return s ? s : XEN_RUN_STORED;
}

static inline const char *xenstore_daemon_path(void)
{
    static char buf[PATH_MAX];
    char *s = getenv("XENSTORED_PATH");

    if ( s )
        return s;

    if ( snprintf(buf, sizeof(buf), "%s/socket", xenstore_daemon_rundir()) >=
         PATH_MAX )
        return NULL;

    return buf;
}

/* Convert strings to permissions.  False if a problem. */
static inline bool xenstore_strings_to_perms(struct xs_permissions *perms,
                                             unsigned int num,
                                             const char *strings)
{
    const char *p;
    char *end;
    unsigned int i;

    for ( p = strings, i = 0; i < num; i++ )
    {
        /* "r", "w", or "b" for both. */
        switch ( *p )
        {
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
        if ( *end || !*p )
        {
            errno = EINVAL;
            return false;
        }

        p = end + 1;
    }

    return true;
}

/* Convert permissions to a string (up to len MAX_STRLEN(unsigned int)+1). */
static inline bool xenstore_perm_to_string(const struct xs_permissions *perm,
                                           char *buffer, size_t buf_len)
{
    switch ( (int)perm->perms & ~XS_PERM_IGNORE )
    {
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

    snprintf(buffer + 1, buf_len - 1, "%i", (int)perm->id);

    return true;
}

/* Given a string and a length, count how many strings (nul terms). */
static inline unsigned int xenstore_count_strings(const char *strings,
                                                  unsigned int len)
{
    unsigned int num;
    const char *p;

    for ( p = strings, num = 0; p < strings + len; p++ )
        if ( *p == '\0' )
            num++;

    return num;
}
#endif /* __XEN_TOOLS_XENSTORE_COMMON__ */
