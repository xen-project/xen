/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>

#ifdef NEED_OWN_ASPRINTF

int vasprintf(char **buffer, const char *fmt, va_list ap)
{
    int size = 0;
    int nchars;

    *buffer = 0;

    nchars = vsnprintf(*buffer, 0, fmt, ap);

    if (nchars >= size)
    {
        char *tmpbuff;
        /* Reallocate buffer now that we know how much space is needed. */
        size = nchars+1;
        tmpbuff = (char*)realloc(*buffer, size);


        if (tmpbuff == NULL) { /* we need to free it*/
            free(*buffer);
            return -1;
        }

        *buffer=tmpbuff;
        /* Try again. */
        nchars = vsnprintf(*buffer, size, fmt, ap);
    }

    if (nchars < 0) return nchars;
    return size;
}

int asprintf(char **buffer, char *fmt, ...)
{
    int status;
    va_list ap;

    va_start (ap, fmt);
    status = vasprintf (buffer, fmt, ap);
    va_end (ap);
    return status;
}

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
