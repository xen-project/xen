/*
 * Copyright (c) 2010, Citrix Systems, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include "xc_private.h"
#include "xg_private.h"

xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(HYPERCALL_BUFFER_NULL) = {
    .hbuf = NULL,
    .param_shadow = NULL,
    HYPERCALL_BUFFER_INIT_NO_BOUNCE
};

void *xc__hypercall_buffer_alloc_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages)
{
    void *p = xencall_alloc_buffer_pages(xch->xcall, nr_pages);

    if (!p)
        return NULL;

    b->hbuf = p;

    return b->hbuf;
}

void xc__hypercall_buffer_free_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages)
{
    xencall_free_buffer_pages(xch->xcall, b->hbuf, nr_pages);
}

void *xc__hypercall_buffer_alloc(xc_interface *xch, xc_hypercall_buffer_t *b, size_t size)
{
    void *p = xencall_alloc_buffer(xch->xcall, size);

    if (!p)
        return NULL;

    b->hbuf = p;

    return b->hbuf;
}

void xc__hypercall_buffer_free(xc_interface *xch, xc_hypercall_buffer_t *b)
{
    xencall_free_buffer(xch->xcall, b->hbuf);
}

int xc__hypercall_bounce_pre(xc_interface *xch, xc_hypercall_buffer_t *b)
{
    void *p;

    /*
     * Catch hypercall buffer declared other than with DECLARE_HYPERCALL_BOUNCE.
     */
    if ( b->ubuf == (void *)-1 || b->dir == XC_HYPERCALL_BUFFER_BOUNCE_NONE )
        abort();

    /*
     * Don't need to bounce a NULL buffer.
     */
    if ( b->ubuf == NULL )
    {
        b->hbuf = NULL;
        return 0;
    }

    p = xc__hypercall_buffer_alloc(xch, b, b->sz);
    if ( p == NULL )
        return -1;

    if ( b->dir == XC_HYPERCALL_BUFFER_BOUNCE_IN || b->dir == XC_HYPERCALL_BUFFER_BOUNCE_BOTH )
        memcpy(b->hbuf, b->ubuf, b->sz);

    return 0;
}

void xc__hypercall_bounce_post(xc_interface *xch, xc_hypercall_buffer_t *b)
{
    /*
     * Catch hypercall buffer declared other than with DECLARE_HYPERCALL_BOUNCE.
     */
    if ( b->ubuf == (void *)-1 || b->dir == XC_HYPERCALL_BUFFER_BOUNCE_NONE )
        abort();

    if ( b->hbuf == NULL )
        return;

    if ( b->dir == XC_HYPERCALL_BUFFER_BOUNCE_OUT || b->dir == XC_HYPERCALL_BUFFER_BOUNCE_BOTH )
        memcpy(b->ubuf, b->hbuf, b->sz);

    xc__hypercall_buffer_free(xch, b);
}

struct xc_hypercall_buffer_array {
    unsigned max_bufs;
    xc_hypercall_buffer_t *bufs;
};

xc_hypercall_buffer_array_t *xc_hypercall_buffer_array_create(xc_interface *xch,
                                                              unsigned n)
{
    xc_hypercall_buffer_array_t *array;
    xc_hypercall_buffer_t *bufs = NULL;

    array = malloc(sizeof(*array));
    if ( array == NULL )
        goto error;

    bufs = calloc(n, sizeof(*bufs));
    if ( bufs == NULL )
        goto error;

    array->max_bufs = n;
    array->bufs     = bufs;

    return array;

error:
    free(bufs);
    free(array);
    return NULL;
}

void *xc__hypercall_buffer_array_alloc(xc_interface *xch,
                                       xc_hypercall_buffer_array_t *array,
                                       unsigned index,
                                       xc_hypercall_buffer_t *hbuf,
                                       size_t size)
{
    void *buf;

    if ( index >= array->max_bufs || array->bufs[index].hbuf )
        abort();

    buf = xc__hypercall_buffer_alloc(xch, hbuf, size);
    if ( buf )
        array->bufs[index] = *hbuf;
    return buf;
}

void *xc__hypercall_buffer_array_get(xc_interface *xch,
                                     xc_hypercall_buffer_array_t *array,
                                     unsigned index,
                                     xc_hypercall_buffer_t *hbuf)
{
    if ( index >= array->max_bufs || array->bufs[index].hbuf == NULL )
        abort();

    *hbuf = array->bufs[index];
    return array->bufs[index].hbuf;
}

void xc_hypercall_buffer_array_destroy(xc_interface *xc,
                                       xc_hypercall_buffer_array_t *array)
{
    unsigned i;

    if ( array == NULL )
        return;

    for (i = 0; i < array->max_bufs; i++ )
        xc__hypercall_buffer_free(xc, &array->bufs[i]);
    free(array->bufs);
    free(array);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
