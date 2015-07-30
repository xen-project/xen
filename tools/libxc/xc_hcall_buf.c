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
#include <pthread.h>

#include "xc_private.h"
#include "xg_private.h"

xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(HYPERCALL_BUFFER_NULL) = {
    .hbuf = NULL,
    .param_shadow = NULL,
    HYPERCALL_BUFFER_INIT_NO_BOUNCE
};

pthread_mutex_t hypercall_buffer_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static void hypercall_buffer_cache_lock(xc_interface *xch)
{
    int saved_errno = errno;
    if ( xch->flags & XC_OPENFLAG_NON_REENTRANT )
        return;
    pthread_mutex_lock(&hypercall_buffer_cache_mutex);
    /* Ignore pthread errors. */
    errno = saved_errno;
}

static void hypercall_buffer_cache_unlock(xc_interface *xch)
{
    int saved_errno = errno;
    if ( xch->flags & XC_OPENFLAG_NON_REENTRANT )
        return;
    pthread_mutex_unlock(&hypercall_buffer_cache_mutex);
    /* Ignore pthread errors. */
    errno = saved_errno;
}

static void *hypercall_buffer_cache_alloc(xc_interface *xch, int nr_pages)
{
    void *p = NULL;

    hypercall_buffer_cache_lock(xch);

    xch->hypercall_buffer_total_allocations++;
    xch->hypercall_buffer_current_allocations++;
    if ( xch->hypercall_buffer_current_allocations > xch->hypercall_buffer_maximum_allocations )
        xch->hypercall_buffer_maximum_allocations = xch->hypercall_buffer_current_allocations;

    if ( nr_pages > 1 )
    {
        xch->hypercall_buffer_cache_toobig++;
    }
    else if ( xch->hypercall_buffer_cache_nr > 0 )
    {
        p = xch->hypercall_buffer_cache[--xch->hypercall_buffer_cache_nr];
        xch->hypercall_buffer_cache_hits++;
    }
    else
    {
        xch->hypercall_buffer_cache_misses++;
    }

    hypercall_buffer_cache_unlock(xch);

    return p;
}

static int hypercall_buffer_cache_free(xc_interface *xch, void *p, int nr_pages)
{
    int rc = 0;

    hypercall_buffer_cache_lock(xch);

    xch->hypercall_buffer_total_releases++;
    xch->hypercall_buffer_current_allocations--;

    if ( nr_pages == 1 && xch->hypercall_buffer_cache_nr < HYPERCALL_BUFFER_CACHE_SIZE )
    {
        xch->hypercall_buffer_cache[xch->hypercall_buffer_cache_nr++] = p;
        rc = 1;
    }

    hypercall_buffer_cache_unlock(xch);

    return rc;
}

void xc__hypercall_buffer_cache_release(xc_interface *xch)
{
    void *p;

    hypercall_buffer_cache_lock(xch);

    DBGPRINTF("hypercall buffer: total allocations:%d total releases:%d",
              xch->hypercall_buffer_total_allocations,
              xch->hypercall_buffer_total_releases);
    DBGPRINTF("hypercall buffer: current allocations:%d maximum allocations:%d",
              xch->hypercall_buffer_current_allocations,
              xch->hypercall_buffer_maximum_allocations);
    DBGPRINTF("hypercall buffer: cache current size:%d",
              xch->hypercall_buffer_cache_nr);
    DBGPRINTF("hypercall buffer: cache hits:%d misses:%d toobig:%d",
              xch->hypercall_buffer_cache_hits,
              xch->hypercall_buffer_cache_misses,
              xch->hypercall_buffer_cache_toobig);

    while ( xch->hypercall_buffer_cache_nr > 0 )
    {
        p = xch->hypercall_buffer_cache[--xch->hypercall_buffer_cache_nr];
        xch->ops->u.privcmd.free_hypercall_buffer(xch, xch->ops_handle, p, 1);
    }

    hypercall_buffer_cache_unlock(xch);
}

void *xc__hypercall_buffer_alloc_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages)
{
    void *p = hypercall_buffer_cache_alloc(xch, nr_pages);

    if ( !p )
        p = xch->ops->u.privcmd.alloc_hypercall_buffer(xch, xch->ops_handle, nr_pages);

    if (!p)
        return NULL;

    b->hbuf = p;

    memset(p, 0, nr_pages * PAGE_SIZE);

    return b->hbuf;
}

void xc__hypercall_buffer_free_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages)
{
    if ( b->hbuf == NULL )
        return;

    if ( !hypercall_buffer_cache_free(xch, b->hbuf, nr_pages) )
        xch->ops->u.privcmd.free_hypercall_buffer(xch, xch->ops_handle, b->hbuf, nr_pages);
}

struct allocation_header {
    int nr_pages;
};

void *xc__hypercall_buffer_alloc(xc_interface *xch, xc_hypercall_buffer_t *b, size_t size)
{
    size_t actual_size = ROUNDUP(size + sizeof(struct allocation_header), PAGE_SHIFT);
    int nr_pages = actual_size >> PAGE_SHIFT;
    struct allocation_header *hdr;

    hdr = xc__hypercall_buffer_alloc_pages(xch, b, nr_pages);
    if ( hdr == NULL )
        return NULL;

    b->hbuf = (void *)(hdr+1);

    hdr->nr_pages = nr_pages;
    return b->hbuf;
}

void xc__hypercall_buffer_free(xc_interface *xch, xc_hypercall_buffer_t *b)
{
    struct allocation_header *hdr;

    if (b->hbuf == NULL)
        return;

    hdr = b->hbuf;
    b->hbuf = --hdr;

    xc__hypercall_buffer_free_pages(xch, b, hdr->nr_pages);
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
     * Do need to bounce a NULL buffer.
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
