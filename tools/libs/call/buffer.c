/*
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

#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "private.h"

#define DBGPRINTF(_m...) \
    xtl_log(xcall->logger, XTL_DEBUG, -1, "xencall:buffer", _m)

#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))

pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static void cache_lock(xencall_handle *xcall)
{
    int saved_errno = errno;
    if ( xcall->flags & XENCALL_OPENFLAG_NON_REENTRANT )
        return;
    pthread_mutex_lock(&cache_mutex);
    /* Ignore pthread errors. */
    errno = saved_errno;
}

static void cache_unlock(xencall_handle *xcall)
{
    int saved_errno = errno;
    if ( xcall->flags & XENCALL_OPENFLAG_NON_REENTRANT )
        return;
    pthread_mutex_unlock(&cache_mutex);
    /* Ignore pthread errors. */
    errno = saved_errno;
}

static void *cache_alloc(xencall_handle *xcall, size_t nr_pages)
{
    void *p = NULL;

    cache_lock(xcall);

    xcall->buffer_total_allocations++;
    xcall->buffer_current_allocations++;
    if ( xcall->buffer_current_allocations > xcall->buffer_maximum_allocations )
        xcall->buffer_maximum_allocations = xcall->buffer_current_allocations;

    if ( nr_pages > 1 )
    {
        xcall->buffer_cache_toobig++;
    }
    else if ( xcall->buffer_cache_nr > 0 )
    {
        p = xcall->buffer_cache[--xcall->buffer_cache_nr];
        xcall->buffer_cache_hits++;
    }
    else
    {
        xcall->buffer_cache_misses++;
    }

    cache_unlock(xcall);

    return p;
}

static int cache_free(xencall_handle *xcall, void *p, size_t nr_pages)
{
    int rc = 0;

    cache_lock(xcall);

    xcall->buffer_total_releases++;
    xcall->buffer_current_allocations--;

    if ( nr_pages == 1 &&
         xcall->buffer_cache_nr < BUFFER_CACHE_SIZE )
    {
        xcall->buffer_cache[xcall->buffer_cache_nr++] = p;
        rc = 1;
    }

    cache_unlock(xcall);

    return rc;
}

void buffer_release_cache(xencall_handle *xcall)
{
    void *p;

    cache_lock(xcall);

    DBGPRINTF("total allocations:%d total releases:%d",
              xcall->buffer_total_allocations,
              xcall->buffer_total_releases);
    DBGPRINTF("current allocations:%d maximum allocations:%d",
              xcall->buffer_current_allocations,
              xcall->buffer_maximum_allocations);
    DBGPRINTF("cache current size:%d",
              xcall->buffer_cache_nr);
    DBGPRINTF("cache hits:%d misses:%d toobig:%d",
              xcall->buffer_cache_hits,
              xcall->buffer_cache_misses,
              xcall->buffer_cache_toobig);

    while ( xcall->buffer_cache_nr > 0 )
    {
        p = xcall->buffer_cache[--xcall->buffer_cache_nr];
        osdep_free_pages(xcall, p, 1);
    }

    cache_unlock(xcall);
}

void *xencall_alloc_buffer_pages(xencall_handle *xcall, size_t nr_pages)
{
    void *p = cache_alloc(xcall, nr_pages);

    if ( !p )
        p = osdep_alloc_pages(xcall, nr_pages);

    if (!p)
        return NULL;

    memset(p, 0, nr_pages * PAGE_SIZE);

    return p;
}

void xencall_free_buffer_pages(xencall_handle *xcall, void *p, size_t nr_pages)
{
    if ( p == NULL )
        return;

    if ( !cache_free(xcall, p, nr_pages) )
        osdep_free_pages(xcall, p, nr_pages);
}

struct allocation_header {
    int nr_pages;
};

void *xencall_alloc_buffer(xencall_handle *xcall, size_t size)
{
    size_t actual_size = ROUNDUP(size + sizeof(struct allocation_header), PAGE_SHIFT);
    int nr_pages = actual_size >> PAGE_SHIFT;
    struct allocation_header *hdr;

    hdr = xencall_alloc_buffer_pages(xcall, nr_pages);
    if ( hdr == NULL )
        return NULL;

    hdr->nr_pages = nr_pages;

    return (void *)(hdr+1);
}

void xencall_free_buffer(xencall_handle *xcall, void *p)
{
    struct allocation_header *hdr;

    if (p == NULL)
        return;

    hdr = p;
    --hdr;

    xencall_free_buffer_pages(xcall, hdr, hdr->nr_pages);
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
