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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <malloc.h>

#include "xc_private.h"
#include "xg_private.h"

xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(HYPERCALL_BUFFER_NULL) = {
    .hbuf = NULL,
    .param_shadow = NULL,
    HYPERCALL_BUFFER_INIT_NO_BOUNCE
};

void *xc__hypercall_buffer_alloc_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages)
{
    size_t size = nr_pages * PAGE_SIZE;
    void *p;
#if defined(_POSIX_C_SOURCE) && !defined(__sun__)
    int ret;
    ret = posix_memalign(&p, PAGE_SIZE, size);
    if (ret != 0)
        return NULL;
#elif defined(__NetBSD__) || defined(__OpenBSD__)
    p = valloc(size);
#else
    p = memalign(PAGE_SIZE, size);
#endif

    if (!p)
        return NULL;

#ifndef __sun__
    if ( mlock(p, size) < 0 )
    {
        free(p);
        return NULL;
    }
#endif

    b->hbuf = p;

    memset(p, 0, size);
    return b->hbuf;
}

void xc__hypercall_buffer_free_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages)
{
    if ( b->hbuf == NULL )
        return;

#ifndef __sun__
    (void) munlock(b->hbuf, nr_pages * PAGE_SIZE);
#endif

    free(b->hbuf);
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
