/******************************************************************************
 * xc_compression.c
 *
 * Checkpoint Compression using Page Delta Algorithm.
 * - A LRU cache of recently dirtied guest pages is maintained.
 * - For each dirty guest page in the checkpoint, if a previous version of the
 * page exists in the cache, XOR both pages and send the non-zero sections
 * to the receiver. The cache is then updated with the newer copy of guest page.
 * - The receiver will XOR the non-zero sections against its copy of the guest
 * page, thereby bringing the guest page up-to-date with the sender side.
 *
 * Copyright (c) 2011 Shriram Rajagopalan (rshriram@cs.ubc.ca).
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include "xc_private.h"
#include "xenctrl.h"
#include "xg_save_restore.h"
#include "xg_private.h"
#include "xc_dom.h"

/* Page Cache for Delta Compression*/
#define DELTA_CACHE_SIZE (XC_PAGE_SIZE * 8192)

/* Internal page buffer to hold dirty pages of a checkpoint,
 * to be compressed after the domain is resumed for execution.
 */
#define PAGE_BUFFER_SIZE (XC_PAGE_SIZE * 8192)

struct cache_page
{
    char *page;
    xen_pfn_t pfn;
    struct cache_page *next;
    struct cache_page *prev;
};

struct compression_ctx
{
    /* compression buffer - holds compressed data */
    char *compbuf;
    unsigned long compbuf_size;
    unsigned long compbuf_pos;

    /* Page buffer to hold pages to be compressed */
    char *inputbuf;
    /* pfns of pages to be compressed */
    xen_pfn_t *sendbuf_pfns;
    unsigned int pfns_len;
    unsigned int pfns_index;

    /* Compression Cache (LRU) */
    char *cache_base;
    struct cache_page **pfn2cache;
    struct cache_page *cache;
    struct cache_page *page_list_head;
    struct cache_page *page_list_tail;
    unsigned long dom_pfnlist_size;
};

#define RUNFLAG 0
#define SKIPFLAG ((char)128)
#define FLAGMASK SKIPFLAG
#define LENMASK ((char)127)

/*
 * see xg_save_restore.h for details on the compressed stream format.
 * delta size = 4 bytes.
 * run header = 1 byte (1 bit for runtype, 7bits for run length).
 *  i.e maximum size of a run = 127 * 4 = 508 bytes.
 * Worst case compression: Entire page has changed.
 * In the worst case, the size of the compressed page is
 *  8 runs of 508 bytes + 1 run of 32 bytes + 9 run headers 
 *  = 4105 bytes.
 * We could detect this worst case and send the entire page with a
 * FULL_PAGE marker, reducing the total size to 4097 bytes. The cost
 * of this size reduction is an additional memcpy, on top of two previous
 * memcpy (to the compressed stream and the cache page in the for loop).
 *
 * We might as well sacrifice an extra 8 bytes instead of a memcpy.
 */
#define WORST_COMP_PAGE_SIZE (XC_PAGE_SIZE + 9)

/*
 * A zero length skip indicates full page.
 */
#define EMPTY_PAGE 0
#define FULL_PAGE SKIPFLAG
#define FULL_PAGE_SIZE (XC_PAGE_SIZE + 1)
#define MAX_DELTAS (XC_PAGE_SIZE/sizeof(uint32_t))

/*
 * Add a pagetable page or a new page (uncached)
 * if srcpage is a pagetable page, cache_page is null.
 * if srcpage is a page that was not previously in the cache,
 *  cache_page points to a free page slot in the cache where
 *  this new page can be copied to.
 */
static int add_full_page(comp_ctx *ctx, char *srcpage, char *cache_page)
{
    char *dest = (ctx->compbuf + ctx->compbuf_pos);

    if ( (ctx->compbuf_pos + FULL_PAGE_SIZE) > ctx->compbuf_size)
        return -1;

    if (cache_page)
        memcpy(cache_page, srcpage, XC_PAGE_SIZE);
    dest[0] = FULL_PAGE;
    memcpy(&dest[1], srcpage, XC_PAGE_SIZE);
    ctx->compbuf_pos += FULL_PAGE_SIZE;

    return FULL_PAGE_SIZE;
}

static int compress_page(comp_ctx *ctx, char *srcpage, char *cache_page)
{
    char *dest = (ctx->compbuf + ctx->compbuf_pos);
    uint32_t *new, *old;

    int off, runptr = 0;
    int wascopying = 0, copying = 0, bytes_skipped = 0;
    int complen = 0, pageoff = 0, runbytes = 0;

    char runlen = 0;

    if ( (ctx->compbuf_pos + WORST_COMP_PAGE_SIZE) > ctx->compbuf_size)
        return -1;

    /*
     * There are no alignment issues here since srcpage is
     * domU's page passed from xc_domain_save and cache_page is
     * a ptr to cache page (cache is page aligned).
     */
    new = (uint32_t*)srcpage;
    old = (uint32_t*)cache_page;

    for (off = 0; off <= MAX_DELTAS; off++)
    {
        /*
         * At (off == MAX_DELTAS), we are processing the last run
         * in the page. Since there is no XORing, make wascopying != copying
         * to satisfy the if-block below.
         */
        copying = ((off < MAX_DELTAS) ? (old[off] != new[off]) : !wascopying);

        if (runlen)
        {
            /* switching between run types or current run is full */
            if ( (wascopying != copying) || (runlen == LENMASK) )
            {
                runbytes = runlen * sizeof(uint32_t);
                runlen |= (wascopying ? RUNFLAG : SKIPFLAG);
                dest[complen++] = runlen;

                if (wascopying) /* RUNFLAG */
                {
                    pageoff = runptr * sizeof(uint32_t);
                    memcpy(dest + complen, srcpage + pageoff, runbytes);
                    memcpy(cache_page + pageoff, srcpage + pageoff, runbytes);
                    complen += runbytes;
                }
                else /* SKIPFLAG */
                {
                    bytes_skipped += runbytes;
                }

                runlen = 0;
                runptr = off;
            }
        }
        runlen++;
        wascopying = copying;
    }

    /*
     * Check for empty page.
     */
    if (bytes_skipped == XC_PAGE_SIZE)
    {
        complen = 1;
        dest[0] = EMPTY_PAGE;
    }
    ctx->compbuf_pos += complen;

    return complen;
}

static
char *get_cache_page(comp_ctx *ctx, xen_pfn_t pfn,
                     int *israw)
{
    struct cache_page *item = NULL;

    item = ctx->pfn2cache[pfn];

    if (!item)
    {
        *israw = 1;

        /* If the list is full, evict a page from the tail end. */
        item = ctx->page_list_tail;
        if (item->pfn != INVALID_PFN)
            ctx->pfn2cache[item->pfn] = NULL;

        item->pfn = pfn;
        ctx->pfn2cache[pfn] = item;
    }
        
    /* 	if requested item is in cache move to head of list */
    if (item != ctx->page_list_head)
    {
        if (item == ctx->page_list_tail)
        {
            /* item at tail of list. */
            ctx->page_list_tail = item->prev;
            (ctx->page_list_tail)->next = NULL;
        }
        else
        {
            /* item in middle of list */
            item->prev->next = item->next;
            item->next->prev = item->prev;
        }

        item->prev = NULL;
        item->next = ctx->page_list_head;
        (ctx->page_list_head)->prev = item;
        ctx->page_list_head = item;
    }

    return (ctx->page_list_head)->page;
}

/* Remove pagetable pages from cache and move to tail, as free pages */
static
void invalidate_cache_page(comp_ctx *ctx, xen_pfn_t pfn)
{
    struct cache_page *item = NULL;

    item = ctx->pfn2cache[pfn];
    if (item)
    {
        if (item != ctx->page_list_tail)
        {
            /* item at head of list */
            if (item == ctx->page_list_head)
            {
                ctx->page_list_head = (ctx->page_list_head)->next;
                (ctx->page_list_head)->prev = NULL;
            }
            else /* item in middle of list */
            {            
                item->prev->next = item->next;
                item->next->prev = item->prev;
            }

            item->next = NULL;
            item->prev = ctx->page_list_tail;
            (ctx->page_list_tail)->next = item;
            ctx->page_list_tail = item;
        }
        ctx->pfn2cache[pfn] = NULL;
        (ctx->page_list_tail)->pfn = INVALID_PFN;
    }
}

int xc_compression_add_page(xc_interface *xch, comp_ctx *ctx,
                            char *page, xen_pfn_t pfn, int israw)
{
    if (pfn > ctx->dom_pfnlist_size)
    {
        ERROR("Invalid pfn passed into "
              "xc_compression_add_page %" PRIpfn "\n", pfn);
        return -2;
    }

    /* pagetable page */
    if (israw)
        invalidate_cache_page(ctx, pfn);
    ctx->sendbuf_pfns[ctx->pfns_len] = israw ? INVALID_PFN : pfn;
    memcpy(ctx->inputbuf + ctx->pfns_len * XC_PAGE_SIZE, page, XC_PAGE_SIZE);
    ctx->pfns_len++;

    /* check if we have run out of space. If so,
     * we need to synchronously compress the pages and flush them out
     */
    if (ctx->pfns_len == NRPAGES(PAGE_BUFFER_SIZE))
        return -1;
    return 0;
}

int xc_compression_compress_pages(xc_interface *xch, comp_ctx *ctx,
                                  char *compbuf, unsigned long compbuf_size,
                                  unsigned long *compbuf_len)
{
    char *cache_copy = NULL, *current_page = NULL;
    int israw, rc = 1;

    if (!ctx->pfns_len || (ctx->pfns_index == ctx->pfns_len)) {
        ctx->pfns_len = ctx->pfns_index = 0;
        return 0;
    }

    ctx->compbuf_pos = 0;
    ctx->compbuf = compbuf;
    ctx->compbuf_size = compbuf_size;

    for (; ctx->pfns_index < ctx->pfns_len; ctx->pfns_index++)
    {
        israw = 0;
        cache_copy = NULL;
        current_page = ctx->inputbuf + ctx->pfns_index * XC_PAGE_SIZE;

        if (ctx->sendbuf_pfns[ctx->pfns_index] == INVALID_PFN)
            israw = 1;
        else
            cache_copy = get_cache_page(ctx,
                                        ctx->sendbuf_pfns[ctx->pfns_index],
                                        &israw);

        if (israw)
            rc = (add_full_page(ctx, current_page, cache_copy) >= 0);
        else
            rc = (compress_page(ctx, current_page, cache_copy) >= 0);

        if ( !rc )
        {
            /* Out of space in outbuf! flush and come back */
            rc = -1;
            break;
        }
    }
    if (compbuf_len)
        *compbuf_len = ctx->compbuf_pos;

    return rc;
}

inline
void xc_compression_reset_pagebuf(xc_interface *xch, comp_ctx *ctx)
{
    ctx->pfns_index = ctx->pfns_len = 0;
}

int xc_compression_uncompress_page(xc_interface *xch, char *compbuf,
                                   unsigned long compbuf_size,
                                   unsigned long *compbuf_pos, char *destpage)
{
    unsigned long pos;
    unsigned int len = 0, pagepos = 0;
    char flag;

    pos = *compbuf_pos;
    if (pos >= compbuf_size)
    {
        ERROR("Out of bounds exception in compression buffer (a):"
              "read ptr:%lu, bufsize = %lu\n",
              *compbuf_pos, compbuf_size);
        return -1;
    }

    switch (compbuf[pos])
    {
    case EMPTY_PAGE:
        pos++;
        break;

    case FULL_PAGE:
        {
            /* Check if the input buffer has 4KB of data */
            if ((pos + FULL_PAGE_SIZE) > compbuf_size)
            {
                ERROR("Out of bounds exception in compression buffer (b):"
                      "read ptr = %lu, bufsize = %lu\n",
                      *compbuf_pos, compbuf_size);
                return -1;
            }
            memcpy(destpage, &compbuf[pos + 1], XC_PAGE_SIZE);
            pos += FULL_PAGE_SIZE;
        }
        break;

    default: /* Normal page with one or more runs */
        {
            do
            {
                flag = compbuf[pos] & FLAGMASK;
                len = (compbuf[pos] & LENMASK) * sizeof(uint32_t);
                /* Sanity Check: Zero-length runs are allowed only for
                 * FULL_PAGE and EMPTY_PAGE.
                 */
                if (!len)
                {
                    ERROR("Zero length run encountered for normal page: "
                          "buffer (d):read ptr = %lu, flag = %u, "
                          "bufsize = %lu, pagepos = %u\n",
                          pos, (unsigned int)flag, compbuf_size, pagepos);
                    return -1;
                }

                pos++;
                if (flag == RUNFLAG)
                {
                    /* Check if the input buffer has len bytes of data
                     * and whether it would fit in the destination page.
                     */
                    if (((pos + len) > compbuf_size)
                        || ((pagepos + len) > XC_PAGE_SIZE))
                    {
                        ERROR("Out of bounds exception in compression "
                              "buffer (c):read ptr = %lu, runlen = %u, "
                              "bufsize = %lu, pagepos = %u\n",
                              pos, len, compbuf_size, pagepos);
                        return -1;
                    }
                    memcpy(&destpage[pagepos], &compbuf[pos], len);
                    pos += len;
                }
                pagepos += len;
            } while ((pagepos < XC_PAGE_SIZE) && (pos < compbuf_size));

            /* Make sure we have copied/skipped 4KB worth of data */
            if (pagepos != XC_PAGE_SIZE)
            {
                ERROR("Invalid data in compression buffer:"
                      "read ptr = %lu, bufsize = %lu, pagepos = %u\n",
                      pos, compbuf_size, pagepos);
                return -1;
            }
        }
    }
    *compbuf_pos = pos;
    return 0;
}

void xc_compression_free_context(xc_interface *xch, comp_ctx *ctx)
{
    if (!ctx) return;

    free(ctx->inputbuf);
    free(ctx->sendbuf_pfns);
    free(ctx->cache_base);
    free(ctx->pfn2cache);
    free(ctx->cache);
    free(ctx);
}

comp_ctx *xc_compression_create_context(xc_interface *xch,
                                        unsigned long p2m_size)
{
    unsigned long i;
    comp_ctx *ctx = NULL;
    unsigned long num_cache_pages = DELTA_CACHE_SIZE/XC_PAGE_SIZE;

    ctx = (comp_ctx *)malloc(sizeof(comp_ctx));
    if (!ctx)
    {
        ERROR("Failed to allocate compression_ctx\n");
        goto error;
    }
    memset(ctx, 0, sizeof(comp_ctx));

    ctx->inputbuf = xc_memalign(xch, XC_PAGE_SIZE, PAGE_BUFFER_SIZE);
    if (!ctx->inputbuf)
    {
        ERROR("Failed to allocate page buffer\n");
        goto error;
    }

    ctx->cache_base = xc_memalign(xch, XC_PAGE_SIZE, DELTA_CACHE_SIZE);
    if (!ctx->cache_base)
    {
        ERROR("Failed to allocate delta cache\n");
        goto error;
    }

    ctx->sendbuf_pfns = malloc(NRPAGES(PAGE_BUFFER_SIZE) *
                               sizeof(xen_pfn_t));
    if (!ctx->sendbuf_pfns)
    {
        ERROR("Could not alloc sendbuf_pfns\n");
        goto error;
    }
    memset(ctx->sendbuf_pfns, -1,
           NRPAGES(PAGE_BUFFER_SIZE) * sizeof(xen_pfn_t));

    ctx->pfn2cache = calloc(p2m_size, sizeof(struct cache_page *));
    if (!ctx->pfn2cache)
    {
        ERROR("Could not alloc pfn2cache map\n");
        goto error;
    }

    ctx->cache = malloc(num_cache_pages * sizeof(struct cache_page));
    if (!ctx->cache)
    {
        ERROR("Could not alloc compression cache\n");
        goto error;
    }

    for (i = 0; i < num_cache_pages; i++)
    {
        ctx->cache[i].pfn = INVALID_PFN;
        ctx->cache[i].page = ctx->cache_base + i * XC_PAGE_SIZE;
        ctx->cache[i].prev = (i == 0) ? NULL : &(ctx->cache[i - 1]);
        ctx->cache[i].next = ((i+1) == num_cache_pages)? NULL :
            &(ctx->cache[i + 1]);
    }
    ctx->page_list_head = &(ctx->cache[0]);
    ctx->page_list_tail = &(ctx->cache[num_cache_pages -1]);
    ctx->dom_pfnlist_size = p2m_size;

    return ctx;
error:
    xc_compression_free_context(xch, ctx);
    return NULL;
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
