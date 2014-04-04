/*
 * Xen domain builder -- core bits.
 *
 * The core code goes here:
 *   - allocate and release domain structs.
 *   - memory management functions.
 *   - misc helper functions.
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
 *
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <zlib.h>
#include <assert.h>

#include "xg_private.h"
#include "xc_dom.h"

/* ------------------------------------------------------------------------ */
/* debugging                                                                */



static const char *default_logfile = "/var/log/xen/domain-builder-ng.log";

int xc_dom_loginit(xc_interface *xch) {
    if (xch->dombuild_logger) return 0;

    if (!xch->dombuild_logger_file) {
        xch->dombuild_logger_file = fopen(default_logfile, "a");
        if (!xch->dombuild_logger_file) {
            PERROR("Could not open logfile `%s'", default_logfile);
            return -1;
        }
    }
    
    xch->dombuild_logger = xch->dombuild_logger_tofree =
        (xentoollog_logger*)
        xtl_createlogger_stdiostream(xch->dombuild_logger_file, XTL_DETAIL,
             XTL_STDIOSTREAM_SHOW_DATE|XTL_STDIOSTREAM_SHOW_PID);
    if (!xch->dombuild_logger)
        return -1;

    xc_dom_printf(xch, "### ----- xc domain builder logfile opened -----");

    return 0;
}

void xc_dom_printf(xc_interface *xch, const char *fmt, ...)
{
    va_list args;
    if (!xch->dombuild_logger) return;
    va_start(args, fmt);
    xtl_logv(xch->dombuild_logger, XTL_DETAIL, -1, "domainbuilder", fmt, args);
    va_end(args);
}

void xc_dom_panic_func(xc_interface *xch,
                       const char *file, int line, xc_error_code err,
                       const char *fmt, ...)
{
    va_list args;
    char msg[XC_MAX_ERROR_MSG_LEN];

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    msg[sizeof(msg)-1] = 0;
    
    xc_report(xch,
              xch->dombuild_logger ? xch->dombuild_logger : xch->error_handler,
              XTL_ERROR, err, "panic: %s:%d: %s",
              file, line, msg);
}

static void print_mem(struct xc_dom_image *dom, const char *name, size_t mem)
{
    if ( mem > (32 * 1024 * 1024) )
        DOMPRINTF("%-24s : %zd MB", name, mem / (1024 * 1024));
    else if ( mem > (32 * 1024) )
        DOMPRINTF("%-24s : %zd kB", name, mem / 1024);
    else
        DOMPRINTF("%-24s : %zd bytes", name, mem);
}

void xc_dom_log_memory_footprint(struct xc_dom_image *dom)
{
    DOMPRINTF("domain builder memory footprint");
    DOMPRINTF("   allocated");
    print_mem(dom, "      malloc", dom->alloc_malloc);
    print_mem(dom, "      anon mmap", dom->alloc_mem_map);
    DOMPRINTF("   mapped");
    print_mem(dom, "      file mmap", dom->alloc_file_map);
    print_mem(dom, "      domU mmap", dom->alloc_domU_map);
}

/* ------------------------------------------------------------------------ */
/* simple memory pool                                                       */

void *xc_dom_malloc(struct xc_dom_image *dom, size_t size)
{
    struct xc_dom_mem *block;

    if ( size > SIZE_MAX - sizeof(*block) )
    {
        DOMPRINTF("%s: unreasonable allocation size", __FUNCTION__);
        return NULL;
    }
    block = malloc(sizeof(*block) + size);
    if ( block == NULL )
    {
        DOMPRINTF("%s: allocation failed", __FUNCTION__);
        return NULL;
    }
    memset(block, 0, sizeof(*block) + size);
    block->next = dom->memblocks;
    dom->memblocks = block;
    dom->alloc_malloc += sizeof(*block) + size;
    if ( size > (100 * 1024) )
        print_mem(dom, __FUNCTION__, size);
    return block->memory;
}

void *xc_dom_malloc_page_aligned(struct xc_dom_image *dom, size_t size)
{
    struct xc_dom_mem *block;

    block = malloc(sizeof(*block));
    if ( block == NULL )
    {
        DOMPRINTF("%s: allocation failed", __FUNCTION__);
        return NULL;
    }
    memset(block, 0, sizeof(*block));
    block->mmap_len = size;
    block->mmap_ptr = mmap(NULL, block->mmap_len,
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
                           -1, 0);
    if ( block->mmap_ptr == MAP_FAILED )
    {
        DOMPRINTF("%s: mmap failed", __FUNCTION__);
        free(block);
        return NULL;
    }
    block->next = dom->memblocks;
    dom->memblocks = block;
    dom->alloc_malloc += sizeof(*block);
    dom->alloc_mem_map += block->mmap_len;
    if ( size > (100 * 1024) )
        print_mem(dom, __FUNCTION__, size);
    return block->mmap_ptr;
}

void *xc_dom_malloc_filemap(struct xc_dom_image *dom,
                            const char *filename, size_t * size,
                            const size_t max_size)
{
    struct xc_dom_mem *block = NULL;
    int fd = -1;
    off_t offset;

    fd = open(filename, O_RDONLY);
    if ( fd == -1 ) {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "failed to open file: %s",
                     strerror(errno));
        goto err;
    }

    if ( (lseek(fd, 0, SEEK_SET) == -1) ||
         ((offset = lseek(fd, 0, SEEK_END)) == -1) ) {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "failed to seek on file: %s",
                     strerror(errno));
        goto err;
    }

    *size = offset;

    if ( max_size && *size > max_size )
    {
        xc_dom_panic(dom->xch, XC_OUT_OF_MEMORY,
                     "tried to map file which is too large");
        goto err;
    }

    block = malloc(sizeof(*block));
    if ( block == NULL ) {
        xc_dom_panic(dom->xch, XC_OUT_OF_MEMORY,
                     "failed to allocate block (%zu bytes)",
                     sizeof(*block));
        goto err;
    }

    memset(block, 0, sizeof(*block));
    block->mmap_len = *size;
    block->mmap_ptr = mmap(NULL, block->mmap_len, PROT_READ,
                           MAP_SHARED, fd, 0);
    if ( block->mmap_ptr == MAP_FAILED ) {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "failed to mmap file: %s",
                     strerror(errno));
        goto err;
    }

    block->next = dom->memblocks;
    dom->memblocks = block;
    dom->alloc_malloc += sizeof(*block);
    dom->alloc_file_map += block->mmap_len;
    close(fd);
    if ( *size > (100 * 1024) )
        print_mem(dom, __FUNCTION__, *size);
    return block->mmap_ptr;

 err:
    if ( fd != -1 )
        close(fd);
    free(block);
    DOMPRINTF("%s: failed (on file `%s')", __FUNCTION__, filename);
    return NULL;
}

static void xc_dom_free_all(struct xc_dom_image *dom)
{
    struct xc_dom_mem *block;

    while ( (block = dom->memblocks) != NULL )
    {
        dom->memblocks = block->next;
        if ( block->mmap_ptr )
            munmap(block->mmap_ptr, block->mmap_len);
        free(block);
    }
}

char *xc_dom_strdup(struct xc_dom_image *dom, const char *str)
{
    size_t len = strlen(str) + 1;
    char *nstr = xc_dom_malloc(dom, len);

    if ( nstr == NULL )
        return NULL;
    memcpy(nstr, str, len);
    return nstr;
}

/* ------------------------------------------------------------------------ */
/* decompression buffer sizing                                              */
int xc_dom_kernel_check_size(struct xc_dom_image *dom, size_t sz)
{
    /* No limit */
    if ( !dom->max_kernel_size )
        return 0;

    if ( sz > dom->max_kernel_size )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                     "kernel image too large");
        return 1;
    }

    return 0;
}

int xc_dom_ramdisk_check_size(struct xc_dom_image *dom, size_t sz)
{
    /* No limit */
    if ( !dom->max_ramdisk_size )
        return 0;

    if ( sz > dom->max_ramdisk_size )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                     "ramdisk image too large");
        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* read files, copy memory blocks, with transparent gunzip                  */

size_t xc_dom_check_gzip(xc_interface *xch, void *blob, size_t ziplen)
{
    unsigned char *gzlen;
    size_t unziplen;

    if ( ziplen < 6 )
        /* Too small.  We need (i.e. the subsequent code relies on)
         * 2 bytes for the magic number plus 4 bytes length. */
        return 0;

    if ( strncmp(blob, "\037\213", 2) )
        /* not gzipped */
        return 0;

    gzlen = blob + ziplen - 4;
    unziplen = (size_t)gzlen[3] << 24 | gzlen[2] << 16 | gzlen[1] << 8 | gzlen[0];
    if ( unziplen > XC_DOM_DECOMPRESS_MAX )
    {
        xc_dom_printf
            (xch,
             "%s: size (zip %zd, unzip %zd) looks insane, skip gunzip",
             __FUNCTION__, ziplen, unziplen);
        return 0;
    }

    return unziplen + 16;
}

int xc_dom_do_gunzip(xc_interface *xch,
                     void *src, size_t srclen, void *dst, size_t dstlen)
{
    z_stream zStream;
    int rc;

    memset(&zStream, 0, sizeof(zStream));
    zStream.next_in = src;
    zStream.avail_in = srclen;
    zStream.next_out = dst;
    zStream.avail_out = dstlen;
    rc = inflateInit2(&zStream, (MAX_WBITS + 32)); /* +32 means "handle gzip" */
    if ( rc != Z_OK )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: inflateInit2 failed (rc=%d)", __FUNCTION__, rc);
        return -1;
    }
    rc = inflate(&zStream, Z_FINISH);
    inflateEnd(&zStream);
    if ( rc != Z_STREAM_END )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: inflate failed (rc=%d)", __FUNCTION__, rc);
        return -1;
    }

    xc_dom_printf(xch, "%s: unzip ok, 0x%zx -> 0x%zx",
                  __FUNCTION__, srclen, dstlen);
    return 0;
}

int xc_dom_try_gunzip(struct xc_dom_image *dom, void **blob, size_t * size)
{
    void *unzip;
    size_t unziplen;

    unziplen = xc_dom_check_gzip(dom->xch, *blob, *size);
    if ( unziplen == 0 )
        return 0;

    if ( xc_dom_kernel_check_size(dom, unziplen) )
        return 0;

    unzip = xc_dom_malloc(dom, unziplen);
    if ( unzip == NULL )
        return -1;

    if ( xc_dom_do_gunzip(dom->xch, *blob, *size, unzip, unziplen) == -1 )
        return -1;

    *blob = unzip;
    *size = unziplen;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* domain memory                                                            */

void *xc_dom_pfn_to_ptr(struct xc_dom_image *dom, xen_pfn_t pfn,
                        xen_pfn_t count)
{
    xen_pfn_t count_out_dummy;
    return xc_dom_pfn_to_ptr_retcount(dom, pfn, count, &count_out_dummy);
}

void *xc_dom_pfn_to_ptr_retcount(struct xc_dom_image *dom, xen_pfn_t pfn,
                                 xen_pfn_t count, xen_pfn_t *count_out)
{
    struct xc_dom_phys *phys;
    xen_pfn_t offset;
    unsigned int page_shift = XC_DOM_PAGE_SHIFT(dom);
    char *mode = "unset";

    *count_out = 0;

    offset = pfn - dom->rambase_pfn;
    if ( offset > dom->total_pages || /* multiple checks to avoid overflows */
         count > dom->total_pages ||
         offset > dom->total_pages - count )
    {
        DOMPRINTF("%s: pfn %"PRI_xen_pfn" out of range (0x%" PRIpfn " > 0x%" PRIpfn ")",
                  __FUNCTION__, pfn, offset, dom->total_pages);
        return NULL;
    }

    /* already allocated? */
    for ( phys = dom->phys_pages; phys != NULL; phys = phys->next )
    {
        if ( pfn >= (phys->first + phys->count) )
            continue;
        if ( count )
        {
            /* size given: must be completely within the already allocated block */
            if ( (pfn + count) <= phys->first )
                continue;
            if ( (pfn < phys->first) ||
                 ((pfn + count) > (phys->first + phys->count)) )
            {
                DOMPRINTF("%s: request overlaps allocated block"
                          " (req 0x%" PRIpfn "+0x%" PRIpfn ","
                          " blk 0x%" PRIpfn "+0x%" PRIpfn ")",
                          __FUNCTION__, pfn, count, phys->first,
                          phys->count);
                return NULL;
            }
            *count_out = count;
        }
        else
        {
            /* no size given: block must be allocated already,
               just hand out a pointer to it */
            if ( pfn < phys->first )
                continue;
            if ( pfn >= phys->first + phys->count )
                continue;
            *count_out = phys->count - (pfn - phys->first);
        }
        return phys->ptr + ((pfn - phys->first) << page_shift);
    }

    /* allocating is allowed with size specified only */
    if ( count == 0 )
    {
        DOMPRINTF("%s: no block found, no size given,"
                  " can't malloc (pfn 0x%" PRIpfn ")",
                  __FUNCTION__, pfn);
        return NULL;
    }

    /* not found, no overlap => allocate */
    phys = xc_dom_malloc(dom, sizeof(*phys));
    if ( phys == NULL )
        return NULL;
    memset(phys, 0, sizeof(*phys));
    phys->first = pfn;
    phys->count = count;

    if ( dom->guest_domid )
    {
        mode = "domU mapping";
        phys->ptr = xc_dom_boot_domU_map(dom, phys->first, phys->count);
        if ( phys->ptr == NULL )
            return NULL;
        dom->alloc_domU_map += phys->count << page_shift;
    }
    else
    {
        int err;

        mode = "anonymous memory";
        phys->ptr = mmap(NULL, phys->count << page_shift,
                         PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
                         -1, 0);
        if ( phys->ptr == MAP_FAILED )
        {
            err = errno;
            xc_dom_panic(dom->xch, XC_OUT_OF_MEMORY,
                         "%s: oom: can't allocate 0x%" PRIpfn " pages"
                         " [mmap, errno=%i (%s)]",
                         __FUNCTION__, count, err, strerror(err));
            return NULL;
        }
        dom->alloc_mem_map += phys->count << page_shift;
    }

#if 1
    DOMPRINTF("%s: %s: pfn 0x%" PRIpfn "+0x%" PRIpfn " at %p",
              __FUNCTION__, mode, phys->first, phys->count, phys->ptr);
#endif
    phys->next = dom->phys_pages;
    dom->phys_pages = phys;
    return phys->ptr;
}

int xc_dom_alloc_segment(struct xc_dom_image *dom,
                         struct xc_dom_seg *seg, char *name,
                         xen_vaddr_t start, xen_vaddr_t size)
{
    unsigned int page_size = XC_DOM_PAGE_SIZE(dom);
    xen_pfn_t pages = (size + page_size - 1) / page_size;
    xen_pfn_t pfn;
    void *ptr;

    if ( start == 0 )
        start = dom->virt_alloc_end;

    if ( start & (page_size - 1) )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: segment start isn't page aligned (0x%" PRIx64 ")",
                     __FUNCTION__, start);
        return -1;
    }
    if ( start < dom->virt_alloc_end )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: segment start too low (0x%" PRIx64 " < 0x%" PRIx64
                     ")", __FUNCTION__, start, dom->virt_alloc_end);
        return -1;
    }

    seg->vstart = start;
    pfn = (seg->vstart - dom->parms.virt_base) / page_size;
    seg->pfn = pfn + dom->rambase_pfn;

    if ( pages > dom->total_pages || /* multiple test avoids overflow probs */
         pfn > dom->total_pages ||
         pages > dom->total_pages - pfn)
    {
        xc_dom_panic(dom->xch, XC_OUT_OF_MEMORY,
                     "%s: segment %s too large (0x%"PRIpfn" > "
                     "0x%"PRIpfn" - 0x%"PRIpfn" pages)",
                     __FUNCTION__, name, pages, dom->total_pages, pfn);
        return -1;
    }

    seg->vend = start + pages * page_size;
    dom->virt_alloc_end = seg->vend;
    if (dom->allocate)
        dom->allocate(dom, dom->virt_alloc_end);

    DOMPRINTF("%-20s:   %-12s : 0x%" PRIx64 " -> 0x%" PRIx64
              "  (pfn 0x%" PRIpfn " + 0x%" PRIpfn " pages)",
              __FUNCTION__, name, seg->vstart, seg->vend, seg->pfn, pages);

    /* map and clear pages */
    ptr = xc_dom_seg_to_ptr(dom, seg);
    if ( ptr == NULL )
        return -1;
    memset(ptr, 0, pages * page_size);

    return 0;
}

int xc_dom_alloc_page(struct xc_dom_image *dom, char *name)
{
    unsigned int page_size = XC_DOM_PAGE_SIZE(dom);
    xen_vaddr_t start;
    xen_pfn_t pfn;

    start = dom->virt_alloc_end;
    dom->virt_alloc_end += page_size;
    if (dom->allocate)
        dom->allocate(dom, dom->virt_alloc_end);
    pfn = (start - dom->parms.virt_base) / page_size;

    DOMPRINTF("%-20s:   %-12s : 0x%" PRIx64 " (pfn 0x%" PRIpfn ")",
              __FUNCTION__, name, start, pfn);
    return pfn;
}

void xc_dom_unmap_one(struct xc_dom_image *dom, xen_pfn_t pfn)
{
    unsigned int page_shift = XC_DOM_PAGE_SHIFT(dom);
    struct xc_dom_phys *phys, *prev = NULL;

    for ( phys = dom->phys_pages; phys != NULL; phys = phys->next )
    {
        if ( (pfn >= phys->first) && (pfn < (phys->first + phys->count)) )
            break;
        prev = phys;
    }
    if ( !phys )
    {
        DOMPRINTF("%s: Huh? no mapping with pfn 0x%" PRIpfn "",
                  __FUNCTION__, pfn);
        return;
    }

    munmap(phys->ptr, phys->count << page_shift);
    if ( prev )
        prev->next = phys->next;
    else
        dom->phys_pages = phys->next;

    xc_domain_cacheflush(dom->xch, dom->guest_domid, phys->first, phys->count);
}

void xc_dom_unmap_all(struct xc_dom_image *dom)
{
    while ( dom->phys_pages )
        xc_dom_unmap_one(dom, dom->phys_pages->first);
}

/* ------------------------------------------------------------------------ */
/* pluggable kernel loaders                                                 */

static struct xc_dom_loader *first_loader = NULL;
static struct xc_dom_arch *first_hook = NULL;

void xc_dom_register_loader(struct xc_dom_loader *loader)
{
    loader->next = first_loader;
    first_loader = loader;
}

static struct xc_dom_loader *xc_dom_find_loader(struct xc_dom_image *dom)
{
    struct xc_dom_loader *loader = first_loader;

    while ( loader != NULL )
    {
        DOMPRINTF("%s: trying %s loader ... ", __FUNCTION__, loader->name);
        if ( loader->probe(dom) == 0 )
        {
            DOMPRINTF("loader probe OK");
            return loader;
        }
        DOMPRINTF("loader probe failed");
        loader = loader->next;
    }
    xc_dom_panic(dom->xch,
                 XC_INVALID_KERNEL, "%s: no loader found", __FUNCTION__);
    return NULL;
}

void xc_dom_register_arch_hooks(struct xc_dom_arch *hooks)
{
    hooks->next = first_hook;
    first_hook = hooks;
}

struct xc_dom_arch *xc_dom_find_arch_hooks(xc_interface *xch, char *guest_type)
{
    struct xc_dom_arch *hooks = first_hook;

    while (  hooks != NULL )
    {
        if ( !strcmp(hooks->guest_type, guest_type))
            return hooks;
        hooks = hooks->next;
    }
    xc_dom_panic(xch, XC_INVALID_KERNEL,
                 "%s: not found (type %s)", __FUNCTION__, guest_type);
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* public interface                                                         */

void xc_dom_release(struct xc_dom_image *dom)
{
    DOMPRINTF_CALLED(dom->xch);
    if ( dom->phys_pages )
        xc_dom_unmap_all(dom);
    xc_dom_free_all(dom);
    free(dom);
}

struct xc_dom_image *xc_dom_allocate(xc_interface *xch,
                                     const char *cmdline, const char *features)
{
    struct xc_dom_image *dom;

    xc_dom_printf(xch, "%s: cmdline=\"%s\", features=\"%s\"",
                  __FUNCTION__, cmdline, features);
    dom = malloc(sizeof(*dom));
    if ( !dom )
        goto err;

    memset(dom, 0, sizeof(*dom));
    dom->xch = xch;

    dom->max_kernel_size = XC_DOM_DECOMPRESS_MAX;
    dom->max_ramdisk_size = XC_DOM_DECOMPRESS_MAX;
    dom->max_devicetree_size = XC_DOM_DECOMPRESS_MAX;

    if ( cmdline )
        dom->cmdline = xc_dom_strdup(dom, cmdline);
    if ( features )
        elf_xen_parse_features(features, dom->f_requested, NULL);

    dom->parms.virt_base = UNSET_ADDR;
    dom->parms.virt_entry = UNSET_ADDR;
    dom->parms.virt_hypercall = UNSET_ADDR;
    dom->parms.virt_hv_start_low = UNSET_ADDR;
    dom->parms.elf_paddr_offset = UNSET_ADDR;

    dom->alloc_malloc += sizeof(*dom);
    return dom;

 err:
    if ( dom )
        xc_dom_release(dom);
    return NULL;
}

int xc_dom_kernel_max_size(struct xc_dom_image *dom, size_t sz)
{
    DOMPRINTF("%s: kernel_max_size=%zx", __FUNCTION__, sz);
    dom->max_kernel_size = sz;
    return 0;
}

int xc_dom_ramdisk_max_size(struct xc_dom_image *dom, size_t sz)
{
    DOMPRINTF("%s: ramdisk_max_size=%zx", __FUNCTION__, sz);
    dom->max_ramdisk_size = sz;
    return 0;
}

int xc_dom_devicetree_max_size(struct xc_dom_image *dom, size_t sz)
{
    DOMPRINTF("%s: devicetree_max_size=%zx", __FUNCTION__, sz);
    dom->max_devicetree_size = sz;
    return 0;
}

int xc_dom_kernel_file(struct xc_dom_image *dom, const char *filename)
{
    DOMPRINTF("%s: filename=\"%s\"", __FUNCTION__, filename);
    dom->kernel_blob = xc_dom_malloc_filemap(dom, filename, &dom->kernel_size,
                                             dom->max_kernel_size);
    if ( dom->kernel_blob == NULL )
        return -1;
    return xc_dom_try_gunzip(dom, &dom->kernel_blob, &dom->kernel_size);
}

int xc_dom_ramdisk_file(struct xc_dom_image *dom, const char *filename)
{
    DOMPRINTF("%s: filename=\"%s\"", __FUNCTION__, filename);
    dom->ramdisk_blob =
        xc_dom_malloc_filemap(dom, filename, &dom->ramdisk_size,
                              dom->max_ramdisk_size);

    if ( dom->ramdisk_blob == NULL )
        return -1;
//    return xc_dom_try_gunzip(dom, &dom->ramdisk_blob, &dom->ramdisk_size);
    return 0;
}

int xc_dom_devicetree_file(struct xc_dom_image *dom, const char *filename)
{
#if defined (__arm__) || defined(__aarch64__)
    DOMPRINTF("%s: filename=\"%s\"", __FUNCTION__, filename);
    dom->devicetree_blob =
        xc_dom_malloc_filemap(dom, filename, &dom->devicetree_size,
                              dom->max_devicetree_size);

    if ( dom->devicetree_blob == NULL )
        return -1;
    return 0;
#else
    errno = -EINVAL;
    return -1;
#endif
}

int xc_dom_kernel_mem(struct xc_dom_image *dom, const void *mem, size_t memsize)
{
    DOMPRINTF_CALLED(dom->xch);
    dom->kernel_blob = (void *)mem;
    dom->kernel_size = memsize;
    return xc_dom_try_gunzip(dom, &dom->kernel_blob, &dom->kernel_size);
}

int xc_dom_ramdisk_mem(struct xc_dom_image *dom, const void *mem,
                       size_t memsize)
{
    DOMPRINTF_CALLED(dom->xch);
    dom->ramdisk_blob = (void *)mem;
    dom->ramdisk_size = memsize;
//    return xc_dom_try_gunzip(dom, &dom->ramdisk_blob, &dom->ramdisk_size);
    return 0;
}

int xc_dom_devicetree_mem(struct xc_dom_image *dom, const void *mem,
                          size_t memsize)
{
    DOMPRINTF_CALLED(dom->xch);
    dom->devicetree_blob = (void *)mem;
    dom->devicetree_size = memsize;
    return 0;
}

int xc_dom_parse_image(struct xc_dom_image *dom)
{
    int i;

    DOMPRINTF_CALLED(dom->xch);

    /* parse kernel image */
    dom->kernel_loader = xc_dom_find_loader(dom);
    if ( dom->kernel_loader == NULL )
        goto err;
    if ( dom->kernel_loader->parser(dom) != 0 )
        goto err;
    if ( dom->guest_type == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: guest_type not set", __FUNCTION__);
        goto err;
    }

    if ( dom->pvh_enabled )
    {
        const char *pvh_features = "writable_descriptor_tables|"
                                   "auto_translated_physmap|"
                                   "supervisor_mode_kernel|"
                                   "hvm_callback_vector";
        elf_xen_parse_features(pvh_features, dom->f_requested, NULL);
    }

    /* check features */
    for ( i = 0; i < XENFEAT_NR_SUBMAPS; i++ )
    {
        dom->f_active[i] |= dom->f_requested[i]; /* cmd line */
        dom->f_active[i] |= dom->parms.f_required[i]; /* kernel   */
        if ( (dom->f_active[i] & dom->parms.f_supported[i]) !=
             dom->f_active[i] )
        {
            xc_dom_panic(dom->xch, XC_INVALID_PARAM,
                         "%s: unsupported feature requested", __FUNCTION__);
            goto err;
        }
    }
    return 0;

 err:
    return -1;
}

int xc_dom_rambase_init(struct xc_dom_image *dom, uint64_t rambase)
{
    dom->rambase_pfn = rambase >> XC_PAGE_SHIFT;
    DOMPRINTF("%s: RAM starts at %"PRI_xen_pfn,
              __FUNCTION__, dom->rambase_pfn);
    return 0;
}

int xc_dom_mem_init(struct xc_dom_image *dom, unsigned int mem_mb)
{
    unsigned int page_shift;
    xen_pfn_t nr_pages;

    dom->arch_hooks = xc_dom_find_arch_hooks(dom->xch, dom->guest_type);
    if ( dom->arch_hooks == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR, "%s: arch hooks not set",
                     __FUNCTION__);
        return -1;
    }

    page_shift = XC_DOM_PAGE_SHIFT(dom);
    nr_pages = mem_mb << (20 - page_shift);

    DOMPRINTF("%s: mem %d MB, pages 0x%" PRIpfn " pages, %dk each",
               __FUNCTION__, mem_mb, nr_pages, 1 << (page_shift-10));
    dom->total_pages = nr_pages;

    DOMPRINTF("%s: 0x%" PRIpfn " pages",
              __FUNCTION__, dom->total_pages);

    return 0;
}

int xc_dom_update_guest_p2m(struct xc_dom_image *dom)
{
    uint32_t *p2m_32;
    uint64_t *p2m_64;
    xen_pfn_t i;

    if ( !dom->p2m_guest )
        return 0;

    switch ( dom->arch_hooks->sizeof_pfn )
    {
    case 4:
        DOMPRINTF("%s: dst 32bit, pages 0x%" PRIpfn "",
                  __FUNCTION__, dom->total_pages);
        p2m_32 = dom->p2m_guest;
        for ( i = 0; i < dom->total_pages; i++ )
            if ( dom->p2m_host[i] != INVALID_P2M_ENTRY )
                p2m_32[i] = dom->p2m_host[i];
            else
                p2m_32[i] = (uint32_t) - 1;
        break;
    case 8:
        DOMPRINTF("%s: dst 64bit, pages 0x%" PRIpfn "",
                  __FUNCTION__, dom->total_pages);
        p2m_64 = dom->p2m_guest;
        for ( i = 0; i < dom->total_pages; i++ )
            if ( dom->p2m_host[i] != INVALID_P2M_ENTRY )
                p2m_64[i] = dom->p2m_host[i];
            else
                p2m_64[i] = (uint64_t) - 1;
        break;
    default:
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "sizeof_pfn is invalid (is %d, can be 4 or 8)",
                     dom->arch_hooks->sizeof_pfn);
        return -1;
    }
    return 0;
}

int xc_dom_build_image(struct xc_dom_image *dom)
{
    unsigned int page_size;

    DOMPRINTF_CALLED(dom->xch);

    /* check for arch hooks */
    if ( dom->arch_hooks == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR, "%s: arch hooks not set",
                     __FUNCTION__);
        goto err;
    }
    page_size = XC_DOM_PAGE_SIZE(dom);

    /* load kernel */
    if ( xc_dom_alloc_segment(dom, &dom->kernel_seg, "kernel",
                              dom->kernel_seg.vstart,
                              dom->kernel_seg.vend -
                              dom->kernel_seg.vstart) != 0 )
        goto err;
    if ( dom->kernel_loader->loader(dom) != 0 )
        goto err;

    /* load ramdisk */
    if ( dom->ramdisk_blob )
    {
        size_t unziplen, ramdisklen;
        void *ramdiskmap;

        if ( !dom->ramdisk_seg.vstart )
        {
            unziplen = xc_dom_check_gzip(dom->xch,
                                         dom->ramdisk_blob, dom->ramdisk_size);
            if ( xc_dom_ramdisk_check_size(dom, unziplen) != 0 )
                unziplen = 0;
        }
        else
            unziplen = 0;

        ramdisklen = unziplen ? unziplen : dom->ramdisk_size;

        if ( xc_dom_alloc_segment(dom, &dom->ramdisk_seg, "ramdisk",
                                  dom->ramdisk_seg.vstart,
                                  ramdisklen) != 0 )
            goto err;
        ramdiskmap = xc_dom_seg_to_ptr(dom, &dom->ramdisk_seg);
        if ( ramdiskmap == NULL )
        {
            DOMPRINTF("%s: xc_dom_seg_to_ptr(dom, &dom->ramdisk_seg) => NULL",
                      __FUNCTION__);
            goto err;
        }
        if ( unziplen )
        {
            if ( xc_dom_do_gunzip(dom->xch,
                                  dom->ramdisk_blob, dom->ramdisk_size,
                                  ramdiskmap, ramdisklen) == -1 )
                goto err;
        }
        else
            memcpy(ramdiskmap, dom->ramdisk_blob, dom->ramdisk_size);
    }

    /* load devicetree */
    if ( dom->devicetree_blob )
    {
        void *devicetreemap;

        if ( xc_dom_alloc_segment(dom, &dom->devicetree_seg, "devicetree",
                                  dom->devicetree_seg.vstart,
                                  dom->devicetree_size) != 0 )
            goto err;
        devicetreemap = xc_dom_seg_to_ptr(dom, &dom->devicetree_seg);
        if ( devicetreemap == NULL )
        {
            DOMPRINTF("%s: xc_dom_seg_to_ptr(dom, &dom->devicetree_seg) => NULL",
                      __FUNCTION__);
            goto err;
        }
        memcpy(devicetreemap, dom->devicetree_blob, dom->devicetree_size);
    }

    /* allocate other pages */
    if ( dom->arch_hooks->alloc_magic_pages(dom) != 0 )
        goto err;
    if ( dom->arch_hooks->count_pgtables )
    {
        if ( dom->arch_hooks->count_pgtables(dom) != 0 )
            goto err;
        if ( (dom->pgtables > 0) &&
             (xc_dom_alloc_segment(dom, &dom->pgtables_seg, "page tables", 0,
                                   dom->pgtables * page_size) != 0) )
                goto err;
    }
    if ( dom->alloc_bootstack )
        dom->bootstack_pfn = xc_dom_alloc_page(dom, "boot stack");
    DOMPRINTF("%-20s: virt_alloc_end : 0x%" PRIx64 "",
              __FUNCTION__, dom->virt_alloc_end);
    DOMPRINTF("%-20s: virt_pgtab_end : 0x%" PRIx64 "",
              __FUNCTION__, dom->virt_pgtab_end);
    return 0;

 err:
    return -1;
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
