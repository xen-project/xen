#ifndef XENCALL_PRIVATE_H
#define XENCALL_PRIVATE_H

#include <xentoollog.h>
#include <xentoolcore_internal.h>

#include <xencall.h>

#include <xen/xen.h>
#include <xen/sys/privcmd.h>

#ifndef PAGE_SHIFT /* Mini-os, Yukk */
#define PAGE_SHIFT           12
#endif
#ifndef __MINIOS__ /* Yukk */
#define PAGE_SIZE            (1UL << PAGE_SHIFT)
#define PAGE_MASK            (~(PAGE_SIZE-1))
#endif

struct xencall_handle {
    xentoollog_logger *logger, *logger_tofree;
    unsigned flags;
    int fd;
    Xentoolcore__Active_Handle tc_ah;

    /*
     * A simple cache of unused, single page, hypercall buffers
     *
     * Protected by a global lock.
     */
#define BUFFER_CACHE_SIZE 4
    int buffer_cache_nr;
    void *buffer_cache[BUFFER_CACHE_SIZE];

    /*
     * Hypercall buffer statistics. All protected by the global
     * buffer_cache lock.
     */
    int buffer_total_allocations;
    int buffer_total_releases;
    int buffer_current_allocations;
    int buffer_maximum_allocations;
    int buffer_cache_hits;
    int buffer_cache_misses;
    int buffer_cache_toobig;
};

int osdep_xencall_open(xencall_handle *xcall);
int osdep_xencall_close(xencall_handle *xcall);

int osdep_hypercall(xencall_handle *xcall, privcmd_hypercall_t *hypercall);

void *osdep_alloc_pages(xencall_handle *xcall, size_t nr_pages);
void osdep_free_pages(xencall_handle *xcall, void *p, size_t nr_pages);

void buffer_release_cache(xencall_handle *xcall);

#define PERROR(_f...) xtl_log(xcall->logger, XTL_ERROR, errno, "xencall", _f)

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
