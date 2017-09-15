#ifndef XENFOREIGNMEMORY_PRIVATE_H
#define XENFOREIGNMEMORY_PRIVATE_H

#include <xentoollog.h>

#include <xenforeignmemory.h>

#include <xentoolcore_internal.h>

#include <xen/xen.h>
#include <xen/sys/privcmd.h>

#ifndef PAGE_SHIFT /* Mini-os, Yukk */
#define PAGE_SHIFT           12
#endif
#ifndef __MINIOS__ /* Yukk */
#define PAGE_SIZE            (1UL << PAGE_SHIFT)
#define PAGE_MASK            (~(PAGE_SIZE-1))
#endif

struct xenforeignmemory_handle {
    xentoollog_logger *logger, *logger_tofree;
    unsigned flags;
    int fd;
    Xentoolcore__Active_Handle tc_ah;
};

int osdep_xenforeignmemory_open(xenforeignmemory_handle *fmem);
int osdep_xenforeignmemory_close(xenforeignmemory_handle *fmem);

void *osdep_xenforeignmemory_map(xenforeignmemory_handle *fmem,
                                 uint32_t dom, void *addr,
                                 int prot, int flags, size_t num,
                                 const xen_pfn_t arr[num], int err[num]);
int osdep_xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                                 void *addr, size_t num);

int osdep_xenforeignmemory_restrict(xenforeignmemory_handle *fmem,
                                    domid_t domid);

#if defined(__NetBSD__) || defined(__sun__)
/* Strictly compat for those two only only */
void *compat_mapforeign_batch(xenforeignmem_handle *fmem, uint32_t dom,
                              void *addr, int prot, int flags,
                              xen_pfn_t *arr, int num);
#endif

#define PERROR(_f...) \
    xtl_log(fmem->logger, XTL_ERROR, errno, "xenforeignmemory", _f)

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
