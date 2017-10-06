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

#ifndef XC_PRIVATE_H
#define XC_PRIVATE_H

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "_paths.h"

#define XC_WANT_COMPAT_MAP_FOREIGN_API
#define XC_INTERNAL_COMPAT_MAP_FOREIGN_API
#include "xenctrl.h"

#include <xencall.h>
#include <xenforeignmemory.h>
#include <xendevicemodel.h>

#include <xen/sys/privcmd.h>

#if defined(HAVE_VALGRIND_MEMCHECK_H) && !defined(NDEBUG) && !defined(__MINIOS__)
/* Compile in Valgrind client requests? */
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_UNDEFINED(addr, len) /* addr, len */
#endif

#if defined(__MINIOS__)
/*
 * MiniOS's libc doesn't know about sys/uio.h or writev().
 * Declare enough of sys/uio.h to compile.
 */
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#else
#include <sys/uio.h>
#endif

#define DECLARE_DOMCTL struct xen_domctl domctl
#define DECLARE_SYSCTL struct xen_sysctl sysctl
#define DECLARE_PHYSDEV_OP struct physdev_op physdev_op
#define DECLARE_FLASK_OP struct xen_flask_op op
#define DECLARE_PLATFORM_OP struct xen_platform_op platform_op

#undef PAGE_SHIFT
#undef PAGE_SIZE
#undef PAGE_MASK
#define PAGE_SHIFT              XC_PAGE_SHIFT
#define PAGE_SIZE               XC_PAGE_SIZE
#define PAGE_MASK               XC_PAGE_MASK

#ifndef ARRAY_SIZE /* MiniOS leaks ARRAY_SIZE into our namespace as part of a
                    * stubdom build.  It shouldn't... */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/*
** Define max dirty page cache to permit during save/restore -- need to balance 
** keeping cache usage down with CPU impact of invalidating too often.
** (Currently 16MB)
*/
#define MAX_PAGECACHE_USAGE (4*1024)

struct xc_interface_core {
    int flags;
    xentoollog_logger *error_handler,   *error_handler_tofree;
    xentoollog_logger *dombuild_logger, *dombuild_logger_tofree;
    struct xc_error last_error; /* for xc_get_last_error */
    FILE *dombuild_logger_file;
    const char *currently_progress_reporting;

    /* Hypercall interface */
    xencall_handle *xcall;

    /* Foreign mappings */
    xenforeignmemory_handle *fmem;

    /* Device model */
    xendevicemodel_handle *dmod;
};

int osdep_privcmd_open(xc_interface *xch);
int osdep_privcmd_close(xc_interface *xch);

void *osdep_alloc_hypercall_buffer(xc_interface *xch, int npages);
void osdep_free_hypercall_buffer(xc_interface *xch, void *ptr, int npages);

void xc_report_error(xc_interface *xch, int code, const char *fmt, ...)
    __attribute__((format(printf,3,4)));
void xc_reportv(xc_interface *xch, xentoollog_logger *lg, xentoollog_level,
                int code, const char *fmt, va_list args)
     __attribute__((format(printf,5,0)));
void xc_report(xc_interface *xch, xentoollog_logger *lg, xentoollog_level,
               int code, const char *fmt, ...)
     __attribute__((format(printf,5,6)));

const char *xc_set_progress_prefix(xc_interface *xch, const char *doing);
void xc_report_progress_single(xc_interface *xch, const char *doing);
void xc_report_progress_step(xc_interface *xch,
                             unsigned long done, unsigned long total);

/* anamorphic macros:  struct xc_interface *xch  must be in scope */

#define IPRINTF(_f, _a...)  do { int IPRINTF_errno = errno; \
        xc_report(xch, xch->error_handler, XTL_INFO,0, _f , ## _a); \
        errno = IPRINTF_errno; \
        } while (0)
#define DPRINTF(_f, _a...) do { int DPRINTF_errno = errno; \
        xc_report(xch, xch->error_handler, XTL_DETAIL,0, _f , ## _a); \
        errno = DPRINTF_errno; \
        } while (0)
#define DBGPRINTF(_f, _a...)  do { int DBGPRINTF_errno = errno; \
        xc_report(xch, xch->error_handler, XTL_DEBUG,0, _f , ## _a); \
        errno = DBGPRINTF_errno; \
        } while (0)

#define ERROR(_m, _a...)  do { int ERROR_errno = errno; \
        xc_report_error(xch,XC_INTERNAL_ERROR,_m , ## _a ); \
        errno = ERROR_errno; \
        } while (0)
#define PERROR(_m, _a...) do { int PERROR_errno = errno; \
        xc_report_error(xch,XC_INTERNAL_ERROR,_m " (%d = %s)", \
        ## _a , errno, xc_strerror(xch, errno)); \
        errno = PERROR_errno; \
        } while (0)

/*
 * HYPERCALL ARGUMENT BUFFERS
 *
 * Augment the public hypercall buffer interface with the ability to
 * bounce between user provided buffers and hypercall safe memory.
 *
 * Use xc_hypercall_bounce_pre/post instead of
 * xc_hypercall_buffer_alloc/free(_pages).  The specified user
 * supplied buffer is automatically copied in/out of the hypercall
 * safe memory.
 */
enum {
    XC_HYPERCALL_BUFFER_BOUNCE_NONE = 0,
    XC_HYPERCALL_BUFFER_BOUNCE_IN   = 1,
    XC_HYPERCALL_BUFFER_BOUNCE_OUT  = 2,
    XC_HYPERCALL_BUFFER_BOUNCE_BOTH = 3
};

/*
 * Declare a named bounce buffer.
 *
 * Normally you should use DECLARE_HYPERCALL_BOUNCE (see below).
 *
 * This declaration should only be used when the user pointer is
 * non-trivial, e.g. when it is contained within an existing data
 * structure.
 */
#define DECLARE_NAMED_HYPERCALL_BOUNCE(_name, _ubuf, _sz, _dir) \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = {  \
        .hbuf = NULL,                                           \
        .param_shadow = NULL,                                   \
        .sz = _sz, .dir = _dir, .ubuf = _ubuf,                  \
    }

/*
 * Declare a bounce buffer shadowing the named user data pointer.
 */
#define DECLARE_HYPERCALL_BOUNCE(_ubuf, _sz, _dir) DECLARE_NAMED_HYPERCALL_BOUNCE(_ubuf, _ubuf, _sz, _dir)

/*
 * Set the size of data to bounce. Useful when the size is not known
 * when the bounce buffer is declared.
 */
#define HYPERCALL_BOUNCE_SET_SIZE(_buf, _sz) do { (HYPERCALL_BUFFER(_buf))->sz = _sz; } while (0)

/*
 * Change the direction.
 *
 * Can only be used if the bounce_pre/bounce_post commands have
 * not been used.
 */
#define HYPERCALL_BOUNCE_SET_DIR(_buf, _dir) do { if ((HYPERCALL_BUFFER(_buf))->hbuf)         \
                                                        assert(1);                            \
                                                   (HYPERCALL_BUFFER(_buf))->dir = _dir;      \
                                                } while (0)

/*
 * Initialise and free hypercall safe memory. Takes care of any required
 * copying.
 */
int xc__hypercall_bounce_pre(xc_interface *xch, xc_hypercall_buffer_t *bounce);
#define xc_hypercall_bounce_pre(_xch, _name) xc__hypercall_bounce_pre(_xch, HYPERCALL_BUFFER(_name))
void xc__hypercall_bounce_post(xc_interface *xch, xc_hypercall_buffer_t *bounce);
#define xc_hypercall_bounce_post(_xch, _name) xc__hypercall_bounce_post(_xch, HYPERCALL_BUFFER(_name))

/*
 * Release hypercall buffer cache
 */
void xc__hypercall_buffer_cache_release(xc_interface *xch);

/*
 * Hypercall interfaces.
 */

static inline int do_xen_version(xc_interface *xch, int cmd, xc_hypercall_buffer_t *dest)
{
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(dest);
    return xencall2(xch->xcall, __HYPERVISOR_xen_version,
                    cmd, HYPERCALL_BUFFER_AS_ARG(dest));
}

static inline int do_physdev_op(xc_interface *xch, int cmd, void *op, size_t len)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(op, len, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce memory for physdev hypercall");
        goto out1;
    }

    ret = xencall2(xch->xcall, __HYPERVISOR_physdev_op,
                   cmd, HYPERCALL_BUFFER_AS_ARG(op));
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            DPRINTF("physdev operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    xc_hypercall_bounce_post(xch, op);
out1:
    return ret;
}

static inline int do_domctl(xc_interface *xch, struct xen_domctl *domctl)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(domctl, sizeof(*domctl), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    domctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;

    if ( xc_hypercall_bounce_pre(xch, domctl) )
    {
        PERROR("Could not bounce buffer for domctl hypercall");
        goto out1;
    }

    ret = xencall1(xch->xcall, __HYPERVISOR_domctl,
                   HYPERCALL_BUFFER_AS_ARG(domctl));
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            DPRINTF("domctl operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    xc_hypercall_bounce_post(xch, domctl);
 out1:
    return ret;
}

static inline int do_sysctl(xc_interface *xch, struct xen_sysctl *sysctl)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(sysctl, sizeof(*sysctl), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    sysctl->interface_version = XEN_SYSCTL_INTERFACE_VERSION;

    if ( xc_hypercall_bounce_pre(xch, sysctl) )
    {
        PERROR("Could not bounce buffer for sysctl hypercall");
        goto out1;
    }

    ret = xencall1(xch->xcall, __HYPERVISOR_sysctl,
                   HYPERCALL_BUFFER_AS_ARG(sysctl));
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            DPRINTF("sysctl operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    xc_hypercall_bounce_post(xch, sysctl);
 out1:
    return ret;
}

static inline int do_platform_op(xc_interface *xch,
                                 struct xen_platform_op *platform_op)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(platform_op, sizeof(*platform_op),
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    platform_op->interface_version = XENPF_INTERFACE_VERSION;

    if ( xc_hypercall_bounce_pre(xch, platform_op) )
    {
        PERROR("Could not bounce buffer for platform_op hypercall");
        return -1;
    }

    ret = xencall1(xch->xcall, __HYPERVISOR_platform_op,
                   HYPERCALL_BUFFER_AS_ARG(platform_op));
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            DPRINTF("platform operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    xc_hypercall_bounce_post(xch, platform_op);
    return ret;
}

static inline int do_multicall_op(xc_interface *xch,
                                  xc_hypercall_buffer_t *call_list,
                                  uint32_t nr_calls)
{
    int ret = -1;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(call_list);

    ret = xencall2(xch->xcall, __HYPERVISOR_multicall,
                   HYPERCALL_BUFFER_AS_ARG(call_list), nr_calls);
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            DPRINTF("multicall operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    return ret;
}

long do_memory_op(xc_interface *xch, int cmd, void *arg, size_t len);

void *xc_map_foreign_ranges(xc_interface *xch, uint32_t dom,
                            size_t size, int prot, size_t chunksize,
                            privcmd_mmap_entry_t entries[], int nentries);

int xc_get_pfn_type_batch(xc_interface *xch, uint32_t dom,
                          unsigned int num, xen_pfn_t *);

void bitmap_64_to_byte(uint8_t *bp, const uint64_t *lp, int nbits);
void bitmap_byte_to_64(uint64_t *lp, const uint8_t *bp, int nbits);

/* Optionally flush file to disk and discard page cache */
void discard_file_cache(xc_interface *xch, int fd, int flush);

#define MAX_MMU_UPDATES 1024
struct xc_mmu {
    mmu_update_t updates[MAX_MMU_UPDATES];
    int          idx;
    unsigned int subject;
};
/* Structure returned by xc_alloc_mmu_updates must be free()'ed by caller. */
struct xc_mmu *xc_alloc_mmu_updates(xc_interface *xch, unsigned int subject);
int xc_add_mmu_update(xc_interface *xch, struct xc_mmu *mmu,
                   unsigned long long ptr, unsigned long long val);
int xc_flush_mmu_updates(xc_interface *xch, struct xc_mmu *mmu);

/* Return 0 on success; -1 on error setting errno. */
int read_exact(int fd, void *data, size_t size); /* EOF => -1, errno=0 */
int write_exact(int fd, const void *data, size_t size);
int writev_exact(int fd, const struct iovec *iov, int iovcnt);

int xc_ffs8(uint8_t x);
int xc_ffs16(uint16_t x);
int xc_ffs32(uint32_t x);
int xc_ffs64(uint64_t x);

#define min(X, Y) ({                             \
            const typeof (X) _x = (X);           \
            const typeof (Y) _y = (Y);           \
            (void) (&_x == &_y);                 \
            (_x < _y) ? _x : _y; })
#define max(X, Y) ({                             \
            const typeof (X) _x = (X);           \
            const typeof (Y) _y = (Y);           \
            (void) (&_x == &_y);                 \
            (_x > _y) ? _x : _y; })

#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

#define DOMPRINTF(fmt, args...) xc_dom_printf(dom->xch, fmt, ## args)
#define DOMPRINTF_CALLED(xch) xc_dom_printf((xch), "%s: called", __FUNCTION__)

/**
 * vm_event operations. Internal use only.
 */
int xc_vm_event_control(xc_interface *xch, uint32_t domain_id, unsigned int op,
                        unsigned int mode, uint32_t *port);
/*
 * Enables vm_event and returns the mapped ring page indicated by param.
 * param can be HVM_PARAM_PAGING/ACCESS/SHARING_RING_PFN
 */
void *xc_vm_event_enable(xc_interface *xch, uint32_t domain_id, int param,
                         uint32_t *port);

int do_dm_op(xc_interface *xch, uint32_t domid, unsigned int nr_bufs, ...);

#endif /* __XC_PRIVATE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
