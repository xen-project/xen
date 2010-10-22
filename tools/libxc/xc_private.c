/******************************************************************************
 * xc_private.c
 *
 * Helper functions for the rest of the library.
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

#include "xc_private.h"
#include "xg_private.h"
#include "xc_dom.h"
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

xc_interface *xc_interface_open(xentoollog_logger *logger,
                                xentoollog_logger *dombuild_logger,
                                unsigned open_flags) {
    xc_interface xch_buf, *xch = &xch_buf;

    xch->fd = -1;
    xch->dombuild_logger_file = 0;
    xc_clear_last_error(xch);

    xch->error_handler   = logger;           xch->error_handler_tofree   = 0;
    xch->dombuild_logger = dombuild_logger;  xch->dombuild_logger_tofree = 0;

    if (!xch->error_handler) {
        xch->error_handler = xch->error_handler_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!xch->error_handler)
            goto err;
    }

    xch = malloc(sizeof(*xch));
    if (!xch) {
        xch = &xch_buf;
        PERROR("Could not allocate new xc_interface struct");
        goto err;
    }
    *xch = xch_buf;

    if (!(open_flags & XC_OPENFLAG_DUMMY)) {
        xch->fd = xc_interface_open_core(xch);
        if (xch->fd < 0)
            goto err;
    }

    return xch;

 err:
    if (xch) xtl_logger_destroy(xch->error_handler_tofree);
    if (xch != &xch_buf) free(xch);
    return 0;
}

static void xc_clean_hcall_buf(xc_interface *xch);

int xc_interface_close(xc_interface *xch)
{
    int rc = 0;

    xtl_logger_destroy(xch->dombuild_logger_tofree);
    xtl_logger_destroy(xch->error_handler_tofree);

    if (xch->fd >= 0) {
        rc = xc_interface_close_core(xch, xch->fd);
        if (rc) PERROR("Could not close hypervisor interface");
    }

    xc_clean_hcall_buf(xch);

    free(xch);
    return rc;
}

static pthread_key_t errbuf_pkey;
static pthread_once_t errbuf_pkey_once = PTHREAD_ONCE_INIT;

const xc_error *xc_get_last_error(xc_interface *xch)
{
    return &xch->last_error;
}

void xc_clear_last_error(xc_interface *xch)
{
    xch->last_error.code = XC_ERROR_NONE;
    xch->last_error.message[0] = '\0';
}

const char *xc_error_code_to_desc(int code)
{
    /* Sync to members of xc_error_code enumeration in xenctrl.h */
    switch ( code )
    {
    case XC_ERROR_NONE:
        return "No error details";
    case XC_INTERNAL_ERROR:
        return "Internal error";
    case XC_INVALID_KERNEL:
        return "Invalid kernel";
    case XC_INVALID_PARAM:
        return "Invalid configuration";
    case XC_OUT_OF_MEMORY:
        return "Out of memory";
    }

    return "Unknown error code";
}

void xc_reportv(xc_interface *xch, xentoollog_logger *lg,
                xentoollog_level level, int code,
                const char *fmt, va_list args) {
    int saved_errno = errno;
    char msgbuf[XC_MAX_ERROR_MSG_LEN];
    char *msg;

    /* Strip newlines from messages.
     * XXX really the messages themselves should have the newlines removed.
     */
    char fmt_nonewline[512];
    int fmt_l;

    fmt_l = strlen(fmt);
    if (fmt_l && fmt[fmt_l-1]=='\n' && fmt_l < sizeof(fmt_nonewline)) {
        memcpy(fmt_nonewline, fmt, fmt_l-1);
        fmt_nonewline[fmt_l-1] = 0;
        fmt = fmt_nonewline;
    }

    if ( level >= XTL_ERROR ) {
        msg = xch->last_error.message;
        xch->last_error.code = code;
    } else {
        msg = msgbuf;
    }
    vsnprintf(msg, XC_MAX_ERROR_MSG_LEN-1, fmt, args);
    msg[XC_MAX_ERROR_MSG_LEN-1] = '\0';

    xtl_log(lg, level, -1, "xc",
            "%s" "%s%s", msg,
            code?": ":"", code ? xc_error_code_to_desc(code) : "");

    errno = saved_errno;
}

void xc_report(xc_interface *xch, xentoollog_logger *lg,
               xentoollog_level level, int code, const char *fmt, ...) {
    va_list args;
    va_start(args,fmt);
    xc_reportv(xch,lg,level,code,fmt,args);
    va_end(args);
}

void xc_report_error(xc_interface *xch, int code, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    xc_reportv(xch, xch->error_handler, XTL_ERROR, code, fmt, args);
    va_end(args);
}

void xc_report_progress_start(xc_interface *xch, const char *doing,
                              unsigned long total) {
    xch->currently_progress_reporting = doing;
    xtl_progress(xch->error_handler, "xc", xch->currently_progress_reporting,
                 0, total);
}

void xc_report_progress_step(xc_interface *xch,
                             unsigned long done, unsigned long total) {
    assert(xch->currently_progress_reporting);
    xtl_progress(xch->error_handler, "xc", xch->currently_progress_reporting,
                 done, total);
}

#ifdef __sun__

int lock_pages(xc_interface *xch, void *addr, size_t len) { return 0; }
void unlock_pages(xc_interface *xch, void *addr, size_t len) { }

int hcall_buf_prep(xc_interface *xch, void **addr, size_t len) { return 0; }
void hcall_buf_release(xc_interface *xch, void **addr, size_t len) { }

static void xc_clean_hcall_buf(xc_interface *xch) { }

#else /* !__sun__ */

int lock_pages(xc_interface *xch, void *addr, size_t len)
{
      int e;
      void *laddr = (void *)((unsigned long)addr & PAGE_MASK);
      size_t llen = (len + ((unsigned long)addr - (unsigned long)laddr) +
                     PAGE_SIZE - 1) & PAGE_MASK;
      e = mlock(laddr, llen);
      return e;
}

void unlock_pages(xc_interface *xch, void *addr, size_t len)
{
    void *laddr = (void *)((unsigned long)addr & PAGE_MASK);
    size_t llen = (len + ((unsigned long)addr - (unsigned long)laddr) +
                   PAGE_SIZE - 1) & PAGE_MASK;
    int saved_errno = errno;
    (void)munlock(laddr, llen);
    errno = saved_errno;
}

static pthread_key_t hcall_buf_pkey;
static pthread_once_t hcall_buf_pkey_once = PTHREAD_ONCE_INIT;
struct hcall_buf {
    xc_interface *xch;
    void *buf;
    void *oldbuf;
};

static void _xc_clean_hcall_buf(void *m)
{
    struct hcall_buf *hcall_buf = m;

    if ( hcall_buf )
    {
        if ( hcall_buf->buf )
        {
            unlock_pages(hcall_buf->xch, hcall_buf->buf, PAGE_SIZE);
            free(hcall_buf->buf);
        }

        free(hcall_buf);
    }

    pthread_setspecific(hcall_buf_pkey, NULL);
}

static void _xc_init_hcall_buf(void)
{
    pthread_key_create(&hcall_buf_pkey, _xc_clean_hcall_buf);
}

static void xc_clean_hcall_buf(xc_interface *xch)
{
    pthread_once(&hcall_buf_pkey_once, _xc_init_hcall_buf);

    _xc_clean_hcall_buf(pthread_getspecific(hcall_buf_pkey));
}

int hcall_buf_prep(xc_interface *xch, void **addr, size_t len)
{
    struct hcall_buf *hcall_buf;

    pthread_once(&hcall_buf_pkey_once, _xc_init_hcall_buf);

    hcall_buf = pthread_getspecific(hcall_buf_pkey);
    if ( !hcall_buf )
    {
        hcall_buf = calloc(1, sizeof(*hcall_buf));
        if ( !hcall_buf )
            goto out;
        hcall_buf->xch = xch;
        pthread_setspecific(hcall_buf_pkey, hcall_buf);
    }

    if ( !hcall_buf->buf )
    {
        hcall_buf->buf = xc_memalign(PAGE_SIZE, PAGE_SIZE);
        if ( !hcall_buf->buf || lock_pages(xch, hcall_buf->buf, PAGE_SIZE) )
        {
            free(hcall_buf->buf);
            hcall_buf->buf = NULL;
            goto out;
        }
    }

    if ( (len < PAGE_SIZE) && !hcall_buf->oldbuf )
    {
        memcpy(hcall_buf->buf, *addr, len);
        hcall_buf->oldbuf = *addr;
        *addr = hcall_buf->buf;
        return 0;
    }

 out:
    return lock_pages(xch, *addr, len);
}

void hcall_buf_release(xc_interface *xch, void **addr, size_t len)
{
    struct hcall_buf *hcall_buf = pthread_getspecific(hcall_buf_pkey);

    if ( hcall_buf && (hcall_buf->buf == *addr) )
    {
        memcpy(hcall_buf->oldbuf, *addr, len);
        *addr = hcall_buf->oldbuf;
        hcall_buf->oldbuf = NULL;
    }
    else
    {
        unlock_pages(xch, *addr, len);
    }
}

#endif

/* NB: arr must be locked */
int xc_get_pfn_type_batch(xc_interface *xch, uint32_t dom,
                          unsigned int num, xen_pfn_t *arr)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(arr, sizeof(*arr) * num, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    if ( xc_hypercall_bounce_pre(xch, arr) )
        return -1;
    domctl.cmd = XEN_DOMCTL_getpageframeinfo3;
    domctl.domain = (domid_t)dom;
    domctl.u.getpageframeinfo3.num = num;
    xc_set_xen_guest_handle(domctl.u.getpageframeinfo3.array, arr);
    rc = do_domctl(xch, &domctl);
    xc_hypercall_bounce_post(xch, arr);
    return rc;
}

int xc_mmuext_op(
    xc_interface *xch,
    struct mmuext_op *op,
    unsigned int nr_ops,
    domid_t dom)
{
    DECLARE_HYPERCALL;
    long ret = -EINVAL;

    if ( hcall_buf_prep(xch, (void **)&op, nr_ops*sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    hypercall.op     = __HYPERVISOR_mmuext_op;
    hypercall.arg[0] = (unsigned long)op;
    hypercall.arg[1] = (unsigned long)nr_ops;
    hypercall.arg[2] = (unsigned long)0;
    hypercall.arg[3] = (unsigned long)dom;

    ret = do_xen_hypercall(xch, &hypercall);

    hcall_buf_release(xch, (void **)&op, nr_ops*sizeof(*op));

 out1:
    return ret;
}

static int flush_mmu_updates(xc_interface *xch, struct xc_mmu *mmu)
{
    int err = 0;
    DECLARE_HYPERCALL;

    if ( mmu->idx == 0 )
        return 0;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu->updates;
    hypercall.arg[1] = (unsigned long)mmu->idx;
    hypercall.arg[2] = 0;
    hypercall.arg[3] = mmu->subject;

    if ( lock_pages(xch, mmu->updates, sizeof(mmu->updates)) != 0 )
    {
        PERROR("flush_mmu_updates: mmu updates lock_pages failed");
        err = 1;
        goto out;
    }

    if ( do_xen_hypercall(xch, &hypercall) < 0 )
    {
        ERROR("Failure when submitting mmu updates");
        err = 1;
    }

    mmu->idx = 0;

    unlock_pages(xch, mmu->updates, sizeof(mmu->updates));

 out:
    return err;
}

struct xc_mmu *xc_alloc_mmu_updates(xc_interface *xch, domid_t dom)
{
    struct xc_mmu *mmu = malloc(sizeof(*mmu));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = 0;
    mmu->subject = dom;
    return mmu;
}

int xc_add_mmu_update(xc_interface *xch, struct xc_mmu *mmu,
                      unsigned long long ptr, unsigned long long val)
{
    mmu->updates[mmu->idx].ptr = ptr;
    mmu->updates[mmu->idx].val = val;

    if ( ++mmu->idx == MAX_MMU_UPDATES )
        return flush_mmu_updates(xch, mmu);

    return 0;
}

int xc_flush_mmu_updates(xc_interface *xch, struct xc_mmu *mmu)
{
    return flush_mmu_updates(xch, mmu);
}

int do_memory_op(xc_interface *xch, int cmd, void *arg, size_t len)
{
    DECLARE_HYPERCALL;
    long ret = -EINVAL;

    hypercall.op     = __HYPERVISOR_memory_op;
    hypercall.arg[0] = (unsigned long)cmd;
    hypercall.arg[1] = (unsigned long)arg;

    if ( len && lock_pages(xch, arg, len) != 0 )
    {
        PERROR("Could not lock memory for XENMEM hypercall");
        goto out1;
    }

    ret = do_xen_hypercall(xch, &hypercall);

    if ( len )
        unlock_pages(xch, arg, len);

 out1:
    return ret;
}

long xc_maximum_ram_page(xc_interface *xch)
{
    return do_memory_op(xch, XENMEM_maximum_ram_page, NULL, 0);
}

long long xc_domain_get_cpu_usage( xc_interface *xch, domid_t domid, int vcpu )
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_getvcpuinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.getvcpuinfo.vcpu   = (uint16_t)vcpu;
    if ( (do_domctl(xch, &domctl) < 0) )
    {
        PERROR("Could not get info on domain");
        return -1;
    }
    return domctl.u.getvcpuinfo.cpu_time;
}

int xc_machphys_mfn_list(xc_interface *xch,
			 unsigned long max_extents,
			 xen_pfn_t *extent_start)
{
    int rc;
    struct xen_machphys_mfn_list xmml = {
        .max_extents = max_extents,
    };

    if ( lock_pages(xch, extent_start, max_extents * sizeof(xen_pfn_t)) != 0 )
    {
        PERROR("Could not lock memory for XENMEM_machphys_mfn_list hypercall");
        return -1;
    }

    set_xen_guest_handle(xmml.extent_start, extent_start);
    rc = do_memory_op(xch, XENMEM_machphys_mfn_list, &xmml, sizeof(xmml));
    if (rc || xmml.nr_extents != max_extents)
        rc = -1;
    else
        rc = 0;

    unlock_pages(xch, extent_start, max_extents * sizeof(xen_pfn_t));

    return rc;
}

int xc_get_pfn_list(xc_interface *xch,
                    uint32_t domid,
                    uint64_t *pfn_buf,
                    unsigned long max_pfns)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(pfn_buf, max_pfns * sizeof(*pfn_buf), XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

#ifdef VALGRIND
    memset(pfn_buf, 0, max_pfns * sizeof(*pfn_buf));
#endif

    if ( xc_hypercall_bounce_pre(xch, pfn_buf) )
    {
        PERROR("xc_get_pfn_list: pfn_buf bounce failed");
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_getmemlist;
    domctl.domain   = (domid_t)domid;
    domctl.u.getmemlist.max_pfns = max_pfns;
    xc_set_xen_guest_handle(domctl.u.getmemlist.buffer, pfn_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, pfn_buf);

    return (ret < 0) ? -1 : domctl.u.getmemlist.num_pfns;
}

long xc_get_tot_pages(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)domid;
    return (do_domctl(xch, &domctl) < 0) ?
        -1 : domctl.u.getdomaininfo.tot_pages;
}

int xc_copy_to_domain_page(xc_interface *xch,
                           uint32_t domid,
                           unsigned long dst_pfn,
                           const char *src_page)
{
    void *vaddr = xc_map_foreign_range(
        xch, domid, PAGE_SIZE, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(vaddr, src_page, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

int xc_clear_domain_page(xc_interface *xch,
                         uint32_t domid,
                         unsigned long dst_pfn)
{
    void *vaddr = xc_map_foreign_range(
        xch, domid, PAGE_SIZE, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memset(vaddr, 0, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

int xc_domctl(xc_interface *xch, struct xen_domctl *domctl)
{
    return do_domctl(xch, domctl);
}

int xc_sysctl(xc_interface *xch, struct xen_sysctl *sysctl)
{
    return do_sysctl(xch, sysctl);
}

int xc_version(xc_interface *xch, int cmd, void *arg)
{
    DECLARE_HYPERCALL_BOUNCE(arg, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT); /* Size unknown until cmd decoded */
    size_t sz = 0;
    int rc;

    switch ( cmd )
    {
    case XENVER_extraversion:
        sz = sizeof(xen_extraversion_t);
        break;
    case XENVER_compile_info:
        sz = sizeof(xen_compile_info_t);
        break;
    case XENVER_capabilities:
        sz = sizeof(xen_capabilities_info_t);
        break;
    case XENVER_changeset:
        sz = sizeof(xen_changeset_info_t);
        break;
    case XENVER_platform_parameters:
        sz = sizeof(xen_platform_parameters_t);
        break;
    }

    HYPERCALL_BOUNCE_SET_SIZE(arg, sz);

    if ( (sz != 0) && xc_hypercall_bounce_pre(xch, arg) )
    {
        PERROR("Could not bounce buffer for version hypercall");
        return -ENOMEM;
    }

#ifdef VALGRIND
    if (sz != 0)
        memset(hypercall_bounce_get(bounce), 0, sz);
#endif

    rc = do_xen_version(xch, cmd, HYPERCALL_BUFFER(arg));

    if ( sz != 0 )
        xc_hypercall_bounce_post(xch, arg);

    return rc;
}

unsigned long xc_make_page_below_4G(
    xc_interface *xch, uint32_t domid, unsigned long mfn)
{
    xen_pfn_t old_mfn = mfn;
    xen_pfn_t new_mfn;

    if ( xc_domain_decrease_reservation_exact(
        xch, domid, 1, 0, &old_mfn) != 0 )
    {
        DPRINTF("xc_make_page_below_4G decrease failed. mfn=%lx\n",mfn);
        return 0;
    }

    if ( xc_domain_increase_reservation_exact(
        xch, domid, 1, 0, XENMEMF_address_bits(32), &new_mfn) != 0 )
    {
        DPRINTF("xc_make_page_below_4G increase failed. mfn=%lx\n",mfn);
        return 0;
    }

    return new_mfn;
}

static void
_xc_clean_errbuf(void * m)
{
    free(m);
    pthread_setspecific(errbuf_pkey, NULL);
}

static void
_xc_init_errbuf(void)
{
    pthread_key_create(&errbuf_pkey, _xc_clean_errbuf);
}

char *safe_strerror(int errcode)
{
#define XS_BUFSIZE 32
    char *errbuf;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    char *strerror_str;

    pthread_once(&errbuf_pkey_once, _xc_init_errbuf);

    errbuf = pthread_getspecific(errbuf_pkey);
    if (errbuf == NULL) {
        errbuf = malloc(XS_BUFSIZE);
        pthread_setspecific(errbuf_pkey, errbuf);
    }

    /*
     * Thread-unsafe strerror() is protected by a local mutex. We copy
     * the string to a thread-private buffer before releasing the mutex.
     */
    pthread_mutex_lock(&mutex);
    strerror_str = strerror(errcode);
    strncpy(errbuf, strerror_str, XS_BUFSIZE);
    errbuf[XS_BUFSIZE-1] = '\0';
    pthread_mutex_unlock(&mutex);

    return errbuf;
}

void bitmap_64_to_byte(uint8_t *bp, const uint64_t *lp, int nbits)
{
    uint64_t l;
    int i, j, b;

    for (i = 0, b = 0; nbits > 0; i++, b += sizeof(l)) {
        l = lp[i];
        for (j = 0; (j < sizeof(l)) && (nbits > 0); j++) {
            bp[b+j] = l;
            l >>= 8;
            nbits -= 8;
        }
    }
}

void bitmap_byte_to_64(uint64_t *lp, const uint8_t *bp, int nbits)
{
    uint64_t l;
    int i, j, b;

    for (i = 0, b = 0; nbits > 0; i++, b += sizeof(l)) {
        l = 0;
        for (j = 0; (j < sizeof(l)) && (nbits > 0); j++) {
            l |= (uint64_t)bp[b+j] << (j*8);
            nbits -= 8;
        }
        lp[i] = l;
    }
}

int read_exact(int fd, void *data, size_t size)
{
    size_t offset = 0;
    ssize_t len;

    while ( offset < size )
    {
        len = read(fd, (char *)data + offset, size - offset);
        if ( (len == -1) && (errno == EINTR) )
            continue;
        if ( len == 0 )
            errno = 0;
        if ( len <= 0 )
            return -1;
        offset += len;
    }

    return 0;
}

int write_exact(int fd, const void *data, size_t size)
{
    size_t offset = 0;
    ssize_t len;

    while ( offset < size )
    {
        len = write(fd, (const char *)data + offset, size - offset);
        if ( (len == -1) && (errno == EINTR) )
            continue;
        if ( len <= 0 )
            return -1;
        offset += len;
    }

    return 0;
}

int xc_ffs8(uint8_t x)
{
    int i;
    for ( i = 0; i < 8; i++ )
        if ( x & (1u << i) )
            return i+1;
    return 0;
}

int xc_ffs16(uint16_t x)
{
    uint8_t h = x>>8, l = x;
    return l ? xc_ffs8(l) : h ? xc_ffs8(h) + 8 : 0;
}

int xc_ffs32(uint32_t x)
{
    uint16_t h = x>>16, l = x;
    return l ? xc_ffs16(l) : h ? xc_ffs16(h) + 16 : 0;
}

int xc_ffs64(uint64_t x)
{
    uint32_t h = x>>32, l = x;
    return l ? xc_ffs32(l) : h ? xc_ffs32(h) + 32 : 0;
}

void *xc_memalign(size_t alignment, size_t size)
{
#if defined(_POSIX_C_SOURCE) && !defined(__sun__)
    int ret;
    void *ptr;
    ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0)
        return NULL;
    return ptr;
#elif defined(__NetBSD__) || defined(__OpenBSD__)
    return valloc(size);
#else
    return memalign(alignment, size);
#endif
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
