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

#ifndef __MINIOS__
#include <dlfcn.h>
#endif

#define XENCTRL_OSDEP "XENCTRL_OSDEP"

#if !defined (__MINIOS__) && !defined(__RUMPUSER_XEN__) && !defined(__RUMPRUN__)
#define DO_DYNAMIC_OSDEP
#endif

/*
 * Returns a (shallow) copy of the xc_osdep_info_t for the
 * active OS interface.
 *
 * On success a handle to the relevant library is opened.  The user
 * must subsequently call xc_osdep_put_info() when it is
 * finished with the library.
 *
 * Logs IFF xch != NULL.
 *
 * Returns:
 *  0 - on success
 * -1 - on error
 */
static int xc_osdep_get_info(xc_interface *xch, xc_osdep_info_t *info)
{
    int rc = -1;
#ifdef DO_DYNAMIC_OSDEP
    const char *lib = getenv(XENCTRL_OSDEP);
    xc_osdep_info_t *pinfo;
    void *dl_handle = NULL;

    if ( lib != NULL )
    {
        if ( getuid() != geteuid() )
        {
            if ( xch ) ERROR("cannot use %s=%s with setuid application", XENCTRL_OSDEP, lib);
            abort();
        }
        if ( getgid() != getegid() )
        {
            if ( xch ) ERROR("cannot use %s=%s with setgid application", XENCTRL_OSDEP, lib);
            abort();
        }

        dl_handle = dlopen(lib, RTLD_LAZY|RTLD_LOCAL);
        if ( !dl_handle )
        {
            if ( xch ) ERROR("unable to open osdep library %s: %s", lib, dlerror());
            goto out;
        }

        pinfo = dlsym(dl_handle, "xc_osdep_info");
        if ( !pinfo )
        {
            if ( xch ) ERROR("unable to find xc_osinteface_info in %s: %s", lib, dlerror());
            goto out;
        }

        *info = *pinfo;
        info->dl_handle = dl_handle;
    }
    else
#endif /*DO_DYNAMIC_OSDEP*/
    {
        *info = xc_osdep_info;
        info->dl_handle = NULL;
    }

    rc = 0;

#ifdef DO_DYNAMIC_OSDEP
out:
    if ( dl_handle && rc == -1 )
        dlclose(dl_handle);
#endif /*DO_DYNAMIC_OSDEP*/

    return rc;
}

static void xc_osdep_put(xc_osdep_info_t *info)
{
#ifdef DO_DYNAMIC_OSDEP
    if ( info->dl_handle )
        dlclose(info->dl_handle);
#endif /*DO_DYNAMIC_OSDEP*/
}

static const char *xc_osdep_type_name(enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD: return "privcmd";
    case XC_OSDEP_EVTCHN:  return "evtchn";
    case XC_OSDEP_GNTTAB:  return "gnttab";
    case XC_OSDEP_GNTSHR:  return "gntshr";
    }
    return "unknown";
}

static struct xc_interface_core *xc_interface_open_common(xentoollog_logger *logger,
                                                          xentoollog_logger *dombuild_logger,
                                                          unsigned open_flags,
                                                          enum xc_osdep_type type)
{
    struct xc_interface_core xch_buf, *xch = &xch_buf;

    xch->type = type;
    xch->flags = open_flags;
    xch->dombuild_logger_file = 0;
    xc_clear_last_error(xch);

    xch->error_handler   = logger;           xch->error_handler_tofree   = 0;
    xch->dombuild_logger = dombuild_logger;  xch->dombuild_logger_tofree = 0;

    xch->hypercall_buffer_cache_nr = 0;

    xch->hypercall_buffer_total_allocations = 0;
    xch->hypercall_buffer_total_releases = 0;
    xch->hypercall_buffer_current_allocations = 0;
    xch->hypercall_buffer_maximum_allocations = 0;
    xch->hypercall_buffer_cache_hits = 0;
    xch->hypercall_buffer_cache_misses = 0;
    xch->hypercall_buffer_cache_toobig = 0;

    xch->ops_handle = XC_OSDEP_OPEN_ERROR;
    xch->ops = NULL;

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
        if ( xc_osdep_get_info(xch, &xch->osdep) < 0 )
            goto err;

        xch->ops = xch->osdep.init(xch, type);
        if ( xch->ops == NULL )
        {
            DPRINTF("OSDEP: interface %d (%s) not supported on this platform",
                  type, xc_osdep_type_name(type));
            goto err_put_iface;
        }

        xch->ops_handle = xch->ops->open(xch);
        if (xch->ops_handle == XC_OSDEP_OPEN_ERROR)
            goto err_put_iface;
    }

    return xch;

err_put_iface:
    xc_osdep_put(&xch->osdep);
 err:
    xtl_logger_destroy(xch->error_handler_tofree);
    if (xch != &xch_buf) free(xch);
    return NULL;
}

static int xc_interface_close_common(xc_interface *xch)
{
    int rc = 0;

    if (!xch)
	return 0;

    rc = xch->ops->close(xch, xch->ops_handle);
    if (rc) PERROR("Could not close hypervisor interface");

    xc__hypercall_buffer_cache_release(xch);

    xtl_logger_destroy(xch->dombuild_logger_tofree);
    xtl_logger_destroy(xch->error_handler_tofree);

    free(xch);
    return rc;
}

int xc_interface_is_fake(void)
{
    xc_osdep_info_t info;

    if ( xc_osdep_get_info(NULL, &info) < 0 )
        return -1;

    /* Have a copy of info so can release the interface now. */
    xc_osdep_put(&info);

    return info.fake;
}

xc_interface *xc_interface_open(xentoollog_logger *logger,
                                xentoollog_logger *dombuild_logger,
                                unsigned open_flags)
{
    xc_interface *xch;

    xch = xc_interface_open_common(logger, dombuild_logger, open_flags,
                                   XC_OSDEP_PRIVCMD);

    return xch;
}

int xc_interface_close(xc_interface *xch)
{
    return xc_interface_close_common(xch);
}


int do_xen_hypercall(xc_interface *xch, privcmd_hypercall_t *hypercall)
{
    return xch->ops->u.privcmd.hypercall(xch, xch->ops_handle, hypercall);
}

xc_evtchn *xc_evtchn_open(xentoollog_logger *logger,
                             unsigned open_flags)
{
    xc_evtchn *xce;

    xce = xc_interface_open_common(logger, NULL, open_flags,
                                   XC_OSDEP_EVTCHN);

    return xce;
}

int xc_evtchn_close(xc_evtchn *xce)
{
    return xc_interface_close_common(xce);
}

xc_gnttab *xc_gnttab_open(xentoollog_logger *logger,
                             unsigned open_flags)
{
    return xc_interface_open_common(logger, NULL, open_flags,
                                    XC_OSDEP_GNTTAB);
}

int xc_gnttab_close(xc_gnttab *xcg)
{
    return xc_interface_close_common(xcg);
}

xc_gntshr *xc_gntshr_open(xentoollog_logger *logger,
                             unsigned open_flags)
{
    return xc_interface_open_common(logger, NULL, open_flags,
                                    XC_OSDEP_GNTSHR);
}

int xc_gntshr_close(xc_gntshr *xcg)
{
    return xc_interface_close_common(xcg);
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

void xc_osdep_log(xc_interface *xch, xentoollog_level level, int code, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    xc_reportv(xch, xch->error_handler, level, code, fmt, args);
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
    set_xen_guest_handle(domctl.u.getpageframeinfo3.array, arr);
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
    DECLARE_HYPERCALL_BOUNCE(op, nr_ops*sizeof(*op), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    long ret = -EINVAL;

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce memory for mmuext op hypercall");
        goto out1;
    }

    hypercall.op     = __HYPERVISOR_mmuext_op;
    hypercall.arg[0] = HYPERCALL_BUFFER_AS_ARG(op);
    hypercall.arg[1] = (unsigned long)nr_ops;
    hypercall.arg[2] = (unsigned long)0;
    hypercall.arg[3] = (unsigned long)dom;

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_bounce_post(xch, op);

 out1:
    return ret;
}

static int flush_mmu_updates(xc_interface *xch, struct xc_mmu *mmu)
{
    int err = 0;
    DECLARE_HYPERCALL;
    DECLARE_NAMED_HYPERCALL_BOUNCE(updates, mmu->updates, mmu->idx*sizeof(*mmu->updates), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( mmu->idx == 0 )
        return 0;

    if ( xc_hypercall_bounce_pre(xch, updates) )
    {
        PERROR("flush_mmu_updates: bounce buffer failed");
        err = 1;
        goto out;
    }

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = HYPERCALL_BUFFER_AS_ARG(updates);
    hypercall.arg[1] = (unsigned long)mmu->idx;
    hypercall.arg[2] = 0;
    hypercall.arg[3] = mmu->subject;

    if ( do_xen_hypercall(xch, &hypercall) < 0 )
    {
        ERROR("Failure when submitting mmu updates");
        err = 1;
    }

    mmu->idx = 0;

    xc_hypercall_bounce_post(xch, updates);

 out:
    return err;
}

struct xc_mmu *xc_alloc_mmu_updates(xc_interface *xch, unsigned int subject)
{
    struct xc_mmu *mmu = malloc(sizeof(*mmu));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = 0;
    mmu->subject = subject;
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
    DECLARE_HYPERCALL_BOUNCE(arg, len, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    long ret = -EINVAL;

    if ( xc_hypercall_bounce_pre(xch, arg) )
    {
        PERROR("Could not bounce memory for XENMEM hypercall");
        goto out1;
    }

    hypercall.op     = __HYPERVISOR_memory_op;
    hypercall.arg[0] = (unsigned long) cmd;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_bounce_post(xch, arg);
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
    DECLARE_HYPERCALL_BOUNCE(extent_start, max_extents * sizeof(xen_pfn_t), XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    struct xen_machphys_mfn_list xmml = {
        .max_extents = max_extents,
    };

    if ( xc_hypercall_bounce_pre(xch, extent_start) )
    {
        PERROR("Could not bounce memory for XENMEM_machphys_mfn_list hypercall");
        return -1;
    }

    set_xen_guest_handle(xmml.extent_start, extent_start);
    rc = do_memory_op(xch, XENMEM_machphys_mfn_list, &xmml, sizeof(xmml));
    if (rc || xmml.nr_extents != max_extents)
        rc = -1;
    else
        rc = 0;

    xc_hypercall_bounce_post(xch, extent_start);

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

    if ( xc_hypercall_bounce_pre(xch, pfn_buf) )
    {
        PERROR("xc_get_pfn_list: pfn_buf bounce failed");
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_getmemlist;
    domctl.domain   = (domid_t)domid;
    domctl.u.getmemlist.max_pfns = max_pfns;
    set_xen_guest_handle(domctl.u.getmemlist.buffer, pfn_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, pfn_buf);

    return (ret < 0) ? -1 : domctl.u.getmemlist.num_pfns;
}

long xc_get_tot_pages(xc_interface *xch, uint32_t domid)
{
    xc_dominfo_t info;
    if ( (xc_domain_getinfo(xch, domid, 1, &info) != 1) ||
         (info.domid != domid) )
        return -1;
    return info.nr_pages;
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
    xc_domain_cacheflush(xch, domid, dst_pfn, 1);
    return 0;
}

int xc_clear_domain_pages(xc_interface *xch,
                          uint32_t domid,
                          unsigned long dst_pfn,
                          int num)
{
    size_t size = num * PAGE_SIZE;
    void *vaddr = xc_map_foreign_range(
        xch, domid, size, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memset(vaddr, 0, size);
    munmap(vaddr, size);
    xc_domain_cacheflush(xch, domid, dst_pfn, num);
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
    size_t sz;
    int rc;

    switch ( cmd )
    {
    case XENVER_version:
        sz = 0;
        break;
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
    case XENVER_get_features:
        sz = sizeof(xen_feature_info_t);
        break;
    case XENVER_pagesize:
        sz = 0;
        break;
    case XENVER_guest_handle:
        sz = sizeof(xen_domain_handle_t);
        break;
    case XENVER_commandline:
        sz = sizeof(xen_commandline_t);
        break;
    default:
        ERROR("xc_version: unknown command %d\n", cmd);
        return -EINVAL;
    }

    HYPERCALL_BOUNCE_SET_SIZE(arg, sz);

    if ( (sz != 0) && xc_hypercall_bounce_pre(xch, arg) )
    {
        PERROR("Could not bounce buffer for version hypercall");
        return -ENOMEM;
    }

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

const char *xc_strerror(xc_interface *xch, int errcode)
{
    if ( xch->flags & XC_OPENFLAG_NON_REENTRANT )
    {
        return strerror(errcode);
    }
    else
    {
#define XS_BUFSIZE 32
        char *errbuf;
        static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        char *strerror_str;

        pthread_once(&errbuf_pkey_once, _xc_init_errbuf);

        errbuf = pthread_getspecific(errbuf_pkey);
        if (errbuf == NULL) {
            errbuf = malloc(XS_BUFSIZE);
            if ( errbuf == NULL )
                return "(failed to allocate errbuf)";
            pthread_setspecific(errbuf_pkey, errbuf);
        }

        /*
         * Thread-unsafe strerror() is protected by a local mutex. We copy the
         * string to a thread-private buffer before releasing the mutex.
         */
        pthread_mutex_lock(&mutex);
        strerror_str = strerror(errcode);
        strncpy(errbuf, strerror_str, XS_BUFSIZE);
        errbuf[XS_BUFSIZE-1] = '\0';
        pthread_mutex_unlock(&mutex);

        return errbuf;
    }
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
