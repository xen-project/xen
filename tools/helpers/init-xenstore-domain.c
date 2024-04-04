#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xenstore.h>
#include <xentoollog.h>
#include <libxl.h>
#include <xen/sys/xenbus_dev.h>
#include <xen-tools/common-macros.h>
#include <xen-xsm/flask/flask.h>
#include <xen/io/xenbus.h>

#include "init-dom-json.h"

#define LAPIC_BASE_ADDRESS  0xfee00000UL

static uint32_t domid = ~0;
static char *kernel;
static char *ramdisk;
static char *flask;
static char *param;
static char *name = "Xenstore";
static int memory;
static int maxmem;
static xen_pfn_t console_gfn;
static xc_evtchn_port_or_error_t console_evtchn;
static xentoollog_level minmsglevel = XTL_PROGRESS;
static void *logger;

static inline uint64_t mb_to_bytes(int mem)
{
    return (uint64_t)mem << 20;
}

static struct option options[] = {
    { "kernel", 1, NULL, 'k' },
    { "memory", 1, NULL, 'm' },
    { "flask", 1, NULL, 'f' },
    { "ramdisk", 1, NULL, 'r' },
    { "param", 1, NULL, 'p' },
    { "name", 1, NULL, 'n' },
    { "maxmem", 1, NULL, 'M' },
    { "verbose", 0, NULL, 'v' },
    { NULL, 0, NULL, 0 }
};

static void usage(void)
{
    fprintf(stderr,
"Usage:\n"
"\n"
"init-xenstore-domain <options>\n"
"\n"
"where options may include:\n"
"\n"
"  --kernel <xenstore-kernel> kernel file of the xenstore domain, mandatory\n"
"  --memory <memory size>     size of the domain in MB, mandatory\n"
"  --flask <flask-label>      optional flask label of the domain\n"
"  --ramdisk <ramdisk-file>   optional ramdisk file for the domain\n"
"  --param <cmdline>          optional additional parameters for the domain\n"
"  --name <name>              name of the domain (default: Xenstore)\n"
"  --maxmem <max size>        maximum memory size in the format:\n"
"                             <MB val>|<a>/<b>|<MB val>:<a>/<b>\n"
"                             (an absolute value in MB, a fraction a/b of\n"
"                             the host memory, or the maximum of both)\n"
"  -v[v[v]]                   verbosity of domain building\n");
}

static int build(xc_interface *xch)
{
    char cmdline[512];
    int rv, xs_fd;
    struct xc_dom_image *dom = NULL;
    int limit_kb = (maxmem ? : memory) * 1024 + X86_HVM_NR_SPECIAL_PAGES * 4;
    uint64_t mem_size = mb_to_bytes(memory);
    uint64_t max_size = mb_to_bytes(maxmem ? : memory);
    struct e820entry e820[3];
    struct xen_domctl_createdomain config = {
        .ssidref = SECINITSID_DOMU,
        .flags = XEN_DOMCTL_CDF_xs_domain,
        .max_vcpus = 1,
        .max_evtchn_port = -1, /* No limit. */

        /*
         * 1 grant frame is enough: we don't need many grants.
         * Mini-OS doesn't like less than 4, though, so use 4.
         * 128 maptrack frames: 256 entries per frame, enough for 32768 domains.
         * Currently Mini-OS only supports grant v1.
         */
        .max_grant_frames = 4,
        .max_maptrack_frames = 128,
        .grant_opts = XEN_DOMCTL_GRANT_version(1),
    };

    xs_fd = open("/dev/xen/xenbus_backend", O_RDWR);
    if ( xs_fd == -1 )
    {
        fprintf(stderr, "Could not open /dev/xen/xenbus_backend\n");
        return -1;
    }

    if ( flask )
    {
        rv = xc_flask_context_to_sid(xch, flask, strlen(flask), &config.ssidref);
        if ( rv )
        {
            fprintf(stderr, "xc_flask_context_to_sid failed\n");
            goto err;
        }
    }

    dom = xc_dom_allocate(xch, NULL, NULL);
    if ( !dom )
    {
        fprintf(stderr, "xc_dom_allocate failed\n");
        rv = -1;
        goto err;
    }

    rv = xc_dom_kernel_file(dom, kernel);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_kernel_file failed\n");
        goto err;
    }

    if ( ramdisk )
    {
        rv = xc_dom_module_file(dom, ramdisk, NULL);
        if ( rv )
        {
            fprintf(stderr, "xc_dom_module_file failed\n");
            goto err;
        }
    }

    rv = xc_dom_boot_xen_init(dom, xch, domid);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_boot_xen_init failed\n");
        goto err;
    }

    /*
     * This is a bodge.  We can't currently inspect the kernel's ELF notes
     * ahead of attempting to construct a domain, so try PVH first, suppressing
     * errors by setting min level to high, and fall back to PV.
     */
    dom->container_type = XC_DOM_HVM_CONTAINER;
    xtl_stdiostream_set_minlevel(logger, XTL_CRITICAL);
    rv = xc_dom_parse_image(dom);
    xtl_stdiostream_set_minlevel(logger, minmsglevel);
    if ( rv )
    {
        dom->container_type = XC_DOM_PV_CONTAINER;
        rv = xc_dom_parse_image(dom);
        if ( rv )
        {
            /* Retry PVH, now with normal logging level. */
            dom->container_type = XC_DOM_HVM_CONTAINER;
            rv = xc_dom_parse_image(dom);
            if ( rv )
            {
                fprintf(stderr, "xc_dom_parse_image failed\n");
                goto err;
            }
        }
    }

    if ( dom->container_type == XC_DOM_HVM_CONTAINER )
    {
        config.flags |= XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap;
        config.arch.emulation_flags = XEN_X86_EMU_LAPIC;
        dom->target_pages = mem_size >> XC_PAGE_SHIFT;
        dom->mmio_size = GB(4) - LAPIC_BASE_ADDRESS;
        dom->lowmem_end = (mem_size > LAPIC_BASE_ADDRESS) ?
                          LAPIC_BASE_ADDRESS : mem_size;
        dom->highmem_end = (mem_size > LAPIC_BASE_ADDRESS) ?
                           GB(4) + mem_size - LAPIC_BASE_ADDRESS : 0;
        dom->mmio_start = LAPIC_BASE_ADDRESS;
        dom->max_vcpus = 1;
        e820[0].addr = 0;
        e820[0].size = (max_size > LAPIC_BASE_ADDRESS) ?
                       LAPIC_BASE_ADDRESS : max_size;
        e820[0].type = E820_RAM;
        e820[1].addr = (X86_HVM_END_SPECIAL_REGION -
                        X86_HVM_NR_SPECIAL_PAGES) << XC_PAGE_SHIFT;
        e820[1].size = X86_HVM_NR_SPECIAL_PAGES << XC_PAGE_SHIFT;
        e820[1].type = E820_RESERVED;
        e820[2].addr = GB(4);
        e820[2].size = (max_size > LAPIC_BASE_ADDRESS) ?
                       max_size - LAPIC_BASE_ADDRESS : 0;
        e820[2].type = E820_RAM;
    }

    rv = xc_domain_create(xch, &domid, &config);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_create failed\n");
        goto err;
    }
    rv = xc_domain_max_vcpus(xch, domid, config.max_vcpus);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_max_vcpus failed\n");
        goto err;
    }
    rv = xc_domain_setmaxmem(xch, domid, limit_kb);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_setmaxmem failed\n");
        goto err;
    }
    console_evtchn = xc_evtchn_alloc_unbound(xch, domid, 0);
    if ( console_evtchn < 0 )
    {
        fprintf(stderr, "xc_evtchn_alloc_unbound failed\n");
        goto err;
    }

    if ( dom->container_type == XC_DOM_PV_CONTAINER )
    {
        rv = xc_domain_set_memmap_limit(xch, domid, limit_kb);
        if ( rv )
        {
            fprintf(stderr, "xc_domain_set_memmap_limit failed\n");
            goto err;
        }
    }

    rv = ioctl(xs_fd, IOCTL_XENBUS_BACKEND_SETUP, domid);
    if ( rv < 0 )
    {
        fprintf(stderr, "Xenbus setup ioctl failed\n");
        goto err;
    }

    if ( param )
        snprintf(cmdline, 512, "--event %d %s", rv, param);
    else
        snprintf(cmdline, 512, "--event %d", rv);

    dom->guest_domid = domid;
    dom->cmdline = xc_dom_strdup(dom, cmdline);
    dom->xenstore_domid = domid;
    dom->console_evtchn = console_evtchn;
    rv = xc_evtchn_alloc_unbound(xch, domid, domid);
    if ( rv < 0 )
    {
        fprintf(stderr, "xc_evtchn_alloc_unbound failed\n");
        goto err;
    }
    dom->xenstore_evtchn = rv;

    rv = xc_dom_mem_init(dom, memory);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_mem_init failed\n");
        goto err;
    }
    rv = xc_dom_boot_mem_init(dom);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_boot_mem_init failed\n");
        goto err;
    }
    if ( dom->container_type == XC_DOM_HVM_CONTAINER )
    {
        rv = xc_domain_set_memory_map(xch, domid, e820,
                                      dom->highmem_end ? 3 : 2);
        if ( rv )
        {
            fprintf(stderr, "xc_domain_set_memory_map failed\n");
            goto err;
        }
    }
    rv = xc_dom_build_image(dom);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_build_image failed\n");
        goto err;
    }
    rv = xc_dom_boot_image(dom);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_boot_image failed\n");
        goto err;
    }
    rv = xc_dom_gnttab_init(dom);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_gnttab_init failed\n");
        goto err;
    }

    rv = xc_domain_set_virq_handler(xch, domid, VIRQ_DOM_EXC);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_set_virq_handler failed\n");
        goto err;
    }
    rv = xc_domain_unpause(xch, domid);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_unpause failed\n");
        goto err;
    }

    rv = 0;
    console_gfn = (dom->container_type == XC_DOM_PV_CONTAINER)
                  ? xc_dom_p2m(dom, dom->console_pfn)
                  : dom->console_pfn;

err:
    if ( dom )
        xc_dom_release(dom);
    if ( xs_fd >= 0 )
        close(xs_fd);

    /* if we failed then destroy the domain */
    if ( rv && domid != ~0 )
        xc_domain_destroy(xch, domid);

    return rv;
}

static int check_domain(xc_interface *xch)
{
    /* Commonly dom0 is the only domain, but buffer a little for efficiency. */
    xc_domaininfo_t info[8];
    uint32_t dom;
    int ret;

    dom = 1;
    while ( (ret = xc_domain_getinfolist(xch, dom, ARRAY_SIZE(info), info)) > 0 )
    {
        for ( size_t i = 0; i < ret; i++ )
        {
            if ( info[i].flags & XEN_DOMINF_xs_domain )
                return 1;
        }
        dom = info[ret - 1].domain + 1;
    }
    if ( ret < 0 && errno != ESRCH )
    {
        fprintf(stderr, "xc_domain_getinfo failed\n");
        return ret;
    }

    return 0;
}

static int parse_maxmem(xc_interface *xch, char *str)
{
    xc_physinfo_t info;
    int rv;
    unsigned long mb = 0, a = 0, b = 0;
    unsigned long val;
    unsigned long *res;
    char *p;
    char *s = str;

    rv = xc_physinfo(xch, &info);
    if ( rv )
    {
        fprintf(stderr, "xc_physinfo failed\n");
        return -1;
    }

    res = &mb;
    for (p = s; *p; s = p + 1)
    {
        val = strtoul(s, &p, 10);
        if ( val == 0 || val >= INT_MAX / 1024 )
            goto err;
        if ( *p == '/' )
        {
            if ( res != &mb || a != 0 )
                goto err;
            a = val;
            res = &b;
            continue;
        }
        if ( *res != 0 )
            goto err;
        *res = val;
        if ( *p != 0 && *p != ':' )
            goto err;
        res = &mb;
    }
    if ( a && !b )
        goto err;

    val = a ? info.total_pages * a / (b * 1024 * 1024 / XC_PAGE_SIZE) : 0;
    if ( val >= INT_MAX / 1024 )
        goto err;

    maxmem = mb < val ? val : mb;
    if ( maxmem < memory )
        maxmem = 0;

    return maxmem;

err:
    fprintf(stderr, "illegal value for maxmem: %s\n", str);
    return -1;
}

static void do_xs_write(struct xs_handle *xsh, char *path, char *val)
{
    if ( !xs_write(xsh, XBT_NULL, path, val, strlen(val)) )
        fprintf(stderr, "writing %s to xenstore failed.\n", path);
}

static void do_xs_write_dom(struct xs_handle *xsh, char *path, char *val)
{
    char full_path[64];

    snprintf(full_path, 64, "/local/domain/%d/%s", domid, path);
    do_xs_write(xsh, full_path, val);
}

int main(int argc, char** argv)
{
    int opt;
    xc_interface *xch;
    struct xs_handle *xsh;
    char buf[16];
    int rv, fd;
    char *maxmem_str = NULL;
    libxl_ctx *ctx;
    libxl_device_p9 p9 = { .backend_domid = 0,
                           .tag = "Xen",
                           .path = XEN_LIB_DIR"/xenstore",
                           .security_model = "none",
                           .type = LIBXL_P9_TYPE_XEN_9PFSD,
    };

    while ( (opt = getopt_long(argc, argv, "v", options, NULL)) != -1 )
    {
        switch ( opt )
        {
        case 'k':
            kernel = optarg;
            break;
        case 'm':
            memory = strtol(optarg, NULL, 10);
            break;
        case 'f':
            flask = optarg;
            break;
        case 'r':
            ramdisk = optarg;
            break;
        case 'p':
            param = optarg;
            break;
        case 'n':
            name = optarg;
            break;
        case 'M':
            maxmem_str = optarg;
            break;
        case 'v':
            if ( minmsglevel )
                minmsglevel--;
            break;
        default:
            usage();
            return 2;
        }
    }

    if ( optind != argc || !kernel || !memory )
    {
        usage();
        return 2;
    }

    logger = xtl_createlogger_stdiostream(stderr, minmsglevel, 0);
    xch = xc_interface_open(logger, logger, 0);
    if ( !xch )
    {
        fprintf(stderr, "xc_interface_open() failed\n");
        rv = 1;
        goto out;
    }

    if ( maxmem_str )
    {
        maxmem = parse_maxmem(xch, maxmem_str);
        if ( maxmem < 0 )
        {
            xc_interface_close(xch);
            rv = 1;
            goto out;
        }
    }

    rv = check_domain(xch);

    if ( !rv )
        rv = build(xch);
    else if ( rv > 0 )
        fprintf(stderr, "xenstore domain already present.\n");

    xc_interface_close(xch);

    if ( rv )
    {
        rv = 1;
        goto out;
    }

    rv = gen_stub_json_config(domid, NULL);
    if ( rv )
    {
        rv = 3;
        goto out;
    }

    xsh = xs_open(0);
    if ( !xsh )
    {
        fprintf(stderr, "xs_open() failed.\n");
        rv = 3;
        goto out;
    }
    snprintf(buf, 16, "%d", domid);
    do_xs_write(xsh, "/tool/xenstored/domid", buf);
    do_xs_write_dom(xsh, "domid", buf);
    do_xs_write_dom(xsh, "name", name);
    snprintf(buf, 16, "%d", memory * 1024);
    do_xs_write_dom(xsh, "memory/target", buf);
    if (maxmem)
        snprintf(buf, 16, "%d", maxmem * 1024);
    do_xs_write_dom(xsh, "memory/static-max", buf);
    xs_close(xsh);

    if ( libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, logger))
    {
        fprintf(stderr, "libxl_ctx_alloc() failed.\n");
        rv = 3;
        goto out;
    }
    libxl_console_add_xenstore(ctx, domid, 0, console_evtchn, console_gfn,
                               NULL);
    libxl_device_9pfs_add(ctx, domid, &p9, NULL);
    libxl_ctx_free(ctx);

    fd = creat(XEN_RUN_DIR "/xenstored.pid", 0666);
    if ( fd < 0 )
    {
        fprintf(stderr, "Creating " XEN_RUN_DIR "/xenstored.pid failed\n");
        rv = 3;
        goto out;
    }
    rv = snprintf(buf, 16, "domid:%d\n", domid);
    rv = write(fd, buf, rv);
    close(fd);
    if ( rv < 0 )
    {
        fprintf(stderr,
                "Writing domid to " XEN_RUN_DIR "/xenstored.pid failed\n");
        rv = 3;
        goto out;
    }

    rv = 0;

 out:
    if ( logger )
        xtl_logger_destroy(logger);

    return rv;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
