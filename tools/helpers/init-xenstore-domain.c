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
#include <xc_dom.h>
#include <xenstore.h>
#include <xen/sys/xenbus_dev.h>
#include <xen-xsm/flask/flask.h>

#include "init-dom-json.h"
#include "_paths.h"

static uint32_t domid = ~0;
static char *kernel;
static char *ramdisk;
static char *flask;
static char *param;
static char *name = "Xenstore";
static int memory;
static int maxmem;

static struct option options[] = {
    { "kernel", 1, NULL, 'k' },
    { "memory", 1, NULL, 'm' },
    { "flask", 1, NULL, 'f' },
    { "ramdisk", 1, NULL, 'r' },
    { "param", 1, NULL, 'p' },
    { "name", 1, NULL, 'n' },
    { "maxmem", 1, NULL, 'M' },
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
"                             the host memory, or the maximum of both)\n");
}

static int build(xc_interface *xch)
{
    char cmdline[512];
    uint32_t ssid;
    xen_domain_handle_t handle = { 0 };
    int rv, xs_fd;
    struct xc_dom_image *dom = NULL;
    int limit_kb = (maxmem ? : (memory + 1)) * 1024;

    xs_fd = open("/dev/xen/xenbus_backend", O_RDWR);
    if ( xs_fd == -1 )
    {
        fprintf(stderr, "Could not open /dev/xen/xenbus_backend\n");
        return -1;
    }

    if ( flask )
    {
        rv = xc_flask_context_to_sid(xch, flask, strlen(flask), &ssid);
        if ( rv )
        {
            fprintf(stderr, "xc_flask_context_to_sid failed\n");
            goto err;
        }
    }
    else
    {
        ssid = SECINITSID_DOMU;
    }
    rv = xc_domain_create(xch, ssid, handle, XEN_DOMCTL_CDF_xs_domain,
                          &domid, NULL);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_create failed\n");
        goto err;
    }
    rv = xc_domain_max_vcpus(xch, domid, 1);
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
    rv = xc_domain_set_memmap_limit(xch, domid, limit_kb);
    if ( rv )
    {
        fprintf(stderr, "xc_domain_set_memmap_limit failed\n");
        goto err;
    }

    rv = ioctl(xs_fd, IOCTL_XENBUS_BACKEND_SETUP, domid);
    if ( rv < 0 )
    {
        fprintf(stderr, "Xenbus setup ioctl failed\n");
        goto err;
    }

    if ( param )
        snprintf(cmdline, 512, "--event %d --internal-db %s", rv, param);
    else
        snprintf(cmdline, 512, "--event %d --internal-db", rv);

    dom = xc_dom_allocate(xch, cmdline, NULL);
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
    rv = xc_dom_parse_image(dom);
    if ( rv )
    {
        fprintf(stderr, "xc_dom_parse_image failed\n");
        goto err;
    }
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
    xc_dominfo_t info;
    uint32_t dom;
    int ret;

    dom = 1;
    while ( (ret = xc_domain_getinfo(xch, dom, 1, &info)) == 1 )
    {
        if ( info.xenstore )
            return 1;
        dom = info.domid + 1;
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

    while ( (opt = getopt_long(argc, argv, "", options, NULL)) != -1 )
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

    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch )
    {
        fprintf(stderr, "xc_interface_open() failed\n");
        return 1;
    }

    if ( maxmem_str )
    {
        maxmem = parse_maxmem(xch, maxmem_str);
        if ( maxmem < 0 )
        {
            xc_interface_close(xch);
            return 1;
        }
    }

    rv = check_domain(xch);

    if ( !rv )
        rv = build(xch);
    else if ( rv > 0 )
        fprintf(stderr, "xenstore domain already present.\n");

    xc_interface_close(xch);

    if ( rv )
        return 1;

    rv = gen_stub_json_config(domid);
    if ( rv )
        return 3;

    xsh = xs_open(0);
    if ( !xsh )
    {
        fprintf(stderr, "xs_open() failed.\n");
        return 3;
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

    fd = creat(XEN_RUN_DIR "/xenstored.pid", 0666);
    if ( fd < 0 )
    {
        fprintf(stderr, "Creating " XEN_RUN_DIR "/xenstored.pid failed\n");
        return 3;
    }
    rv = snprintf(buf, 16, "domid:%d\n", domid);
    rv = write(fd, buf, rv);
    close(fd);
    if ( rv < 0 )
    {
        fprintf(stderr,
                "Writing domid to " XEN_RUN_DIR "/xenstored.pid failed\n");
        return 3;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
