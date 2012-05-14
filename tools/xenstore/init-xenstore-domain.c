#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <xenctrl.h>
#include <xc_dom.h>
#include <xenstore.h>
#include <xen/sys/xenbus_dev.h>

static uint32_t domid = -1;

static int build(xc_interface *xch, char** argv)
{
	char cmdline[512];
	uint32_t ssid;
	xen_domain_handle_t handle = { 0 };
	int rv;
	int xs_fd = open("/dev/xen/xenbus_backend", O_RDWR);
	struct xc_dom_image *dom;
	int maxmem = atoi(argv[2]);
	int limit_kb = (maxmem + 1)*1024;

	rv = xc_flask_context_to_sid(xch, argv[3], strlen(argv[3]), &ssid);
	if (rv) return rv;
	rv = xc_domain_create(xch, ssid, handle, 0, &domid);
	if (rv) return rv;
	rv = xc_domain_max_vcpus(xch, domid, 1);
	if (rv) return rv;
	rv = xc_domain_setmaxmem(xch, domid, limit_kb);
	if (rv) return rv;
	rv = xc_domain_set_memmap_limit(xch, domid, limit_kb);
	if (rv) return rv;

	rv = ioctl(xs_fd, IOCTL_XENBUS_BACKEND_SETUP, domid);
	if (rv < 0) return rv;
	snprintf(cmdline, 512, "--event %d --internal-db", rv);

	dom = xc_dom_allocate(xch, cmdline, NULL);
	rv = xc_dom_kernel_file(dom, argv[1]);
	if (rv) return rv;
	rv = xc_dom_boot_xen_init(dom, xch, domid);
	if (rv) return rv;
	rv = xc_dom_parse_image(dom);
	if (rv) return rv;
	rv = xc_dom_mem_init(dom, maxmem);
	if (rv) return rv;
	rv = xc_dom_boot_mem_init(dom);
	if (rv) return rv;
	rv = xc_dom_build_image(dom);
	if (rv) return rv;
	rv = xc_dom_boot_image(dom);
	if (rv) return rv;

	xc_dom_release(dom);

	rv = xc_domain_set_virq_handler(xch, domid, VIRQ_DOM_EXC);
	if (rv) return rv;
	rv = xc_domain_unpause(xch, domid);
	if (rv) return rv;

	return 0;
}

int main(int argc, char** argv)
{
	xc_interface *xch;
	struct xs_handle *xsh;
	char buf[16];
	int rv;

	if (argc != 4) {
		printf("Use: %s <xenstore-kernel> <memory_mb> <flask-label>\n", argv[0]);
		return 2;
	}

	xch = xc_interface_open(NULL, NULL, 0);
	if (!xch) return 1;

	rv = build(xch, argv);

	xc_interface_close(xch);

	if (rv) return 1;

	xsh = xs_open(0);
	rv = snprintf(buf, 16, "%d", domid);
	xs_write(xsh, XBT_NULL, "/tool/xenstored/domid", buf, rv);
	xs_daemon_close(xsh);

	return 0;
}
