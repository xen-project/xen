/*
 * xencov: extract test coverage information from Xen.
 *
 * Copyright (c) 2013, 2016, Citrix Systems R&D Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xenctrl.h>

static xc_interface *xch = NULL;

int cov_sysctl(int op, struct xen_sysctl *sysctl,
               struct xc_hypercall_buffer *buf, uint32_t buf_size)
{
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(buf);

    memset(sysctl, 0, sizeof(*sysctl));
    sysctl->cmd = XEN_SYSCTL_coverage_op;

    sysctl->u.coverage_op.cmd = op;
    sysctl->u.coverage_op.size = buf_size;
    set_xen_guest_handle(sysctl->u.coverage_op.buffer, buf);

    return xc_sysctl(xch, sysctl);
}

static void cov_read(const char *fn)
{
    struct xen_sysctl sys;
    uint32_t total_len;
    DECLARE_HYPERCALL_BUFFER(uint8_t, p);
    FILE *f;

    if (cov_sysctl(XEN_SYSCTL_COVERAGE_get_size, &sys, NULL, 0) < 0)
        err(1, "getting total length");
    total_len = sys.u.coverage_op.size;

    /* Shouldn't exceed a few hundred kilobytes */
    if (total_len > 8u * 1024u * 1024u)
        errx(1, "gcov data too big %u bytes\n", total_len);

    p = xc_hypercall_buffer_alloc(xch, p, total_len);
    if (!p)
        err(1, "allocating buffer");

    memset(p, 0, total_len);
    if (cov_sysctl(XEN_SYSCTL_COVERAGE_read, &sys, HYPERCALL_BUFFER(p),
                    total_len) < 0)
        err(1, "getting gcov data");

    if (!strcmp(fn, "-"))
        f = stdout;
    else
        f = fopen(fn, "w");

    if (!f)
        err(1, "opening output file");

    if (fwrite(p, 1, total_len, f) != total_len)
        err(1, "writing gcov data to file");

    if (f != stdout)
        fclose(f);

    xc_hypercall_buffer_free(xch, p);
}

static void cov_reset(void)
{
    struct xen_sysctl sys;

    if (cov_sysctl(XEN_SYSCTL_COVERAGE_reset, &sys, NULL, 0) < 0)
        err(1, "resetting gcov information");
}

static void usage(int exit_code)
{
    FILE *out = exit_code ? stderr : stdout;

    fprintf(out, "xencov {reset|read} [<filename>]\n"
        "\treset       reset information\n"
        "\tread        read information from xen to filename\n"
        "\tfilename    optional filename (default output)\n"
        );
    exit(exit_code);
}

int main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            usage(0);
            break;
        default:
            usage(1);
        }
    }

    argv += optind;
    argc -= optind;
    if (argc <= 0)
        usage(1);

    xch = xc_interface_open(NULL, NULL, 0);
    if (!xch)
        err(1, "opening xc interface");

    if (strcmp(argv[0], "reset") == 0)
        cov_reset();
    else if (strcmp(argv[0], "read") == 0)
        cov_read(argc > 1 ? argv[1] : "-");
    else
        usage(1);

    xc_interface_close(xch);

    return 0;
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
