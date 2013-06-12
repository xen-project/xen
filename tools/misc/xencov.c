/*
 * xencov: handle test coverage information from Xen.
 *
 * Copyright (c) 2013, Citrix Systems R&D Ltd.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xenctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

static xc_interface *gcov_xch = NULL;

static void gcov_init(void)
{
    gcov_xch = xc_interface_open(NULL, NULL, 0);
    if ( !gcov_xch )
        err(1, "opening interface");
}

int gcov_get_info(int op, struct xen_sysctl *sys, struct xc_hypercall_buffer *ptr)
{
    struct xen_sysctl_coverage_op *cov;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(ptr);

    memset(sys, 0, sizeof(*sys));
    sys->cmd = XEN_SYSCTL_coverage_op;

    cov = &sys->u.coverage_op;
    cov->cmd = op;
    set_xen_guest_handle(cov->u.raw_info, ptr);

    return xc_sysctl(gcov_xch, sys);
}

static void gcov_read(const char *fn, int reset)
{
    struct xen_sysctl sys;
    uint32_t total_len;
    DECLARE_HYPERCALL_BUFFER(uint8_t, p);
    FILE *f;
    int op = reset ? XEN_SYSCTL_COVERAGE_read_and_reset :
                     XEN_SYSCTL_COVERAGE_read;

    /* get total length */
    if ( gcov_get_info(XEN_SYSCTL_COVERAGE_get_total_size, &sys, NULL) < 0 )
        err(1, "getting total length");
    total_len = sys.u.coverage_op.u.total_size;
    fprintf(stderr, "returned %u bytes\n", (unsigned) total_len);

    /* safe check */
    if ( total_len > 16u * 1024u * 1024u )
        errx(1, "coverage size too big %u bytes\n", total_len);

    /* allocate */
    p = xc_hypercall_buffer_alloc(gcov_xch, p, total_len);
    if ( p == NULL )
        err(1, "allocating memory for coverage");

    /* get data */
    memset(p, 0, total_len);
    if ( gcov_get_info(op, &sys, HYPERCALL_BUFFER(p)) < 0 )
        err(1, "getting coverage information");

    /* write to a file */
    if ( strcmp(fn, "-") == 0 )
        f = stdout;
    else
        f = fopen(fn, "w");
    if ( !f )
        err(1, "opening output file");
    if ( fwrite(p, 1, total_len, f) != total_len )
        err(1, "writing coverage to file");
    if (f != stdout)
        fclose(f);
    xc_hypercall_buffer_free(gcov_xch, p);
}

static void gcov_reset(void)
{
    struct xen_sysctl sys;

    if ( gcov_get_info(XEN_SYSCTL_COVERAGE_reset, &sys, NULL) < 0 )
        err(1, "resetting coverage information");
}

static void usage(int exit_code)
{
    FILE *out = exit_code ? stderr : stdout;

    fprintf(out, "xencov {reset|read|read-reset} [<filename>]\n"
        "\treset       reset information\n"
        "\tread        read information from xen to filename\n"
        "\tread-reset  read and reset information from xen to filename\n"
        "\tfilename  optional filename (default output)\n"
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

    gcov_init();

    if ( strcmp(argv[0], "reset") == 0 )
        gcov_reset();
    else if ( strcmp(argv[0], "read") == 0 )
        gcov_read(argc > 1 ? argv[1] : "-", 0);
    else if ( strcmp(argv[0], "read-reset") == 0 )
        gcov_read(argc > 1 ? argv[1] : "-", 1);
    else
        usage(1);

    return 0;
}

