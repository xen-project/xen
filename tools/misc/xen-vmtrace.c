/******************************************************************************
 * tools/vmtrace.c
 *
 * Demonstrative tool for collecting Intel Processor Trace data from Xen.
 *  Could be used to externally monitor a given vCPU in given DomU.
 *
 * Copyright (C) 2020 by CERT Polska - NASK PIB
 *
 * Authors: Michał Leszczyński, michal.leszczynski@cert.pl
 * Date:    June, 2020
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xenforeignmemory.h>

#define MSR_RTIT_CTL                        0x00000570
#define  RTIT_CTL_OS                        (1 <<  2)
#define  RTIT_CTL_USR                       (1 <<  3)
#define  RTIT_CTL_BRANCH_EN                 (1 << 13)

static xc_interface *xch;
static xenforeignmemory_handle *fh;
static uint32_t domid, vcpu;
static size_t size;
static char *buf;

static sig_atomic_t interrupted;
static void close_handler(int signum)
{
    interrupted = 1;
}

static int get_more_data(void)
{
    static uint64_t last_pos;
    uint64_t pos;

    if ( xc_vmtrace_output_position(xch, domid, vcpu, &pos) )
    {
        perror("xc_vmtrace_output_position()");
        return -1;
    }

    if ( pos > last_pos )
        fwrite(buf + last_pos, pos - last_pos, 1, stdout);
    else if ( pos < last_pos )
    {
        /* buffer wrapped */
        fwrite(buf + last_pos, size - last_pos, 1, stdout);
        fwrite(buf, pos, 1, stdout);
    }

    last_pos = pos;
    return 0;
}

int main(int argc, char **argv)
{
    int rc, exit = 1;
    xenforeignmemory_resource_handle *fres = NULL;

    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if ( argc != 3 )
    {
        fprintf(stderr, "Usage: %s <domid> <vcpu_id>\n", argv[0]);
        fprintf(stderr, "It's recommended to redirect thisprogram's output to file\n");
        fprintf(stderr, "or to pipe it's output to xxd or other program.\n");
        return 1;
    }

    domid = atoi(argv[1]);
    vcpu  = atoi(argv[2]);

    xch = xc_interface_open(NULL, NULL, 0);
    fh = xenforeignmemory_open(NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open()");
    if ( !fh )
        err(1, "xenforeignmemory_open()");

    rc = xenforeignmemory_resource_size(
        fh, domid, XENMEM_resource_vmtrace_buf, vcpu, &size);
    if ( rc )
        err(1, "xenforeignmemory_resource_size()");

    fres = xenforeignmemory_map_resource(
        fh, domid, XENMEM_resource_vmtrace_buf, vcpu,
        0, size >> XC_PAGE_SHIFT, (void **)&buf, PROT_READ, 0);
    if ( !fres )
        err(1, "xenforeignmemory_map_resource()");

    if ( xc_vmtrace_set_option(
             xch, domid, vcpu, MSR_RTIT_CTL,
             RTIT_CTL_BRANCH_EN | RTIT_CTL_USR | RTIT_CTL_OS) )
    {
        perror("xc_vmtrace_set_option()");
        goto out;
    }

    if ( xc_vmtrace_reset_and_enable(xch, domid, vcpu) )
    {
        perror("xc_vmtrace_enable()");
        goto out;
    }

    while ( !interrupted )
    {
        xc_domaininfo_t dominfo;

        if ( get_more_data() )
            goto out;

        usleep(1000 * 100);

        if ( xc_domain_getinfo_single(xch, domid, &dominfo) < 0 ||
             (dominfo.flags & XEN_DOMINF_shutdown) )
        {
            if ( get_more_data() )
                goto out;
            break;
        }
    }

    exit = 0;

 out:
    if ( xc_vmtrace_disable(xch, domid, vcpu) )
        perror("xc_vmtrace_disable()");

    if ( fres && xenforeignmemory_unmap_resource(fh, fres) )
        perror("xenforeignmemory_unmap_resource()");

    return exit;
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
