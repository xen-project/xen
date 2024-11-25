/* 
 * xen-hvmcrash.c
 *
 * Attempt to crash an HVM guest by injecting #DF to every vcpu
 * 
 * Copyright (c) 2010 Citrix Systems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <xenctrl.h>
#include <xendevicemodel.h>

#include <xen/asm/x86-defns.h>

int
main(int argc, char **argv)
{
    int domid;
    xc_interface *xch;
    xendevicemodel_handle *dmod;
    xc_domaininfo_t dominfo;
    int vcpu_id, ret;
    bool injected = false;

    if (argc != 2 || !argv[1] || (domid = atoi(argv[1])) < 0) {
        fprintf(stderr, "usage: %s <domid>\n", argv[0]);
        exit(1);
    }

    xch = xc_interface_open(0, 0, 0);
    if (!xch) {
        fprintf(stderr, "error: can't open libxc handle\n");
        exit(1);
    }

    ret = xc_domain_getinfo_single(xch, domid, &dominfo);
    if (ret < 0) {
        perror("xc_domain_getinfo");
        exit(1);
    }

    if (!(dominfo.flags & XEN_DOMINF_hvm_guest)) {
        fprintf(stderr, "domain %d is not HVM\n", domid);
        exit(1);
    }

    ret = xc_domain_pause(xch, domid);
    if (ret < 0) {
        perror("xc_domain_pause");
        exit(-1);
    }

    dmod = xc_interface_dmod_handle(xch);

    for (vcpu_id = 0; vcpu_id <= dominfo.max_vcpu_id; vcpu_id++) {
        printf("Injecting #DF to vcpu ID #%d...\n", vcpu_id);
        ret = xendevicemodel_inject_event(dmod, domid, vcpu_id,
                                X86_EXC_DF,
                                XEN_DMOP_EVENT_hw_exc, 0, 0, 0);
        if (ret < 0) {
            fprintf(stderr, "Could not inject #DF to vcpu ID #%d: %s\n",
                    vcpu_id, strerror(errno));
            continue;
        }
        injected = true;
    }

    ret = xc_domain_unpause(xch, domid);
    if (ret < 0) {
        perror("xc_domain_unpause");
        exit(1);
    }

    if (!injected) {
        fprintf(stderr, "Could not inject #DF to any vcpu!\n");
        exit(1);
    }

    return 0;
}
