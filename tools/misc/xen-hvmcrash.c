/* 
 * xen-hvmcrash.c
 *
 * Attempt to crash an HVM guest by overwriting RIP/EIP with a bogus value
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <xenctrl.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/hvm/save.h>

int
main(int argc, char **argv)
{
    int domid;
    xc_interface *xch;
    xc_dominfo_t dominfo;
    int ret;
    uint32_t len;
    uint8_t *buf;
    uint32_t off;
    struct hvm_save_descriptor *descriptor;

    if (argc != 2 || !argv[1] || (domid = atoi(argv[1])) < 0) {
        fprintf(stderr, "usage: %s <domid>\n", argv[0]);
        exit(1);
    }

    xch = xc_interface_open(0, 0, 0);
    if (!xch) {
        fprintf(stderr, "error: can't open libxc handle\n");
        exit(1);
    }

    ret = xc_domain_getinfo(xch, domid, 1, &dominfo);
    if (ret < 0) {
        perror("xc_domain_getinfo");
        exit(1);
    }

    if (!dominfo.hvm) {
        fprintf(stderr, "domain %d is not HVM\n", domid);
        exit(1);
    }

    ret = xc_domain_pause(xch, domid);
    if (ret < 0) {
        perror("xc_domain_pause");
        exit(-1);
    }

    /*
     * Calling with zero buffer length should return the buffer length
     * required.
     */
    ret = xc_domain_hvm_getcontext(xch, domid, 0, 0);
    if (ret < 0) {
        perror("xc_domain_hvm_getcontext");
        exit(1);
    }
    
    len = ret;
    buf = malloc(len);
    if (buf == NULL) {
        perror("malloc");
        exit(1);
    }

    ret = xc_domain_hvm_getcontext(xch, domid, buf, len);
    if (ret < 0) {
        perror("xc_domain_hvm_getcontext");
        exit(1);
    }

    off = 0;

    while (off < len) {
        descriptor = (struct hvm_save_descriptor *)(buf + off);

        off += sizeof (struct hvm_save_descriptor);

        if (descriptor->typecode == HVM_SAVE_CODE(CPU)) {
            HVM_SAVE_TYPE(CPU) *cpu;

            /* Overwrite EIP/RIP with some recognisable but bogus value */
            cpu = (HVM_SAVE_TYPE(CPU) *)(buf + off);
            printf("CPU[%d]: RIP = %" PRIx64 "\n", descriptor->instance, cpu->rip);
            cpu->rip = 0xf001;
        } else if (descriptor->typecode == HVM_SAVE_CODE(END)) {
            break;
        }

        off += descriptor->length;
    }

    ret = xc_domain_hvm_setcontext(xch, domid, buf, len);
    if (ret < 0) {
        perror("xc_domain_hvm_setcontext");
        exit(1);
    }

    ret = xc_domain_unpause(xch, domid);
    if (ret < 0) {
        perror("xc_domain_unpause");
        exit(1);
    }

    return 0;
}
