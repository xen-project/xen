/*
 * QEMU Xen PV Machine
 *
 * Copyright (c) 2007 Red Hat
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "vl.h"
#include "xen_console.h"
#include "xenfb.h"

extern void init_blktap(void);


/* The Xen PV machine currently provides
 *   - a virtual framebuffer
 *   - ....
 */
static void xen_init_pv(uint64_t ram_size, int vga_ram_size, char *boot_device,
			DisplayState *ds, const char **fd_filename,
			int snapshot,
			const char *kernel_filename,
			const char *kernel_cmdline,
			const char *initrd_filename,
			const char *direct_pci)
{
    struct xenfb *xenfb;
    extern int domid;


#ifndef CONFIG_STUBDOM
    /* Initialize tapdisk client */
    init_blktap();
#endif

    /* Connect to text console */
    if (serial_hds[0]) {
        if (xencons_init(domid, serial_hds[0]) < 0) {
            fprintf(stderr, "Could not connect to domain console\n");
            exit(1);
        }
    }

    /* Prepare PVFB state */
    xenfb = xenfb_new(domid, ds);
    if (xenfb == NULL) {
        fprintf(stderr, "Could not create framebuffer (%s)\n",
                strerror(errno));
        exit(1);
    }
}

QEMUMachine xenpv_machine = {
    "xenpv",
    "Xen Para-virtualized PC",
    xen_init_pv,
};

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
