/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include "ofh.h"

static struct ofh_ihandle _ih_cons;

void
ofh_vty_init(ofdn_t chosen, ulong b)
{
    void *mem = ofd_mem(b);
    u32 ih = DRELA((u32)&_ih_cons, b);
    struct ofh_ihandle *ihp = (struct ofh_ihandle *)((ulong)ih);
    ofdn_t n = 0;
    s32 ret;
    u32 chan = OFH_CONS_XEN;

    ihp->ofi_intf = NULL;

    /* find the vty */
    n = ofd_node_find(mem,
                      DRELA((const char *)"/vdevice/vty", b));
    if (n > 0) {
        /* PAPR VTERM */
        ret = ofd_getprop(mem, n, DRELA((const char *)"reg", b),
                          &chan, sizeof (chan));
        if (ret != (s32)sizeof (chan)) {
            chan = 0;
        }
    } else {
        /* xen console */
        u32 addr;

        n = ofd_node_find(mem, DRELA((const char *)"/xen/console", b));
        if (n > 0) {
            ret = ofd_getprop(mem, n, DRELA((const char *)"reg", b),
                              &addr, sizeof (addr));
            if (addr == 0) {
                ihp->ofi_intf = NULL;
            } else {
                ihp->ofi_intf = (struct xencons_interface *)(ulong)addr;
            }
        }
    }
    if (n > 0) {
        ihp->ofi_node = n;
    }
    ihp->ofi_chan = chan;
    ofh_cons_init(ihp, b);

    ofd_prop_add(mem, chosen, DRELA((const char *)"stdout", b),
                 &ih, sizeof (ih));
    ofd_prop_add(mem, chosen, DRELA((const char *)"stdin", b),
                 &ih, sizeof (ih));
}


