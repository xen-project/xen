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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/kernel.h>
#include "of-devtree.h"

void ofd_prop_print(
    const char *head,
    const char *path,
    const char *name,
    const char *prop,
    size_t sz)
{
    if ( path[0] == '/' && path[1] == '\0' ) {
        path = "";
    }
    printk("%s: %s/%s: 0x%lx\n", head, path,  name, sz);

#define DEBUG_PROP
#ifdef DEBUG_PROP
    int i;
    int isstr = sz;
    const char *b = prop;

    for ( i = 0; i < sz; i++ ) {
        /* see if there is any non printable characters */
        if ( !isprint(b[i]) ) {
            /* not printable */
            if (b[i] != '\0' || (i + 1) != sz) {
                /* not the end of string */
                isstr = 0;
                break;
            }
        }
    }

    if ( isstr > 0 ) {
        printk("%s: \t%s\n", head, b);
    } else if ( sz != 0 ) {
        printk("%s: \t0x", head);

        for ( i = 0; i < sz; i++ ) {
            if ( (i % 4) == 0 && i != 0 ) {
                if ( (i % 16) == 0 && i != 0 ) {
                    printk("\n%s: \t0x", head);
                } else {
                    printk(" 0x");
                }
            }
            if (b[i] < 0x10) {
                printk("0");
            }
            printk("%x", b[i]);
        }
        printk("\n");
    }
#else
    (void)prop;
#endif
}

void ofd_dump_props(void *mem, const char *pre, ofdn_t n, int dump)
{
    ofdn_t p;
    char name[128];
    char prop[256] __attribute__ ((aligned (__alignof__ (u64))));
    int sz;
    const char *path;

    if ( n == OFD_ROOT ) {
        path = "";
    } else {
        path = ofd_node_path(mem, n);
    }

    if (dump & OFD_DUMP_NAMES) {
        printk("%s: %s: phandle 0x%x\n", pre, path, n);
    }

    p = ofd_nextprop(mem, n, NULL, name);
    while ( p > 0 ) {
        sz = ofd_getprop(mem, n, name, prop, sizeof (prop));
        if ( sz > 0 && sz > sizeof (prop) ) {
            sz = sizeof (prop);
        }

        if ( dump & OFD_DUMP_VALUES ) {
            ofd_prop_print(pre, path, name, prop, sz);
        }

        p = ofd_nextprop(mem, n, name, name);
    }
}

void ofd_walk(void *m, const char *pre, ofdn_t p, walk_fn fn, int arg)
{
    ofdn_t n;

    if ( fn != NULL ) {
        (*fn)(m, pre, p, arg);
    }

    /* child */
    n = ofd_node_child(m, p);
    if ( n != 0 ) {
        ofd_walk(m, pre, n, fn, arg);
    }

    /* peer */
    n = ofd_node_peer(m, p);
    if ( n != 0 ) {
        ofd_walk(m, pre, n, fn, arg);
    }
}
