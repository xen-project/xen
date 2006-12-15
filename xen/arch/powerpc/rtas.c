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
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include "of-devtree.h"
#include "rtas.h"

static int rtas_halt_token = -1;
static int rtas_reboot_token = -1;
int rtas_entry;
unsigned long rtas_msr;
unsigned long rtas_base;
unsigned long rtas_end;

struct rtas_args {
    int ra_token;
    int ra_nargs;
    int ra_nrets;
    int ra_args[10];
} __attribute__ ((aligned(8)));

static int rtas_call(struct rtas_args *r)
{
    if (rtas_entry == 0)
        return -ENOSYS;

    return prom_call(r, rtas_base, rtas_entry, rtas_msr);
}

int __init rtas_init(void *m)
{
    static const char halt[] = "power-off";
    static const char reboot[] = "system-reboot";
    ofdn_t n;

    if (rtas_entry == 0)
        return -ENOSYS;

    n = ofd_node_find(m, "/rtas");
    if (n <= 0)
        return -ENOSYS;

    ofd_getprop(m, n, halt,
                &rtas_halt_token, sizeof (rtas_halt_token));
    ofd_getprop(m, n, reboot,
                &rtas_reboot_token, sizeof (rtas_reboot_token));
    return 1;
}

int
rtas_halt(void)
{
    struct rtas_args r;

    if (rtas_halt_token == -1)
        return -1;

    r.ra_token = rtas_halt_token;
    r.ra_nargs = 2;
    r.ra_nrets = 1;
    r.ra_args[0] = 0;
    r.ra_args[1] = 0;

    return rtas_call(&r);
}

int
rtas_reboot(void)
{
    struct rtas_args r;

    if (rtas_reboot_token == -1)
        return -ENOSYS;

    r.ra_token = rtas_reboot_token;
    r.ra_nargs = 2;
    r.ra_nrets = 1;
    r.ra_args[0] = 0;
    r.ra_args[1] = 0;

    return rtas_call(&r);
}
