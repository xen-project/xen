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
 * Copyright (C) IBM Corp. 2006, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include "of-devtree.h"
#include "rtas.h"

int rtas_entry;
unsigned long rtas_msr;
unsigned long rtas_base;
unsigned long rtas_end;

int rtas_call(void *r)
{
    if (rtas_entry == 0)
        return -ENOSYS;

    return prom_call(r, rtas_base, rtas_entry, rtas_msr);
}

/* rtas always uses physical address */
void *rtas_remote_addr(ulong addr, ulong length)
{
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    ulong mfn;
    ulong mfn_end;

    mfn = gmfn_to_mfn(d, addr >> PAGE_SHIFT);
    if (mfn == INVALID_MFN)
        return NULL;

    /* a little paranoid since almost everyone will pass us page
     * bounded thingies, but just in case */
    mfn_end = gmfn_to_mfn(d, (addr + length) >> PAGE_SHIFT);
    if (mfn_end == INVALID_MFN)
        return NULL;

    return (void *)((mfn << PAGE_SHIFT) | (addr & (PAGE_SIZE - 1)));
}

/* these do not proxy */
#define RTAS_HALT 0
#define RTAS_REBOOT 1

struct rtas_token rt_power_off = { .name = "power-off", .token = -1, };
struct rtas_token rt_system_reboot = { .name = "system-reboot", .token = -1};

static struct rtas_token *tokens[] = {
    /* these do not proxy */
    [RTAS_HALT] = &rt_power_off,
    [RTAS_REBOOT] = &rt_system_reboot,
    &rt_nvram_store,
    &rt_nvram_fetch,
    &rt_manage_flash,
    &rt_validate_flash,
    &rt_update_reboot_flash
};

static int rtas_proxy;

int __init rtas_init(void *m)
{
    ofdn_t n;
    int i;

    if (rtas_entry == 0)
        return -ENOSYS;

    n = ofd_node_find(m, "/rtas");
    if (n <= 0)
        return -ENOSYS;

    for (i = 0; i < ARRAY_SIZE(tokens); i++) {
        ofd_getprop(m, n, tokens[i]->name,
                    &tokens[i]->token, sizeof (tokens[i]->token));
        if (!rtas_proxy && tokens[i]->proxy && tokens[i]->token != -1)
            rtas_proxy = 1;
    }
    return 1;
}

int rtas_proxy_init(void *m)
{
    static const char path[] = "/rtas";
    ofdn_t p;
    ofdn_t n;
    int i;

    if (!rtas_proxy)
        return -1;

    printk("Create a new /rtas with tokens Xen is willing to proxy\n");

    p = ofd_node_find(m, "/");

    n = ofd_node_add(m, p, path, sizeof(path));
    ofd_prop_add(m, n, "name", &path[1], sizeof (path) - 1);

    /* and the tokens for proxy */
    for (i = 0; i < ARRAY_SIZE(tokens); i++) {
        if (tokens[i]->proxy && tokens[i]->token != -1)
            ofd_prop_add(m, n, tokens[i]->name, &i, sizeof (i));
    }
    return n;
}

int do_rtas_proxy(ulong arg)
{
    struct rtas_args *r;
    unsigned i;
    int token;
    ulong sz;

    if (!IS_PRIV(current->domain))
        return -EPERM;
    if (!rtas_proxy)
        return -ENOSYS;

    /* has to be at least 5 words */
    sz = (3 + 1 + 1) * sizeof (int);
    r = rtas_remote_addr(arg, sz);
    if (r == NULL) {
        /* this is about all we can do at this point */
        return -1;
    }
    /* make sure we can deal with everything */
    sz = (3 + r->ra_nargs + r->ra_nrets) * sizeof (int);
    if (rtas_remote_addr(arg, sz) == NULL) {
        r->ra_args[r->ra_nargs] = RTAS_HW;
        return -1;
    }

    i = r->ra_token;
    token = tokens[i]->token;

    if (i < ARRAY_SIZE(tokens) &&
        tokens[i]->proxy != NULL &&
        token != -1)
        return tokens[i]->proxy(token, r);

    return -1;
}

int
rtas_halt(void)
{
    struct rtas_args r;
    int token = tokens[RTAS_HALT]->token;

    if (token == -1)
        return -1;

    r.ra_token = token;
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

    int token = tokens[RTAS_REBOOT]->token;

    if (token == -1)
        return -1;

    r.ra_token = token;
    r.ra_nargs = 2;
    r.ra_nrets = 1;
    r.ra_args[0] = 0;
    r.ra_args[1] = 0;

    return rtas_call(&r);
}
