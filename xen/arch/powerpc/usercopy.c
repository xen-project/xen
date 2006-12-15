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
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/sched.h>
#include <xen/lib.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/debugger.h>

/* XXX need to return error, not panic, if domain passed a bad pointer */
unsigned long paddr_to_maddr(unsigned long paddr)
{
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    ulong gpfn;
    ulong offset;
    ulong pa = paddr;

    offset = pa & ~PAGE_MASK;
    gpfn = pa >> PAGE_SHIFT;

    pa = gmfn_to_mfn(d, gpfn);
    if (pa == INVALID_MFN) {
        printk("%s: Dom:%d bad paddr: 0x%lx\n",
               __func__, d->domain_id, paddr);
        return 0;
    }

    pa <<= PAGE_SHIFT;
    pa |= offset;

    return pa;
}
