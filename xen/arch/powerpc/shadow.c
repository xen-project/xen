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
#include <xen/types.h>
#include <xen/shadow.h>
#include <public/dom0_ops.h>

int shadow_control_op(struct domain *d, 
                      dom0_shadow_control_t *sc,
                      XEN_GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    if ( unlikely(d == current->domain) )
    {
        DPRINTK("Don't try to do a shadow op on yourself!\n");
        return -EINVAL;
    }

    switch ( sc->op )
    {
    case DOM0_SHADOW_CONTROL_OP_OFF:
        return 0;

    case DOM0_SHADOW2_CONTROL_OP_GET_ALLOCATION:
        sc->mb = 0;
        return 0;
    case DOM0_SHADOW2_CONTROL_OP_SET_ALLOCATION:
        if (sc->mb > 0) {
            BUG();
            return -ENOMEM;
        }
        return 0;

    default:
        printk("Bad shadow op %u\n", sc->op);
        BUG();
        return -EINVAL;
    }
}
