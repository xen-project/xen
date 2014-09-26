/******************************************************************************
 * arch/x86/mm/mem_paging.c
 *
 * Memory paging support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <asm/p2m.h>
#include <xen/mem_event.h>


int mem_paging_memop(struct domain *d, xen_mem_event_op_t *mec)
{
    if ( unlikely(!d->mem_event->paging.ring_page) )
        return -ENODEV;

    switch( mec->op )
    {
    case XENMEM_paging_op_nominate:
    {
        unsigned long gfn = mec->gfn;
        return p2m_mem_paging_nominate(d, gfn);
    }
    break;

    case XENMEM_paging_op_evict:
    {
        unsigned long gfn = mec->gfn;
        return p2m_mem_paging_evict(d, gfn);
    }
    break;

    case XENMEM_paging_op_prep:
    {
        unsigned long gfn = mec->gfn;
        return p2m_mem_paging_prep(d, gfn, mec->buffer);
    }
    break;

    default:
        return -ENOSYS;
        break;
    }
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
