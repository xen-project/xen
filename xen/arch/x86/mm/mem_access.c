/******************************************************************************
 * arch/x86/mm/mem_access.c
 *
 * Memory access support.
 *
 * Copyright (c) 2011 Virtuata, Inc.
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
#include <asm/mem_event.h>


int mem_access_memop(struct domain *d, xen_mem_event_op_t *meo)
{
    int rc;

    switch( meo->op )
    {
    case XENMEM_access_op_resume:
    {
        p2m_mem_access_resume(d);
        rc = 0;
    }
    break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

int mem_access_send_req(struct domain *d, mem_event_request_t *req)
{
    int rc = mem_event_claim_slot(d, &d->mem_event->access);
    if ( rc < 0 )
        return rc;

    mem_event_put_request(d, &d->mem_event->access, req);

    return 0;
} 

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
