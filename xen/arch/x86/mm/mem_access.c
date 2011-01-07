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


int mem_access_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                      XEN_GUEST_HANDLE(void) u_domctl)
{
    int rc;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    switch( mec->op )
    {
    case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_RESUME:
    {
        p2m_mem_access_resume(p2m);
        rc = 0;
    }
    break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
