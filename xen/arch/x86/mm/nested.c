/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/nested.c
 *
 * Parts of this code are Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 */

#include <xen/sched.h>
#include <asm/p2m.h>
#include "mm-locks.h"
#include "p2m.h"

void p2m_nestedp2m_init(struct p2m_domain *p2m)
{
    INIT_LIST_HEAD(&p2m->np2m_list);

    p2m->np2m_base = P2M_BASE_EADDR;
    p2m->np2m_generation = 0;
}

int p2m_init_nestedp2m(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    mm_lock_init(&d->arch.nested_p2m_lock);
    for ( i = 0; i < MAX_NESTEDP2M; i++ )
    {
        d->arch.nested_p2m[i] = p2m = p2m_init_one(d);
        if ( p2m == NULL )
        {
            p2m_teardown_nestedp2m(d);
            return -ENOMEM;
        }
        p2m->p2m_class = p2m_nested;
        p2m->write_p2m_entry_pre = NULL;
        p2m->write_p2m_entry_post = nestedp2m_write_p2m_entry_post;
        list_add(&p2m->np2m_list, &p2m_get_hostp2m(d)->np2m_list);
    }

    return 0;
}

void p2m_teardown_nestedp2m(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    for ( i = 0; i < MAX_NESTEDP2M; i++ )
    {
        if ( !d->arch.nested_p2m[i] )
            continue;
        p2m = d->arch.nested_p2m[i];
        list_del(&p2m->np2m_list);
        p2m_free_one(p2m);
        d->arch.nested_p2m[i] = NULL;
    }
}
