/******************************************************************************
 * common/grant_table.c
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2004 K A Fraser
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

#include <xen/config.h>
#include <xen/sched.h>

#define update_shared_flags(x,y,z) (0)

static long gnttab_update_pin_status(gnttab_update_pin_status_t *uop)
{
    domid_t        dom, sdom;
    grant_ref_t    ref;
    u16            pin_flags;
    struct domain *ld, *rd;
    u32            sflags;
    active_grant_entry_t *act;
    grant_entry_t *sha;
    long           rc = 0;

    ld = current;

    if ( unlikely(__get_user(dom, &uop->dom)) || 
         unlikely(__get_user(ref, &uop->ref)) ||
         unlikely(__get_user(pin_flags, &uop->pin_flags)) )
        return -EFAULT;

    pin_flags &= (GNTPIN_dev_accessible | 
                  GNTPIN_host_accessible |
                  GNTPIN_readonly);

    if ( unlikely(ref >= NR_GRANT_ENTRIES) || 
         unlikely(pin_flags == GNTPIN_readonly) )
        return -EINVAL;

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) )
        return -ESRCH;

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    if ( act->status == 0 )
    {
        if ( unlikely(pin_flags == 0) )
            goto out;

        sflags = sha->flags;
        sdom   = sha->domid;

        do {
            if ( unlikely((sflags & GTF_type_mask) != GTF_permit_access) ||
                 unlikely(sdom != ld->domain) )
            {
            }
        
            sflags |= GTF_reading;
            if ( !(pin_flags & GNTPIN_readonly) )
            {
                sflags |= GTF_writing;
                if ( unlikely(sflags & GTF_readonly) )
                {
                }
            }
        }
        while ( !update_shared_flags(sha, sflags, sdom) );

        act->status = pin_flags;
        act->domid  = sdom;

        /* XXX MAP XXX */
    }
    else if ( pin_flags == 0 )
    {
        if ( unlikely((act->status & 
                       (GNTPIN_wmap_mask|GNTPIN_rmap_mask)) != 0) )
        {
        }

        clear_bit(_GTF_writing, &sha->flags);
        clear_bit(_GTF_reading, &sha->flags);

        act->status = 0;

        /* XXX UNMAP XXX */
    }
    else 
    {
        if ( pin_flags & GNTPIN_readonly )
        {
            if ( !(act->status & GNTPIN_readonly) )
            {
            }
        }
        else if ( act->status & GNTPIN_readonly )
        {
        }

        if ( pin_flags & GNTPIN_host_accessible )
        {
            if ( !(act->status & GNTPIN_host_accessible) )
            {
                /* XXX MAP XXX */
            }
        }
        else if ( act->status & GNTPIN_host_accessible )
        {
            /* XXX UNMAP XXX */
        }

        act->status &= ~GNTPIN_dev_accessible;
        act->status |= pin_flags & GNTPIN_dev_accessible; 
    }

 out:
    put_domain(rd);
    return rc;
}

long do_grant_table_op(gnttab_op_t *uop)
{
    long rc;
    u32  cmd;

    if ( unlikely(!access_ok(VERIFY_WRITE, uop, sizeof(*uop))) ||
         unlikely(__get_user(cmd, &uop->cmd)) )
        return -EFAULT;

    switch ( cmd )
    {
    case GNTTABOP_update_pin_status:
        rc = gnttab_update_pin_status(&uop->u.update_pin_status);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

int grant_table_create(struct domain *d)
{
    grant_table_t *t;
    int            i;

    if ( (t = xmalloc(sizeof(grant_table_t))) == NULL )
        goto no_mem;

    /* Simple stuff. */
    t->shared = NULL;
    t->active = NULL;
    spin_lock_init(&t->lock);
    for ( i = 0; i < GNT_MAPHASH_SZ; i++ )
        t->maphash[i] = GNT_MAPHASH_INVALID;

    /* Active grant-table page. */
    if ( (t->active = xmalloc(sizeof(active_grant_entry_t) * 
                              NR_GRANT_ENTRIES)) == NULL )
        goto no_mem;

    /* Set up shared grant-table page. */
    if ( (t->shared = (void *)alloc_xenheap_page()) == NULL )
        goto no_mem;
    memset(t->shared, 0, PAGE_SIZE);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(t->shared), d);

    /* Okay, install the structure. */
    d->grant_table = t;
    return 0;

 no_mem:
    if ( t != NULL )
    {
        if ( t->active != NULL )
            xfree(t->active);
        xfree(t);
    }
    return -ENOMEM;
}

void grant_table_destroy(struct domain *d)
{
    grant_table_t *t;

    if ( (t = d->grant_table) != NULL )
    {
        /* Free memory relating to this grant table. */
        d->grant_table = NULL;
        free_xenheap_page((unsigned long)t->shared);
        xfree(t->active);
        xfree(t);
    }
}

void grant_table_init(void)
{
    /* Nothing. */
}
