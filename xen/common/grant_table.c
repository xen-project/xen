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

static inline void
check_tlb_flush(
    active_grant_entry_t *a)
{
    if ( unlikely(NEED_FLUSH(tlbflush_time[smp_processor_id()],
                             a->tlbflush_timestamp)) )
    {
        perfc_incr(need_flush_tlb_flush);
        local_flush_tlb();
    }
}

static void
make_entry_mappable(
    grant_table_t *t, active_grant_entry_t *a)
{
    u16 *ph = &t->maphash[GNT_MAPHASH(a->frame)];
    a->next = *ph;
    *ph = a - t->active;
}

static void
make_entry_unmappable(
    grant_table_t *t, active_grant_entry_t *a)
{
    active_grant_entry_t *p;
    u16 *ph = &t->maphash[GNT_MAPHASH(a->frame)];
    while ( (p = &t->active[*ph]) != a )
        ph = &p->next;
    *ph = a->next;
    a->next = GNT_MAPHASH_INVALID;
    check_tlb_flush(a);
}

static long
gnttab_update_pin_status(
    gnttab_update_pin_status_t *uop)
{
    domid_t        dom, sdom;
    grant_ref_t    ref;
    u16            pin_flags;
    struct domain *ld, *rd;
    u16            sflags, prev_sflags;
    active_grant_entry_t *act;
    grant_entry_t *sha;
    long           rc = 0;

    ld = current;

    /* Bitwise-OR avoids short-circuiting which screws control flow. */
    if ( unlikely(__get_user(dom, &uop->dom) |
                  __get_user(ref, &uop->ref) |
                  __get_user(pin_flags, &uop->pin_flags)) )
    {
        DPRINTK("Fault while reading gnttab_update_pin_status_t.\n");
        return -EFAULT;
    }

    pin_flags &= (GNTPIN_dev_accessible | 
                  GNTPIN_host_accessible |
                  GNTPIN_readonly);

    if ( unlikely(ref >= NR_GRANT_ENTRIES) || 
         unlikely(pin_flags == GNTPIN_readonly) )
    {
        DPRINTK("Bad ref (%d) or flags (%x).\n", ref, pin_flags);
        return -EINVAL;
    }

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) )
    {
        DPRINTK("Could not find domain %d\n", dom);
        return -ESRCH;
    }

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    if ( act->status == 0 )
    {
        if ( unlikely(pin_flags == 0) )
            goto out;

        /* CASE 1: Activating a previously inactive entry. */

        sflags = sha->flags;
        sdom   = sha->domid;

        for ( ; ; )
        {
            u32 scombo, prev_scombo;

            if ( unlikely((sflags & GTF_type_mask) != GTF_permit_access) ||
                 unlikely(sdom != ld->domain) )
            {
                DPRINTK("Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                        sflags, sdom, ld->domain);
                rc = -EINVAL;
                goto out;
            }

            sflags |= GTF_reading;
            if ( !(pin_flags & GNTPIN_readonly) )
            {
                sflags |= GTF_writing;
                if ( unlikely(sflags & GTF_readonly) )
                {
                    DPRINTK("Attempt to write-pin a read-only grant entry.\n");
                    rc = -EINVAL;
                    goto out;
                }
            }

            /* Merge two 16-bit values into a 32-bit combined update. */
            /* NB. Endianness! */
            prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

            /* NB. prev_sflags is updated in place to seen value. */
            if ( unlikely(cmpxchg_user((u32 *)&sha->flags, prev_scombo, 
                                       prev_scombo | GTF_writing)) )
            {
                DPRINTK("Fault while modifying shared flags and domid.\n");
                rc = -EINVAL;
                goto out;
            }

            /* Did the combined update work (did we see what we expected?). */
            if ( prev_scombo == scombo )
                break;

            /* Didn't see what we expected. Split out the seen flags & dom. */
            /* NB. Endianness! */
            sflags = (u16)prev_scombo;
            sdom   = (u16)(prev_scombo >> 16);
        }

        /* rmb(); */ /* not on x86 */

        act->status = pin_flags;
        act->domid  = sdom;
        act->frame  = sha->frame;

        make_entry_mappable(rd->grant_table, act);
    }
    else if ( pin_flags == 0 )
    {
        /* CASE 2: Deactivating a previously active entry. */

        if ( unlikely((act->status & 
                       (GNTPIN_wmap_mask|GNTPIN_rmap_mask)) != 0) )
        {
            DPRINTK("Attempt to deactivate a mapped g.e. (%x)\n", act->status);
            rc = -EINVAL;
            goto out;
        }

        act->status = 0;
        make_entry_unmappable(rd->grant_table, act);

        clear_bit(_GTF_writing, &sha->flags);
        clear_bit(_GTF_reading, &sha->flags);
    }
    else 
    {
        /* CASE 3: Active modications to an already active entry. */

        /*
         * Check mapping counts up front, as necessary.
         * After this compound check, the operation cannot fail.
         */
        if ( ((pin_flags & (GNTPIN_readonly|GNTPIN_host_accessible)) !=
              GNTPIN_host_accessible) &&
             (unlikely((act->status & GNTPIN_wmap_mask) != 0) ||
              (((pin_flags & GNTPIN_host_accessible) == 0) &&
               unlikely((act->status & GNTPIN_rmap_mask) != 0))) )
        {
            DPRINTK("Attempt to reduce pinning of a mapped g.e. (%x,%x)\n",
                    pin_flags, act->status);
            rc = -EINVAL;
            goto out;
        }

        /* Check for changes to host accessibility. */
        if ( pin_flags & GNTPIN_host_accessible )
        {
            if ( !(act->status & GNTPIN_host_accessible) )
                make_entry_mappable(rd->grant_table, act);
        }
        else if ( act->status & GNTPIN_host_accessible )
            make_entry_unmappable(rd->grant_table, act);

        /* Check for changes to write accessibility. */
        if ( pin_flags & GNTPIN_readonly )
        {
            if ( !(act->status & GNTPIN_readonly) )
            {
                check_tlb_flush(act);
                clear_bit(_GTF_writing, &sha->flags);
            }
        }
        else if ( act->status & GNTPIN_readonly )
        {
            sflags = sha->flags;
            do {
                prev_sflags = sflags;

                if ( unlikely(prev_sflags & GTF_readonly) )
                {
                    DPRINTK("Attempt to write-pin a read-only grant entry.\n");
                    rc = -EINVAL;
                    goto out;
                }
                
                /* NB. prev_sflags is updated in place to seen value. */
                if ( unlikely(cmpxchg_user(&sha->flags, prev_sflags, 
                                           prev_sflags | GTF_writing)) )
                {
                    DPRINTK("Fault while modifying shared flags.\n");
                    rc = -EINVAL;
                    goto out;
                }
            }
            while ( prev_sflags != sflags );
        }

        /* Update status word -- this includes device accessibility. */
        act->status &= ~(GNTPIN_dev_accessible |
                         GNTPIN_host_accessible |
                         GNTPIN_readonly);
        act->status |= pin_flags;
    }

    /* Unchecked and unconditional. */
    (void)__put_user(act->frame, &uop->dev_bus_addr);
    (void)__put_user(act->frame, &uop->host_phys_addr);

 out:
    put_domain(rd);
    return rc;
}

long 
do_grant_table_op(
    gnttab_op_t *uop)
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

int 
grant_table_create(
    struct domain *d)
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

void
grant_table_destroy(
    struct domain *d)
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

void
grant_table_init(
    void)
{
    /* Nothing. */
}
