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

#define PIN_FAIL(_rc, _f, _a...)   \
    do {                           \
        DPRINTK( _f, ## _a );      \
        rc = -(_rc);               \
        goto out;                  \
    } while ( 0 )

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
    u16            sflags;
    active_grant_entry_t *act;
    grant_entry_t *sha;
    long           rc = 0;
    unsigned long  frame;

    /*
     * We bound the number of times we retry CMPXCHG on memory locations
     * that we share with a guest OS. The reason is that the guest can modify
     * that location at a higher rate than we can read-modify-CMPXCHG, so
     * the guest could cause us to livelock. There are a few cases
     * where it is valid for the guest to race our updates (e.g., to change
     * the GTF_readonly flag), so we allow a few retries before failing.
     */
    int            retries = 0;

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

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", dom);
        return -ESRCH;
    }

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    spin_lock(&rd->grant_table->lock);

    if ( act->status == 0 )
    {
        if ( unlikely(pin_flags == 0) )
            goto out;

        /* CASE 1: Activating a previously inactive entry. */

        sflags = sha->flags;
        sdom   = sha->domid;

        for ( ; ; )
        {
            u32 scombo, prev_scombo, new_scombo;

            if ( unlikely((sflags & GTF_type_mask) != GTF_permit_access) ||
                 unlikely(sdom != ld->domain) )
                PIN_FAIL(EINVAL,
                         "Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                        sflags, sdom, ld->domain);

            /* Merge two 16-bit values into a 32-bit combined update. */
            /* NB. Endianness! */
            prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

            new_scombo = scombo | GTF_reading;
            if ( !(pin_flags & GNTPIN_readonly) )
            {
                new_scombo |= GTF_writing;
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(EINVAL,
                             "Attempt to write-pin a r/o grant entry.\n");
            }

            /* NB. prev_scombo is updated in place to seen value. */
            if ( unlikely(cmpxchg_user((u32 *)&sha->flags,
                                       prev_scombo, 
                                       new_scombo)) )
                PIN_FAIL(EINVAL,
                         "Fault while modifying shared flags and domid.\n");

            /* Did the combined update work (did we see what we expected?). */
            if ( likely(prev_scombo == scombo) )
                break;

            if ( retries++ == 4 )
                PIN_FAIL(EINVAL,
                         "Shared grant entry is unstable.\n");

            /* Didn't see what we expected. Split out the seen flags & dom. */
            /* NB. Endianness! */
            sflags = (u16)prev_scombo;
            sdom   = (u16)(prev_scombo >> 16);
        }

        /* rmb(); */ /* not on x86 */
        frame = sha->frame;
        if ( unlikely(!pfn_is_ram(frame)) || 
             unlikely(!((pin_flags & GNTPIN_readonly) ? 
                        get_page(&frame_table[frame], rd) : 
                        get_page_and_type(&frame_table[frame], rd, 
                                          PGT_writable_page))) )
        {
            clear_bit(_GTF_writing, &sha->flags);
            clear_bit(_GTF_reading, &sha->flags);
            PIN_FAIL(EINVAL, 
                     "Could not pin the granted frame!\n");
        }

        act->status = pin_flags;
        act->domid  = sdom;
        act->frame  = frame;

        make_entry_mappable(rd->grant_table, act);
    }
    else if ( pin_flags == 0 )
    {
        /* CASE 2: Deactivating a previously active entry. */

        if ( unlikely((act->status & 
                       (GNTPIN_wmap_mask|GNTPIN_rmap_mask)) != 0) )
            PIN_FAIL(EINVAL,
                     "Attempt to deactiv a mapped g.e. (%x)\n", act->status);

        frame = act->frame;
        if ( !(act->status & GNTPIN_readonly) )
            put_page_type(&frame_table[frame]);
        put_page(&frame_table[frame]);

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
            PIN_FAIL(EINVAL,
                     "Attempt to reduce pinning of a mapped g.e. (%x,%x)\n",
                    pin_flags, act->status);

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
                put_page_type(&frame_table[act->frame]);
                check_tlb_flush(act);
                clear_bit(_GTF_writing, &sha->flags);
            }
        }
        else if ( act->status & GNTPIN_readonly )
        {
            sflags = sha->flags;

            for ( ; ; )
            {
                u16 prev_sflags;
                
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(EINVAL,
                             "Attempt to write-pin a r/o grant entry.\n");

                if ( unlikely(!get_page_type(&frame_table[act->frame],
                                             PGT_writable_page)) )
                    PIN_FAIL(EINVAL,
                             "Attempt to write-pin a unwritable page.\n");

                prev_sflags = sflags;

                /* NB. prev_sflags is updated in place to seen value. */
                if ( unlikely(cmpxchg_user(&sha->flags, prev_sflags, 
                                           prev_sflags | GTF_writing)) )
                    PIN_FAIL(EINVAL,
                             "Fault while modifying shared flags.\n");

                if ( likely(prev_sflags == sflags) )
                    break;

                if ( retries++ == 4 )
                    PIN_FAIL(EINVAL,
                             "Shared grant entry is unstable.\n");

                sflags = prev_sflags;
            }
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
    spin_unlock(&rd->grant_table->lock);
    put_domain(rd);
    return rc;
}

static long 
gnttab_setup_table(
    gnttab_setup_table_t *uop)
{
    gnttab_setup_table_t  op;
    struct domain        *d;

    if ( unlikely(__copy_from_user(&op, uop, sizeof(op)) != 0) )
    {
        DPRINTK("Fault while reading gnttab_setup_table_t.\n");
        return -EFAULT;
    }

    if ( unlikely(op.nr_frames > 1) )
    {
        DPRINTK("Xen only supports one grant-table frame per domain.\n");
        return -EINVAL;
    }

    if ( op.dom == DOMID_SELF )
        op.dom = current->domain;

    if ( unlikely((d = find_domain_by_id(op.dom)) == NULL) )
    {
        DPRINTK("Bad domid %d.\n", op.dom);
        return -ESRCH;
    }

    if ( op.nr_frames == 1 )
    {
        ASSERT(d->grant_table != NULL);

        if ( unlikely(put_user(virt_to_phys(d->grant_table) >> PAGE_SHIFT,
                               &op.frame_list[0])) )
        {
            DPRINTK("Fault while writing frame list.\n");
            put_domain(d);
            return -EFAULT;
        }
    }

    put_domain(d);
    return 0;
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
    case GNTTABOP_setup_table:
        rc = gnttab_setup_table(&uop->u.setup_table);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

int
gnttab_try_map(
    struct domain *rd, struct domain *ld, unsigned long frame, int op)
{
    grant_table_t        *t;
    active_grant_entry_t *a;
    u16                  *ph, h;

    if ( unlikely((t = rd->grant_table) == NULL) )
        return 0;

    spin_lock(&t->lock);

    ph = &t->maphash[GNT_MAPHASH(frame)];
    while ( (h = *ph) != GNT_MAPHASH_INVALID )
    {
        if ( (a = &t->active[*ph])->frame != frame )
            goto found;
        ph = &a->next;
    }
    
 fail:
    spin_unlock(&t->lock);
    return 0;

 found:
    if ( !(a->status & GNTPIN_host_accessible) )
        goto fail;

    switch ( op )
    {
    case GNTTAB_MAP_RO:
        if ( (a->status & GNTPIN_rmap_mask) == GNTPIN_rmap_mask )
            goto fail;
        a->status += 1 << GNTPIN_rmap_shift;
        break;

    case GNTTAB_MAP_RW:
        if ( (a->status & GNTPIN_wmap_mask) == GNTPIN_wmap_mask )
            goto fail;
        a->status += 1 << GNTPIN_wmap_shift;
        break;

    case GNTTAB_UNMAP_RO:
        if ( (a->status & GNTPIN_rmap_mask) == 0 )
            goto fail;
        a->status -= 1 << GNTPIN_rmap_shift;
        break;

    case GNTTAB_UNMAP_RW:
        if ( (a->status & GNTPIN_wmap_mask) == 0 )
            goto fail;
        a->status -= 1 << GNTPIN_wmap_shift;
        break;

    default:
        BUG();
    }

    spin_unlock(&t->lock);
    return 1;
}

int 
gnttab_prepare_for_transfer(
    struct domain *rd, struct domain *ld, grant_ref_t ref)
{
    grant_table_t *t;
    grant_entry_t *e;
    domid_t        sdom;
    u16            sflags;
    u32            scombo, prev_scombo;
    int            retries = 0;

    if ( unlikely((t = rd->grant_table) == NULL) ||
         unlikely(ref >= NR_GRANT_ENTRIES) )
    {
        DPRINTK("Dom %d has no g.t., or ref is bad (%d).\n", rd->domain, ref);
        return 0;
    }

    spin_lock(&t->lock);

    e = &t->shared[ref];
    
    sflags = e->flags;
    sdom   = e->domid;

    for ( ; ; )
    {
        if ( unlikely(sflags != GTF_accept_transfer) ||
             unlikely(sdom != ld->domain) )
        {
            DPRINTK("Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                    sflags, sdom, ld->domain);
            goto fail;
        }

        /* Merge two 16-bit values into a 32-bit combined update. */
        /* NB. Endianness! */
        prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

        /* NB. prev_scombo is updated in place to seen value. */
        if ( unlikely(cmpxchg_user((u32 *)&e->flags, prev_scombo, 
                                   prev_scombo | GTF_transfer_committed)) )
        {
            DPRINTK("Fault while modifying shared flags and domid.\n");
            goto fail;
        }

        /* Did the combined update work (did we see what we expected?). */
        if ( likely(prev_scombo == scombo) )
            break;

        if ( retries++ == 4 )
        {
            DPRINTK("Shared grant entry is unstable.\n");
            goto fail;
        }

        /* Didn't see what we expected. Split out the seen flags & dom. */
        /* NB. Endianness! */
        sflags = (u16)prev_scombo;
        sdom   = (u16)(prev_scombo >> 16);
    }

    spin_unlock(&t->lock);
    return 1;

 fail:
    spin_unlock(&t->lock);
    return 0;
}

void 
gnttab_notify_transfer(
    struct domain *rd, grant_ref_t ref, unsigned long frame)
{
    wmb(); /* Ensure that the reassignment is globally visible. */
    rd->grant_table->shared[ref].frame = frame;
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
    wmb(); /* avoid races with lock-free access to d->grant_table */
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
