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
        rc = (_rc);                \
        goto fail;                 \
    } while ( 0 )

static inline int
get_maptrack_handle(
    grant_table_t *t)
{
    unsigned int h;
    if ( unlikely((h = t->maptrack_head) == NR_MAPTRACK_ENTRIES) )
        return -1;
    t->maptrack_head = t->maptrack[h].ref_and_flags >> MAPTRACK_REF_SHIFT;
    return h;
}

static inline void
put_maptrack_handle(
    grant_table_t *t, int handle)
{
    t->maptrack[handle].ref_and_flags = t->maptrack_head << MAPTRACK_REF_SHIFT;
    t->maptrack_head = handle;
}

static void
__gnttab_map_grant_ref(
    gnttab_map_grant_ref_t *uop)
{
    domid_t        dom, sdom;
    grant_ref_t    ref;
    struct domain *ld, *rd;
    u16            flags, sflags;
    int            handle;
    active_grant_entry_t *act;
    grant_entry_t *sha;
    s16            rc = 0;
    unsigned long  frame;

    /*
     * We bound the number of times we retry CMPXCHG on memory locations that
     * we share with a guest OS. The reason is that the guest can modify that
     * location at a higher rate than we can read-modify-CMPXCHG, so the guest
     * could cause us to livelock. There are a few cases where it is valid for
     * the guest to race our updates (e.g., to change the GTF_readonly flag),
     * so we allow a few retries before failing.
     */
    int            retries = 0;

    ld = current->domain;

    /* Bitwise-OR avoids short-circuiting which screws control flow. */
    if ( unlikely(__get_user(dom, &uop->dom) |
                  __get_user(ref, &uop->ref) |
                  __get_user(flags, &uop->flags)) )
    {
        DPRINTK("Fault while reading gnttab_map_grant_ref_t.\n");
        return; /* don't set status */
    }

    if ( unlikely(ref >= NR_GRANT_ENTRIES) || 
         unlikely((flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0) )
    {
        DPRINTK("Bad ref (%d) or flags (%x).\n", ref, flags);
        (void)__put_user(GNTST_bad_gntref, &uop->handle);
        return;
    }

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", dom);
        (void)__put_user(GNTST_bad_domain, &uop->handle);
        return;
    }

    if ( unlikely((handle = get_maptrack_handle(ld->grant_table)) == -1) )
    {
        put_domain(rd);
        DPRINTK("No more map handles available\n");
        (void)__put_user(GNTST_no_device_space, &uop->handle);
        return;
    }

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    spin_lock(&rd->grant_table->lock);
    
    if ( act->pin == 0 )
    {
        /* CASE 1: Activating a previously inactive entry. */

        sflags = sha->flags;
        sdom   = sha->domid;

        for ( ; ; )
        {
            u32 scombo, prev_scombo, new_scombo;

            if ( unlikely((sflags & GTF_type_mask) != GTF_permit_access) ||
                 unlikely(sdom != ld->id) )
                PIN_FAIL(GNTST_general_error,
                         "Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                        sflags, sdom, ld->id);

            /* Merge two 16-bit values into a 32-bit combined update. */
            /* NB. Endianness! */
            prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

            new_scombo = scombo | GTF_reading;
            if ( !(flags & GNTMAP_readonly) )
            {
                new_scombo |= GTF_writing;
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");
            }

            /* NB. prev_scombo is updated in place to seen value. */
            if ( unlikely(cmpxchg_user((u32 *)&sha->flags,
                                       prev_scombo, 
                                       new_scombo)) )
                PIN_FAIL(GNTST_general_error,
                         "Fault while modifying shared flags and domid.\n");

            /* Did the combined update work (did we see what we expected?). */
            if ( likely(prev_scombo == scombo) )
                break;

            if ( retries++ == 4 )
                PIN_FAIL(GNTST_general_error,
                         "Shared grant entry is unstable.\n");

            /* Didn't see what we expected. Split out the seen flags & dom. */
            /* NB. Endianness! */
            sflags = (u16)prev_scombo;
            sdom   = (u16)(prev_scombo >> 16);
        }

        /* rmb(); */ /* not on x86 */
        frame = sha->frame;
        if ( unlikely(!pfn_is_ram(frame)) || 
             unlikely(!((flags & GNTMAP_readonly) ? 
                        get_page(&frame_table[frame], rd) : 
                        get_page_and_type(&frame_table[frame], rd, 
                                          PGT_writable_page))) )
        {
            clear_bit(_GTF_writing, &sha->flags);
            clear_bit(_GTF_reading, &sha->flags);
            PIN_FAIL(GNTST_general_error, 
                     "Could not pin the granted frame!\n");
        }

        if ( flags & GNTMAP_device_map )
            act->pin += (flags & GNTMAP_readonly) ? 
                GNTPIN_devr_inc : GNTPIN_devw_inc;
        if ( flags & GNTMAP_host_map )
            act->pin += (flags & GNTMAP_readonly) ?
                GNTPIN_hstr_inc : GNTPIN_hstw_inc;
        act->domid = sdom;
        act->frame = frame;
    }
    else 
    {
        /* CASE 2: Active modications to an already active entry. */

        /*
         * A cheesy check for possible pin-count overflow.
         * A more accurate check cannot be done with a single comparison.
         */
        if ( (act->pin & 0x80808080U) != 0 )
            PIN_FAIL(ENOSPC, "Risk of counter overflow %08x\n", act->pin);

        if ( !(flags & GNTMAP_readonly) && 
             !((sflags = sha->flags) & GTF_writing) )
        {
            for ( ; ; )
            {
                u16 prev_sflags;
                
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");

                prev_sflags = sflags;

                /* NB. prev_sflags is updated in place to seen value. */
                if ( unlikely(cmpxchg_user(&sha->flags, prev_sflags, 
                                           prev_sflags | GTF_writing)) )
                    PIN_FAIL(GNTST_general_error,
                             "Fault while modifying shared flags.\n");

                if ( likely(prev_sflags == sflags) )
                    break;

                if ( retries++ == 4 )
                    PIN_FAIL(GNTST_general_error,
                             "Shared grant entry is unstable.\n");

                sflags = prev_sflags;
            }

            if ( unlikely(!get_page_type(&frame_table[act->frame],
                                         PGT_writable_page)) )
            {
                clear_bit(_GTF_writing, &sha->flags);
                PIN_FAIL(GNTST_general_error,
                         "Attempt to write-pin a unwritable page.\n");
            }
        }

        if ( flags & GNTMAP_device_map )
            act->pin += (flags & GNTMAP_readonly) ? 
                GNTPIN_devr_inc : GNTPIN_devw_inc;
        if ( flags & GNTMAP_host_map )
            act->pin += (flags & GNTMAP_readonly) ?
                GNTPIN_hstr_inc : GNTPIN_hstw_inc;
    }

    ld->grant_table->maptrack[handle].domid         = dom;
    ld->grant_table->maptrack[handle].ref_and_flags =
        (ref << MAPTRACK_REF_SHIFT) | (flags & MAPTRACK_GNTMAP_MASK);

    /* Unchecked and unconditional. */
    (void)__put_user(handle, &uop->handle);
    (void)__put_user(act->frame,  &uop->dev_bus_addr);

    spin_unlock(&rd->grant_table->lock);
    put_domain(rd);
    return;

 fail:
    (void)__put_user(rc, &uop->handle);
    spin_unlock(&rd->grant_table->lock);
    put_domain(rd);
    put_maptrack_handle(ld->grant_table, handle);
}

static long
gnttab_map_grant_ref(
    gnttab_map_grant_ref_t *uop, unsigned int count)
{
    int i;
    for ( i = 0; i < count; i++ )
        __gnttab_map_grant_ref(&uop[i]);
    return 0;
}

static void
__gnttab_unmap_grant_ref(
    gnttab_unmap_grant_ref_t *uop)
{
    domid_t        dom;
    grant_ref_t    ref;
    u16            handle;
    struct domain *ld, *rd;

    active_grant_entry_t *act;
    grant_entry_t *sha;
    grant_mapping_t *map;
    s16            rc = 0;
    unsigned long  frame, virt;

    ld = current->domain;

    /* Bitwise-OR avoids short-circuiting which screws control flow. */
    if ( unlikely(__get_user(virt, &uop->host_virt_addr) |
                  __get_user(frame, &uop->dev_bus_addr) |
                  __get_user(handle, &uop->handle)) )
    {
        DPRINTK("Fault while reading gnttab_unmap_grant_ref_t.\n");
        return; /* don't set status */
    }

    map = &ld->grant_table->maptrack[handle];

    if ( unlikely(handle >= NR_MAPTRACK_ENTRIES) ||
         unlikely(!(map->ref_and_flags & MAPTRACK_GNTMAP_MASK)) )
    {
        DPRINTK("Bad handle (%d).\n", handle);
        (void)__put_user(GNTST_bad_handle, &uop->status);
        return;
    }

    dom = map->domid;
    ref = map->ref_and_flags >> MAPTRACK_REF_SHIFT;

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", dom);
        (void)__put_user(GNTST_bad_domain, &uop->status);
        return;
    }

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    spin_lock(&rd->grant_table->lock);

    if ( frame != 0 )
    {
        if ( unlikely(frame != act->frame) )
            PIN_FAIL(GNTST_general_error,
                     "Bad frame number doesn't match gntref.\n");
        if ( map->ref_and_flags & GNTMAP_device_map )
            act->pin -= (map->ref_and_flags & GNTMAP_readonly) ? 
                GNTPIN_devr_inc : GNTPIN_devw_inc;
    }
    else
    {
        frame = act->frame;
    }

    if ( (virt != 0) && (map->ref_and_flags & GNTMAP_host_map) )
    {
        act->pin -= (map->ref_and_flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;
    }

    if ( ((act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0) &&
              !(map->ref_and_flags & GNTMAP_readonly) )
    {
        put_page_type(&frame_table[frame]);
        clear_bit(_GTF_writing, &sha->flags);
    }

    if ( act->pin == 0 )
    {
        put_page(&frame_table[frame]);
        clear_bit(_GTF_reading, &sha->flags);
    }

 fail:
    (void)__put_user(rc, &uop->status);
    spin_unlock(&rd->grant_table->lock);
    put_domain(rd);
}

static long
gnttab_unmap_grant_ref(
    gnttab_unmap_grant_ref_t *uop, unsigned int count)
{
    int i;
    for ( i = 0; i < count; i++ )
        __gnttab_unmap_grant_ref(&uop[i]);
    return 0;
}

static long 
gnttab_setup_table(
    gnttab_setup_table_t *uop, unsigned int count)
{
    gnttab_setup_table_t  op;
    struct domain        *d;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
    {
        DPRINTK("Fault while reading gnttab_setup_table_t.\n");
        return -EFAULT;
    }

    if ( unlikely(op.nr_frames > 1) )
    {
        DPRINTK("Xen only supports one grant-table frame per domain.\n");
        (void)put_user(GNTST_general_error, &uop->status);
        return 0;
    }

    if ( op.dom == DOMID_SELF )
    {
        op.dom = current->domain->id;
    }
    else if ( unlikely(!IS_PRIV(current->domain)) )
    {
        (void)put_user(GNTST_permission_denied, &uop->status);
        return 0;
    }

    if ( unlikely((d = find_domain_by_id(op.dom)) == NULL) )
    {
        DPRINTK("Bad domid %d.\n", op.dom);
        (void)put_user(GNTST_bad_domain, &uop->status);
        return 0;
    }

    if ( op.nr_frames == 1 )
    {
        ASSERT(d->grant_table != NULL);
        (void)put_user(GNTST_okay, &uop->status);
        (void)put_user(virt_to_phys(d->grant_table) >> PAGE_SHIFT,
                       &uop->frame_list[0]);
    }

    put_domain(d);
    return 0;
}

long 
do_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    long rc;

    /* XXX stubbed out XXX */
    return -ENOSYS;

    if ( count > 512 )
        return -EINVAL;

    LOCK_BIGLOCK(current->domain);

    switch ( cmd )
    {
    case GNTTABOP_map_grant_ref:
        if ( unlikely(!access_ok(VERIFY_WRITE, uop,
                                 count * sizeof(gnttab_map_grant_ref_t))) )
            return -EFAULT;
        rc = gnttab_map_grant_ref((gnttab_map_grant_ref_t *)uop, count);
        break;
    case GNTTABOP_unmap_grant_ref:
        if ( unlikely(!access_ok(VERIFY_WRITE, uop,
                                 count * sizeof(gnttab_unmap_grant_ref_t))) )
            return -EFAULT;
        rc = gnttab_unmap_grant_ref((gnttab_unmap_grant_ref_t *)uop, count);
        break;
    case GNTTABOP_setup_table:
        rc = gnttab_setup_table((gnttab_setup_table_t *)uop, count);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    UNLOCK_BIGLOCK(current->domain);

    return rc;
}

int
gnttab_check_unmap(
    struct domain *rd, struct domain *ld, unsigned long frame, int readonly)
{
    return 0;
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
        DPRINTK("Dom %d has no g.t., or ref is bad (%d).\n", rd->id, ref);
        return 0;
    }

    spin_lock(&t->lock);

    e = &t->shared[ref];
    
    sflags = e->flags;
    sdom   = e->domid;

    for ( ; ; )
    {
        if ( unlikely(sflags != GTF_accept_transfer) ||
             unlikely(sdom != ld->id) )
        {
            DPRINTK("Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                    sflags, sdom, ld->id);
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

    if ( (t = xmalloc(sizeof(*t))) == NULL )
        goto no_mem;

    /* Simple stuff. */
    memset(t, 0, sizeof(*t));
    spin_lock_init(&t->lock);

    /* Active grant table. */
    if ( (t->active = xmalloc(sizeof(active_grant_entry_t) * 
                              NR_GRANT_ENTRIES)) == NULL )
        goto no_mem;
    memset(t->active, 0, sizeof(active_grant_entry_t) * NR_GRANT_ENTRIES);

    if ( (t->maptrack = (void *)alloc_xenheap_page()) == NULL )
        goto no_mem;
    memset(t->maptrack, 0, PAGE_SIZE);
    for ( i = 0; i < NR_MAPTRACK_ENTRIES; i++ )
        t->maptrack[i].ref_and_flags = (i+1) << MAPTRACK_REF_SHIFT;

    /* Shared grant table. */
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
        if ( t->maptrack != NULL )
            free_xenheap_page((unsigned long)t->maptrack);
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
        free_xenheap_page((unsigned long)t->maptrack);
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
