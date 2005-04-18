/******************************************************************************
 * common/grant_table.c
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2005 Christopher Clark
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

#define GRANT_DEBUG 0
#define GRANT_DEBUG_VERBOSE 0

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/shadow.h>
#include <xen/mm.h>

#define PIN_FAIL(_lbl, _rc, _f, _a...)   \
    do {                           \
        DPRINTK( _f, ## _a );      \
        rc = (_rc);                \
        goto _lbl;                 \
    } while ( 0 )

static inline int
get_maptrack_handle(
    grant_table_t *t)
{
    unsigned int h;
    if ( unlikely((h = t->maptrack_head) == t->maptrack_limit) )
        return -1;
    t->maptrack_head = t->maptrack[h].ref_and_flags >> MAPTRACK_REF_SHIFT;
    t->map_count++;
    return h;
}

static inline void
put_maptrack_handle(
    grant_table_t *t, int handle)
{
    t->maptrack[handle].ref_and_flags = t->maptrack_head << MAPTRACK_REF_SHIFT;
    t->maptrack_head = handle;
    t->map_count--;
}

static int
__gnttab_activate_grant_ref(
    struct domain          *mapping_d,          /* IN */
    struct exec_domain     *mapping_ed,
    struct domain          *granting_d,
    grant_ref_t             ref,
    u16                     dev_hst_ro_flags,
    unsigned long           host_virt_addr,
    unsigned long          *pframe )            /* OUT */
{
    domid_t               sdom;
    u16                   sflags;
    active_grant_entry_t *act;
    grant_entry_t        *sha;
    s16                   rc = 1;
    unsigned long         frame = 0;
    int                   retries = 0;

    /*
     * Objectives of this function:
     * . Make the record ( granting_d, ref ) active, if not already.
     * . Update shared grant entry of owner, indicating frame is mapped.
     * . Increment the owner act->pin reference counts.
     * . get_page on shared frame if new mapping.
     * . get_page_type if this is first RW mapping of frame.
     * . Add PTE to virtual address space of mapping_d, if necessary.
     * Returns:
     * .  -ve: error
     * .    1: ok
     * .    0: ok and TLB invalidate of host_virt_addr needed.
     *
     * On success, *pframe contains mfn.
     */

    /*
     * We bound the number of times we retry CMPXCHG on memory locations that
     * we share with a guest OS. The reason is that the guest can modify that
     * location at a higher rate than we can read-modify-CMPXCHG, so the guest
     * could cause us to livelock. There are a few cases where it is valid for
     * the guest to race our updates (e.g., to change the GTF_readonly flag),
     * so we allow a few retries before failing.
     */

    act = &granting_d->grant_table->active[ref];
    sha = &granting_d->grant_table->shared[ref];

    spin_lock(&granting_d->grant_table->lock);

    if ( act->pin == 0 )
    {
        /* CASE 1: Activating a previously inactive entry. */

        sflags = sha->flags;
        sdom   = sha->domid;

        for ( ; ; )
        {
            u32 scombo, prev_scombo, new_scombo;

            if ( unlikely((sflags & GTF_type_mask) != GTF_permit_access) ||
                 unlikely(sdom != mapping_d->id) )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                        sflags, sdom, mapping_d->id);

            /* Merge two 16-bit values into a 32-bit combined update. */
            /* NB. Endianness! */
            prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

            new_scombo = scombo | GTF_reading;
            if ( !(dev_hst_ro_flags & GNTMAP_readonly) )
            {
                new_scombo |= GTF_writing;
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");
            }

            /* NB. prev_scombo is updated in place to seen value. */
            if ( unlikely(cmpxchg_user((u32 *)&sha->flags,
                                       prev_scombo,
                                       new_scombo)) )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Fault while modifying shared flags and domid.\n");

            /* Did the combined update work (did we see what we expected?). */
            if ( likely(prev_scombo == scombo) )
                break;

            if ( retries++ == 4 )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Shared grant entry is unstable.\n");

            /* Didn't see what we expected. Split out the seen flags & dom. */
            /* NB. Endianness! */
            sflags = (u16)prev_scombo;
            sdom   = (u16)(prev_scombo >> 16);
        }

        /* rmb(); */ /* not on x86 */

        frame = __gpfn_to_mfn_foreign(granting_d, sha->frame);

        if ( unlikely(!pfn_valid(frame)) ||
             unlikely(!((dev_hst_ro_flags & GNTMAP_readonly) ?
                        get_page(&frame_table[frame], granting_d) :
                        get_page_and_type(&frame_table[frame], granting_d,
                                          PGT_writable_page))) )
        {
            clear_bit(_GTF_writing, &sha->flags);
            clear_bit(_GTF_reading, &sha->flags);
            PIN_FAIL(unlock_out, GNTST_general_error,
                     "Could not pin the granted frame (%lx)!\n", frame);
        }

        if ( dev_hst_ro_flags & GNTMAP_device_map )
            act->pin += (dev_hst_ro_flags & GNTMAP_readonly) ?
                GNTPIN_devr_inc : GNTPIN_devw_inc;
        if ( dev_hst_ro_flags & GNTMAP_host_map )
            act->pin += (dev_hst_ro_flags & GNTMAP_readonly) ?
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
            PIN_FAIL(unlock_out, ENOSPC, "Risk of counter overflow %08x\n", act->pin);

        frame = act->frame;

        if ( !(dev_hst_ro_flags & GNTMAP_readonly) && 
             !((sflags = sha->flags) & GTF_writing) )
        {
            for ( ; ; )
            {
                u16 prev_sflags;
                
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");

                prev_sflags = sflags;

                /* NB. prev_sflags is updated in place to seen value. */
                if ( unlikely(cmpxchg_user(&sha->flags, prev_sflags, 
                                           prev_sflags | GTF_writing)) )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                         "Fault while modifying shared flags.\n");

                if ( likely(prev_sflags == sflags) )
                    break;

                if ( retries++ == 4 )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                             "Shared grant entry is unstable.\n");

                sflags = prev_sflags;
            }

            if ( unlikely(!get_page_type(&frame_table[frame],
                                         PGT_writable_page)) )
            {
                clear_bit(_GTF_writing, &sha->flags);
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Attempt to write-pin a unwritable page.\n");
            }
        }

        if ( dev_hst_ro_flags & GNTMAP_device_map )
            act->pin += (dev_hst_ro_flags & GNTMAP_readonly) ? 
                GNTPIN_devr_inc : GNTPIN_devw_inc;
        if ( dev_hst_ro_flags & GNTMAP_host_map )
            act->pin += (dev_hst_ro_flags & GNTMAP_readonly) ?
                GNTPIN_hstr_inc : GNTPIN_hstw_inc;
    }

    /* At this point:
     * act->pin updated to reflect mapping.
     * sha->flags updated to indicate to granting domain mapping done.
     * frame contains the mfn.
     */

    spin_unlock(&granting_d->grant_table->lock);

    if ( (host_virt_addr != 0) && (dev_hst_ro_flags & GNTMAP_host_map) )
    {
        /* Write update into the pagetable
         */

        rc = update_grant_va_mapping( host_virt_addr,
                                (frame << PAGE_SHIFT) | _PAGE_PRESENT  |
                                                        _PAGE_ACCESSED |
                                                        _PAGE_DIRTY    |
                       ((dev_hst_ro_flags & GNTMAP_readonly) ? 0 : _PAGE_RW),
                       mapping_d, mapping_ed );

        /* IMPORTANT: (rc == 0) => must flush / invalidate entry in TLB.
         * This is done in the outer gnttab_map_grant_ref.
         */

        if ( 0 > rc )
        {
            /* Abort. */

            spin_lock(&granting_d->grant_table->lock);

            if ( dev_hst_ro_flags & GNTMAP_readonly )
                act->pin -= GNTPIN_hstr_inc;
            else
            {
                act->pin -= GNTPIN_hstw_inc;
                if ( (act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) == 0 )
                {
                    clear_bit(_GTF_writing, &sha->flags);
                    put_page_type(&frame_table[frame]);
                }
            }
            if ( act->pin == 0 )
            {
                clear_bit(_GTF_reading, &sha->flags);
                put_page(&frame_table[frame]);
            }

            spin_unlock(&granting_d->grant_table->lock);
        }

    }
    *pframe = frame;
    return rc;

 unlock_out:
    spin_unlock(&granting_d->grant_table->lock);
    return rc;
}

static int
__gnttab_map_grant_ref(
    gnttab_map_grant_ref_t *uop,
    unsigned long *va)
{
    domid_t               dom;
    grant_ref_t           ref;
    struct domain        *ld, *rd;
    struct exec_domain   *led;
    u16                   dev_hst_ro_flags;
    int                   handle;
    unsigned long         frame = 0, host_virt_addr;
    int                   rc;

    /* Returns 0 if TLB flush / invalidate required by caller.
     * va will indicate the address to be invalidated. */

    led = current;
    ld = led->domain;

    /* Bitwise-OR avoids short-circuiting which screws control flow. */
    if ( unlikely(__get_user(dom, &uop->dom) |
                  __get_user(ref, &uop->ref) |
                  __get_user(host_virt_addr, &uop->host_virt_addr) |
                  __get_user(dev_hst_ro_flags, &uop->flags)) )
    {
        DPRINTK("Fault while reading gnttab_map_grant_ref_t.\n");
        return -EFAULT; /* don't set status */
    }


    if ( ((host_virt_addr != 0) || (dev_hst_ro_flags & GNTMAP_host_map) ) &&
         unlikely(!__addr_ok(host_virt_addr)))
    {
        DPRINTK("Bad virtual address (%x) or flags (%x).\n",
                host_virt_addr, dev_hst_ro_flags);
        (void)__put_user(GNTST_bad_virt_addr, &uop->handle);
        return GNTST_bad_gntref;
    }

    if ( unlikely(ref >= NR_GRANT_ENTRIES) ||
         unlikely((dev_hst_ro_flags & (GNTMAP_device_map|GNTMAP_host_map)) ==
0) )
    {
        DPRINTK("Bad ref (%d) or flags (%x).\n", ref, dev_hst_ro_flags);
        (void)__put_user(GNTST_bad_gntref, &uop->handle);
        return GNTST_bad_gntref;
    }

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", dom);
        (void)__put_user(GNTST_bad_domain, &uop->handle);
        return GNTST_bad_domain;
    }

    /* get a maptrack handle */
    if ( unlikely((handle = get_maptrack_handle(ld->grant_table)) == -1) )
    {
        int              i;
        grant_mapping_t *new_mt;
        grant_table_t   *lgt      = ld->grant_table;

        /* grow the maptrack table */
        if ( (new_mt = (void *)alloc_xenheap_pages(lgt->maptrack_order + 1)) == NULL )
        {
            put_domain(rd);
            DPRINTK("No more map handles available\n");
            (void)__put_user(GNTST_no_device_space, &uop->handle);
            return GNTST_no_device_space;
        }

        memcpy(new_mt, lgt->maptrack, PAGE_SIZE << lgt->maptrack_order);
        for ( i = lgt->maptrack_limit; i < (lgt->maptrack_limit << 1); i++ )
            new_mt[i].ref_and_flags = (i+1) << MAPTRACK_REF_SHIFT;

        free_xenheap_pages((unsigned long)lgt->maptrack, lgt->maptrack_order);
        lgt->maptrack          = new_mt;
        lgt->maptrack_order   += 1;
        lgt->maptrack_limit  <<= 1;

        printk("Doubled maptrack size\n");
        handle = get_maptrack_handle(ld->grant_table);
    }

#if GRANT_DEBUG_VERBOSE
    DPRINTK("Mapping grant ref (%hu) for domain (%hu) with flags (%x)\n",
            ref, dom, dev_hst_ro_flags);
#endif

    if ( 0 <= ( rc = __gnttab_activate_grant_ref( ld, led, rd, ref,
                                                  dev_hst_ro_flags,
                                                  host_virt_addr, &frame)))
    {
        /* Only make the maptrack live _after_ writing the pte,
         * in case we overwrite the same frame number, causing a
         *  maptrack walk to find it
         */
        ld->grant_table->maptrack[handle].domid = dom;

        ld->grant_table->maptrack[handle].ref_and_flags
            = (ref << MAPTRACK_REF_SHIFT) |
              (dev_hst_ro_flags & MAPTRACK_GNTMAP_MASK);

        (void)__put_user(frame, &uop->dev_bus_addr);

        if ( dev_hst_ro_flags & GNTMAP_host_map )
            *va = host_virt_addr;

        (void)__put_user(handle, &uop->handle);
    }
    else
    {
        (void)__put_user(rc, &uop->handle);
        put_maptrack_handle(ld->grant_table, handle);
    }

    put_domain(rd);
    return rc;
}

static long
gnttab_map_grant_ref(
    gnttab_map_grant_ref_t *uop, unsigned int count)
{
    int i, flush = 0;
    unsigned long va[8];

    for ( i = 0; i < count; i++ )
        if ( __gnttab_map_grant_ref(&uop[i],
             &va[ (flush < 8 ? flush : 0) ]   ) == 0)
            flush++;

    if ( flush != 0 )
    {
        if ( flush <= 8 )
            for ( i = 0; i < flush; i++ )
                flush_tlb_one_mask(current->domain->cpuset, va[i]);
        else 
            local_flush_tlb();
    }

    return 0;
}

static int
__gnttab_unmap_grant_ref(
    gnttab_unmap_grant_ref_t *uop,
    unsigned long *va)
{
    domid_t        dom;
    grant_ref_t    ref;
    u16            handle;
    struct domain *ld, *rd;

    active_grant_entry_t *act;
    grant_entry_t *sha;
    grant_mapping_t *map;
    u16            flags;
    s16            rc = 1;
    unsigned long  frame, virt;

    ld = current->domain;

    /* Bitwise-OR avoids short-circuiting which screws control flow. */
    if ( unlikely(__get_user(virt, &uop->host_virt_addr) |
                  __get_user(frame, &uop->dev_bus_addr) |
                  __get_user(handle, &uop->handle)) )
    {
        DPRINTK("Fault while reading gnttab_unmap_grant_ref_t.\n");
        return -EFAULT; /* don't set status */
    }

    map = &ld->grant_table->maptrack[handle];

    if ( unlikely(handle >= ld->grant_table->maptrack_limit) ||
         unlikely(!(map->ref_and_flags & MAPTRACK_GNTMAP_MASK)) )
    {
        DPRINTK("Bad handle (%d).\n", handle);
        (void)__put_user(GNTST_bad_handle, &uop->status);
        return GNTST_bad_handle;
    }

    dom   = map->domid;
    ref   = map->ref_and_flags >> MAPTRACK_REF_SHIFT;
    flags = map->ref_and_flags & MAPTRACK_GNTMAP_MASK;

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", dom);
        (void)__put_user(GNTST_bad_domain, &uop->status);
        return GNTST_bad_domain;
    }
#if GRANT_DEBUG_VERBOSE
    DPRINTK("Unmapping grant ref (%hu) for domain (%hu) with handle (%hu)\n",
            ref, dom, handle);
#endif

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    spin_lock(&rd->grant_table->lock);

    if ( frame == 0 )
        frame = act->frame;
    else if ( frame == GNTUNMAP_DEV_FROM_VIRT )
    {
        if ( !( flags & GNTMAP_device_map ) )
            PIN_FAIL(unmap_out, GNTST_bad_dev_addr,
                     "Bad frame number: frame not mapped for device access.\n");
        frame = act->frame;

        /* frame will be unmapped for device access below if virt addr ok */
    }
    else
    {
        if ( unlikely(frame != act->frame) )
            PIN_FAIL(unmap_out, GNTST_general_error,
                     "Bad frame number doesn't match gntref.\n");
        if ( flags & GNTMAP_device_map )
            act->pin -= (flags & GNTMAP_readonly) ? GNTPIN_devr_inc
                                                  : GNTPIN_devw_inc;

        map->ref_and_flags &= ~GNTMAP_device_map;
        (void)__put_user(0, &uop->dev_bus_addr);

        /* frame is now unmapped for device access */
    }

    if ( (virt != 0) &&
         (flags & GNTMAP_host_map) &&
         ((act->pin & (GNTPIN_hstw_mask | GNTPIN_hstr_mask)) > 0))
    {
        l1_pgentry_t   *pl1e;
        unsigned long   _ol1e;

        pl1e = &linear_pg_table[l1_linear_offset(virt)];
                                                                                            
        if ( unlikely(__get_user(_ol1e, (unsigned long *)pl1e) != 0) )
        {
            DPRINTK("Could not find PTE entry for address %x\n", virt);
            rc = -EINVAL;
            goto unmap_out;
        }

        /* check that the virtual address supplied is actually
         * mapped to act->frame.
         */
        if ( unlikely((_ol1e >> PAGE_SHIFT) != frame ))
        {
            DPRINTK("PTE entry %x for address %x doesn't match frame %x\n",
                    _ol1e, virt, frame);
            rc = -EINVAL;
            goto unmap_out;
        }

        /* Delete pagetable entry
         */
        if ( unlikely(__put_user(0, (unsigned long *)pl1e)))
        {
            DPRINTK("Cannot delete PTE entry at %x for virtual address %x\n",
                    pl1e, virt);
            rc = -EINVAL;
            goto unmap_out;
        }

        map->ref_and_flags &= ~GNTMAP_host_map;

        act->pin -= (flags & GNTMAP_readonly) ? GNTPIN_hstr_inc
                                              : GNTPIN_hstw_inc;

        if ( frame == GNTUNMAP_DEV_FROM_VIRT )
        {
            act->pin -= (flags & GNTMAP_readonly) ? GNTPIN_devr_inc
                                                  : GNTPIN_devw_inc;

            map->ref_and_flags &= ~GNTMAP_device_map;
            (void)__put_user(0, &uop->dev_bus_addr);
        }

        rc = 0;
        *va = virt;
    }

    if ( (map->ref_and_flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0)
    {
        map->ref_and_flags = 0;
        put_maptrack_handle(ld->grant_table, handle);
    }

    /* If just unmapped a writable mapping, mark as dirtied */
    if ( unlikely(shadow_mode_log_dirty(rd)) &&
        !( flags & GNTMAP_readonly ) )
         mark_dirty(rd, frame);

    /* If the last writable mapping has been removed, put_page_type */
    if ( ( (act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask) ) == 0) &&
         ( !( flags & GNTMAP_readonly ) ) )
    {
        clear_bit(_GTF_writing, &sha->flags);
        put_page_type(&frame_table[frame]);
    }

    if ( act->pin == 0 )
    {
        clear_bit(_GTF_reading, &sha->flags);
        put_page(&frame_table[frame]);
    }

 unmap_out:
    (void)__put_user(rc, &uop->status);
    spin_unlock(&rd->grant_table->lock);
    put_domain(rd);
    return rc;
}

static long
gnttab_unmap_grant_ref(
    gnttab_unmap_grant_ref_t *uop, unsigned int count)
{
    int i, flush = 0;
    unsigned long va[8];

    for ( i = 0; i < count; i++ )
        if ( __gnttab_unmap_grant_ref(&uop[i],
             &va[ (flush < 8 ? flush : 0) ]   ) == 0)
            flush++;

    if ( flush != 0 )
    {
        if ( flush <= 8 )
            for ( i = 0; i < flush; i++ )
                flush_tlb_one_mask(current->domain->cpuset, va[i]);
        else 
            local_flush_tlb();
    }

    return 0;
}

static long 
gnttab_setup_table(
    gnttab_setup_table_t *uop, unsigned int count)
{
    gnttab_setup_table_t  op;
    struct domain        *d;
    int                   i;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
    {
        DPRINTK("Fault while reading gnttab_setup_table_t.\n");
        return -EFAULT;
    }

    if ( unlikely(op.nr_frames > NR_GRANT_FRAMES) )
    {
        DPRINTK("Xen only supports at most %d grant-table frames per domain.\n",
                NR_GRANT_FRAMES);
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

    if ( op.nr_frames <= NR_GRANT_FRAMES )
    {
        ASSERT(d->grant_table != NULL);
        (void)put_user(GNTST_okay, &uop->status);

        for ( i = 0; i < op.nr_frames; i++ )
            (void)put_user( (
                virt_to_phys( (char*)(d->grant_table->shared)+(i*PAGE_SIZE) )
                              >> PAGE_SHIFT ), &uop->frame_list[i]);
    }

    put_domain(d);
    return 0;
}

#if GRANT_DEBUG
static int
gnttab_dump_table(gnttab_dump_table_t *uop)
{
    grant_table_t        *gt;
    gnttab_dump_table_t   op;
    struct domain        *d;
    u32                   shared_mfn;
    active_grant_entry_t *act;
    grant_entry_t         sha_copy;
    grant_mapping_t      *maptrack;
    int                   i;


    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
    {
        DPRINTK("Fault while reading gnttab_dump_table_t.\n");
        return -EFAULT;
    }

    if ( op.dom == DOMID_SELF )
    {
        op.dom = current->domain->id;
    }

    if ( unlikely((d = find_domain_by_id(op.dom)) == NULL) )
    {
        DPRINTK("Bad domid %d.\n", op.dom);
        (void)put_user(GNTST_bad_domain, &uop->status);
        return 0;
    }

    ASSERT(d->grant_table != NULL);
    gt = d->grant_table;
    (void)put_user(GNTST_okay, &uop->status);

    shared_mfn = virt_to_phys(d->grant_table->shared);

    DPRINTK("Grant table for dom (%hu) MFN (%x)\n",
            op.dom, shared_mfn);

    ASSERT(d->grant_table->active != NULL);
    ASSERT(d->grant_table->shared != NULL);
    ASSERT(d->grant_table->maptrack != NULL);

    for ( i = 0; i < NR_GRANT_ENTRIES; i++ )
    {
        sha_copy =  gt->shared[i];

        if ( sha_copy.flags )
        {
            DPRINTK("Grant: dom (%hu) SHARED (%d) flags:(%hx) dom:(%hu) frame:(%lx)\n",
                    op.dom, i, sha_copy.flags, sha_copy.domid, sha_copy.frame);
        }
    }

    spin_lock(&gt->lock);

    for ( i = 0; i < NR_GRANT_ENTRIES; i++ )
    {
        act = &gt->active[i];

        if ( act->pin )
        {
            DPRINTK("Grant: dom (%hu) ACTIVE (%d) pin:(%x) dom:(%hu) frame:(%lx)\n",
                    op.dom, i, act->pin, act->domid, act->frame);
        }
    }

    for ( i = 0; i < gt->maptrack_limit; i++ )
    {
        maptrack = &gt->maptrack[i];

        if ( maptrack->ref_and_flags & MAPTRACK_GNTMAP_MASK )
        {
            DPRINTK("Grant: dom (%hu) MAP (%d) ref:(%hu) flags:(%x) dom:(%hu)\n",
                    op.dom, i,
                    maptrack->ref_and_flags >> MAPTRACK_REF_SHIFT,
                    maptrack->ref_and_flags & MAPTRACK_GNTMAP_MASK,
                    maptrack->domid);
        }
    }

    spin_unlock(&gt->lock);

    put_domain(d);
    return 0;
}
#endif

long 
do_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    long rc;

    if ( count > 512 )
        return -EINVAL;

    LOCK_BIGLOCK(current->domain);

    rc = -EFAULT;
    switch ( cmd )
    {
    case GNTTABOP_map_grant_ref:
        if ( unlikely(!array_access_ok(
            VERIFY_WRITE, uop, count, sizeof(gnttab_map_grant_ref_t))) )
            goto out;
        rc = gnttab_map_grant_ref((gnttab_map_grant_ref_t *)uop, count);
        break;
    case GNTTABOP_unmap_grant_ref:
        if ( unlikely(!array_access_ok(
            VERIFY_WRITE, uop, count, sizeof(gnttab_unmap_grant_ref_t))) )
            goto out;
        rc = gnttab_unmap_grant_ref((gnttab_unmap_grant_ref_t *)uop, count);
        break;
    case GNTTABOP_setup_table:
        rc = gnttab_setup_table((gnttab_setup_table_t *)uop, count);
        break;
#if GRANT_DEBUG
    case GNTTABOP_dump_table:
        rc = gnttab_dump_table((gnttab_dump_table_t *)uop);
        break;
#endif
    default:
        rc = -ENOSYS;
        break;
    }

out:
    UNLOCK_BIGLOCK(current->domain);

    return rc;
}

int
gnttab_check_unmap(
    struct domain *rd, struct domain *ld, unsigned long frame, int readonly)
{
    /* Called when put_page is invoked on a page belonging to a foreign domain.
     * Instead of decrementing the frame table ref count, locate the grant
     * table entry, if any, and if found, decrement that count.
     * Called a _lot_ at domain creation because pages mapped by priv domains
     * also traverse this.
     */

    /* Note: if the same frame is mapped multiple times, and then one of
     *       the ptes is overwritten, which maptrack handle gets invalidated?
     * Advice: don't do it.
     */

    unsigned int handle, ref, refcount;
    grant_table_t        *lgt, *rgt;
    active_grant_entry_t *act;
    grant_mapping_t      *map;
    int found = 0;

    lgt = ld->grant_table;

#if GRANT_DEBUG_VERBOSE
    if ( ld->id != 0 )
    {
        DPRINTK("Foreign unref rd(%d) ld(%d) frm(%x) flgs(%x).\n",
                rd->id, ld->id, frame, readonly);
    }
#endif

    /* Fast exit if we're not mapping anything using grant tables */
    if ( lgt->map_count == 0 )
        return 0;

    if ( get_domain(rd) == 0 )
    {
        DPRINTK("gnttab_check_unmap: couldn't get_domain rd(%d)\n", rd->id);
        return 0;
    }

    rgt = rd->grant_table;

    for ( handle = 0; handle < lgt->maptrack_limit; handle++ )
    {
        map = &lgt->maptrack[handle];


        /* cwc22: if multiple grants of the same frame are disallowed,
         * then the readonly check here can be changed to cause an early abort
         * if we've matched on frame, but not on write permission.
         */
        if ( ( map->ref_and_flags & MAPTRACK_GNTMAP_MASK ) &&
             ( readonly ? 1 : (!(map->ref_and_flags & GNTMAP_readonly))))
        {
            ref = (map->ref_and_flags >> MAPTRACK_REF_SHIFT);
            act = &rgt->active[ref];

            spin_lock(&rgt->lock);

            if ( act->frame != frame )
            {
                spin_unlock(&rgt->lock);
                continue;
            }

            refcount = act->pin & ( readonly ? GNTPIN_hstr_mask
                                             : GNTPIN_hstw_mask );
            if ( refcount == 0 )
            {
                spin_unlock(&rgt->lock);
                continue;
            }

            /* gotcha */
            DPRINTK("Grant unref rd(%d) ld(%d) frm(%x) flgs(%x).\n",
                    rd->id, ld->id, frame, readonly);

            if ( readonly )
                act->pin -= GNTPIN_hstr_inc;
            else
            {
                act->pin -= GNTPIN_hstw_inc;

                /* any more granted writable mappings? */
                if ( (act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) == 0 )
                {
                    clear_bit(_GTF_writing, &rgt->shared[ref].flags);
                    put_page_type(&frame_table[frame]);
                }
            }

            if ( act->pin == 0 )
            {
                clear_bit(_GTF_reading, &rgt->shared[ref].flags);
                put_page(&frame_table[frame]);
            }
            spin_unlock(&rgt->lock);

            clear_bit(GNTMAP_host_map, &map->ref_and_flags);

            if ( !(map->ref_and_flags & GNTMAP_device_map) )
                put_maptrack_handle(lgt, handle);

            found = 1;
            break;
        }
    }
    put_domain(rd);

    return found;
}

int 
gnttab_prepare_for_transfer(
    struct domain *rd, struct domain *ld, grant_ref_t ref)
{
    grant_table_t *rgt;
    grant_entry_t *sha;
    domid_t        sdom;
    u16            sflags;
    u32            scombo, prev_scombo;
    int            retries = 0;
    unsigned long  target_pfn;

    DPRINTK("gnttab_prepare_for_transfer rd(%hu) ld(%hu) ref(%hu).\n",
            rd->id, ld->id, ref);

    if ( unlikely((rgt = rd->grant_table) == NULL) ||
         unlikely(ref >= NR_GRANT_ENTRIES) )
    {
        DPRINTK("Dom %d has no g.t., or ref is bad (%d).\n", rd->id, ref);
        return 0;
    }

    spin_lock(&rgt->lock);

    sha = &rgt->shared[ref];
    
    sflags = sha->flags;
    sdom   = sha->domid;

    for ( ; ; )
    {
        target_pfn = sha->frame;

        if ( unlikely(target_pfn >= max_page ) )
        {
            DPRINTK("Bad pfn (%x)\n", target_pfn);
            goto fail;
        }

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
        if ( unlikely(cmpxchg_user((u32 *)&sha->flags, prev_scombo, 
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

    spin_unlock(&rgt->lock);
    return 1;

 fail:
    spin_unlock(&rgt->lock);
    return 0;
}

void 
gnttab_notify_transfer(
    struct domain *rd, struct domain *ld, grant_ref_t ref, unsigned long frame)
{
    grant_entry_t  *sha;
    unsigned long   pfn;

    DPRINTK("gnttab_notify_transfer rd(%hu) ld(%hu) ref(%hu).\n",
            rd->id, ld->id, ref);

    sha = &rd->grant_table->shared[ref];

    spin_lock(&rd->grant_table->lock);

    pfn = sha->frame;

    if ( unlikely(pfn >= max_page ) )
        DPRINTK("Bad pfn (%x)\n", pfn);
    else
    {
        machine_to_phys_mapping[frame] = pfn;

        if ( unlikely(shadow_mode_log_dirty(ld)))
             mark_dirty(ld, frame);

        if (shadow_mode_translate(ld))
            __phys_to_machine_mapping[pfn] = frame;
    }
    sha->frame = __mfn_to_gpfn(rd, frame);
    sha->domid = rd->id;
    wmb();
    sha->flags = ( GTF_accept_transfer | GTF_transfer_completed );

    spin_unlock(&rd->grant_table->lock);

    return;
}

int 
grant_table_create(
    struct domain *d)
{
    grant_table_t *t;
    int            i;

    if ( (t = xmalloc(grant_table_t)) == NULL )
        goto no_mem;

    /* Simple stuff. */
    memset(t, 0, sizeof(*t));
    spin_lock_init(&t->lock);

    /* Active grant table. */
    if ( (t->active = xmalloc_array(active_grant_entry_t, NR_GRANT_ENTRIES))
         == NULL )
        goto no_mem;
    memset(t->active, 0, sizeof(active_grant_entry_t) * NR_GRANT_ENTRIES);

    /* Tracking of mapped foreign frames table */
    if ( (t->maptrack = (void *)alloc_xenheap_page()) == NULL )
        goto no_mem;
    t->maptrack_order = 0;
    t->maptrack_limit = PAGE_SIZE / sizeof(grant_mapping_t);
    memset(t->maptrack, 0, PAGE_SIZE);
    for ( i = 0; i < t->maptrack_limit; i++ )
        t->maptrack[i].ref_and_flags = (i+1) << MAPTRACK_REF_SHIFT;

    /* Shared grant table. */
    if ( (t->shared = (void *)alloc_xenheap_pages(ORDER_GRANT_FRAMES)) == NULL )
        goto no_mem;
    memset(t->shared, 0, NR_GRANT_FRAMES * PAGE_SIZE);

    for ( i = 0; i < NR_GRANT_FRAMES; i++ )
    {
        SHARE_PFN_WITH_DOMAIN(virt_to_page((char *)(t->shared)+(i*PAGE_SIZE)), d);
        machine_to_phys_mapping[ (virt_to_phys((char*)(t->shared)+(i*PAGE_SIZE))
                                 >> PAGE_SHIFT) ] = INVALID_M2P_ENTRY;
    }

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
gnttab_release_dev_mappings(grant_table_t *gt)
{
    grant_mapping_t        *map;
    domid_t                 dom;
    grant_ref_t             ref;
    u16                     handle;
    struct domain          *ld, *rd;
    unsigned long           frame;
    active_grant_entry_t   *act;
    grant_entry_t          *sha;

    ld = current->domain;

    for ( handle = 0; handle < gt->maptrack_limit; handle++ )
    {
        map = &gt->maptrack[handle];

        if ( map->ref_and_flags & GNTMAP_device_map )
        {
            dom = map->domid;
            ref = map->ref_and_flags >> MAPTRACK_REF_SHIFT;

            DPRINTK("Grant release (%hu) ref:(%hu) flags:(%x) dom:(%hu)\n",
                    handle, ref,
                    map->ref_and_flags & MAPTRACK_GNTMAP_MASK, dom);

            if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
                 unlikely(ld == rd) )
            {
                if ( rd != NULL )
                    put_domain(rd);

                printk(KERN_WARNING "Grant release: Could not find domain %d\n", dom);
                continue;
            }

            act = &rd->grant_table->active[ref];
            sha = &rd->grant_table->shared[ref];

            spin_lock(&rd->grant_table->lock);

            if ( act->pin & (GNTPIN_devw_mask | GNTPIN_devr_mask) )
            {
                frame = act->frame;

                if ( ( (act->pin & GNTPIN_hstw_mask) == 0 ) &&
                     ( (act->pin & GNTPIN_devw_mask) >  0 ) )
                {
                    clear_bit(_GTF_writing, &sha->flags);
                    put_page_type(&frame_table[frame]);
                }

                act->pin &= ~(GNTPIN_devw_mask | GNTPIN_devr_mask);

                if ( act->pin == 0 )
                {
                    clear_bit(_GTF_reading, &sha->flags);
                    map->ref_and_flags = 0;
                    put_page(&frame_table[frame]);
                }
                else
                    map->ref_and_flags &= ~GNTMAP_device_map;
            }

            spin_unlock(&rd->grant_table->lock);

            put_domain(rd);
        }
    }
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
        free_xenheap_pages((unsigned long)t->shared, ORDER_GRANT_FRAMES);
        free_xenheap_page((unsigned long)t->maptrack); //cwc22
        xfree(t->active);
        xfree(t);
    }
}

void
grant_table_init(
    void)
{
    /* Nothing. */
    DPRINTK("Grant table init\n");
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
