/* -*-  Mode:C++; c-file-style:BSD; c-basic-offset:4; tab-width:4 -*- */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/shadow.h>
#include <asm/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/trace.h>


/********

To use these shadow page tables, guests must not rely on the ACCESSED
and DIRTY bits on L2 pte's being accurate -- they will typically all be set.

I doubt this will break anything. (If guests want to use the va_update
mechanism they've signed up for this anyhow...)

There's a per-domain shadow table spin lock which works fine for SMP
hosts. We don't have to worry about interrupts as no shadow operations
happen in an interrupt context. It's probably not quite ready for SMP
guest operation as we have to worry about synchonisation between gpte
and spte updates. Its possible that this might only happen in a
hypercall context, in which case we'll probably at have a per-domain
hypercall lock anyhow (at least initially).

********/


static inline void free_shadow_page(struct mm_struct *m, 
                                    struct pfn_info *page)
{
    unsigned long type = page->u.inuse.type_info & PGT_type_mask;

    m->shadow_page_count--;

    if (type == PGT_l1_page_table)
        perfc_decr(shadow_l1_pages);
    else if (type == PGT_l2_page_table)
        perfc_decr(shadow_l2_pages);
    else printk("Free shadow weird page type pfn=%08x type=%08x\n",
                frame_table-page, page->u.inuse.type_info);
    
    free_domheap_page(page);
}

static void __free_shadow_table( struct mm_struct *m )
{
    int j, free=0;
    struct shadow_status *a,*next;
 
    // the code assumes you're not using the page tables i.e.
    // the domain is stopped and cr3 is something else!!

    // walk the hash table and call free_shadow_page on all pages

    shadow_audit(m,1);

    for(j=0;j<shadow_ht_buckets;j++)
    {
        a = &m->shadow_ht[j];        
        if (a->pfn)
        {
            free_shadow_page( m, 
                              &frame_table[a->spfn_and_flags & PSH_pfn_mask] );
            a->pfn = 0;
            a->spfn_and_flags = 0;
            free++;
        }
        next=a->next;
        a->next=NULL;
        a=next;
        while(a)
        { 
            struct shadow_status *next = a->next;

            free_shadow_page( m, 
                              &frame_table[a->spfn_and_flags & PSH_pfn_mask] );
            a->pfn = 0;
            a->spfn_and_flags = 0;
            free++;
            a->next = m->shadow_ht_free;           
            m->shadow_ht_free = a;
            a=next;
        }
        shadow_audit(m,0);
    }
    SH_LOG("Free shadow table. Freed= %d",free);
}


#define TABLE_OP_ZERO_L2 1
#define TABLE_OP_ZERO_L1 2
#define TABLE_OP_FREE_L1 3

static inline int shadow_page_op( struct mm_struct *m, unsigned int op, 
								  unsigned int gpfn,
                                  struct pfn_info *spfn_info, int *work )
{
    unsigned int spfn = spfn_info-frame_table;
	int restart = 0;

    switch( op )
    {
	case TABLE_OP_ZERO_L2:
	{
		if ( (spfn_info->u.inuse.type_info & PGT_type_mask) == 
             PGT_l2_page_table )
		{
			unsigned long * spl1e = map_domain_mem( spfn<<PAGE_SHIFT );
#ifdef __i386__
			memset(spl1e, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE * sizeof(*spl1e));
#endif
			unmap_domain_mem( spl1e );
		}
    }
	break;
	
	case TABLE_OP_ZERO_L1:
	{
		if ( (spfn_info->u.inuse.type_info & PGT_type_mask) == 
             PGT_l1_page_table )
		{
			unsigned long * spl1e = map_domain_mem( spfn<<PAGE_SHIFT );
			memset( spl1e, 0, ENTRIES_PER_L1_PAGETABLE * sizeof(*spl1e) );
			unmap_domain_mem( spl1e );
		}
    }
	break;

	case TABLE_OP_FREE_L1:
	{
		if ( (spfn_info->u.inuse.type_info & PGT_type_mask) == 
             PGT_l1_page_table )
		{
			// lock is already held
			delete_shadow_status( m, gpfn );
			restart = 1; // we need to go to start of list again
		}
    }

	break;
	
	default:
		BUG();

    }
    return restart;
}

static void __scan_shadow_table( struct mm_struct *m, unsigned int op )
{
    int j, work=0;
    struct shadow_status *a, *next;
 
    // the code assumes you're not using the page tables i.e.
    // the domain is stopped and cr3 is something else!!

    // walk the hash table and call free_shadow_page on all pages

    shadow_audit(m,1);

    for(j=0;j<shadow_ht_buckets;j++)
    {
	retry:
        a = &m->shadow_ht[j];     
		next = a->next;
        if (a->pfn)
        {
            if ( shadow_page_op( m, op, a->pfn,								 
								 &frame_table[a->spfn_and_flags & PSH_pfn_mask], 
								 &work ) )
				goto retry;
        }
        a=next;
        while(a)
        { 
			next = a->next;
            if ( shadow_page_op( m, op, a->pfn,
								 &frame_table[a->spfn_and_flags & PSH_pfn_mask],
								 &work ) )
				goto retry;
            a=next;
        }
        shadow_audit(m,0);
    }
    SH_VLOG("Scan shadow table. Work=%d l1=%d l2=%d", work, perfc_value(shadow_l1_pages), perfc_value(shadow_l2_pages));
}


void shadow_mode_init(void)
{
}

int shadow_mode_enable( struct domain *p, unsigned int mode )
{
    struct mm_struct *m = &p->mm;
    struct shadow_status **fptr;
    int i;

    // allocate hashtable
    m->shadow_ht = xmalloc(shadow_ht_buckets * 
                           sizeof(struct shadow_status));
    if( m->shadow_ht == NULL )
        goto nomem;

    memset(m->shadow_ht, 0, shadow_ht_buckets * sizeof(struct shadow_status));

    // allocate space for first lot of extra nodes
    m->shadow_ht_extras = xmalloc(sizeof(void*) + 
                                  (shadow_ht_extra_size * 
                                   sizeof(struct shadow_status)));
    if( m->shadow_ht_extras == NULL )
        goto nomem;

    memset( m->shadow_ht_extras, 0, sizeof(void*) + (shadow_ht_extra_size * 
                                                     sizeof(struct shadow_status)) );

    m->shadow_extras_count++;
 
    // add extras to free list
    fptr = &m->shadow_ht_free;
    for ( i=0; i<shadow_ht_extra_size; i++ )
    {
        *fptr = &m->shadow_ht_extras[i];
        fptr = &(m->shadow_ht_extras[i].next);
    }
    *fptr = NULL;
    *((struct shadow_status ** ) 
      &m->shadow_ht_extras[shadow_ht_extra_size]) = NULL;

    if ( mode == SHM_logdirty )
    {
        m->shadow_dirty_bitmap_size = (p->max_pages+63)&(~63);
        m->shadow_dirty_bitmap = 
            xmalloc( m->shadow_dirty_bitmap_size/8);
        if( m->shadow_dirty_bitmap == NULL )
        {
            m->shadow_dirty_bitmap_size = 0;
			BUG();
            goto nomem;
        }
        memset(m->shadow_dirty_bitmap,0,m->shadow_dirty_bitmap_size/8);
    }

    m->shadow_mode = mode;

    // call shadow_mk_pagetable
    __shadow_mk_pagetable( m );
    return 0;

nomem:
    if( m->shadow_ht ) {
		xfree( m->shadow_ht ); m->shadow_ht = NULL; };

    if( m->shadow_ht_extras )  {
		xfree( m->shadow_ht_extras ); m->shadow_ht_extras = NULL; };

    return -ENOMEM;
}

void __shadow_mode_disable(struct domain *d)
{
    struct mm_struct *m = &d->mm;
    struct shadow_status *next;

    __free_shadow_table(m);
    m->shadow_mode = 0;

    SH_VLOG("freed tables count=%d l1=%d l2=%d",
           m->shadow_page_count, perfc_value(shadow_l1_pages), 
           perfc_value(shadow_l2_pages));

    next = m->shadow_ht_extras;
    while ( next )
    {
        struct shadow_status * this = next;
        m->shadow_extras_count--;
        next = *((struct shadow_status **)(&next[shadow_ht_extra_size]));
        xfree(this);
    }

    SH_LOG("freed extras, now %d", m->shadow_extras_count);

    if ( m->shadow_dirty_bitmap  )
    {
        xfree( m->shadow_dirty_bitmap );
        m->shadow_dirty_bitmap = 0;
        m->shadow_dirty_bitmap_size = 0;
    }

    // free the hashtable itself
    xfree( m->shadow_ht );

	m->shadow_ht = NULL;
	m->shadow_ht_extras = NULL;
}

static int shadow_mode_table_op(struct domain *d, 
							    dom0_shadow_control_t *sc)
{
    unsigned int op = sc->op;
    struct mm_struct *m = &d->mm;
    int rc = 0;

    // since Dom0 did the hypercall, we should be running with it's page
    // tables right now. Calling flush on yourself would be really
    // stupid.

    ASSERT(spin_is_locked(&d->mm.shadow_lock));

    if ( m == &current->mm )
    {
        printk("Don't try and flush your own page tables!\n");
        return -EINVAL;
    }
   
    SH_VLOG("shadow mode table op %08lx %08lx count %d",pagetable_val( m->pagetable),pagetable_val(m->shadow_table), m->shadow_page_count);

    shadow_audit(m,1);

    switch(op)
    {
    case DOM0_SHADOW_CONTROL_OP_FLUSH:
        __free_shadow_table( m );  
        break;
   
    case DOM0_SHADOW_CONTROL_OP_CLEAN:   // zero all-non hypervisor
	{
		__scan_shadow_table( m, TABLE_OP_ZERO_L2 );
		__scan_shadow_table( m, TABLE_OP_ZERO_L1 );

		goto send_bitmap;
	}
		

    case DOM0_SHADOW_CONTROL_OP_CLEAN2:  // zero all L2, free L1s
    {
		int i,j,zero=1;
		
		__scan_shadow_table( m, TABLE_OP_ZERO_L2 );
		__scan_shadow_table( m, TABLE_OP_FREE_L1 );
		
	send_bitmap:
		sc->stats.fault_count       = d->mm.shadow_fault_count;
		sc->stats.dirty_count       = d->mm.shadow_dirty_count;
		sc->stats.dirty_net_count   = d->mm.shadow_dirty_net_count;
		sc->stats.dirty_block_count = d->mm.shadow_dirty_block_count;

		d->mm.shadow_fault_count       = 0;
		d->mm.shadow_dirty_count       = 0;
		d->mm.shadow_dirty_net_count   = 0;
		d->mm.shadow_dirty_block_count = 0;
	
		sc->pages = d->max_pages;

		if( d->max_pages > sc->pages || 
			!sc->dirty_bitmap || !d->mm.shadow_dirty_bitmap )
		{
			rc = -EINVAL;
			goto out;
		}

	
#define chunk (8*1024) // do this in 1KB chunks for L1 cache
	
		for(i=0;i<d->max_pages;i+=chunk)
		{
			int bytes = ((  ((d->max_pages-i) > (chunk))?
							(chunk):(d->max_pages-i) ) + 7) / 8;
	    
			copy_to_user( sc->dirty_bitmap + (i/(8*sizeof(unsigned long))),
						  d->mm.shadow_dirty_bitmap +(i/(8*sizeof(unsigned long))),
						  bytes );
	    
			for(j=0; zero && j<bytes/sizeof(unsigned long);j++)
			{
				if( d->mm.shadow_dirty_bitmap[j] != 0 )
					zero = 0;
			}

			memset( d->mm.shadow_dirty_bitmap +(i/(8*sizeof(unsigned long))),
					0, bytes);
		}

#if 0   /* This optimisation is dangerous for some uses of this function.
		 disable for the moment */
        /* Might as well stop the domain as an optimization. */
		if ( zero )
            domain_pause_by_systemcontroller(d);
#endif

		break;
    }

    case DOM0_SHADOW_CONTROL_OP_PEEK:
    {
		int i;

		sc->stats.fault_count       = d->mm.shadow_fault_count;
		sc->stats.dirty_count       = d->mm.shadow_dirty_count;
		sc->stats.dirty_net_count   = d->mm.shadow_dirty_net_count;
		sc->stats.dirty_block_count = d->mm.shadow_dirty_block_count;
	
		if( d->max_pages > sc->pages || 
			!sc->dirty_bitmap || !d->mm.shadow_dirty_bitmap )
		{
			rc = -EINVAL;
			goto out;
		}
	
		sc->pages = d->max_pages;
	
#define chunk (8*1024) // do this in 1KB chunks for L1 cache
	
		for(i=0;i<d->max_pages;i+=chunk)
		{
			int bytes = ((  ((d->max_pages-i) > (chunk))?
							(chunk):(d->max_pages-i) ) + 7) / 8;
	    
			copy_to_user( sc->dirty_bitmap + (i/(8*sizeof(unsigned long))),
						  d->mm.shadow_dirty_bitmap +(i/(8*sizeof(unsigned long))),
						  bytes );	    
		}

		break;
    }

	default:
		BUG();

    }


out:

    SH_VLOG("shadow mode table op : page count %d", m->shadow_page_count);

    shadow_audit(m,1);

    // call shadow_mk_pagetable
    __shadow_mk_pagetable( m );

    return rc;
}

int shadow_mode_control(struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int cmd = sc->op;
    int rc = 0;

    domain_pause(d);
    synchronise_pagetables(~0UL);

    shadow_lock(&d->mm);

    if ( cmd == DOM0_SHADOW_CONTROL_OP_OFF )
    {
        shadow_mode_disable(d);
    }
    else if ( cmd == DOM0_SHADOW_CONTROL_OP_ENABLE_TEST )
    {
        shadow_mode_disable(d);
        rc = shadow_mode_enable(d, SHM_test);
    } 
    else if ( cmd == DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY )
    {
        shadow_mode_disable(d);
        rc = shadow_mode_enable(d, SHM_logdirty);
    } 
    else if ( shadow_mode(d) && 
              (cmd >= DOM0_SHADOW_CONTROL_OP_FLUSH) && 
              (cmd <= DOM0_SHADOW_CONTROL_OP_CLEAN2) )
    {
        rc = shadow_mode_table_op(d, sc);
    }
    else
    {
        rc = -EINVAL;
    }

    shadow_unlock(&d->mm);

    domain_unpause(d);

    return rc;
}

static inline struct pfn_info *alloc_shadow_page(struct mm_struct *m)
{
	struct pfn_info *page;
    m->shadow_page_count++;
    page = alloc_domheap_page(NULL);

	if( unlikely(page == NULL) )
	{
		printk("Couldn't alloc shadow page! count=%d\n",
			   m->shadow_page_count);
		SH_VLOG("Shadow tables l1=%d l2=%d",
				perfc_value(shadow_l1_pages), 
				perfc_value(shadow_l2_pages));
		BUG();  // FIXME: try a shadow flush to free up some memory
	}

	return page;
}

void unshadow_table( unsigned long gpfn, unsigned int type )
{
    unsigned long spfn;
	struct domain *d = frame_table[gpfn].u.inuse.domain;

    SH_VLOG("unshadow_table type=%08x gpfn=%08lx",
            type,
            gpfn );

    perfc_incrc(unshadow_table_count);

    // this function is the same for both l1 and l2 tables

    // even in the SMP guest case, there won't be a race here as
    // this CPU was the one that cmpxchg'ed the page to invalid

    spfn = __shadow_status(&d->mm, gpfn) & PSH_pfn_mask;

    delete_shadow_status(&d->mm, gpfn);

    free_shadow_page(&d->mm, &frame_table[spfn] );

}


unsigned long shadow_l2_table( 
    struct mm_struct *m, unsigned long gpfn )
{
    struct pfn_info *spfn_info;
    unsigned long spfn;
    l2_pgentry_t *spl2e, *gpl2e;
    int i;

    SH_VVLOG("shadow_l2_table( %08lx )",gpfn);

    perfc_incrc(shadow_l2_table_count);

    // XXX in future, worry about racing in SMP guests 
    //      -- use cmpxchg with PSH_pending flag to show progress (and spin)

    spfn_info = alloc_shadow_page(m);

    ASSERT( spfn_info ); // XXX deal with failure later e.g. blow cache

    spfn_info->u.inuse.type_info = PGT_l2_page_table;
    perfc_incr(shadow_l2_pages);

    spfn = (unsigned long) (spfn_info - frame_table);

    // mark pfn as being shadowed, update field to point at shadow
    set_shadow_status(m, gpfn, spfn | PSH_shadowed);
 
    // we need to do this before the linear map is set up
    spl2e = (l2_pgentry_t *) map_domain_mem(spfn << PAGE_SHIFT);

#ifdef __i386__
    // get hypervisor and 2x linear PT mapings installed 
    memcpy(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
    spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((gpfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(frame_table[gpfn].u.inuse.domain->mm.perdomain_pt) | 
                      __PAGE_HYPERVISOR);
#endif

    // can't use the linear map as we may not be in the right PT
    gpl2e = (l2_pgentry_t *) map_domain_mem(gpfn << PAGE_SHIFT);

    // proactively create entries for pages that are already shadowed
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        unsigned long spte = 0;

#if 0  // Turns out this doesn't really help
        unsigned long gpte;

        gpte = l2_pgentry_val(gpl2e[i]);

        if (gpte & _PAGE_PRESENT)
        {
            unsigned long s_sh = 
                __shadow_status(p, gpte>>PAGE_SHIFT);

            l2pde_general( m, &gpte, &spte, s_sh );

        }
#endif

        spl2e[i] = mk_l2_pgentry( spte );

    }

    // its arguable we should 'preemptively shadow' a few active L1 pages
    // to avoid taking a string of faults when 'jacking' a running domain

    unmap_domain_mem( gpl2e );
    unmap_domain_mem( spl2e );

    SH_VLOG("shadow_l2_table( %08lx -> %08lx)",gpfn,spfn);

    return spfn;
}


int shadow_fault( unsigned long va, long error_code )
{
    unsigned long gpte, spte;
    struct mm_struct *m = &current->mm;

    SH_VVLOG("shadow_fault( va=%08lx, code=%ld )", va, error_code );

    check_pagetable( current, current->mm.pagetable, "pre-sf" );

    if ( unlikely(__get_user(gpte, (unsigned long*)&linear_pg_table[va>>PAGE_SHIFT])) )
    {
        SH_VVLOG("shadow_fault - EXIT: read gpte faulted" );
        return 0;  // propagate to guest
    }

    if ( ! (gpte & _PAGE_PRESENT) )
    {
        SH_VVLOG("shadow_fault - EXIT: gpte not present (%lx)",gpte );
        return 0;  // we're not going to be able to help
    }

    if ( (error_code & 2)  && ! (gpte & _PAGE_RW) )
    {
        // write fault on RO page
        return 0;
    }

    // take the lock and reread gpte

    shadow_lock(m);
	
    if ( unlikely(__get_user(gpte, (unsigned long*)&linear_pg_table[va>>PAGE_SHIFT])) )
    {
        SH_VVLOG("shadow_fault - EXIT: read gpte faulted" );
        shadow_unlock(m);
        return 0;  // propagate to guest
    }

    if ( unlikely(!(gpte & _PAGE_PRESENT)) )
    {
        SH_VVLOG("shadow_fault - EXIT: gpte not present (%lx)",gpte );
        shadow_unlock(m);
        return 0;  // we're not going to be able to help
    }

    if ( error_code & 2  )  
    {  // write fault
        if ( likely(gpte & _PAGE_RW) )
        {
            l1pte_write_fault( m, &gpte, &spte );
        }
        else
        {   // write fault on RO page
            SH_VVLOG("shadow_fault - EXIT: write fault on RO page (%lx)",gpte );
            shadow_unlock(m);
            return 0; // propagate to guest
            // not clear whether we should set accessed bit here...
        }
    }
    else
    {
        l1pte_read_fault( m, &gpte, &spte );
    }

    SH_VVLOG("plan: gpte=%08lx  spte=%08lx", gpte, spte );

    // write back updated gpte
    // XXX watch out for read-only L2 entries! (not used in Linux)
    if ( unlikely( __put_user( gpte, (unsigned long*)&linear_pg_table[va>>PAGE_SHIFT])) )
        domain_crash();  // fixme!

    if ( unlikely( __put_user( spte, (unsigned long*)&shadow_linear_pg_table[va>>PAGE_SHIFT])) )
    { 
        // failed:
        //  the L1 may not be shadowed, or the L2 entry may be insufficient

        unsigned long gpde, spde, gl1pfn, sl1pfn, sl1ss;

        SH_VVLOG("3: not shadowed or l2 insufficient gpte=%08lx  spte=%08lx",gpte,spte );

        gpde = l2_pgentry_val(linear_l2_table[va>>L2_PAGETABLE_SHIFT]);

        gl1pfn = gpde>>PAGE_SHIFT;

        sl1ss = __shadow_status(&current->mm, gl1pfn);
        if ( ! (sl1ss & PSH_shadowed) )
        {
            // this L1 is NOT already shadowed so we need to shadow it
            struct pfn_info *sl1pfn_info;
            unsigned long *gpl1e, *spl1e;
            int i;
            sl1pfn_info = alloc_shadow_page( &current->mm ); 
            sl1pfn_info->u.inuse.type_info = PGT_l1_page_table;
			
            sl1pfn = sl1pfn_info - frame_table;

            SH_VVLOG("4a: l1 not shadowed ( %08lx )",sl1pfn);
            perfc_incrc(shadow_l1_table_count);
            perfc_incr(shadow_l1_pages);

            set_shadow_status(&current->mm, gl1pfn, PSH_shadowed | sl1pfn);

            l2pde_general( m, &gpde, &spde, sl1pfn );

            linear_l2_table[va>>L2_PAGETABLE_SHIFT] = mk_l2_pgentry(gpde);
            shadow_linear_l2_table[va>>L2_PAGETABLE_SHIFT] =  mk_l2_pgentry(spde);

            gpl1e = (unsigned long *) &(linear_pg_table[
                (va>>PAGE_SHIFT) & ~(ENTRIES_PER_L1_PAGETABLE-1) ]);

            spl1e = (unsigned long *) &shadow_linear_pg_table[
                (va>>PAGE_SHIFT) & ~(ENTRIES_PER_L1_PAGETABLE-1) ];


            for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
            {
                l1pte_no_fault( m, &gpl1e[i], &spl1e[i] );
            }


        }
        else
        {
            // this L1 was shadowed (by another PT) but we didn't have an L2
            // entry for it

            SH_VVLOG("4b: was shadowed, l2 missing ( %08lx )",sl1pfn);

            sl1pfn = sl1ss & PSH_pfn_mask;
            l2pde_general( m, &gpde, &spde, sl1pfn );

            linear_l2_table[va>>L2_PAGETABLE_SHIFT] = mk_l2_pgentry(gpde);
            shadow_linear_l2_table[va>>L2_PAGETABLE_SHIFT] = mk_l2_pgentry(spde);
   
        }              

        shadow_linear_pg_table[va>>PAGE_SHIFT] = mk_l1_pgentry(spte);
        // (we need to do the above even if we've just made the shadow L1)

    } // end of fixup writing the shadow L1 directly failed
     
    perfc_incrc(shadow_fixup_count);

	m->shadow_fault_count++;

    check_pagetable( current, current->mm.pagetable, "post-sf" );

    shadow_unlock(m);

    return 1; // let's try the faulting instruction again...

}


void shadow_l1_normal_pt_update( unsigned long pa, unsigned long gpte,
                                 unsigned long *prev_spfn_ptr,
                                 l1_pgentry_t **prev_spl1e_ptr )
{
    unsigned long gpfn, spfn, spte, prev_spfn = *prev_spfn_ptr;    
    l1_pgentry_t * spl1e, * prev_spl1e = *prev_spl1e_ptr;


    SH_VVLOG("shadow_l1_normal_pt_update pa=%08lx, gpte=%08lx, prev_spfn=%08lx, prev_spl1e=%p\n",
             pa,gpte,prev_spfn, prev_spl1e);

    // to get here, we know the l1 page *must* be shadowed

    gpfn = pa >> PAGE_SHIFT;
    spfn = __shadow_status(&current->mm, gpfn) & PSH_pfn_mask;

    if ( spfn == prev_spfn )
    {
        spl1e = prev_spl1e;
    }
    else
    {
        if( prev_spl1e ) unmap_domain_mem( prev_spl1e );
        spl1e = (l1_pgentry_t *) map_domain_mem( spfn << PAGE_SHIFT );
        *prev_spfn_ptr  = spfn;
        *prev_spl1e_ptr = spl1e;
    }

    // XXX we assume only pagetables can be shadowed; 
    // this will have to change to allow arbitrary CoW etc.

    l1pte_no_fault( &current->mm, &gpte, &spte );


    spl1e[(pa & ~PAGE_MASK) / sizeof(l1_pgentry_t) ] = mk_l1_pgentry( spte );

}

void shadow_l2_normal_pt_update( unsigned long pa, unsigned long gpte )
{
    unsigned long gpfn, spfn, spte;
    l2_pgentry_t * sp2le;
    unsigned long s_sh=0;

    SH_VVLOG("shadow_l2_normal_pt_update pa=%08lx, gpte=%08lx",pa,gpte);

    // to get here, we know the l2 page has a shadow

    gpfn = pa >> PAGE_SHIFT;
    spfn = __shadow_status(&current->mm, gpfn) & PSH_pfn_mask;


    spte = 0;

    if( gpte & _PAGE_PRESENT )
        s_sh = __shadow_status(&current->mm, gpte >> PAGE_SHIFT);

    sp2le = (l2_pgentry_t *) map_domain_mem( spfn << PAGE_SHIFT );
    // no real need for a cache here

    l2pde_general( &current->mm, &gpte, &spte, s_sh );

    // XXXX Should mark guest pte as DIRTY and ACCESSED too!!!!!

    sp2le[(pa & ~PAGE_MASK) / sizeof(l2_pgentry_t) ] = 
        mk_l2_pgentry( spte );

    unmap_domain_mem( (void *) sp2le );
}


#if SHADOW_DEBUG

static int sh_l2_present;
static int sh_l1_present;
char * sh_check_name;

#define FAIL(_f, _a...)                             \
{printk("XXX %s-FAIL (%d,%d)" _f " g=%08lx s=%08lx\n",  sh_check_name, level, i, ## _a , gpte, spte ); BUG();}

static int check_pte( struct mm_struct *m, 
                      unsigned long gpte, unsigned long spte, int level, int i )
{
    unsigned long mask, gpfn, spfn;

    if ( spte == 0 || spte == 0xdeadface || spte == 0x00000E00)
        return 1;  // always safe

    if ( !(spte & _PAGE_PRESENT) )
        FAIL("Non zero not present spte");

    if( level == 2 ) sh_l2_present++;
    if( level == 1 ) sh_l1_present++;

    if ( !(gpte & _PAGE_PRESENT) )
        FAIL("Guest not present yet shadow is");

    mask = ~(_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW|0xFFFFF000);

    if ( (spte & mask) != (gpte & mask ) )
        FAIL("Corrupt?");

    if ( (spte & _PAGE_DIRTY ) && !(gpte & _PAGE_DIRTY) )
        FAIL("Dirty coherence");

    if ( (spte & _PAGE_ACCESSED ) && !(gpte & _PAGE_ACCESSED) )
        FAIL("Accessed coherence");

    if ( (spte & _PAGE_RW ) && !(gpte & _PAGE_RW) )
        FAIL("RW coherence");

    if ( (spte & _PAGE_RW ) && !((gpte & _PAGE_RW) && (gpte & _PAGE_DIRTY) ))
        FAIL("RW2 coherence");
 
    spfn = spte>>PAGE_SHIFT;
    gpfn = gpte>>PAGE_SHIFT;

    if ( gpfn == spfn )
    {
        if ( level > 1 )
            FAIL("Linear map ???");    // XXX this will fail on BSD

        return 1;
    }
    else
    {
        if ( level < 2 )
            FAIL("Shadow in L1 entry?");

        if ( __shadow_status(p, gpfn) != (PSH_shadowed | spfn) )
            FAIL("spfn problem g.sf=%08lx", 
                 __shadow_status(p, gpfn) );
    }

    return 1;
}


static int check_l1_table( struct mm_struct *m, unsigned long va, 
                           unsigned long g2, unsigned long s2 )
{
    int j;
    unsigned long *gpl1e, *spl1e;

    //gpl1e = (unsigned long *) &(linear_pg_table[ va>>PAGE_SHIFT]);
    //spl1e = (unsigned long *) &(shadow_linear_pg_table[ va>>PAGE_SHIFT]);

    gpl1e = map_domain_mem( g2<<PAGE_SHIFT );
    spl1e = map_domain_mem( s2<<PAGE_SHIFT );

    for ( j = 0; j < ENTRIES_PER_L1_PAGETABLE; j++ )
    {
        unsigned long gpte = gpl1e[j];
        unsigned long spte = spl1e[j];
  
        check_pte( p, gpte, spte, 1, j );
    }
 
    unmap_domain_mem( spl1e );
    unmap_domain_mem( gpl1e );

    return 1;
}

#define FAILPT(_f, _a...)                             \
{printk("XXX FAIL %s-PT" _f "\n", s, ## _a ); BUG();}

int check_pagetable( struct mm_struct *m, pagetable_t pt, char *s )
{
    unsigned long gptbase = pagetable_val(pt);
    unsigned long gpfn, spfn;
    int i;
    l2_pgentry_t *gpl2e, *spl2e;

    sh_check_name = s;

    SH_VVLOG("%s-PT Audit",s);

    sh_l2_present = sh_l1_present = 0;

    gpfn =  gptbase >> PAGE_SHIFT;

    if ( ! (__shadow_status(p, gpfn) & PSH_shadowed) )
    {
        printk("%s-PT %08lx not shadowed\n", s, gptbase);

        if( __shadow_status(p, gpfn) != 0 ) BUG();

        return 0;
    }
 
    spfn = __shadow_status(p, gpfn) & PSH_pfn_mask;

    if ( ! __shadow_status(p, gpfn) == (PSH_shadowed | spfn) )
        FAILPT("ptbase shadow inconsistent1");

    gpl2e = (l2_pgentry_t *) map_domain_mem( gpfn << PAGE_SHIFT );
    spl2e = (l2_pgentry_t *) map_domain_mem( spfn << PAGE_SHIFT );

    //ipl2e = (l2_pgentry_t *) map_domain_mem( spfn << PAGE_SHIFT );


    if ( memcmp( &spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
                 &gpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
                 ((SH_LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT))-DOMAIN_ENTRIES_PER_L2_PAGETABLE)
                 * sizeof(l2_pgentry_t)) )
    {
        printk("gpfn=%08lx spfn=%08lx\n", gpfn, spfn);
        for (i=DOMAIN_ENTRIES_PER_L2_PAGETABLE; 
             i<(SH_LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT));
             i++ )
            printk("+++ (%d) %08lx %08lx\n",i,
                   l2_pgentry_val(gpl2e[i]), l2_pgentry_val(spl2e[i]) );
        FAILPT("hypervisor entries inconsistent");
    }

    if ( (l2_pgentry_val(spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT]) != 
          l2_pgentry_val(gpl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT])) )
        FAILPT("hypervisor linear map inconsistent");

    if ( (l2_pgentry_val(spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT]) != 
          ((spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR)) )
        FAILPT("hypervisor shadow linear map inconsistent %08lx %08lx",
               l2_pgentry_val(spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT]),
               (spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR
            );

    if ( (l2_pgentry_val(spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT]) !=
          ((__pa(frame_table[gpfn].u.inuse.domain->mm.perdomain_pt) | __PAGE_HYPERVISOR))) )
        FAILPT("hypervisor per-domain map inconsistent");


    // check the whole L2
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        unsigned long gpte = l2_pgentry_val(gpl2e[i]);
        unsigned long spte = l2_pgentry_val(spl2e[i]);

        check_pte( p, gpte, spte, 2, i );
    }


    // go back and recurse
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        unsigned long gpte = l2_pgentry_val(gpl2e[i]);
        unsigned long spte = l2_pgentry_val(spl2e[i]);

        if ( spte )    
            check_l1_table( p,
                            i<<L2_PAGETABLE_SHIFT,
                            gpte>>PAGE_SHIFT, spte>>PAGE_SHIFT );

    }

    unmap_domain_mem( spl2e );
    unmap_domain_mem( gpl2e );

    SH_VVLOG("PT verified : l2_present = %d, l1_present = %d\n",
             sh_l2_present, sh_l1_present );
 
    return 1;
}


#endif
