/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/mm.h>
#include <xeno/shadow.h>
#include <asm/domain_page.h>
#include <asm/page.h>

#ifdef CONFIG_SHADOW


#if SHADOW_DEBUG
#define MEM_VLOG(_f, _a...)                             \
  printk("DOM%llu: (file=shadow.c, line=%d) " _f "\n", \
         current->domain , __LINE__ , ## _a )
#else
#define MEM_VLOG(_f, _a...) 
#endif

#if 0
#define MEM_VVLOG(_f, _a...)                             \
  printk("DOM%llu: (file=shadow.c, line=%d) " _f "\n", \
         current->domain , __LINE__ , ## _a )
#else
#define MEM_VVLOG(_f, _a...) 
#endif


/********

To use these shadow page tables, guests must not rely on the ACCESSED
and DIRTY bits on L2 pte's being accurate -- they will typically all be set.

I doubt this will break anything. (If guests want to use the va_update
mechanism they've signed up for this anyhow...)

********/


pagetable_t shadow_mk_pagetable( unsigned long gptbase, 
					unsigned int shadowmode )
{
	unsigned long gpfn, spfn=0;

	MEM_VVLOG("shadow_mk_pagetable( gptbase=%08lx, mode=%d )",
			 gptbase, shadowmode );

	if ( unlikely(shadowmode) ) 
	{
		gpfn =  gptbase >> PAGE_SHIFT;
		
		if ( likely(frame_table[gpfn].shadow_and_flags & PSH_shadowed) )
		{
			spfn = frame_table[gpfn].shadow_and_flags & PSH_pfn_mask;
		}
		else
		{
			spfn = shadow_l2_table( gpfn );
		}      
	}

	return mk_pagetable(spfn << PAGE_SHIFT);
}

void unshadow_table( unsigned long gpfn, unsigned int type )
{
	unsigned long spfn;

    MEM_VLOG("unshadow_table type=%08x gpfn=%08lx, spfn=%08lx",
		 type,
		 gpfn,
		 frame_table[gpfn].shadow_and_flags & PSH_pfn_mask );

	perfc_incrc(unshadow_table_count);

	// this function is the same for both l1 and l2 tables

	// even in the SMP guest case, there won't be a race here as
    // this CPU was the one that cmpxchg'ed the page to invalid

	spfn = frame_table[gpfn].shadow_and_flags & PSH_pfn_mask;
	frame_table[gpfn].shadow_and_flags=0;
	frame_table[spfn].shadow_and_flags=0;

#if 0 // XXX leave as might be useful for later debugging
	{ 
		int i;
		unsigned long * spl1e = map_domain_mem( spfn<<PAGE_SHIFT );

		for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
	        {
				spl1e[i] = 0xdead0000;
			}
		unmap_domain_mem( spl1e );
	}
#endif

	if (type == PGT_l1_page_table)
		perfc_decr(shadow_l1_pages);
    else
		perfc_decr(shadow_l2_pages);

	//free_domain_page( &frame_table[spfn] );

	{
    unsigned long flags;
    spin_lock_irqsave(&free_list_lock, flags);
    list_add(&frame_table[spfn].list, &free_list);
    free_pfns++;
    spin_unlock_irqrestore(&free_list_lock, flags);
	}

}


unsigned long shadow_l2_table( unsigned long gpfn )
{
	struct pfn_info *spfn_info;
	unsigned long spfn;
	l2_pgentry_t *spl2e, *gpl2e;
	int i;

	MEM_VVLOG("shadow_l2_table( %08lx )",gpfn);

	perfc_incrc(shadow_l2_table_count);
	perfc_incr(shadow_l2_pages);

    // XXX in future, worry about racing in SMP guests 
    //      -- use cmpxchg with PSH_pending flag to show progress (and spin)

	spfn_info = alloc_domain_page( NULL ); // XXX account properly later 

    ASSERT( spfn_info ); // XXX deal with failure later e.g. blow cache

	spfn = (unsigned long) (spfn_info - frame_table);

	// mark pfn as being shadowed, update field to point at shadow
	frame_table[gpfn].shadow_and_flags = spfn | PSH_shadowed;

	// mark shadow pfn as being a shadow, update field to point at  pfn	
	frame_table[spfn].shadow_and_flags = gpfn | PSH_shadow;
	
	// we need to do this before the linear map is set up
	spl2e = (l2_pgentry_t *) map_domain_mem(spfn << PAGE_SHIFT);

	// get hypervisor and 2x linear PT mapings installed 
	memcpy(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
    spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((gpfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(frame_table[gpfn].u.domain->mm.perdomain_pt) | 
                      __PAGE_HYPERVISOR);

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
				frame_table[ gpte>>PAGE_SHIFT ].shadow_and_flags;

			if( s_sh & PSH_shadowed ) // PSH_shadowed
			{
				if ( unlikely( (frame_table[gpte>>PAGE_SHIFT].type_and_flags & PGT_type_mask) == PGT_l2_page_table) )
                {
					printk("Linear mapping detected\n");
  				    spte = gpte & ~_PAGE_RW;
                }
				else
                {
  				    spte = ( gpte & ~PAGE_MASK ) | (s_sh<<PAGE_SHIFT) |
						_PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED ;
				}
				// XXX should probably update guest to ACCESSED|DIRTY too...

		    }

		}
#endif

		spl2e[i] = mk_l2_pgentry( spte );

	}

	// its arguable we should 'preemptively shadow' a few active L1 pages
    // to avoid taking a string of faults when 'jacking' a running domain

    unmap_domain_mem( gpl2e );
    unmap_domain_mem( spl2e );

	MEM_VLOG("shadow_l2_table( %08lx -> %08lx)",gpfn,spfn);


	return spfn;
}


int shadow_fault( unsigned long va, long error_code )
{
	unsigned long gpte, spte;

	MEM_VVLOG("shadow_fault( va=%08lx, code=%ld )", va, error_code );

    check_pagetable( current->mm.pagetable, "pre-sf" );

	if ( unlikely(__get_user(gpte, (unsigned long*)&linear_pg_table[va>>PAGE_SHIFT])) )
	{
		MEM_VVLOG("shadow_fault - EXIT: read gpte faulted" );
		return 0;  // propagate to guest
	}

	if ( ! (gpte & _PAGE_PRESENT) )
	{
		MEM_VVLOG("shadow_fault - EXIT: gpte not present (%lx)",gpte );
		return 0;  // we're not going to be able to help
    }

    spte = gpte;

	if ( error_code & 2  )  
	{  // write fault
		if ( gpte & _PAGE_RW )
	    {
			gpte |= _PAGE_DIRTY | _PAGE_ACCESSED;
			spte |= _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED; 
            // (we're about to dirty it anyhow...)
		}
		else
		{   // write fault on RO page
            MEM_VVLOG("shadow_fault - EXIT: write fault on RO page (%lx)",gpte );
			return 0; // propagate to guest
			// not clear whether we should set accessed bit here...
		}
	}
	else
	{
		gpte |= _PAGE_ACCESSED;
        spte |= _PAGE_ACCESSED; // about to happen anyway
		if ( ! (gpte & _PAGE_DIRTY) ) 
			spte &= ~_PAGE_RW;  // force clear unless already dirty
	}

 	MEM_VVLOG("plan: gpte=%08lx  spte=%08lx", gpte, spte );

	// write back updated gpte
    // XXX watch out for read-only L2 entries! (not used in Linux)
	if ( unlikely( __put_user( gpte, (unsigned long*)&linear_pg_table[va>>PAGE_SHIFT])) )
		BUG();  // fixme!

    if ( unlikely( __put_user( spte, (unsigned long*)&shadow_linear_pg_table[va>>PAGE_SHIFT])) )
	{ 
		// failed:
        //  the L1 may not be shadowed, or the L2 entry may be insufficient

		unsigned long gpde, spde, gl1pfn, sl1pfn;

        MEM_VVLOG("3: not shadowed or l2 insufficient gpte=%08lx  spte=%08lx",gpte,spte );

        gpde = l2_pgentry_val(linear_l2_table[va>>L2_PAGETABLE_SHIFT]);

        gl1pfn = gpde>>PAGE_SHIFT;

        if ( ! (frame_table[gl1pfn].shadow_and_flags & PSH_shadowed ) )
        {
            // this L1 is NOT already shadowed so we need to shadow it
            struct pfn_info *sl1pfn_info;
            unsigned long *gpl1e, *spl1e;
            int i;
            sl1pfn_info = alloc_domain_page( NULL ); // XXX account properly! 
            sl1pfn = sl1pfn_info - frame_table;

            MEM_VVLOG("4a: l1 not shadowed ( %08lx )",sl1pfn);
	        perfc_incrc(shadow_l1_table_count);
	        perfc_incr(shadow_l1_pages);

            sl1pfn_info->shadow_and_flags = PSH_shadow | gl1pfn;
            frame_table[gl1pfn].shadow_and_flags = PSH_shadowed | sl1pfn;

            gpde = gpde | _PAGE_ACCESSED | _PAGE_DIRTY;
            spde = (gpde & ~PAGE_MASK) | _PAGE_RW | (sl1pfn<<PAGE_SHIFT);
        

            linear_l2_table[va>>L2_PAGETABLE_SHIFT] = mk_l2_pgentry(gpde);
            shadow_linear_l2_table[va>>L2_PAGETABLE_SHIFT] =  mk_l2_pgentry(spde);

            gpl1e = (unsigned long *) &(linear_pg_table[
                         (va>>PAGE_SHIFT) & ~(ENTRIES_PER_L1_PAGETABLE-1) ]);

            spl1e = (unsigned long *) &shadow_linear_pg_table[
                         (va>>PAGE_SHIFT) & ~(ENTRIES_PER_L1_PAGETABLE-1) ];


			// XXX can only do this is the shadow/guest is writeable
            // disable write protection if ! gpde & _PAGE_RW ????

            for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
	        {
#if SHADOW_OPTIMISE
                if ( (gpl1e[i] & (_PAGE_PRESENT|_PAGE_ACCESSED) ) == 
                                (_PAGE_PRESENT|_PAGE_ACCESSED) )
                {
                    spl1e[i] = gpl1e[i];
                    if ( !(gpl1e[i] & _PAGE_DIRTY) )
                        spl1e[i] &= ~_PAGE_RW;
                }
                else
#endif
                    spl1e[i] = 0;
            }


        }
        else
        {
            // this L1 was shadowed (by another PT) but we didn't have an L2
            // entry for it

            sl1pfn = frame_table[gl1pfn].shadow_and_flags & PSH_pfn_mask;

            MEM_VVLOG("4b: was shadowed, l2 missing ( %08lx )",sl1pfn);

		    spde = (gpde & ~PAGE_MASK) | (sl1pfn<<PAGE_SHIFT) | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY;

            gpde = gpde | _PAGE_ACCESSED | _PAGE_DIRTY;


			if ( unlikely( (sl1pfn<<PAGE_SHIFT) == (gl1pfn<<PAGE_SHIFT)  ) )
			{   // detect linear map, and keep pointing at guest
                MEM_VLOG("4c: linear mapping ( %08lx )",sl1pfn);
				spde = (spde & ~PAGE_MASK) | (gl1pfn<<PAGE_SHIFT);
			}

            linear_l2_table[va>>L2_PAGETABLE_SHIFT] = mk_l2_pgentry(gpde);
            shadow_linear_l2_table[va>>L2_PAGETABLE_SHIFT] = mk_l2_pgentry(spde);
			

        }              

    shadow_linear_pg_table[va>>PAGE_SHIFT] = mk_l1_pgentry(spte);
    // (we need to do the above even if we've just made the shadow L1)

    } // end of fixup writing the shadow L1 directly failed
    	
    perfc_incrc(shadow_fixup_count);

    check_pagetable( current->mm.pagetable, "post-sf" );

    return 1; // let's try the faulting instruction again...

}


void shadow_l1_normal_pt_update( unsigned long pa, unsigned long gpte,
                                 unsigned long *prev_spfn_ptr,
				 l1_pgentry_t **prev_spl1e_ptr )
{
    unsigned long gpfn, spfn, spte, prev_spfn = *prev_spfn_ptr;    
    l1_pgentry_t * spl1e, * prev_spl1e = *prev_spl1e_ptr;


MEM_VVLOG("shadow_l1_normal_pt_update pa=%08lx, gpte=%08lx, prev_spfn=%08lx, prev_spl1e=%08lx\n",
pa,gpte,prev_spfn, prev_spl1e);

    // to get here, we know the l1 page *must* be shadowed

    gpfn = pa >> PAGE_SHIFT;
    spfn = frame_table[gpfn].shadow_and_flags & PSH_pfn_mask;

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
	// XXX we assume only pagetables can be shadowed; this will have to change
	// to allow arbitrary CoW etc.

    spte = 0;

#if SHADOW_OPTIMISE
	if ( (gpte & (_PAGE_PRESENT|_PAGE_ACCESSED) ) == 
		 (_PAGE_PRESENT|_PAGE_ACCESSED) )
    {
        spte = gpte;
		if ( !(gpte & _PAGE_DIRTY ) )
			gpte &= ~ _PAGE_RW;
	}
#endif

	spl1e[(pa & ~PAGE_MASK) / sizeof(l1_pgentry_t) ] = 
		mk_l1_pgentry( spte );

	//unmap_domain_mem( (void *) spl1e );
}

void shadow_l2_normal_pt_update( unsigned long pa, unsigned long gpte )
{
    unsigned long gpfn, spfn, spte;
    l2_pgentry_t * sp2le;
    unsigned long s_sh;

    MEM_VVLOG("shadow_l2_normal_pt_update pa=%08lx, gpte=%08lx",pa,gpte);

    // to get here, we know the l2 page has a shadow

    gpfn = pa >> PAGE_SHIFT;
    spfn = frame_table[gpfn].shadow_and_flags & PSH_pfn_mask;

    sp2le = (l2_pgentry_t *) map_domain_mem( spfn << PAGE_SHIFT );
    // no real need for a cache here

    spte = 0;

    s_sh = frame_table[gpte >> PAGE_SHIFT].shadow_and_flags;
		
	if ( s_sh ) // PSH_shadowed
	{
		if ( unlikely( (frame_table[gpte>>PAGE_SHIFT].type_and_flags & PGT_type_mask) == PGT_l2_page_table) )
		{ 
            // linear page table case
			spte = (gpte & ~_PAGE_RW) | _PAGE_DIRTY | _PAGE_ACCESSED; 
	    }
	    else
			spte = (gpte & ~PAGE_MASK) | (s_sh<<PAGE_SHIFT) | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED;

	}

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

int check_pte( unsigned long gpte, unsigned long spte, int level, int i )
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
			FAIL("Linear map ???");			 // XXX this will fail on BSD

#if 0 // might be a RO mapping of a page table page
		if ( frame_table[gpfn].shadow_and_flags != 0 )
        {
			FAIL("Should have been shadowed g.sf=%08lx s.sf=%08lx", 
				 frame_table[gpfn].shadow_and_flags,
				 frame_table[spfn].shadow_and_flags);
        }
		else
#endif
			return 1;
	}
	else
	{
		if ( level < 2 )
			FAIL("Shadow in L1 entry?");

		if ( frame_table[gpfn].shadow_and_flags != (PSH_shadowed | spfn) )
			FAIL("spfn problem g.sf=%08lx s.sf=%08lx [g.sf]=%08lx [s.sf]=%08lx", 
				 frame_table[gpfn].shadow_and_flags,
				 frame_table[spfn].shadow_and_flags,
				 frame_table[frame_table[gpfn].shadow_and_flags&PSH_pfn_mask].shadow_and_flags,
				 frame_table[frame_table[spfn].shadow_and_flags&PSH_pfn_mask].shadow_and_flags
				 );

		if ( frame_table[spfn].shadow_and_flags != (PSH_shadow | gpfn) )
			FAIL("gpfn problem g.sf=%08lx s.sf=%08lx", 
				 frame_table[gpfn].shadow_and_flags,
				 frame_table[spfn].shadow_and_flags);

	}

	return 1;
}


int check_l1_table( unsigned long va, unsigned long g2, unsigned long s2 )
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
		
		check_pte( gpte, spte, 1, j );
	}
	
	unmap_domain_mem( spl1e );
	unmap_domain_mem( gpl1e );

	return 1;
}

#define FAILPT(_f, _a...)                             \
{printk("XXX FAIL %s-PT" _f "\n", s, ## _a ); BUG();}

int check_pagetable( pagetable_t pt, char *s )
{
	unsigned long gptbase = pagetable_val(pt);
	unsigned long gpfn, spfn;
	int i;
	l2_pgentry_t *gpl2e, *spl2e;

	sh_check_name = s;

    MEM_VVLOG("%s-PT Audit",s);

	sh_l2_present = sh_l1_present = 0;

	gpfn =  gptbase >> PAGE_SHIFT;

	if ( ! (frame_table[gpfn].shadow_and_flags & PSH_shadowed) )
	{
		printk("%s-PT %08lx not shadowed\n", s, gptbase);

		if( frame_table[gpfn].shadow_and_flags != 0 ) BUG();

		return 0;
	}
	
    spfn = frame_table[gpfn].shadow_and_flags & PSH_pfn_mask;

	if ( ! frame_table[gpfn].shadow_and_flags == (PSH_shadowed | spfn) )
		FAILPT("ptbase shadow inconsistent1");

	if ( ! frame_table[spfn].shadow_and_flags == (PSH_shadow | gpfn) )
		FAILPT("ptbase shadow inconsistent2");

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
		  ((__pa(frame_table[gpfn].u.domain->mm.perdomain_pt) | __PAGE_HYPERVISOR))) )
		FAILPT("hypervisor per-domain map inconsistent");


	// check the whole L2
	for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
	{
		unsigned long gpte = l2_pgentry_val(gpl2e[i]);
		unsigned long spte = l2_pgentry_val(spl2e[i]);

		check_pte( gpte, spte, 2, i );
	}


	// go back and recurse
	for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
	{
		unsigned long gpte = l2_pgentry_val(gpl2e[i]);
		unsigned long spte = l2_pgentry_val(spl2e[i]);

		if ( spte )	   
			check_l1_table( 
				i<<L2_PAGETABLE_SHIFT,
				gpte>>PAGE_SHIFT, spte>>PAGE_SHIFT );

	}

	unmap_domain_mem( spl2e );
	unmap_domain_mem( gpl2e );

	MEM_VVLOG("PT verified : l2_present = %d, l1_present = %d\n",
		   sh_l2_present, sh_l1_present );
	
	return 1;
}


#endif


#endif // CONFIG_SHADOW



