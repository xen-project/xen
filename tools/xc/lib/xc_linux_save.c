/******************************************************************************
 * xc_linux_save.c
 * 
 * Save the state of a running Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include <asm-xen/suspend.h>

#define BATCH_SIZE 1024   /* 1024 pages (4MB) at a time */

#define DEBUG 0
#define DDEBUG 0

#if DEBUG
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#if DDEBUG
#define DDPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DDPRINTF(_f, _a...) ((void)0)
#endif



/* This may allow us to create a 'quiet' command-line option, if necessary. */
#define verbose_printf(_f, _a...) \
    do {                          \
        if ( !verbose ) break;    \
        printf( _f , ## _a );     \
        fflush(stdout);           \
    } while ( 0 )

/*
 * Returns TRUE if the given machine frame number has a unique mapping
 * in the guest's pseudophysical map.
 * 0x80000000-3 mark the shared_info, and blk/net rings
 */
#define MFN_IS_IN_PSEUDOPHYS_MAP(_mfn) \
    (((_mfn) < (1024*1024)) && \
     ( ( (live_mfn_to_pfn_table[_mfn] < nr_pfns) && \
       (live_pfn_to_mfn_table[live_mfn_to_pfn_table[_mfn]] == (_mfn)) ) || \
\
       (live_mfn_to_pfn_table[_mfn] >= 0x80000000 && \
	live_mfn_to_pfn_table[_mfn] <= 0x80000003 ) || \
	live_pfn_to_mfn_table[live_mfn_to_pfn_table[_mfn]] == 0x80000004 )  )
     
/* Returns TRUE if MFN is successfully converted to a PFN. */
#define translate_mfn_to_pfn(_pmfn)         \
({                                          \
    unsigned long mfn = *(_pmfn);           \
    int _res = 1;                           \
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )   \
        _res = 0;                           \
    else                                    \
        *(_pmfn) = live_mfn_to_pfn_table[mfn];   \
    _res;                                   \
})


/* test_bit */
inline int test_bit ( int nr, volatile void * addr)
{
    return ( ((unsigned long*)addr)[nr/(sizeof(unsigned long)*8)] >> 
	     (nr % (sizeof(unsigned long)*8) ) ) & 1;
}

inline void clear_bit ( int nr, volatile void * addr)
{
    ((unsigned long*)addr)[nr/(sizeof(unsigned long)*8)] &= 
	~(1 << (nr % (sizeof(unsigned long)*8) ) );
}

inline void set_bit ( int nr, volatile void * addr)
{
    ((unsigned long*)addr)[nr/(sizeof(unsigned long)*8)] |= 
	(1 << (nr % (sizeof(unsigned long)*8) ) );
}


int xc_linux_save(int xc_handle,
                  u64 domid, 
		  unsigned int flags,
		  int (*writerfn)(void *, const void *, size_t),
		  void *writerst )
{
    dom0_op_t op;
    int rc = 1, i, j, k, n, last_iter, iter = 0;
    unsigned long mfn;
    int verbose = flags & XCFLAGS_VERBOSE;
    int live = flags & XCFLAGS_LIVE;
    int debug = flags & XCFLAGS_DEBUG;
    int sent_last_iter, sent_this_iter, max_iters;

    /* Remember if we stopped the guest, so we can restart it on exit. */
    int we_stopped_it = 0;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    
    /* A copy of the CPU context of the guest. */
    full_execution_context_t ctxt;

    /* A copy of the domain's name. */
    char name[MAX_DOMAIN_NAME];

    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;
    unsigned long *pfn_batch = NULL;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long page[1024];

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long *live_pfn_to_mfn_frame_list;
    unsigned long pfn_to_mfn_frame_list[1024];

    /* Live mapping of the table mapping each PFN to its current MFN. */
    unsigned long *live_pfn_to_mfn_table = NULL;
    /* Live mapping of system MFN to PFN table. */
    unsigned long *live_mfn_to_pfn_table = NULL;
    
    /* Live mapping of shared info structure */
    unsigned long *live_shinfo;

    /* base of the region in which domain memory is mapped */
    unsigned char *region_base;

    /* A temporary mapping, and a copy, of the guest's suspend record. */
    suspend_record_t *p_srec;

    /* number of pages we're dealing with */
    unsigned long nr_pfns;

    /* bitmap of pages left to send */
    unsigned long *to_send, *to_fix;

    int needed_to_fix = 0;
    int total_sent    = 0;
    
    if ( mlock(&ctxt, sizeof(ctxt) ) )
    {
        PERROR("Unable to mlock ctxt");
        return 1;
    }

    /* Ensure that the domain exists, and that it is stopped. */
    for ( ; ; )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = (domid_t)domid;
        op.u.getdomaininfo.ctxt = &ctxt;
        if ( (do_dom0_op(xc_handle, &op) < 0) || 
             ((u64)op.u.getdomaininfo.domain != domid) )
        {
            PERROR("Could not get info on domain");
            goto out;
        }

        memcpy(name, op.u.getdomaininfo.name, sizeof(name));
        shared_info_frame = op.u.getdomaininfo.shared_info_frame;

        if ( op.u.getdomaininfo.state == DOMSTATE_STOPPED )
            break;

        we_stopped_it = 1;

        op.cmd = DOM0_STOPDOMAIN;
        op.u.stopdomain.domain = (domid_t)domid;
        if ( do_dom0_op(xc_handle, &op) != 0 )
        {
            we_stopped_it = 0;
            PERROR("Stopping target domain failed");
            goto out;
        }

        usleep(1000); // 1ms
	printf("Sleep for 1ms\n");
    }

    /* A cheesy test to see whether the domain contains valid state. */
    if ( ctxt.pt_base == 0 )
    {
        ERROR("Domain is not in a valid Linux guest OS state");
        goto out;
    }

    /* Map the suspend-record MFN to pin it. The page must be owned by 
       domid for this to succeed. */
    p_srec = mfn_mapper_map_single(xc_handle, domid,
				 sizeof(*p_srec), PROT_READ, 
				 ctxt.cpu_ctxt.esi );

    if (!p_srec)
    {
        ERROR("Couldn't map state record");
        goto out;
    }

    nr_pfns = p_srec->nr_pfns;

    /* cheesy sanity check */
    if ( nr_pfns > 1024*1024 )
    {
        ERROR("Invalid state record -- pfn count out of range");
        goto out;
    }

    /* the pfn_to_mfn_frame_list fits in a single page */
    live_pfn_to_mfn_frame_list = 
	mfn_mapper_map_single(xc_handle, domid, 
			      PAGE_SIZE, PROT_READ, 
			      p_srec->pfn_to_mfn_frame_list );

    if (!live_pfn_to_mfn_frame_list)
    {
        ERROR("Couldn't map pfn_to_mfn_frame_list");
        goto out;
    }

    /* Track the mfn_to_pfn table down from the domains PT */
    {
	unsigned long *pgd;
	unsigned long mfn_to_pfn_table_start_mfn;

	pgd = mfn_mapper_map_single(xc_handle, domid, 
				PAGE_SIZE, PROT_READ, 
				ctxt.pt_base>>PAGE_SHIFT);

	mfn_to_pfn_table_start_mfn = 
	    pgd[HYPERVISOR_VIRT_START>>L2_PAGETABLE_SHIFT]>>PAGE_SHIFT;

	live_mfn_to_pfn_table = 
	    mfn_mapper_map_single(xc_handle, ~0ULL, 
				  PAGE_SIZE*1024, PROT_READ, 
				  mfn_to_pfn_table_start_mfn );
    }

    /* Map all the frames of the pfn->mfn table. For migrate to succeed, 
       the guest must not change which frames are used for this purpose. 
       (its not clear why it would want to change them, and we'll be OK
       from a safety POV anyhow. */

    live_pfn_to_mfn_table = mfn_mapper_map_batch( xc_handle, domid, 
						  PROT_READ,
						  live_pfn_to_mfn_frame_list,
						  (nr_pfns+1023)/1024 );  
    if( !live_pfn_to_mfn_table )
    {
        PERROR("Couldn't map pfn_to_mfn table");
        goto out;
    }


    /* Canonicalise the pfn-to-mfn table frame-number list. */
    memcpy( pfn_to_mfn_frame_list, live_pfn_to_mfn_frame_list, PAGE_SIZE );
    for ( i = 0; i < nr_pfns; i += 1024 )
    {
        if ( !translate_mfn_to_pfn(&pfn_to_mfn_frame_list[i/1024]) )
        {
            ERROR("Frame # in pfn-to-mfn frame list is not in pseudophys");
            goto out;
        }
    }

    /* At this point, we can start the domain again if we're doing a
       live suspend */

    if( live )
    { 
	if ( xc_shadow_control( xc_handle, domid, 
			   DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY,
			   NULL, 0 ) < 0 )
	{
	    ERROR("Couldn't enable shadow mode");
	    goto out;
	}

	if ( xc_domain_start( xc_handle, domid ) < 0 )
	{
	    ERROR("Couldn't restart domain");
	    goto out;
	}

	last_iter = 0;
	sent_last_iter = 1<<20; // 4GB's worth of pages
	max_iters = 9; // limit us to 10 time round loop
    }
    else
	last_iter = 1;


    /* Setup to_send bitmap */
    {
	int sz = (nr_pfns/8) + 8; // includes slop at end of array
	
	to_send = malloc( sz );
	to_fix  = calloc( 1, sz );

	if (!to_send || !to_fix)
	{
	    ERROR("Couldn't allocate to_send array");
	    goto out;
	}
	memset( to_send, 0xff, sz );

	if ( mlock( to_send, sz ) )
	{
	    PERROR("Unable to mlock to_send");
	    return 1;
	}
    }


    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type = calloc(BATCH_SIZE, sizeof(unsigned long));
    pfn_batch = calloc(BATCH_SIZE, sizeof(unsigned long));

    if ( (pfn_type == NULL) || (pfn_batch == NULL) )
    {
        errno = ENOMEM;
        goto out;
    }

    if ( mlock( pfn_type, BATCH_SIZE * sizeof(unsigned long) ) )
    {
	ERROR("Unable to mlock");
	goto out;
    }


    /*
     * Quick belt and braces sanity check.
     */
#if DEBUG
    for ( i = 0; i < nr_pfns; i++ )
    {
        mfn = live_pfn_to_mfn_table[i];

	if( (live_mfn_to_pfn_table[mfn] != i) && (mfn != 0x80000004) )
	    printf("i=0x%x mfn=%x live_mfn_to_pfn_table=%x\n",
		   i,mfn,live_mfn_to_pfn_table[mfn]);
    }
#endif

    /* Map the shared info frame */
    live_shinfo = mfn_mapper_map_single(xc_handle, domid,
					PAGE_SIZE, PROT_READ,
					shared_info_frame);

    if (!live_shinfo)
    {
        ERROR("Couldn't map live_shinfo");
        goto out;
    }

    /* Start writing out the saved-domain record. */

    if ( (*writerfn)(writerst, "LinuxGuestRecord",    16) ||
         (*writerfn)(writerst, name,                  sizeof(name)) ||
         (*writerfn)(writerst, &nr_pfns,              sizeof(unsigned long)) ||
         (*writerfn)(writerst, pfn_to_mfn_frame_list, PAGE_SIZE) )
    {
        ERROR("Error when writing to state file (1)");
        goto out;
    }

    /* Now write out each data page, canonicalising page tables as we go... */

    while(1)
    {
	unsigned int prev_pc, batch, sent_this_iter;

	iter++;

	sent_this_iter = 0;
	prev_pc = 0;
	verbose_printf("Saving memory pages: iter %d   0%%", iter);

	n=0;
	while( n < nr_pfns )
	{
	    unsigned int this_pc = (n * 100) / nr_pfns;
	    if ( (this_pc - prev_pc) >= 5 )
	    {
		verbose_printf("\b\b\b\b%3d%%", this_pc);
		prev_pc = this_pc;
	    }


	    /* load pfn_type[] with the mfn of all the pages we're doing in
	       this batch. */

	    for( batch = 0; batch < BATCH_SIZE && n < nr_pfns ; n++ )
	    {

		if(0 && debug)
		    fprintf(stderr,"%d pfn= %08lx mfn= %08lx %d   [mfn]= %08lx\n",
			    iter, n, live_pfn_to_mfn_table[n],
			    test_bit(n,to_send),
			    live_mfn_to_pfn_table[live_pfn_to_mfn_table[n]&0xFFFFF]);


		if ( !test_bit(n, to_send ) &&
		    !( last_iter && test_bit(n, to_fix ) ) ) continue;
		
		pfn_batch[batch] = n;
		pfn_type[batch] = live_pfn_to_mfn_table[n];

		if( pfn_type[batch] == 0x80000004 )
		{
		    set_bit( n, to_fix );
		    if( iter>1 )
			DDPRINTF("Urk! netbuf race: iter %d, pfn %lx. mfn %lx\n",
			       iter,n,pfn_type[batch]);
		    continue;
		}

		if ( last_iter && test_bit(n, to_fix ) && !test_bit(n, to_send ))
		{
		    needed_to_fix++;
		    DPRINTF("Fix! iter %d, pfn %lx. mfn %lx\n",
			       iter,n,pfn_type[batch]);
		}

		clear_bit( n, to_fix ); 

		batch++;
	    }
	    
	    DDPRINTF("batch %d:%d (n=%d)\n",iter,batch,n);

	    if(batch == 0) goto skip; // vanishingly unlikely...
 	    
	    if ( (region_base = mfn_mapper_map_batch( xc_handle, domid, 
						      PROT_READ,
						      pfn_type,
						      batch )) == 0)
	    {
		PERROR("map batch failed");
		goto out;
	    }
	    
	    if ( get_pfn_type_batch(xc_handle, domid, batch, pfn_type) )
	    {
		ERROR("get_pfn_type_batch failed");
		goto out;
	    }
	    
	    for( j = 0; j < batch; j++ )
	    {
		if((pfn_type[j]>>29) == 7)
		{
		    DDPRINTF("type fail: page %i mfn %08lx\n",j,pfn_type[j]);
		    continue;
		}
		
		if(0 && debug)
		    fprintf(stderr,"%d pfn= %08lx mfn= %08lx [mfn]= %08lx sum= %08lx\n",
			    iter, 
			    (pfn_type[j] & PGT_type_mask) | pfn_batch[j],
			    pfn_type[j],
			    live_mfn_to_pfn_table[pfn_type[j]&(~PGT_type_mask)],
			    csum_page(region_base + (PAGE_SIZE*j))
			);

		/* canonicalise mfn->pfn */
		pfn_type[j] = (pfn_type[j] & PGT_type_mask) |
		    pfn_batch[j];
		//live_mfn_to_pfn_table[pfn_type[j]&~PGT_type_mask];

	    }

	    
	    if ( (*writerfn)(writerst, &batch, sizeof(int) ) )
	    {
		ERROR("Error when writing to state file (2)");
		goto out;
	    }

	    if ( (*writerfn)(writerst, pfn_type, sizeof(unsigned long)*j ) )
	    {
		ERROR("Error when writing to state file (3)");
		goto out;
	    }
	    
	    /* entering this loop, pfn_type is now in pfns (Not mfns) */
	    for( j = 0; j < batch; j++ )
	    {
		/* write out pages in batch */
		
		if((pfn_type[j]>>29) == 7)
		{
		    DDPRINTF("SKIP BOGUS page %i mfn %08lx\n",j,pfn_type[j]);
		    continue;
		}
		
		if ( ((pfn_type[j] & PGT_type_mask) == L1TAB) || 
		     ((pfn_type[j] & PGT_type_mask) == L2TAB) )
		{
		    
		    memcpy(page, region_base + (PAGE_SIZE*j), PAGE_SIZE);
		    
		    for ( k = 0; 
			  k < (((pfn_type[j] & PGT_type_mask) == L2TAB) ? 
		       (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT) : 1024); 
			  k++ )
		    {
			unsigned long pfn;

			if ( !(page[k] & _PAGE_PRESENT) ) continue;
			mfn = page[k] >> PAGE_SHIFT;		    
			pfn = live_mfn_to_pfn_table[mfn];

			if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
			{
			    // I don't think this should ever happen

			    printf("FNI %d : [%08lx,%d] pte=%08lx, mfn=%08lx, pfn=%08lx [mfn]=%08lx\n",
				   j, pfn_type[j], k,
				   page[k], mfn, live_mfn_to_pfn_table[mfn],
				   (live_mfn_to_pfn_table[mfn]<nr_pfns)? 
				   live_pfn_to_mfn_table[live_mfn_to_pfn_table[mfn]]: 0xdeadbeef);

			    pfn = 0; // be suspicious, very suspicious
			    
			    //goto out;  // let's try our luck


			}
			page[k] &= PAGE_SIZE - 1;
			page[k] |= pfn << PAGE_SHIFT;
			
#if DEBUG
			printf("L%d i=%d pfn=%d mfn=%d k=%d pte=%08lx xpfn=%d\n",
			       pfn_type[j]>>29,
			       j,i,mfn,k,page[k],page[k]>>PAGE_SHIFT);
#endif			  
			
		    } /* end of page table rewrite for loop */
		    
		    if ( (*writerfn)(writerst, page, PAGE_SIZE) )
		    {
			ERROR("Error when writing to state file (4)");
			goto out;
		    }
		    
		}  /* end of it's a PT page */
		else
		{  /* normal page */

		    if ( (*writerfn)(writerst, region_base + (PAGE_SIZE*j), PAGE_SIZE) )
		    {
			ERROR("Error when writing to state file (5)");
			goto out;
		    }
		}
	    } /* end of the write out for this batch */
	    
	    sent_this_iter += batch;

	} /* end of this while loop for this iteration */

	munmap(region_base, batch*PAGE_SIZE);

    skip: 

	total_sent += sent_this_iter;

	verbose_printf("\b\b\b\b100%% (%d pages)\n", sent_this_iter );
	
	if ( last_iter )
	{
	    verbose_printf("Total pages sent= %d (%.2fx)\n", 
			   total_sent, ((float)total_sent)/nr_pfns );
	    verbose_printf("(of which %d were fixups)\n", needed_to_fix  );
	}       

	if ( debug && last_iter )
	{
	    int minusone = -1;
	    memset( to_send, 0xff, nr_pfns/8 );
	    debug = 0;
	    printf("Entering debug resend-all mode\n");
    
	    /* send "-1" to put receiver into debug mode */
	    if ( (*writerfn)(writerst, &minusone, sizeof(int)) )
	    {
		ERROR("Error when writing to state file (6)");
		goto out;
	    }

	    continue;
	}

	if ( last_iter )
	    break;

	if ( live )
	{
	    if ( ( sent_this_iter > (sent_last_iter * 0.95) ) ||
		 (iter >= max_iters) || (sent_this_iter < 10) )
	    {
		DPRINTF("Start last iteration\n");
		last_iter = 1;

		xc_domain_stop_sync( xc_handle, domid );

	    } 

	    if ( xc_shadow_control( xc_handle, domid, 
				    DOM0_SHADOW_CONTROL_OP_CLEAN,
				    to_send, nr_pfns ) != nr_pfns ) 
	    {
		ERROR("Error flushing shadow PT");
		goto out;
	    }

	    sent_last_iter = sent_this_iter;

	}


    } /* end of while 1 */

    DPRINTF("All memory is saved\n");

    /* Success! */
    rc = 0;
    
    /* Zero terminate */
    if ( (*writerfn)(writerst, &rc, sizeof(int)) )
    {
	ERROR("Error when writing to state file (6)");
	goto out;
    }

    /* Get the final execution context */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    op.u.getdomaininfo.ctxt = &ctxt;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
	 ((u64)op.u.getdomaininfo.domain != domid) )
    {
	PERROR("Could not get info on domain");
	goto out;
    }

    /* Canonicalise the suspend-record frame number. */
    if ( !translate_mfn_to_pfn(&ctxt.cpu_ctxt.esi) )
    {
        ERROR("State record is not in range of pseudophys map");
        goto out;
    }

    /* Canonicalise each GDT frame number. */
    for ( i = 0; i < ctxt.gdt_ents; i += 512 )
    {
        if ( !translate_mfn_to_pfn(&ctxt.gdt_frames[i]) )
        {
            ERROR("GDT frame is not in range of pseudophys map");
            goto out;
        }
    }

    /* Canonicalise the page table base pointer. */
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(ctxt.pt_base >> PAGE_SHIFT) )
    {
        ERROR("PT base is not in range of pseudophys map");
        goto out;
    }
    ctxt.pt_base = live_mfn_to_pfn_table[ctxt.pt_base >> PAGE_SHIFT] << PAGE_SHIFT;

    if ( (*writerfn)(writerst, &ctxt,                 sizeof(ctxt)) ||
         (*writerfn)(writerst, live_shinfo,           PAGE_SIZE) )
    {
        ERROR("Error when writing to state file (1)");
        goto out;
    }
    munmap(live_shinfo, PAGE_SIZE);

out:
    /* Restart the domain if we had to stop it to save its state. */
    if ( we_stopped_it )
    {
	printf("Restart domain\n");
        op.cmd = DOM0_STARTDOMAIN;
        op.u.startdomain.domain = (domid_t)domid;
        (void)do_dom0_op(xc_handle, &op);
    }

    if ( pfn_type != NULL )
        free(pfn_type);

    DPRINTF("Save exit rc=%d\n",rc);
    
    return !!rc;

}
