/******************************************************************************
 * xc_linux_restore.c
 * 
 * Restore the state of a Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include <asm-xen/suspend.h>
#include <zlib.h>

#define MAX_BATCH_SIZE 1024

#define DEBUG 0

#if DEBUG
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif


/* This may allow us to create a 'quiet' command-line option, if necessary. */
#define verbose_printf(_f, _a...) \
    do {                          \
        if ( !verbose ) break;    \
        printf( _f , ## _a );     \
        fflush(stdout);           \
    } while ( 0 )

static int get_pfn_list(int xc_handle,
                        u64 domain_id, 
                        unsigned long *pfn_buf, 
                        unsigned long max_pfns)
{
    dom0_op_t op;
    int ret;
    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = (domid_t)domain_id;
    op.u.getmemlist.max_pfns = max_pfns;
    op.u.getmemlist.buffer   = pfn_buf;

    if ( mlock(pfn_buf, max_pfns * sizeof(unsigned long)) != 0 )
    {
        PERROR("Could not lock pfn list buffer");
        return -1;
    }    

    ret = do_dom0_op(xc_handle, &op);

    (void)munlock(pfn_buf, max_pfns * sizeof(unsigned long));

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}


int xc_linux_restore(int xc_handle,
		     u64 dom,
                     unsigned int flags,
		     int (*readerfn)(void *, void *, size_t),
		     void *readerst,
                     u64 *pdomid)
{
    dom0_op_t op;
    int rc = 1, i, j, n, k;
    unsigned long mfn, pfn, xpfn;
    unsigned int prev_pc, this_pc;
    int verbose = flags & XCFLAGS_VERBOSE;
    int verify = 0; 

    /* Number of page frames in use by this Linux session. */
    unsigned long nr_pfns;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info[PAGE_SIZE]; /* saved contents from file */
    
    /* A copy of the CPU context of the guest. */
    full_execution_context_t ctxt;

    /* First 16 bytes of the state file must contain 'LinuxGuestRecord'. */
    char signature[16];
    
    /* A copy of the domain's name. */
    char name[MAX_DOMAIN_NAME];

    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *ppage;

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long pfn_to_mfn_frame_list[1024];

    /* A table mapping each PFN to its new MFN. */
    unsigned long *pfn_to_mfn_table = NULL;

    /* A temporary mapping of the guest's suspend record. */
    suspend_record_t *p_srec;

    mfn_mapper_t *region_mapper, *mapper_handle1;
    char *region_base;

    mmu_t *mmu = NULL;

    int pm_handle = -1;

    /* used by debug verify code */
    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];

    if ( mlock(&ctxt, sizeof(ctxt) ) )
    {   
        /* needed for when we do the build dom0 op, 
	   but might as well do early */
        PERROR("Unable to mlock ctxt");
        return 1;
    }

    /* Start writing out the saved-domain record. */
    if ( (*readerfn)(readerst, signature, 16) ||
         (memcmp(signature, "LinuxGuestRecord", 16) != 0) )
    {
        ERROR("Unrecognised state format -- no signature found");
        goto out;
    }

    if ( (*readerfn)(readerst, name,                  sizeof(name)) ||
         (*readerfn)(readerst, &nr_pfns,              sizeof(unsigned long)) ||
         (*readerfn)(readerst, pfn_to_mfn_frame_list, PAGE_SIZE) )
    {
        ERROR("Error when reading from state file");
        goto out;
    }

    for ( i = 0; i < MAX_DOMAIN_NAME; i++ )
    {
        if ( name[i] == '\0' ) break;
        if ( name[i] & 0x80 )
        {
            ERROR("Random characters in domain name");
            goto out;
        }
    }
    name[MAX_DOMAIN_NAME-1] = '\0';

    if ( nr_pfns > 1024*1024 )
    {
        ERROR("Invalid state file -- pfn count out of range");
        goto out;
    }

    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_to_mfn_table = calloc(1, 4 * nr_pfns);
    pfn_type         = calloc(1, 4 * nr_pfns);    

    if ( (pfn_to_mfn_table == NULL) || (pfn_type == NULL) )
    {
        errno = ENOMEM;
        goto out;
    }

    /* Set the domain's name to that from the restore file */
    if ( xc_domain_setname( xc_handle, dom, name ) )
    {
        ERROR("Could not set domain name");
        goto out;
    }

    /* Set the domain's initial memory allocation 
       to that from the restore file */

    if ( xc_domain_setinitialmem( xc_handle, dom, nr_pfns * (PAGE_SIZE / 1024)) )
    {
        ERROR("Could not set domain initial memory");
        goto out;
    }

    /* Get the domain's shared-info frame. */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)dom;
    op.u.getdomaininfo.ctxt = NULL;
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        ERROR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = op.u.getdomaininfo.shared_info_frame;

    if ( (pm_handle = init_pfn_mapper((domid_t)dom)) < 0 )
        goto out;



    /* Build the pfn-to-mfn table. We choose MFN ordering returned by Xen. */
    if ( get_pfn_list(xc_handle, dom, pfn_to_mfn_table, nr_pfns) != nr_pfns )
    {
        ERROR("Did not read correct number of frame numbers for new dom");
        goto out;
    }

    if ( (mmu = init_mmu_updates(xc_handle, dom)) == NULL )
    {
        ERROR("Could not initialise for MMU updates");
        goto out;
    }


    if ( (region_mapper = mfn_mapper_init(xc_handle, dom,
					  MAX_BATCH_SIZE*PAGE_SIZE, 
					  PROT_WRITE )) 
	 == NULL )
        goto out;

    region_base = mfn_mapper_base( region_mapper );

    verbose_printf("Reloading memory pages:   0%%");

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    prev_pc = 0;

    n=0;
    while(1)
    {
	int j;
	unsigned long region_pfn_type[1024];

        this_pc = (n * 100) / nr_pfns;
        if ( (this_pc - prev_pc) >= 5 )
        {
            verbose_printf("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        if ( (*readerfn)(readerst, &j, sizeof(int)) )
        {
            ERROR("Error when reading from state file");
            goto out;
        }

	DPRINTF("batch %d\n",j);
	
	if (j == -1)
	{
	    verify = 1;
	    printf("Entering page verify mode\n");
	    continue;
	}

	if (j == 0) 
	{
	    break;  // our work here is done
	}

	if( j > MAX_BATCH_SIZE )
	{
	    ERROR("Max batch size exceeded. Giving up.");
	    goto out;
	}
	
        if ( (*readerfn)(readerst, region_pfn_type, j*sizeof(unsigned long)) )
        {
            ERROR("Error when reading from state file");
            goto out;
        }

	for(i=0;i<j;i++)
	{
            if ((region_pfn_type[i]>>29) == 7)
		continue;

	    pfn = region_pfn_type[i] & ~PGT_type_mask;
	    mfn = pfn_to_mfn_table[pfn];
	    
	    mfn_mapper_queue_entry( region_mapper, i<<PAGE_SHIFT, 
				    mfn, PAGE_SIZE );
	}

	if( mfn_mapper_flush_queue(region_mapper) )
	{
	    ERROR("Couldn't map page region");
	    goto out;
	}


	for(i=0;i<j;i++)
	{
	    unsigned long *ppage;

	    pfn = region_pfn_type[i] & ~PGT_type_mask;

            if ((region_pfn_type[i]>>29) == 7)
		continue;

            if (pfn>nr_pfns)
	    {
		ERROR("pfn out of range");
		goto out;
	    }

	    region_pfn_type[i] &= PGT_type_mask;

	    pfn_type[pfn] = region_pfn_type[i];

	    mfn = pfn_to_mfn_table[pfn];

	    if ( verify )
		ppage = (unsigned long*) buf;  // debug case
	    else
		ppage = (unsigned long*) (region_base + i*PAGE_SIZE);

	    if ( (*readerfn)(readerst, ppage, PAGE_SIZE) )
	    {
		ERROR("Error when reading from state file");
		goto out;
	    }

	    switch( region_pfn_type[i] )
	    {
	    case 0:
		break;

	    case L1TAB:
	    {
		for ( k = 0; k < 1024; k++ )
		{
		    if ( ppage[k] & _PAGE_PRESENT )
		    {
			xpfn = ppage[k] >> PAGE_SHIFT;

			if ( xpfn >= nr_pfns )
			{
			    ERROR("Frame number in type %d page table is out of range. i=%d k=%d pfn=0x%x nr_pfns=%d",region_pfn_type[i]>>29,i,k,xpfn,nr_pfns);
			    goto out;
			}

			ppage[k] &= (PAGE_SIZE - 1) & ~(_PAGE_GLOBAL | _PAGE_PAT);
			ppage[k] |= pfn_to_mfn_table[xpfn] << PAGE_SHIFT;
		    }
		}
	    }
	    break;

	    case L2TAB:
	    {
		for ( k = 0; k < (HYPERVISOR_VIRT_START>>L2_PAGETABLE_SHIFT); k++ )
		{
		    if ( ppage[k] & _PAGE_PRESENT )
		    {
			xpfn = ppage[k] >> PAGE_SHIFT;

			if ( xpfn >= nr_pfns )
			{
			    ERROR("Frame number in type %d page table is out of range. i=%d k=%d pfn=%d nr_pfns=%d",region_pfn_type[i]>>29,i,k,xpfn,nr_pfns);

			    goto out;
			}
#if 0
			if ( region_pfn_type[pfn] != L1TAB )
			{
			    ERROR("Page table mistyping");
			    goto out;
			}
#endif
			ppage[k] &= (PAGE_SIZE - 1) & ~(_PAGE_GLOBAL | _PAGE_PSE);
			ppage[k] |= pfn_to_mfn_table[xpfn] << PAGE_SHIFT;
		    }
		}
	    }
	    break;

	    default:
		ERROR("Bogus page type %x page table is out of range. i=%d nr_pfns=%d",region_pfn_type[i],i,nr_pfns);
		goto out;

	    } // end of page type switch statement

	    if ( verify )
	    {
		int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE );
		if (res)
		{
		    int v;
		    printf("************** pfn=%x type=%x gotcs=%08lx actualcs=%08lx\n",pfn,pfn_type[pfn],csum_page(region_base + i*PAGE_SIZE),csum_page(buf));
		    for(v=0;v<4;v++)
		    {
			unsigned long * p = (unsigned long *) (region_base + i*PAGE_SIZE);
			if ( buf[v] != p[v] )
			    printf("    %d: %08lx %08lx\n",
				   v, buf[v], p[v] );
		    }

		}
	    }

	    if ( add_mmu_update(xc_handle, mmu,
				(mfn<<PAGE_SHIFT) | MMU_MACHPHYS_UPDATE, pfn) )
		goto out;

	} // end of 'batch' for loop

	n+=j; // crude stats

    }

    DPRINTF("Received all pages\n");

    mfn_mapper_close( region_mapper );

    /*
     * Pin page tables. Do this after writing to them as otherwise Xen
     * will barf when doing the type-checking.
     */
    for ( i = 0; i < nr_pfns; i++ )
    {
        if ( pfn_type[i] == L1TAB )
        {
            if ( add_mmu_update(xc_handle, mmu,
                                (pfn_to_mfn_table[i]<<PAGE_SHIFT) | 
                                MMU_EXTENDED_COMMAND,
                                MMUEXT_PIN_L1_TABLE) )
	    {
		printf("ERR pin L1 pfn=%lx mfn=%lx\n");
                goto out;
	    }
        }
        else if ( pfn_type[i] == L2TAB )
        {
            if ( add_mmu_update(xc_handle, mmu,
                                (pfn_to_mfn_table[i]<<PAGE_SHIFT) | 
                                MMU_EXTENDED_COMMAND,
                                MMUEXT_PIN_L2_TABLE) )
	    {
		printf("ERR pin L2 pfn=%lx mfn=%lx\n");
                goto out;
	    }
        }
    }

    if ( finish_mmu_updates(xc_handle, mmu) )
        goto out;

    verbose_printf("\b\b\b\b100%%\nMemory reloaded.\n");


    if ( (*readerfn)(readerst, &ctxt,                 sizeof(ctxt)) ||
         (*readerfn)(readerst, shared_info,           PAGE_SIZE) )
    {
        ERROR("Error when reading from state file");
        goto out;
    }

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    pfn = ctxt.cpu_ctxt.esi;
    if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NONE) )
    {
        ERROR("Suspend record frame number is bad");
        goto out;
    }
    ctxt.cpu_ctxt.esi = mfn = pfn_to_mfn_table[pfn];
    p_srec = map_pfn_writeable(pm_handle, mfn);
    p_srec->resume_info.nr_pages    = nr_pfns;
    p_srec->resume_info.shared_info = shared_info_frame << PAGE_SHIFT;
    p_srec->resume_info.flags       = 0;
    unmap_pfn(pm_handle, p_srec);

    /* Uncanonicalise each GDT frame number. */
    if ( ctxt.gdt_ents > 8192 )
    {
        ERROR("GDT entry count out of range");
        goto out;
    }
    for ( i = 0; i < ctxt.gdt_ents; i += 512 )
    {
        pfn = ctxt.gdt_frames[i];
        if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NONE) )
        {
            ERROR("GDT frame number is bad");
            goto out;
        }
        ctxt.gdt_frames[i] = pfn_to_mfn_table[pfn];
    }

    /* Uncanonicalise the page table base pointer. */
    pfn = ctxt.pt_base >> PAGE_SHIFT;
    if ( (pfn >= nr_pfns) || (pfn_type[pfn] != L2TAB) )
    {
        printf("PT base is bad. pfn=%d nr=%d type=%08lx %08lx\n",
	       pfn, nr_pfns, pfn_type[pfn], L2TAB);
        ERROR("PT base is bad.");
        goto out;
    }
    ctxt.pt_base = pfn_to_mfn_table[pfn] << PAGE_SHIFT;


    /* clear any pending events and the selector */
    memset( &(((shared_info_t *)shared_info)->evtchn_pending[0]),
	    0, sizeof (((shared_info_t *)shared_info)->evtchn_pending)+
	    sizeof(((shared_info_t *)shared_info)->evtchn_pending_sel) );

    /* Copy saved contents of shared-info page. No checking needed. */
    ppage = map_pfn_writeable(pm_handle, shared_info_frame);
    memcpy(ppage, shared_info, sizeof(shared_info_t));
    unmap_pfn(pm_handle, ppage);


    /* Uncanonicalise the pfn-to-mfn table frame-number list. */
    if ( (mapper_handle1 = mfn_mapper_init(xc_handle, dom,
					   1024*1024, PROT_WRITE )) 
	 == NULL )
        goto out;
	
    for ( i = 0; i < (nr_pfns+1023)/1024; i++ )
    {
	unsigned long pfn, mfn;

        pfn = pfn_to_mfn_frame_list[i];
        if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NONE) )
        {
            ERROR("PFN-to-MFN frame number is bad");
            goto out;
        }
	mfn = pfn_to_mfn_table[pfn];

	mfn_mapper_queue_entry( mapper_handle1, i<<PAGE_SHIFT, 
				mfn, PAGE_SIZE );
    }
    
    if ( mfn_mapper_flush_queue(mapper_handle1) )
    {
        ERROR("Couldn't map pfn_to_mfn table");
        goto out;
    }

    memcpy( mfn_mapper_base( mapper_handle1 ), pfn_to_mfn_table, 
	    nr_pfns*sizeof(unsigned long) );

    mfn_mapper_close( mapper_handle1 );

    /*
     * Safety checking of saved context:
     *  1. cpu_ctxt is fine, as Xen checks that on context switch.
     *  2. fpu_ctxt is fine, as it can't hurt Xen.
     *  3. trap_ctxt needs the code selectors checked.
     *  4. fast_trap_idx is checked by Xen.
     *  5. ldt base must be page-aligned, no more than 8192 ents, ...
     *  6. gdt already done, and further checking is done by Xen.
     *  7. check that guestos_ss is safe.
     *  8. pt_base is already done.
     *  9. debugregs are checked by Xen.
     *  10. callback code selectors need checking.
     */
    for ( i = 0; i < 256; i++ )
    {
        ctxt.trap_ctxt[i].vector = i;
        if ( (ctxt.trap_ctxt[i].cs & 3) == 0 )
            ctxt.trap_ctxt[i].cs = FLAT_GUESTOS_CS;
    }
    if ( (ctxt.guestos_ss & 3) == 0 )
        ctxt.guestos_ss = FLAT_GUESTOS_DS;
    if ( (ctxt.event_callback_cs & 3) == 0 )
        ctxt.event_callback_cs = FLAT_GUESTOS_CS;
    if ( (ctxt.failsafe_callback_cs & 3) == 0 )
        ctxt.failsafe_callback_cs = FLAT_GUESTOS_CS;
    if ( ((ctxt.ldt_base & (PAGE_SIZE - 1)) != 0) ||
         (ctxt.ldt_ents > 8192) ||
         (ctxt.ldt_base > HYPERVISOR_VIRT_START) ||
         ((ctxt.ldt_base + ctxt.ldt_ents*8) > HYPERVISOR_VIRT_START) )
    {
        ERROR("Bad LDT base or size");
        goto out;
    }
   
    op.cmd = DOM0_BUILDDOMAIN;
    op.u.builddomain.domain   = (domid_t)dom;
    op.u.builddomain.num_vifs = 1;
    op.u.builddomain.ctxt = &ctxt;
    rc = do_dom0_op(xc_handle, &op);

    /* don't start the domain as we have console etc to set up */
  
    if( rc == 0 )
    {
	/* Success: print the domain id. */
	verbose_printf("DOM=%llu\n", dom);
	return 0;
    }


 out:
    if ( rc != 0 )  // destroy if something went wrong
    {
        if ( dom != 0 )
        {
	    xc_domain_destroy( xc_handle, dom, 1 );
        }
    }

    if ( mmu != NULL )
        free(mmu);

    if ( pm_handle >= 0 )
        (void)close_pfn_mapper(pm_handle);

    if ( pfn_to_mfn_table != NULL )
        free(pfn_to_mfn_table);
    if ( pfn_type != NULL )
        free(pfn_type);


    if ( rc == 0 )
        *pdomid = dom;

    DPRINTF("Restore exit with rc=%d\n",rc);

    return rc;
}
