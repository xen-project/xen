/******************************************************************************
 * xc_linux_save.c
 * 
 * Save the state of a running Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include <asm-xen/suspend.h>
#include <zlib.h>

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
 */
#define MFN_IS_IN_PSEUDOPHYS_MAP(_mfn) \
    (((_mfn) < (1024*1024)) &&          \
     (live_pfn_to_mfn_table[live_mfn_to_pfn_table[_mfn]] == (_mfn)))

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

static int check_pfn_ownership(int xc_handle, 
                               unsigned long mfn, 
                               u64 dom)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn    = mfn;
    op.u.getpageframeinfo.domain = (domid_t)dom;
    return (do_dom0_op(xc_handle, &op) >= 0);
}

#define GETPFN_ERR (~0U)
static unsigned int get_pfn_type(int xc_handle, 
                                 unsigned long mfn, 
                                 u64 dom)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn    = mfn;
    op.u.getpageframeinfo.domain = (domid_t)dom;
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        PERROR("Unexpected failure when getting page frame info!");
        return GETPFN_ERR;
    }
    return op.u.getpageframeinfo.type;
}

static int checked_write(gzFile fd, void *buf, size_t count)
{
    int rc;
    while ( ((rc = gzwrite(fd, buf, count)) == -1) && (errno = EINTR) )
        continue;
    return rc == count;
}

int xc_linux_save(int xc_handle,
                  u64 domid, 
                  const char *state_file, 
                  int verbose)
{
    dom0_op_t op;
    int rc = 1, i, j, k, n;
    unsigned long mfn;
    unsigned int prev_pc, this_pc;

    /* state of the new MFN mapper */
    mfn_mapper_t *mapper_handle1, *mapper_handle2;

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
    suspend_record_t *p_srec, srec;

    /* The name and descriptor of the file that we are writing to. */
    int    fd;
    gzFile gfd;

    int pm_handle = -1;

    if ( (fd = open(state_file, O_CREAT|O_EXCL|O_WRONLY, 0644)) == -1 )
    {
        PERROR("Could not open file for writing");
        return 1;
    }

    /*
     * Compression rate 1: we want speed over compression. We're mainly going
     * for those zero pages, after all.
     */
    if ( (gfd = gzdopen(fd, "wb1")) == NULL )
    {
        ERROR("Could not allocate compression state for state file");
        close(fd);
        return 1;
    }

    /* Ensure that the domain exists, and that it is stopped. */
    for ( ; ; )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = (domid_t)domid;
        if ( (do_dom0_op(xc_handle, &op) < 0) || 
             ((u64)op.u.getdomaininfo.domain != domid) )
        {
            PERROR("Could not get info on domain");
            goto out;
        }

        memcpy(&ctxt, &op.u.getdomaininfo.ctxt, sizeof(ctxt));
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

        sleep(1);
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
				 sizeof(srec), PROT_READ, 
				 ctxt.cpu_ctxt.esi );

    if (!p_srec)
    {
        ERROR("Couldn't map state record");
        goto out;
    }

    memcpy( &srec, p_srec, sizeof(srec) );

    /* cheesy sanity check */
    if ( srec.nr_pfns > 1024*1024 )
    {
        ERROR("Invalid state record -- pfn count out of range");
        goto out;
    }

    /* the pfn_to_mfn_frame_list fits in a single page */
    live_pfn_to_mfn_frame_list = 
	mfn_mapper_map_single(xc_handle, domid, 
			      PAGE_SIZE, PROT_READ, 
			      srec.pfn_to_mfn_frame_list );

    if (!live_pfn_to_mfn_frame_list)
    {
        ERROR("Couldn't map pfn_to_mfn_frame_list");
        goto out;
    }
   

    if ( (mapper_handle1 = mfn_mapper_init(xc_handle, domid,
					   1024*1024, PROT_READ )) 
	 == NULL )
        goto out;
	
    for ( i = 0; i < (srec.nr_pfns+1023)/1024; i++ )
    {
	/* Grab a copy of the pfn-to-mfn table frame list. 
	 This has the effect of preventing the page from being freed and
	 given to another domain. (though the domain is stopped anyway...) */
	mfn_mapper_queue_entry( mapper_handle1, i<<PAGE_SHIFT, 
				live_pfn_to_mfn_frame_list[i],
				PAGE_SIZE );
    }
    
    if ( mfn_mapper_flush_queue(mapper_handle1) )
    {
        ERROR("Couldn't map pfn_to_mfn table");
        goto out;
    }

    live_pfn_to_mfn_table = mfn_mapper_base( mapper_handle1 );



    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type         = calloc(1, 4 * srec.nr_pfns);

    if ( (pfn_type == NULL) )
    {
        errno = ENOMEM;
        goto out;
    }



    /* Track the mfn_to_pfn table down from the domains PT */
    {
	unsigned long *pgd;
	unsigned long mfn_to_pfn_table_start_mfn;

    pgd = mfn_mapper_map_single(xc_handle, domid, 
				PAGE_SIZE, PROT_READ, 
				ctxt.pt_base>>PAGE_SHIFT);
/*
    printf("pt mfn=%d pfn=%d type=%08x pte=%08x\n",ctxt.pt_base>>PAGE_SHIFT,
	   mfn_to_pfn_table[ctxt.pt_base>>PAGE_SHIFT],
	   pfn_type[mfn_to_pfn_table[ctxt.pt_base>>PAGE_SHIFT]],
	   pgd[HYPERVISOR_VIRT_START>>L2_PAGETABLE_SHIFT] );
*/
    mfn_to_pfn_table_start_mfn = pgd[HYPERVISOR_VIRT_START>>L2_PAGETABLE_SHIFT]>>PAGE_SHIFT;

    live_mfn_to_pfn_table = 
	mfn_mapper_map_single(xc_handle, ~0ULL, 
			      PAGE_SIZE*1024, PROT_READ, 
			      mfn_to_pfn_table_start_mfn );
    }


    /*
     * Construct the local pfn-to-mfn and mfn-to-pfn tables. On exit from this
     * loop we have each MFN mapped at most once. Note that there may be MFNs
     * that aren't mapped at all: we detect these by MFN_IS_IN_PSEUDOPHYS_MAP.
     */

    for ( i = 0; i < srec.nr_pfns; i++ )
    {
        mfn = live_pfn_to_mfn_table[i];

#if 1  /* XXX use the master mfn_to_pfn table???? */


	if( live_mfn_to_pfn_table[mfn] != i )
	    printf("i=%d mfn=%d live_mfn_to_pfn_table=%d\n",
		   i,mfn,live_mfn_to_pfn_table[mfn]);

        /* Query page type by MFN, but store it by PFN. */
        if ( (pfn_type[i] = get_pfn_type(xc_handle, mfn, domid)) == 
             GETPFN_ERR )
            goto out;
#endif

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

    /* Canonicalise the pfn-to-mfn table frame-number list. */
    memcpy( pfn_to_mfn_frame_list, live_pfn_to_mfn_frame_list, PAGE_SIZE );
    for ( i = 0; i < srec.nr_pfns; i += 1024 )
    {
        if ( !translate_mfn_to_pfn(&pfn_to_mfn_frame_list[i/1024]) )
        {
            ERROR("Frame # in pfn-to-mfn frame list is not in pseudophys");
            goto out;
        }
    }

    /* Start writing out the saved-domain record. */
    live_shinfo = mfn_mapper_map_single(xc_handle, domid,
					PAGE_SIZE, PROT_READ,
					shared_info_frame);

    if (!live_shinfo)
    {
        ERROR("Couldn't map live_shinfo");
        goto out;
    }

    /* Belts and braces safety check on the shared info record */
    if ( !check_pfn_ownership(xc_handle, shared_info_frame, domid) )
    {
        ERROR("Invalid shared_info_frame");
        goto out;
    }

    if ( !checked_write(gfd, "LinuxGuestRecord",    16) ||
         !checked_write(gfd, name,                  sizeof(name)) ||
         !checked_write(gfd, &srec.nr_pfns,         sizeof(unsigned long)) ||
         !checked_write(gfd, &ctxt,                 sizeof(ctxt)) ||
         !checked_write(gfd, live_shinfo,           PAGE_SIZE) ||
         !checked_write(gfd, pfn_to_mfn_frame_list, PAGE_SIZE) ||
         !checked_write(gfd, pfn_type,              4 * srec.nr_pfns) )
    {
        ERROR("Error when writing to state file");
        goto out;
    }
    munmap(live_shinfo, PAGE_SIZE);

    verbose_printf("Saving memory pages:   0%%");

#define BATCH_SIZE 1024   /* 1024 pages (4MB) at a time */

    if ( (mapper_handle2 = mfn_mapper_init(xc_handle, domid,
					   BATCH_SIZE*4096, PROT_READ )) 
	 == NULL )
        goto out;

    region_base = mfn_mapper_base( mapper_handle2 );

    /* Now write out each data page, canonicalising page tables as we go... */
    prev_pc = 0;
    for ( n = 0; n < srec.nr_pfns; )
    {
        this_pc = (n * 100) / srec.nr_pfns;
        if ( (this_pc - prev_pc) >= 5 )
        {
            verbose_printf("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }


	for( j = 0, i = n; j < BATCH_SIZE && i < srec.nr_pfns ; j++, i++ )
	{
	    /* queue up mappings for all of the pages in this batch */

//printf("region n=%d j=%d i=%d mfn=%d\n",n,j,i,live_pfn_to_mfn_table[i]);
	    mfn_mapper_queue_entry( mapper_handle2, j<<PAGE_SHIFT, 
				    live_pfn_to_mfn_table[i],
				    PAGE_SIZE );
	}

	if( mfn_mapper_flush_queue(mapper_handle2) )
	{
	    ERROR("Couldn't map page region");
	    goto out;
	}

#if 0	   
	typer_handle = get_type_init( xc_handle, BATCH_SIZE )

	for( j = 0, i = n; j < BATCH_SIZE && i < srec.nr_pfns ; j++, i++ )
	{
	    /* queue up ownership and type checks for all pages in batch */

	    get_type_queue_entry( typer_handle, domain, 
				  pfn_to_mfn_frame_list[i] );
	}

	region_type = get_type;

#endif

	for( j = 0, i = n; j < BATCH_SIZE && i < srec.nr_pfns ; j++, i++ )
	{
	    /* write out pages in batch */

	    if ( (pfn_type[i] == L1TAB) || (pfn_type[i] == L2TAB) )
	    {
		
		memcpy(page, region_base + (PAGE_SIZE*j), PAGE_SIZE);

		for ( k = 0; 
		      k < ((pfn_type[i] == L2TAB) ? 
			   (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT) : 1024); 
		      k++ )
		{
		    if ( !(page[k] & _PAGE_PRESENT) ) continue;
		    mfn = page[k] >> PAGE_SHIFT;
		    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
		    {
			ERROR("Frame number in pagetable page is invalid");
			goto out;
		    }
		    page[k] &= PAGE_SIZE - 1;
 		    page[k] |= live_mfn_to_pfn_table[mfn] << PAGE_SHIFT;

		}

		if ( !checked_write(gfd, page, PAGE_SIZE) )
		{
		    ERROR("Error when writing to state file");
		    goto out;
		}


	    }
	    else
	    {
		if ( !checked_write(gfd, region_base + (PAGE_SIZE*j), PAGE_SIZE) )
		{
		    ERROR("Error when writing to state file");
		    goto out;
		}
	    }
	}
	
	n+=j; /* i is the master loop counter */
    }

    verbose_printf("\b\b\b\b100%%\nMemory saved.\n");

    /* Success! */
    rc = 0;

out:
    /* Restart the domain if we had to stop it to save its state. */
    if ( we_stopped_it )
    {
	printf("Restart domain\n");
        op.cmd = DOM0_STARTDOMAIN;
        op.u.startdomain.domain = (domid_t)domid;
        (void)do_dom0_op(xc_handle, &op);
    }

    gzclose(gfd);

    if ( pfn_type != NULL )
        free(pfn_type);

    /* On error, make sure the file is deleted. */
    if ( rc != 0 )
        unlink(state_file);
    
    return !!rc;


}
