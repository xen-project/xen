/******************************************************************************
 * xc_linux_restore.c
 * 
 * Restore the state of a Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include <xen/linux/suspend.h>

#define MAX_BATCH_SIZE 1024

#define DEBUG 0

#if DEBUG
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

static int get_pfn_list(int xc_handle,
                        u32 domain_id, 
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

/** Read the vmconfig string from the state input.
 * It is stored as a 4-byte count 'n' followed by n bytes.
 * The config data is stored in a new string in 'ioctxt->vmconfig',
 * and is null-terminated. The count is stored in 'ioctxt->vmconfig_n'.
 *
 * @param ioctxt i/o context
 * @return 0 on success, non-zero on error.
 */
static int read_vmconfig(XcIOContext *ioctxt)
{
    int err = -1;

    if ( xcio_read(ioctxt, &ioctxt->vmconfig_n, sizeof(ioctxt->vmconfig_n)) )
        goto exit;

    ioctxt->vmconfig = malloc(ioctxt->vmconfig_n + 1);
    if ( ioctxt->vmconfig == NULL ) 
        goto exit;

    if ( xcio_read(ioctxt, ioctxt->vmconfig, ioctxt->vmconfig_n) )
        goto exit;

    ioctxt->vmconfig[ioctxt->vmconfig_n] = '\0';
    err = 0;

  exit:
    if ( err )
    {
        if ( ioctxt->vmconfig != NULL )
            free(ioctxt->vmconfig);
        ioctxt->vmconfig = NULL;
        ioctxt->vmconfig_n = 0;
    }
    return err;
}

int xc_linux_restore(int xc_handle, XcIOContext *ioctxt)
{
    dom0_op_t op;
    int rc = 1, i, n, k;
    unsigned long mfn, pfn, xpfn;
    unsigned int prev_pc, this_pc;
    u32 dom = 0;
    int verify = 0; 

    /* Number of page frames in use by this Linux session. */
    unsigned long nr_pfns;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info_page[PAGE_SIZE]; /* saved contents from file */
    shared_info_t *shared_info = (shared_info_t *)shared_info_page;
    
    /* A copy of the CPU context of the guest. */
    full_execution_context_t ctxt;

    /* First 16 bytes of the state file must contain 'LinuxGuestRecord'. */
    char signature[16];
    
    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;

    /* A table of MFNs to map in the current region */
    unsigned long *region_mfn = NULL;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *ppage = NULL;

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long pfn_to_mfn_frame_list[1024];

    /* A table mapping each PFN to its new MFN. */
    unsigned long *pfn_to_mfn_table = NULL;

    /* used by mapper for updating the domain's copy of the table */
    unsigned long *live_pfn_to_mfn_table = NULL;

    /* A temporary mapping of the guest's suspend record. */
    suspend_record_t *p_srec;

    char *region_base;

    mmu_t *mmu = NULL;

    /* used by debug verify code */
    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];

    xcio_info(ioctxt, "xc_linux_restore start\n");

    if ( mlock(&ctxt, sizeof(ctxt) ) )
    {
        /* needed for when we do the build dom0 op, 
           but might as well do early */
        PERROR("Unable to mlock ctxt");
        return 1;
    }

    /* Start reading the saved-domain record. */
    if ( xcio_read(ioctxt, signature, 16) ||
         (memcmp(signature, "LinuxGuestRecord", 16) != 0) )
    {
        xcio_error(ioctxt, "Unrecognised state format -- no signature found");
        goto out;
    }

    if ( xcio_read(ioctxt, &nr_pfns,              sizeof(unsigned long)) ||
         xcio_read(ioctxt, pfn_to_mfn_frame_list, PAGE_SIZE) )
    {
        xcio_error(ioctxt, "Error reading header");
        goto out;
    }

    if ( read_vmconfig(ioctxt) )
    {
        xcio_error(ioctxt, "Error writing vmconfig");
        goto out;
    }

    if ( nr_pfns > 1024*1024 )
    {
        xcio_error(ioctxt, "Invalid state file -- pfn count out of range");
        goto out;
    }

    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_to_mfn_table = calloc(1, 4 * nr_pfns);
    pfn_type         = calloc(1, 4 * nr_pfns);    
    region_mfn       = calloc(1, 4 * MAX_BATCH_SIZE);    

    if ( (pfn_to_mfn_table == NULL) ||
         (pfn_type == NULL) || 
         (region_mfn == NULL) ) 
    {
        errno = ENOMEM;
        goto out;
    }
    
    if ( mlock(region_mfn, 4 * MAX_BATCH_SIZE ) )
    {
        xcio_error(ioctxt, "Could not mlock region_mfn");
        goto out;
    }

    /* Create domain on CPU -1 so that it may auto load-balance in future. */
    if ( xc_domain_create(xc_handle, nr_pfns * (PAGE_SIZE / 1024),
                          -1, 1, &dom) )
    {
	xcio_error(ioctxt, "Could not create domain. pfns=%d, %dKB",
		   nr_pfns,nr_pfns * (PAGE_SIZE / 1024));
        goto out;
    }
    
    ioctxt->domain = dom;
    xcio_info(ioctxt, "Created domain %ld\n",dom);

    /* Get the domain's shared-info frame. */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)dom;
    op.u.getdomaininfo.ctxt = NULL;
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        xcio_error(ioctxt, "Could not get information on new domain");
        goto out;
    }
    shared_info_frame = op.u.getdomaininfo.shared_info_frame;

    if(ioctxt->flags & XCFLAGS_CONFIGURE)
    {
        if(xcio_configure_domain(ioctxt))
        {
           xcio_error(ioctxt, "Configuring domain failed"); 
           goto out;
        }
    }

    /* Build the pfn-to-mfn table. We choose MFN ordering returned by Xen. */
    if ( get_pfn_list(xc_handle, dom, pfn_to_mfn_table, nr_pfns) != nr_pfns )
    {
        xcio_error(ioctxt, "Did not read correct number of frame "
                   "numbers for new dom");
        goto out;
    }

    if ( (mmu = init_mmu_updates(xc_handle, dom)) == NULL )
    {
        xcio_error(ioctxt, "Could not initialise for MMU updates");
        goto out;
    }

    xcio_info(ioctxt, "Reloading memory pages:   0%%");

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    prev_pc = 0;

    n = 0;
    while ( 1 )
    {
        int j;
        unsigned long region_pfn_type[MAX_BATCH_SIZE];

        this_pc = (n * 100) / nr_pfns;
        if ( (this_pc - prev_pc) >= 5 )
        {
            xcio_info(ioctxt, "\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        if ( xcio_read(ioctxt, &j, sizeof(int)) )
        {
            xcio_error(ioctxt, "Error when reading from state file");
            goto out;
        }

        DPRINTF("batch %d\n",j);
 
        if ( j == -1 )
        {
            verify = 1;
            printf("Entering page verify mode\n");
            continue;
        }

        if ( j == 0 )
            break;  /* our work here is done */

        if ( j > MAX_BATCH_SIZE )
        {
            xcio_error(ioctxt, "Max batch size exceeded. Giving up.");
            goto out;
        }
 
        if ( xcio_read(ioctxt, region_pfn_type, j*sizeof(unsigned long)) ) {
            xcio_error(ioctxt, "Error when reading from state file");
            goto out;
        }

        for ( i = 0; i < j; i++ )
        {
            if ( (region_pfn_type[i] & LTAB_MASK) == XTAB)
            {
                region_mfn[i] = 0; /* we know map will fail, but don't care */
            }
            else
            {  
                pfn = region_pfn_type[i] & ~LTAB_MASK;
                region_mfn[i] = pfn_to_mfn_table[pfn];
            }          
        }
 
        if ( (region_base = xc_map_foreign_batch( xc_handle, dom, 
                                                  PROT_WRITE,
                                                  region_mfn,
                                                  j )) == 0 )
        {
            xcio_error(ioctxt, "map batch failed");
            goto out;
        }

        for ( i = 0; i < j; i++ )
        {
            unsigned long *ppage;

            pfn = region_pfn_type[i] & ~LTAB_MASK;

            if ( (region_pfn_type[i] & LTAB_MASK) == XTAB) continue;

            if (pfn>nr_pfns)
            {
                xcio_error(ioctxt, "pfn out of range");
                goto out;
            }

            region_pfn_type[i] &= LTAB_MASK;

            pfn_type[pfn] = region_pfn_type[i];

            mfn = pfn_to_mfn_table[pfn];

            if ( verify )
                ppage = (unsigned long*) buf;  /* debug case */
            else
                ppage = (unsigned long*) (region_base + i*PAGE_SIZE);

            if ( xcio_read(ioctxt, ppage, PAGE_SIZE) )
            {
                xcio_error(ioctxt, "Error when reading from state file");
                goto out;
            }

            switch( region_pfn_type[i] & LTABTYPE_MASK )
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
                            xcio_error(ioctxt, "Frame number in type %lu page "
                                       "table is out of range. i=%d k=%d "
                                       "pfn=0x%lx nr_pfns=%lu", 
                                       region_pfn_type[i]>>28, i, 
                                       k, xpfn, nr_pfns);
                            goto out;
                        }

                        ppage[k] &= (PAGE_SIZE - 1) & 
                            ~(_PAGE_GLOBAL | _PAGE_PAT);
                        ppage[k] |= pfn_to_mfn_table[xpfn] << PAGE_SHIFT;
                    }
                }
            }
            break;

            case L2TAB:
            {
                for ( k = 0; 
                      k < (HYPERVISOR_VIRT_START>>L2_PAGETABLE_SHIFT); 
                      k++ )
                {
                    if ( ppage[k] & _PAGE_PRESENT )
                    {
                        xpfn = ppage[k] >> PAGE_SHIFT;

                        if ( xpfn >= nr_pfns )
                        {
                            xcio_error(ioctxt, "Frame number in type %lu page"
                                       " table is out of range. i=%d k=%d "
                                       "pfn=%lu nr_pfns=%lu",
                                       region_pfn_type[i]>>28, i, k, 
                                       xpfn, nr_pfns);
                            goto out;
                        }

                        ppage[k] &= (PAGE_SIZE - 1) & 
                            ~(_PAGE_GLOBAL | _PAGE_PSE);
                        ppage[k] |= pfn_to_mfn_table[xpfn] << PAGE_SHIFT;
                    }
                }
            }
            break;

            default:
                xcio_error(ioctxt, "Bogus page type %lx page table is "
                           "out of range. i=%d nr_pfns=%lu", 
                           region_pfn_type[i], i, nr_pfns);
                goto out;

            } /* end of page type switch statement */

            if ( verify )
            {
                int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE );
                if ( res )
                {
                    int v;
                    printf("************** pfn=%lx type=%lx gotcs=%08lx "
                           "actualcs=%08lx\n", pfn, pfn_type[pfn], 
                           csum_page(region_base + i*PAGE_SIZE), 
                           csum_page(buf));
                    for ( v = 0; v < 4; v++ )
                    {
                        unsigned long *p = (unsigned long *)
                            (region_base + i*PAGE_SIZE);
                        if ( buf[v] != p[v] )
                            printf("    %d: %08lx %08lx\n",
                                   v, buf[v], p[v] );
                    }
                }
            }

            if ( add_mmu_update(xc_handle, mmu,
                                (mfn<<PAGE_SHIFT) | MMU_MACHPHYS_UPDATE, pfn) )
            {
                printf("machpys mfn=%ld pfn=%ld\n",mfn,pfn);
                goto out;
            }

        } /* end of 'batch' for loop */

        munmap( region_base, j*PAGE_SIZE );
        n+=j; /* crude stats */
    }

    xcio_info(ioctxt, "Received all pages\n");

    /*
     * Pin page tables. Do this after writing to them as otherwise Xen
     * will barf when doing the type-checking.
     */
    for ( i = 0; i < nr_pfns; i++ )
    {
        if ( pfn_type[i] == (L1TAB|LPINTAB) )
        {
            if ( add_mmu_update(xc_handle, mmu,
                                (pfn_to_mfn_table[i]<<PAGE_SHIFT) | 
                                MMU_EXTENDED_COMMAND,
                                MMUEXT_PIN_L1_TABLE) ) {
                printf("ERR pin L1 pfn=%lx mfn=%lx\n",
                       (unsigned long)i, pfn_to_mfn_table[i]);
                goto out;
            }
        }
    }

    /* must pin all L1's before L2's (need consistent va back ptr) */
    for ( i = 0; i < nr_pfns; i++ )
    {
        if ( pfn_type[i] == (L2TAB|LPINTAB) )
        {
            if ( add_mmu_update(xc_handle, mmu,
                                (pfn_to_mfn_table[i]<<PAGE_SHIFT) | 
                                MMU_EXTENDED_COMMAND,
                                MMUEXT_PIN_L2_TABLE) )
            {
                printf("ERR pin L2 pfn=%lx mfn=%lx\n",
                       (unsigned long)i, pfn_to_mfn_table[i]);
                goto out;
            }
        }
    }

    if ( finish_mmu_updates(xc_handle, mmu) ) goto out;

    xcio_info(ioctxt, "\b\b\b\b100%%\n");
    xcio_info(ioctxt, "Memory reloaded.\n");

    /* Get the list of PFNs that are not in the psuedo-phys map */
    {
	unsigned int count, *pfntab;
	int rc;

	if ( xcio_read(ioctxt, &count, sizeof(count)) )
	{
	    xcio_error(ioctxt, "Error when reading from state file");
	    goto out;
	}

	pfntab = malloc( sizeof(unsigned int) * count );
	if ( pfntab == NULL )
	{
	    xcio_error(ioctxt, "Out of memory");
	    goto out;
	}

	if ( xcio_read(ioctxt, pfntab, sizeof(unsigned int)*count) )
	{
	    xcio_error(ioctxt, "Error when reading pfntab from state file");
	    goto out;
	}

	for ( i = 0; i < count; i++ )
	{
	    unsigned long pfn = pfntab[i];
	    pfntab[i]=pfn_to_mfn_table[pfn];
	    pfn_to_mfn_table[pfn] = 0x80000001;  // not in pmap
	}

	if ( count > 0 )
	{
	    if ( (rc = do_dom_mem_op( xc_handle,
				       MEMOP_decrease_reservation,
				       pfntab, count, 0, dom )) <0 )
	    {
		xcio_error(ioctxt, "Could not decrease reservation : %d",rc);
		goto out;
	    }
	    else
	    {
		printf("Decreased reservation by %d pages\n", count);
	    }
	}	
    }

    if ( xcio_read(ioctxt, &ctxt,            sizeof(ctxt)) ||
         xcio_read(ioctxt, shared_info_page, PAGE_SIZE) )
    {
        xcio_error(ioctxt, "Error when reading from state file");
        goto out;
    }

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    pfn = ctxt.cpu_ctxt.esi;
    if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NOTAB) )
    {
        xcio_error(ioctxt, "Suspend record frame number is bad");
        goto out;
    }
    ctxt.cpu_ctxt.esi = mfn = pfn_to_mfn_table[pfn];
    p_srec = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_WRITE, mfn);
    p_srec->resume_info.nr_pages    = nr_pfns;
    p_srec->resume_info.shared_info = shared_info_frame << PAGE_SHIFT;
    p_srec->resume_info.flags       = 0;
    munmap(p_srec, PAGE_SIZE);

    /* Uncanonicalise each GDT frame number. */
    if ( ctxt.gdt_ents > 8192 )
    {
        xcio_error(ioctxt, "GDT entry count out of range");
        goto out;
    }

    for ( i = 0; i < ctxt.gdt_ents; i += 512 )
    {
        pfn = ctxt.gdt_frames[i];
        if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NOTAB) )
        {
            xcio_error(ioctxt, "GDT frame number is bad");
            goto out;
        }
        ctxt.gdt_frames[i] = pfn_to_mfn_table[pfn];
    }

    /* Uncanonicalise the page table base pointer. */
    pfn = ctxt.pt_base >> PAGE_SHIFT;
    if ( (pfn >= nr_pfns) || ((pfn_type[pfn]&LTABTYPE_MASK) != L2TAB) )
    {
        printf("PT base is bad. pfn=%lu nr=%lu type=%08lx %08lx\n",
               pfn, nr_pfns, pfn_type[pfn], (unsigned long)L2TAB);
        xcio_error(ioctxt, "PT base is bad.");
        goto out;
    }
    ctxt.pt_base = pfn_to_mfn_table[pfn] << PAGE_SHIFT;

    /* clear any pending events and the selector */
    memset(&(shared_info->evtchn_pending[0]), 0,
	   sizeof (shared_info->evtchn_pending));
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_data[i].evtchn_pending_sel = 0;

    /* Copy saved contents of shared-info page. No checking needed. */
    ppage = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_WRITE, shared_info_frame);
    memcpy(ppage, shared_info, sizeof(shared_info_t));
    munmap(ppage, PAGE_SIZE);

    /* Uncanonicalise the pfn-to-mfn table frame-number list. */
    for ( i = 0; i < (nr_pfns+1023)/1024; i++ )
    {
        unsigned long pfn, mfn;

        pfn = pfn_to_mfn_frame_list[i];
        if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NOTAB) )
        {
            xcio_error(ioctxt, "PFN-to-MFN frame number is bad");
            goto out;
        }
        mfn = pfn_to_mfn_table[pfn];
        pfn_to_mfn_frame_list[i] = mfn;
    }
    
    if ( (live_pfn_to_mfn_table = 
	  xc_map_foreign_batch(xc_handle, dom, 
                               PROT_WRITE,
                               pfn_to_mfn_frame_list,
                               (nr_pfns+1023)/1024 )) == 0 )
    {
        xcio_error(ioctxt, "Couldn't map pfn_to_mfn table");
        goto out;
    }

    memcpy(live_pfn_to_mfn_table, pfn_to_mfn_table, 
           nr_pfns*sizeof(unsigned long) );

    munmap(live_pfn_to_mfn_table, ((nr_pfns+1023)/1024)*PAGE_SIZE);

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
        xcio_error(ioctxt, "Bad LDT base or size");
        goto out;
    }

    xcio_info(ioctxt, "Domain ready to be built.\n");

    op.cmd = DOM0_BUILDDOMAIN;
    op.u.builddomain.domain   = (domid_t)dom;
    op.u.builddomain.ctxt = &ctxt;
    rc = do_dom0_op(xc_handle, &op);

    if ( rc != 0 )
    {
        xcio_error(ioctxt, "Couldn't build the domain");
        goto out;
    }

    if ( ioctxt->flags & XCFLAGS_CONFIGURE )
    {
        xcio_info(ioctxt, "Domain ready to be unpaused\n");
        op.cmd = DOM0_UNPAUSEDOMAIN;
        op.u.unpausedomain.domain = (domid_t)dom;
        rc = do_dom0_op(xc_handle, &op);
    }

    if ( rc == 0 )
    {
        /* Success: print the domain id. */
        xcio_info(ioctxt, "DOM=%lu\n", dom);
        return 0;
    }


 out:
    if ( (rc != 0) && (dom != 0) )
        xc_domain_destroy(xc_handle, dom);
    if ( mmu != NULL )
        free(mmu);
    if ( pfn_to_mfn_table != NULL )
        free(pfn_to_mfn_table);
    if ( pfn_type != NULL )
        free(pfn_type);

    if ( rc == 0 )
        ioctxt->domain = dom;

    DPRINTF("Restore exit with rc=%d\n",rc);
    return rc;
}
