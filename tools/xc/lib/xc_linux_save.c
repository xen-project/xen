/******************************************************************************
 * xc_linux_save.c
 * 
 * Save the state of a running Xenolinux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include <asm-xeno/suspend.h>
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
     (pfn_to_mfn_table[mfn_to_pfn_table[_mfn]] == (_mfn)))

/* Returns TRUE if MFN is successfully converted to a PFN. */
#define translate_mfn_to_pfn(_pmfn)         \
({                                          \
    unsigned long mfn = *(_pmfn);           \
    int _res = 1;                           \
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )   \
        _res = 0;                           \
    else                                    \
        *(_pmfn) = mfn_to_pfn_table[mfn];   \
    _res;                                   \
})

static int check_pfn_ownership(int xc_handle, 
                               unsigned long mfn, 
                               unsigned int dom)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn    = mfn;
    op.u.getpageframeinfo.domain = dom;
    return (do_dom0_op(xc_handle, &op) >= 0);
}

#define GETPFN_ERR (~0U)
static unsigned int get_pfn_type(int xc_handle, 
                                 unsigned long mfn, 
                                 unsigned int dom)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn    = mfn;
    op.u.getpageframeinfo.domain = dom;
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
                  unsigned int domid, 
                  const char *state_file, 
                  int verbose)
{
    dom0_op_t op;
    int rc = 1, i, j;
    unsigned long mfn;
    unsigned int prev_pc, this_pc;

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
    unsigned long *ppage, page[1024];

    /* A temporary mapping, and a copy, of the pfn-to-mfn table frame list. */
    unsigned long *p_pfn_to_mfn_frame_list, pfn_to_mfn_frame_list[1024];
    /* A temporary mapping of one frame in the above list. */
    unsigned long *pfn_to_mfn_frame;

    /* A table mapping each PFN to its current MFN. */
    unsigned long *pfn_to_mfn_table = NULL;
    /* A table mapping each current MFN to its canonical PFN. */
    unsigned long *mfn_to_pfn_table = NULL;
    
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
        op.u.getdomaininfo.domain = domid;
        if ( (do_dom0_op(xc_handle, &op) < 0) || 
             (op.u.getdomaininfo.domain != domid) )
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
        op.u.stopdomain.domain = domid;
        (void)do_dom0_op(xc_handle, &op);

        sleep(1);
    }

    /* A cheesy test to see whether the domain contains valid state. */
    if ( ctxt.pt_base == 0 )
    {
        ERROR("Domain is not in a valid Xenolinux state");
        goto out;
    }

    if ( (pm_handle = init_pfn_mapper()) < 0 )
        goto out;

    /* Is the suspend-record MFN actually valid for this domain? */
    if ( !check_pfn_ownership(xc_handle, ctxt.i386_ctxt.esi, domid) )
    {
        ERROR("Invalid state record pointer");
        goto out;
    }

    /* If the suspend-record MFN is okay then grab a copy of it to @srec. */
    p_srec = map_pfn(pm_handle, ctxt.i386_ctxt.esi);
    memcpy(&srec, p_srec, sizeof(srec));
    unmap_pfn(pm_handle, p_srec);

    if ( srec.nr_pfns > 1024*1024 )
    {
        ERROR("Invalid state record -- pfn count out of range");
        goto out;
    }

    if ( !check_pfn_ownership(xc_handle, srec.pfn_to_mfn_frame_list, domid) )
    {
        ERROR("Invalid pfn-to-mfn frame list pointer");
        goto out;
    }

    /* Grab a copy of the pfn-to-mfn table frame list. */
    p_pfn_to_mfn_frame_list = map_pfn(pm_handle, srec.pfn_to_mfn_frame_list);
    memcpy(pfn_to_mfn_frame_list, p_pfn_to_mfn_frame_list, PAGE_SIZE);
    unmap_pfn(pm_handle, p_pfn_to_mfn_frame_list);

    /* We want zeroed memory so use calloc rather than malloc. */
    mfn_to_pfn_table = calloc(1, 4 * 1024 * 1024);
    pfn_to_mfn_table = calloc(1, 4 * srec.nr_pfns);
    pfn_type         = calloc(1, 4 * srec.nr_pfns);

    if ( (mfn_to_pfn_table == NULL) ||
         (pfn_to_mfn_table == NULL) ||
         (pfn_type == NULL) )
    {
        errno = ENOMEM;
        goto out;
    }


    /*
     * Construct the local pfn-to-mfn and mfn-to-pfn tables. On exit from this
     * loop we have each MFN mapped at most once. Note that there may be MFNs
     * that aren't mapped at all: we detect these by MFN_IS_IN_PSEUDOPHYS_MAP.
     */
    pfn_to_mfn_frame = NULL;
    for ( i = 0; i < srec.nr_pfns; i++ )
    {
        /* Each frameful of table frames must be checked & mapped on demand. */
        if ( (i & 1023) == 0 )
        {
            mfn = pfn_to_mfn_frame_list[i/1024];
            if ( !check_pfn_ownership(xc_handle, mfn, domid) )
            {
                ERROR("Invalid frame number if pfn-to-mfn frame list");
                goto out;
            }
            if ( pfn_to_mfn_frame != NULL )
                unmap_pfn(pm_handle, pfn_to_mfn_frame);
            pfn_to_mfn_frame = map_pfn(pm_handle, mfn);
        }
        
        mfn = pfn_to_mfn_frame[i & 1023];

        if ( !check_pfn_ownership(xc_handle, mfn, domid) )
        {
            ERROR("Invalid frame specified with pfn-to-mfn table");
            goto out;
        }

        /* Did we map this MFN already? That would be invalid! */
        if ( MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
        {
            ERROR("A machine frame appears twice in pseudophys space");
            goto out;
        }

        pfn_to_mfn_table[i] = mfn;
        mfn_to_pfn_table[mfn] = i;

        /* Query page type by MFN, but store it by PFN. */
        if ( (pfn_type[i] = get_pfn_type(xc_handle, mfn, domid)) == 
             GETPFN_ERR )
            goto out;
    }

    /* Canonicalise the suspend-record frame number. */
    if ( !translate_mfn_to_pfn(&ctxt.i386_ctxt.esi) )
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
    ctxt.pt_base = mfn_to_pfn_table[ctxt.pt_base >> PAGE_SHIFT] << PAGE_SHIFT;

    /* Canonicalise the pfn-to-mfn table frame-number list. */
    for ( i = 0; i < srec.nr_pfns; i += 1024 )
    {
        if ( !translate_mfn_to_pfn(&pfn_to_mfn_frame_list[i/1024]) )
        {
            ERROR("Frame # in pfn-to-mfn frame list is not in pseudophys");
            goto out;
        }
    }

    /* Start writing out the saved-domain record. */
    ppage = map_pfn(pm_handle, shared_info_frame);
    if ( !checked_write(gfd, "XenoLinuxSuspend",    16) ||
         !checked_write(gfd, name,                  sizeof(name)) ||
         !checked_write(gfd, &srec.nr_pfns,         sizeof(unsigned long)) ||
         !checked_write(gfd, &ctxt,                 sizeof(ctxt)) ||
         !checked_write(gfd, ppage,                 PAGE_SIZE) ||
         !checked_write(gfd, pfn_to_mfn_frame_list, PAGE_SIZE) ||
         !checked_write(gfd, pfn_type,              4 * srec.nr_pfns) )
    {
        ERROR("Error when writing to state file");
        goto out;
    }
    unmap_pfn(pm_handle, ppage);

    verbose_printf("Saving memory pages:   0%%");

    /* Now write out each data page, canonicalising page tables as we go... */
    prev_pc = 0;
    for ( i = 0; i < srec.nr_pfns; i++ )
    {
        this_pc = (i * 100) / srec.nr_pfns;
        if ( (this_pc - prev_pc) >= 5 )
        {
            verbose_printf("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        mfn = pfn_to_mfn_table[i];

        ppage = map_pfn(pm_handle, mfn);
        memcpy(page, ppage, PAGE_SIZE);
        unmap_pfn(pm_handle, ppage);

        if ( (pfn_type[i] == L1TAB) || (pfn_type[i] == L2TAB) )
        {
            for ( j = 0; 
                  j < ((pfn_type[i] == L2TAB) ? 
                       (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT) : 1024); 
                  j++ )
            {
                if ( !(page[j] & _PAGE_PRESENT) ) continue;
                mfn = page[j] >> PAGE_SHIFT;
                if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
                {
                    ERROR("Frame number in pagetable page is invalid");
                    goto out;
                }
                page[j] &= PAGE_SIZE - 1;
                page[j] |= mfn_to_pfn_table[mfn] << PAGE_SHIFT;
            }
        }

        if ( !checked_write(gfd, page, PAGE_SIZE) )
        {
            ERROR("Error when writing to state file");
            goto out;
        }
    }

    verbose_printf("\b\b\b\b100%%\nMemory saved.\n");

    /* Success! */
    rc = 0;

 out:
    /* Restart the domain if we had to stop it to save its state. */
    if ( we_stopped_it )
    {
        op.cmd = DOM0_STARTDOMAIN;
        op.u.startdomain.domain = domid;
        (void)do_dom0_op(xc_handle, &op);
    }

    gzclose(gfd);

    if ( pm_handle >= 0 )
        (void)close_pfn_mapper(pm_handle);

    if ( pfn_to_mfn_table != NULL )
        free(pfn_to_mfn_table);
    if ( mfn_to_pfn_table != NULL )
        free(mfn_to_pfn_table);
    if ( pfn_type != NULL )
        free(pfn_type);

    /* On error, make sure the file is deleted. */
    if ( rc != 0 )
        unlink(state_file);
    
    return !!rc;
}
