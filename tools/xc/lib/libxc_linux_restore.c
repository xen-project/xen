/******************************************************************************
 * libxc_linux_restore.c
 * 
 * Restore the state of a Xenolinux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "libxc_private.h"
#include <asm-xeno/suspend.h>
#include <zlib.h>

/* This may allow us to create a 'quiet' command-line option, if necessary. */
#define verbose_printf(_f, _a...) \
    do {                          \
        if ( !verbose ) break;    \
        printf( _f , ## _a );     \
        fflush(stdout);           \
    } while ( 0 )

static int get_pfn_list(int xc_handle,
                        int domain_id, 
                        unsigned long *pfn_buf, 
                        unsigned long max_pfns)
{
    dom0_op_t op;
    int ret;
    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = domain_id;
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

#define MAX_MMU_UPDATES 1024

static int flush_mmu_updates(int xc_handle,
                             mmu_update_t *mmu_updates,
                             int *mmu_update_idx)
{
    int err = 0;
    privcmd_hypercall_t hypercall;

    if ( *mmu_update_idx == 0 )
        return 0;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu_updates;
    hypercall.arg[1] = (unsigned long)*mmu_update_idx;

    if ( mlock(mmu_updates, sizeof(mmu_updates)) != 0 )
    {
        PERROR("Could not lock pagetable update array");
        err = 1;
        goto out;
    }

    if ( do_xen_hypercall(xc_handle, &hypercall) < 0 )
    {
        ERROR("Failure when submitting mmu updates");
        err = 1;
    }

    *mmu_update_idx = 0;
    
    (void)munlock(mmu_updates, sizeof(mmu_updates));

 out:
    return err;
}

static int add_mmu_update(int xc_handle,
                          mmu_update_t *mmu_updates,
                          int *mmu_update_idx,
                          unsigned long ptr, 
                          unsigned long val)
{
    mmu_updates[*mmu_update_idx].ptr = ptr;
    mmu_updates[*mmu_update_idx].val = val;
    if ( ++*mmu_update_idx == MAX_MMU_UPDATES )
        return flush_mmu_updates(xc_handle, mmu_updates, mmu_update_idx);
    return 0;
}

static int checked_read(gzFile fd, void *buf, size_t count)
{
    int rc;
    while ( ((rc = gzread(fd, buf, count)) == -1) && (errno == EINTR) )
        continue;
    return rc == count;
}

int xc_linux_restore(int xc_handle,
                     const char *state_file,
                     int verbose)
{
    dom0_op_t op;
    int rc = 1, i, j;
    unsigned long mfn, pfn, dom = 0;
    unsigned int prev_pc, this_pc;
    
    /* Number of page frames in use by this XenoLinux session. */
    unsigned long nr_pfns;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info[PAGE_SIZE]; /* saved contents from file */
    
    /* A copy of the CPU context of the guest. */
    full_execution_context_t ctxt;

    /* First 16 bytes of the state file must contain 'XenoLinuxSuspend'. */
    char signature[16];
    
    /* A copy of the domain's name. */
    char name[MAX_DOMAIN_NAME];

    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *ppage, page[1024];

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long pfn_to_mfn_frame_list[1024];

    /* A table mapping each PFN to its new MFN. */
    unsigned long *pfn_to_mfn_table = NULL;

    /* A temporary mapping of the guest's suspend record. */
    suspend_record_t *p_srec;

    /* The name and descriptor of the file that we are reading from. */
    int    fd;
    gzFile gfd;

    mmu_update_t mmu_updates[MAX_MMU_UPDATES];
    int mmu_update_idx = 0;

    int pm_handle = -1;

    if ( (fd = open(state_file, O_RDONLY)) == -1 )
    {
        PERROR("Could not open state file for reading");
        return 1;
    }

    if ( (gfd = gzdopen(fd, "rb")) == NULL )
    {
        ERROR("Could not allocate decompression state for state file");
        close(fd);
        return 1;
    }

    /* Start writing out the saved-domain record. */
    if ( !checked_read(gfd, signature, 16) ||
         (memcmp(signature, "XenoLinuxSuspend", 16) != 0) )
    {
        ERROR("Unrecognised state format -- no signature found");
        goto out;
    }

    if ( !checked_read(gfd, name,                  sizeof(name)) ||
         !checked_read(gfd, &nr_pfns,              sizeof(unsigned long)) ||
         !checked_read(gfd, &ctxt,                 sizeof(ctxt)) ||
         !checked_read(gfd, shared_info,           PAGE_SIZE) ||
         !checked_read(gfd, pfn_to_mfn_frame_list, PAGE_SIZE) )
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

    if ( !checked_read(gfd, pfn_type, 4 * nr_pfns) )
    {
        ERROR("Error when reading from state file");
        goto out;
    }

    /* Create a new domain of the appropriate size, and find it's dom_id. */
    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.memory_kb = nr_pfns * (PAGE_SIZE / 1024);
    memcpy(op.u.createdomain.name, name, MAX_DOMAIN_NAME);
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        ERROR("Could not create new domain");
        goto out;
    }
    dom = op.u.createdomain.domain;

    /* Get the domain's shared-info frame. */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = dom;
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        ERROR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = op.u.getdomaininfo.shared_info_frame;

    if ( (pm_handle = init_pfn_mapper()) < 0 )
        goto out;

    /* Copy saved contents of shared-info page. No checking needed. */
    ppage = map_pfn(pm_handle, shared_info_frame);
    memcpy(ppage, shared_info, PAGE_SIZE);
    unmap_pfn(pm_handle, ppage);

    /* Build the pfn-to-mfn table. We choose MFN ordering returned by Xen. */
    if ( get_pfn_list(xc_handle, dom, pfn_to_mfn_table, nr_pfns) != nr_pfns )
    {
        ERROR("Did not read correct number of frame numbers for new dom");
        goto out;
    }

    verbose_printf("Reloading memory pages:   0%%");

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    prev_pc = 0;
    for ( i = 0; i < nr_pfns; i++ )
    {
        this_pc = (i * 100) / nr_pfns;
        if ( (this_pc - prev_pc) >= 5 )
        {
            verbose_printf("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        mfn = pfn_to_mfn_table[i];

        if ( !checked_read(gfd, page, PAGE_SIZE) )
        {
            ERROR("Error when reading from state file");
            goto out;
        }

        ppage = map_pfn(pm_handle, mfn);
        switch ( pfn_type[i] )
        {
        case L1TAB:
            memset(ppage, 0, PAGE_SIZE);
            if ( add_mmu_update(xc_handle, mmu_updates, &mmu_update_idx,
                                (mfn<<PAGE_SHIFT) | MMU_EXTENDED_COMMAND,
                                MMUEXT_PIN_L1_TABLE) )
                goto out;
            for ( j = 0; j < 1024; j++ )
            {
                if ( page[j] & _PAGE_PRESENT )
                {
                    if ( (pfn = page[j] >> PAGE_SHIFT) >= nr_pfns )
                    {
                        ERROR("Frame number in page table is out of range");
                        goto out;
                    }
                    if ( (pfn_type[pfn] != NONE) && (page[j] & _PAGE_RW) )
                    {
                        ERROR("Write access requested for a restricted frame");
                        goto out;
                    }
                    page[j] &= (PAGE_SIZE - 1) & ~(_PAGE_GLOBAL | _PAGE_PAT);
                    page[j] |= pfn_to_mfn_table[pfn] << PAGE_SHIFT;
                }
                if ( add_mmu_update(xc_handle, mmu_updates, &mmu_update_idx,
                                    (unsigned long)&ppage[j], page[j]) )
                    goto out;
            }
            break;
        case L2TAB:
            memset(ppage, 0, PAGE_SIZE);
            if ( add_mmu_update(xc_handle, mmu_updates, &mmu_update_idx,
                                (mfn<<PAGE_SHIFT) | MMU_EXTENDED_COMMAND,
                                MMUEXT_PIN_L2_TABLE) )
                goto out;
            for ( j = 0; j < (HYPERVISOR_VIRT_START>>L2_PAGETABLE_SHIFT); j++ )
            {
                if ( page[j] & _PAGE_PRESENT )
                {
                    if ( (pfn = page[j] >> PAGE_SHIFT) >= nr_pfns )
                    {
                        ERROR("Frame number in page table is out of range");
                        goto out;
                    }
                    if ( pfn_type[pfn] != L1TAB )
                    {
                        ERROR("Page table mistyping");
                        goto out;
                    }
                    /* Haven't reached the L1 table yet. Ensure it is safe! */
                    if ( pfn > i )
                    {
                        unsigned long **l1 = map_pfn(pm_handle, 
                                                     pfn_to_mfn_table[pfn]);
                        memset(l1, 0, PAGE_SIZE);
                        unmap_pfn(pm_handle, l1);
                    }
                    page[j] &= (PAGE_SIZE - 1) & ~(_PAGE_GLOBAL | _PAGE_PSE);
                    page[j] |= pfn_to_mfn_table[pfn] << PAGE_SHIFT;
                }
                if ( add_mmu_update(xc_handle, mmu_updates, &mmu_update_idx,
                                    (unsigned long)&ppage[j], page[j]) )
                    goto out;
            }
            break;
        default:
            memcpy(ppage, page, PAGE_SIZE);
            break;
        }
        /* NB. Must flush before unmapping page, as pass VAs to Xen. */
        if ( flush_mmu_updates(xc_handle, mmu_updates, &mmu_update_idx) )
            goto out;
        unmap_pfn(pm_handle, ppage);

        if ( add_mmu_update(xc_handle, mmu_updates, &mmu_update_idx,
                            (mfn<<PAGE_SHIFT) | MMU_MACHPHYS_UPDATE, i) )
            goto out;
    }

    if ( flush_mmu_updates(xc_handle, mmu_updates, &mmu_update_idx) )
        goto out;

    verbose_printf("\b\b\b\b100%%\nMemory reloaded.\n");

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    pfn = ctxt.i386_ctxt.esi;
    if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NONE) )
    {
        ERROR("Suspend record frame number is bad");
        goto out;
    }
    ctxt.i386_ctxt.esi = mfn = pfn_to_mfn_table[pfn];
    p_srec = map_pfn(pm_handle, mfn);
    p_srec->resume_info.nr_pages    = nr_pfns;
    p_srec->resume_info.shared_info = shared_info_frame << PAGE_SHIFT;
    p_srec->resume_info.dom_id      = dom;
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
        ERROR("PT base is bad");
        goto out;
    }
    ctxt.pt_base = pfn_to_mfn_table[pfn] << PAGE_SHIFT;

    /* Uncanonicalise the pfn-to-mfn table frame-number list. */
    for ( i = 0; i < nr_pfns; i += 1024 )
    {
        unsigned long copy_size = (nr_pfns - i) * sizeof(unsigned long);
        if ( copy_size > PAGE_SIZE ) copy_size = PAGE_SIZE;
        pfn = pfn_to_mfn_frame_list[i/1024];
        if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NONE) )
        {
            ERROR("PFN-to-MFN frame number is bad");
            goto out;
        }
        ppage = map_pfn(pm_handle, pfn_to_mfn_table[pfn]);
        memcpy(ppage, &pfn_to_mfn_table[i], copy_size);        
        unmap_pfn(pm_handle, ppage);
    }

    /*
     * Safety checking of saved context:
     *  1. i386_ctxt is fine, as Xen checks that on context switch.
     *  2. i387_ctxt is fine, as it can't hurt Xen.
     *  3. trap_ctxt needs the code selectors checked.
     *  4. fast_trap_idx is checked by Xen.
     *  5. ldt base must be page-aligned, no more than 8192 ents, ...
     *  6. gdt already done, and further checking is done by Xen.
     *  7. check that ring1_ss is safe.
     *  8. pt_base is already done.
     *  9. debugregs are checked by Xen.
     *  10. callback code selectors need checking.
     */
    for ( i = 0; i < 256; i++ )
    {
        ctxt.trap_ctxt[i].vector = i;
        if ( (ctxt.trap_ctxt[i].cs & 3) == 0 )
            ctxt.trap_ctxt[i].cs = FLAT_RING1_CS;
    }
    if ( (ctxt.ring1_ss & 3) == 0 )
        ctxt.ring1_ss = FLAT_RING1_DS;
    if ( (ctxt.event_callback_cs & 3) == 0 )
        ctxt.event_callback_cs = FLAT_RING1_CS;
    if ( (ctxt.failsafe_callback_cs & 3) == 0 )
        ctxt.failsafe_callback_cs = FLAT_RING1_CS;
    if ( ((ctxt.ldt_base & (PAGE_SIZE - 1)) != 0) ||
         (ctxt.ldt_ents > 8192) ||
         (ctxt.ldt_base > HYPERVISOR_VIRT_START) ||
         ((ctxt.ldt_base + ctxt.ldt_ents*8) > HYPERVISOR_VIRT_START) )
    {
        ERROR("Bad LDT base or size");
        goto out;
    }

    op.cmd = DOM0_BUILDDOMAIN;
    op.u.builddomain.domain   = dom;
    op.u.builddomain.num_vifs = 1;
    memcpy(&op.u.builddomain.ctxt, &ctxt, sizeof(ctxt));
    rc = do_dom0_op(xc_handle, &op);

 out:
    if ( rc != 0 )
    {
        if ( dom != 0 )
        {
            op.cmd = DOM0_DESTROYDOMAIN;
            op.u.destroydomain.domain = dom;
            op.u.destroydomain.force  = 1;
            (void)do_dom0_op(xc_handle, &op);
        }
    }
    else
    {
        /* Success: print the domain id. */
        verbose_printf("DOM=%ld\n", dom);
    }

    if ( pm_handle >= 0 )
        (void)close_pfn_mapper(pm_handle);

    if ( pfn_to_mfn_table != NULL )
        free(pfn_to_mfn_table);
    if ( pfn_type != NULL )
        free(pfn_type);

    gzclose(gfd);

    return (rc == 0) ? dom : rc;
}
