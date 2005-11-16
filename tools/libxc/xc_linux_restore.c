/******************************************************************************
 * xc_linux_restore.c
 * 
 * Restore the state of a Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xg_save_restore.h"

/* max mfn of the whole machine */
static unsigned long max_mfn; 

/* virtual starting address of the hypervisor */
static unsigned long hvirt_start; 

/* #levels of page tables used by the currrent guest */
static unsigned int pt_levels; 

/* total number of pages used by the current guest */
static unsigned long max_pfn;

/* Live mapping of the table mapping each PFN to its current MFN. */
static unsigned long *live_p2m = NULL;

/* A table mapping each PFN to its new MFN. */
static unsigned long *p2m = NULL;


static ssize_t
read_exact(int fd, void *buf, size_t count)
{
    int r = 0, s;
    unsigned char *b = buf;

    while (r < count) {
        s = read(fd, &b[r], count - r);
        if ((s == -1) && (errno == EINTR))
            continue;
        if (s <= 0) { 
            break;
        } 
        r += s;
    }

    return (r == count) ? 1 : 0; 
}

/*
** In the state file (or during transfer), all page-table pages are 
** converted into a 'canonical' form where references to actual mfns 
** are replaced with references to the corresponding pfns. 
** This function inverts that operation, replacing the pfn values with 
** the (now known) appropriate mfn values. 
*/
int uncanonicalize_pagetable(unsigned long type, void *page) 
{ 
    int i, pte_last; 
    unsigned long pfn; 
    uint64_t pte; 

    pte_last = PAGE_SIZE / ((pt_levels == 2)? 4 : 8); 

    /* Now iterate through the page table, uncanonicalizing each PTE */
    for(i = 0; i < pte_last; i++) { 
        
        if(pt_levels == 2) 
            pte = ((uint32_t *)page)[i]; 
        else 
            pte = ((uint64_t *)page)[i]; 

        if(pte & _PAGE_PRESENT) { 

            pfn = (pte >> PAGE_SHIFT) & 0xffffffff;
            
            if(pfn >= max_pfn) { 
                ERR("Frame number in type %lu page table is out of range: "
                    "i=%d pfn=0x%lx max_pfn=%lu", 
                    type >> 28, i, pfn, max_pfn);
                return 0; 
            } 
            
            
            pte &= 0xffffff0000000fffULL;
            pte |= (uint64_t)p2m[pfn] << PAGE_SHIFT;

            if(pt_levels == 2) 
                ((uint32_t *)page)[i] = (uint32_t)pte; 
            else 
                ((uint64_t *)page)[i] = (uint64_t)pte; 

        

        }
    }
    
    return 1; 
}

int xc_linux_restore(int xc_handle, int io_fd, 
                     uint32_t dom, unsigned long nr_pfns, 
                     unsigned int store_evtchn, unsigned long *store_mfn,
                     unsigned int console_evtchn, unsigned long *console_mfn)
{
    dom0_op_t op;
    int rc = 1, i, n;
    unsigned long mfn, pfn; 
    unsigned int prev_pc, this_pc;
    int verify = 0;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info_page[PAGE_SIZE]; /* saved contents from file */
    shared_info_t *shared_info = (shared_info_t *)shared_info_page;
    
    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    /* A table containing the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;

    /* A table of MFNs to map in the current region */
    unsigned long *region_mfn = NULL;

    /* Types of the pfns in the current region */
    unsigned long region_pfn_type[MAX_BATCH_SIZE];

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *page = NULL;

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long *p2m_frame_list = NULL; 

    /* A temporary mapping of the guest's start_info page. */
    start_info_t *start_info;

    char *region_base;

    xc_mmu_t *mmu = NULL;

    /* used by debug verify code */
    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];

    struct mmuext_op pin[MAX_PIN_BATCH];
    unsigned int nr_pins = 0;


    max_pfn = nr_pfns; 

    DPRINTF("xc_linux_restore start: max_pfn = %lx\n", max_pfn);


    if(!get_platform_info(xc_handle, dom, 
                          &max_mfn, &hvirt_start, &pt_levels)) {
        ERR("Unable to get platform info."); 
        return 1;
    }


    if (mlock(&ctxt, sizeof(ctxt))) {
        /* needed for build dom0 op, but might as well do early */
        ERR("Unable to mlock ctxt");
        return 1;
    }


    /* Only have to worry about vcpu 0 even for SMP */
    if (xc_domain_get_vcpu_context( xc_handle, dom, 0, &ctxt)) {
        ERR("Could not get vcpu context");
        goto out;
    }

    
    /* Read the saved P2M frame list */
    if(!(p2m_frame_list = malloc(P2M_FL_SIZE))) { 
        ERR("Couldn't allocate p2m_frame_list array");
        goto out;
    }
    
    if (!read_exact(io_fd, p2m_frame_list, P2M_FL_SIZE)) { 
        ERR("read p2m_frame_list failed");
        goto out;
    }

    
    /* We want zeroed memory so use calloc rather than malloc. */
    p2m        = calloc(sizeof(unsigned long), max_pfn); 
    pfn_type   = calloc(sizeof(unsigned long), max_pfn);    
    region_mfn = calloc(sizeof(unsigned long), MAX_BATCH_SIZE);

    if ((p2m == NULL) || (pfn_type == NULL) || (region_mfn == NULL)) {
        ERR("memory alloc failed");
        errno = ENOMEM;
        goto out;
    }
    
    if (mlock(region_mfn, sizeof(unsigned long) * MAX_BATCH_SIZE)) {
        ERR("Could not mlock region_mfn");
        goto out;
    }

    /* Get the domain's shared-info frame. */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)dom;
    if (xc_dom0_op(xc_handle, &op) < 0) {
        ERR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = op.u.getdomaininfo.shared_info_frame;

    if(xc_domain_setmaxmem(xc_handle, dom, PFN_TO_KB(max_pfn)) != 0) { 
        errno = ENOMEM;
        goto out;
    }
    
    if(xc_domain_memory_increase_reservation(
           xc_handle, dom, max_pfn, 0, 0, NULL) != 0) { 
        ERR("Failed to increase reservation by %lx KB\n", PFN_TO_KB(max_pfn));
        errno = ENOMEM;
        goto out;
    }

    DPRINTF("Increased domain reservation by %lx KB\n", PFN_TO_KB(max_pfn)); 

    /* Build the pfn-to-mfn table. We choose MFN ordering returned by Xen. */
    if (xc_get_pfn_list(xc_handle, dom, p2m, max_pfn) != max_pfn) {
        ERR("Did not read correct number of frame numbers for new dom");
        goto out;
    }
    
    if(!(mmu = xc_init_mmu_updates(xc_handle, dom))) { 
        ERR("Could not initialise for MMU updates");
        goto out;
    }


    DPRINTF("Reloading memory pages:   0%%\n");

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    prev_pc = 0;

    n = 0;
    while (1) { 

        int j;

        this_pc = (n * 100) / max_pfn;
        if ( (this_pc - prev_pc) >= 5 )
        {
            PPRINTF("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        if (!read_exact(io_fd, &j, sizeof(int))) { 
            ERR("Error when reading batch size");
            goto out;
        }

        PPRINTF("batch %d\n",j);
 
        if (j == -1) {
            verify = 1;
            fprintf(stderr, "Entering page verify mode\n");
            continue;
        }

        if (j == 0)
            break;  /* our work here is done */

        if (j > MAX_BATCH_SIZE) { 
            ERR("Max batch size exceeded. Giving up.");
            goto out;
        }
 
        if (!read_exact(io_fd, region_pfn_type, j*sizeof(unsigned long))) { 
            ERR("Error when reading region pfn types");
            goto out;
        }

        for (i = 0; i < j; i++) { 

            if ((region_pfn_type[i] & LTAB_MASK) == XTAB)
                region_mfn[i] = 0; /* we know map will fail, but don't care */
            else 
                region_mfn[i] = p2m[region_pfn_type[i] & ~LTAB_MASK]; 

        }
 
        if (!(region_base = xc_map_foreign_batch(
                  xc_handle, dom, PROT_WRITE, region_mfn, j))) {  
            ERR("map batch failed");
            goto out;
        }

        for ( i = 0; i < j; i++ )
        {
            void *page;
            unsigned long pagetype; 

            pfn      = region_pfn_type[i] & ~LTAB_MASK;
            pagetype = region_pfn_type[i] & LTAB_MASK; 

            if (pagetype == XTAB) 
                /* a bogus/unmapped page: skip it */
                continue;

            if (pfn > max_pfn) {
                ERR("pfn out of range");
                goto out;
            }

            pfn_type[pfn] = pagetype; 

            mfn = p2m[pfn];

            /* In verify mode, we use a copy; otherwise we work in place */
            page = verify ? (void *)buf : (region_base + i*PAGE_SIZE); 

            if (!read_exact(io_fd, page, PAGE_SIZE)) { 
                ERR("Error when reading page (type was %lx)", pagetype);
                goto out;
            }

            pagetype &= LTABTYPE_MASK; 

            if(pagetype >= L1TAB && pagetype <= L4TAB) { 
                
                /* 
                ** A page table page - need to 'uncanonicalize' it, i.e. 
                ** replace all the references to pfns with the corresponding 
                ** mfns for the new domain. 
                ** 
                ** On PAE we need to ensure that PGDs are in MFNs < 4G, and 
                ** so we may need to update the p2m after the main loop. 
                ** Hence we defer canonicalization of L1s until then. 
                */
                if(pt_levels != 3 || pagetype != L1TAB) { 

                    if(!uncanonicalize_pagetable(pagetype, page)) {
                        ERR("failed uncanonicalize pt!\n"); 
                        goto out; 
                    }

                } 
                    
            } else if(pagetype != NOTAB) { 

                ERR("Bogus page type %lx page table is out of range: "
                    "i=%d max_pfn=%lu", pagetype, i, max_pfn);
                goto out;

            } 


            if (verify) {

                int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE);

                if (res) { 

                    int v;

                    DPRINTF("************** pfn=%lx type=%lx gotcs=%08lx "
                            "actualcs=%08lx\n", pfn, pfn_type[pfn], 
                            csum_page(region_base + i*PAGE_SIZE), 
                            csum_page(buf));

                    for (v = 0; v < 4; v++) {
                        
                        unsigned long *p = (unsigned long *) 
                            (region_base + i*PAGE_SIZE);
                        if (buf[v] != p[v])
                            DPRINTF("    %d: %08lx %08lx\n", v, buf[v], p[v]);
                    }
                }
            }

            if (xc_add_mmu_update(xc_handle, mmu, 
                                  (((unsigned long long)mfn) << PAGE_SHIFT) 
                                  | MMU_MACHPHYS_UPDATE, pfn)) {
                ERR("failed machpys update mfn=%lx pfn=%lx", mfn, pfn);
                goto out;
            }
        } /* end of 'batch' for loop */

        munmap(region_base, j*PAGE_SIZE);
        n+= j; /* crude stats */
    }

    DPRINTF("Received all pages\n");

    if(pt_levels == 3) { 

        /* 
        ** XXX SMH on PAE we need to ensure PGDs are in MFNs < 4G. This 
        ** is a little awkward and involves (a) finding all such PGDs and
        ** replacing them with 'lowmem' versions; (b) upating the p2m[] 
        ** with the new info; and (c) canonicalizing all the L1s using the
        ** (potentially updated) p2m[]. 
        ** 
        ** This is relatively slow (and currently involves two passes through
        ** the pfn_type[] array), but at least seems to be correct. May wish
        ** to consider more complex approaches to optimize this later. 
        */

        int j, k; 

        /* First pass: find all L3TABs current in > 4G mfns and get new mfns */
        for (i = 0; i < max_pfn; i++) {
            
            if (((pfn_type[i] & LTABTYPE_MASK)==L3TAB) && (p2m[i]>0xfffffUL)) {

                unsigned long new_mfn; 
                uint64_t l3ptes[4]; 
                uint64_t *l3tab; 

                l3tab = (uint64_t *)
                    xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, 
                                         PROT_READ, p2m[i]); 

                for(j = 0; j < 4; j++) 
                    l3ptes[j] = l3tab[j]; 
                
                munmap(l3tab, PAGE_SIZE); 

                if (!(new_mfn=xc_make_page_below_4G(xc_handle, dom, p2m[i]))) {
                    ERR("Couldn't get a page below 4GB :-(");
                    goto out;
                }
                
                p2m[i] = new_mfn;
                if (xc_add_mmu_update(xc_handle, mmu, 
                                      (((unsigned long long)new_mfn) 
                                       << PAGE_SHIFT) | 
                                      MMU_MACHPHYS_UPDATE, i)) {
                    ERR("Couldn't m2p on PAE root pgdir");
                    goto out;
                }
                
                l3tab = (uint64_t *)
                    xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, 
                                         PROT_READ | PROT_WRITE, p2m[i]); 
                
                for(j = 0; j < 4; j++) 
                    l3tab[j] = l3ptes[j]; 
                
                munmap(l3tab, PAGE_SIZE); 
                
            }
        }

        /* Second pass: find all L1TABs and uncanonicalize them */
        j = 0; 

        for(i = 0; i < max_pfn; i++) { 
            
            if (((pfn_type[i] & LTABTYPE_MASK)==L1TAB)) { 
                region_mfn[j] = p2m[i]; 
                j++; 
            }

            if(i == (max_pfn-1) || j == MAX_BATCH_SIZE) { 

                if (!(region_base = xc_map_foreign_batch(
                          xc_handle, dom, PROT_READ | PROT_WRITE, 
                          region_mfn, j))) {  
                    ERR("map batch failed");
                    goto out;
                }

                for(k = 0; k < j; k++) {
                    if(!uncanonicalize_pagetable(L1TAB, 
                                                 region_base + k*PAGE_SIZE)) {
                        ERR("failed uncanonicalize pt!\n"); 
                        goto out; 
                    } 
                }
                
                munmap(region_base, j*PAGE_SIZE); 
                j = 0; 
            }
        }

    }


    if (xc_finish_mmu_updates(xc_handle, mmu)) { 
        ERR("Error doing finish_mmu_updates()"); 
        goto out;
    } 


    /*
     * Pin page tables. Do this after writing to them as otherwise Xen
     * will barf when doing the type-checking.
     */
    for (i = 0; i < max_pfn; i++) {

        if ( (pfn_type[i] & LPINTAB) == 0 )
            continue;

        switch(pfn_type[i]) { 

        case (L1TAB|LPINTAB): 
            pin[nr_pins].cmd = MMUEXT_PIN_L1_TABLE;
            break; 
            
        case (L2TAB|LPINTAB): 
            pin[nr_pins].cmd = MMUEXT_PIN_L2_TABLE;
            break; 
            
        case (L3TAB|LPINTAB): 
            pin[nr_pins].cmd = MMUEXT_PIN_L3_TABLE;
            break; 

        case (L4TAB|LPINTAB):
            pin[nr_pins].cmd = MMUEXT_PIN_L4_TABLE;
            break; 
            
        default: 
            continue; 
        }

        pin[nr_pins].arg1.mfn = p2m[i];

        nr_pins ++; 
        
        if (i == (max_pfn-1) || nr_pins == MAX_PIN_BATCH) {
            if (xc_mmuext_op(xc_handle, pin, nr_pins, dom) < 0) { 
                ERR("Failed to pin batch of %d page tables", nr_pins); 
                goto out;
            } 
            nr_pins = 0;
        }
    }

    DPRINTF("\b\b\b\b100%%\n");
    DPRINTF("Memory reloaded.\n");

    /* Get the list of PFNs that are not in the psuedo-phys map */
    {
        unsigned int count;
        unsigned long *pfntab;
        int rc;

        if (!read_exact(io_fd, &count, sizeof(count))) { 
            ERR("Error when reading pfn count");
            goto out;
        }

        if(!(pfntab = malloc(sizeof(unsigned long) * count))) { 
            ERR("Out of memory");
            goto out;
        }
        
        if (!read_exact(io_fd, pfntab, sizeof(unsigned long)*count)) { 
            ERR("Error when reading pfntab");
            goto out;
        }

        for (i = 0; i < count; i++) {

            unsigned long pfn = pfntab[i];

            if(pfn > max_pfn) 
                /* shouldn't happen - continue optimistically */
                continue; 

            pfntab[i] = p2m[pfn];   
            p2m[pfn]  = INVALID_P2M_ENTRY; // not in pseudo-physical map 
        }
        
        if (count > 0) {

            struct xen_memory_reservation reservation = {
                .extent_start = pfntab,
                .nr_extents   = count,
                .extent_order = 0,
                .domid        = dom
            };

            if ((rc = xc_memory_op(xc_handle, XENMEM_decrease_reservation,
                                   &reservation)) != count) { 
                ERR("Could not decrease reservation : %d", rc);
                goto out;
            } else
                DPRINTF("Decreased reservation by %d pages\n", count);
        } 
    }

    if (!read_exact(io_fd, &ctxt, sizeof(ctxt)) || 
        !read_exact(io_fd, shared_info_page, PAGE_SIZE)) { 
        ERR("Error when reading ctxt or shared info page");
        goto out;
    }

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    pfn = ctxt.user_regs.edx;
    if ((pfn >= max_pfn) || (pfn_type[pfn] != NOTAB)) {
        ERR("Suspend record frame number is bad");
        goto out;
    }
    ctxt.user_regs.edx = mfn = p2m[pfn];
    start_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ | PROT_WRITE, mfn);
    start_info->nr_pages    = max_pfn;
    start_info->shared_info = shared_info_frame << PAGE_SHIFT;
    start_info->flags       = 0;
    *store_mfn = start_info->store_mfn       = p2m[start_info->store_mfn];
    start_info->store_evtchn                 = store_evtchn;
    *console_mfn = start_info->console_mfn   = p2m[start_info->console_mfn];
    start_info->console_evtchn               = console_evtchn;
    munmap(start_info, PAGE_SIZE);

    /* Uncanonicalise each GDT frame number. */
    if (ctxt.gdt_ents > 8192) {
        ERR("GDT entry count out of range");
        goto out;
    }

    for (i = 0; i < ctxt.gdt_ents; i += 512) {
        pfn = ctxt.gdt_frames[i];
        if ((pfn >= max_pfn) || (pfn_type[pfn] != NOTAB)) {
            ERR("GDT frame number is bad");
            goto out;
        }
        ctxt.gdt_frames[i] = p2m[pfn];
    }

    /* Uncanonicalise the page table base pointer. */
    pfn = ctxt.ctrlreg[3] >> PAGE_SHIFT;

    if (pfn >= max_pfn) {
        ERR("PT base is bad: pfn=%lu max_pfn=%lu type=%08lx",
            pfn, max_pfn, pfn_type[pfn]); 
        goto out;
    }

    if ((pt_levels == 2) && ((pfn_type[pfn]&LTABTYPE_MASK) != L2TAB)) { 
        ERR("PT base is bad. pfn=%lu nr=%lu type=%08lx %08lx",
            pfn, max_pfn, pfn_type[pfn], (unsigned long)L2TAB);
        goto out;
    }

    if ((pt_levels == 3) && ((pfn_type[pfn]&LTABTYPE_MASK) != L3TAB)) { 
        ERR("PT base is bad. pfn=%lu nr=%lu type=%08lx %08lx",
            pfn, max_pfn, pfn_type[pfn], (unsigned long)L3TAB);
        goto out;
    }
    
    ctxt.ctrlreg[3] = p2m[pfn] << PAGE_SHIFT;

    /* clear any pending events and the selector */
    memset(&(shared_info->evtchn_pending[0]), 0,
           sizeof (shared_info->evtchn_pending));
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_data[i].evtchn_pending_sel = 0;

    /* Copy saved contents of shared-info page. No checking needed. */
    page = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_WRITE, shared_info_frame);
    memcpy(page, shared_info, sizeof(shared_info_t));
    munmap(page, PAGE_SIZE);
    
    /* Uncanonicalise the pfn-to-mfn table frame-number list. */
    for (i = 0; i < P2M_FL_ENTRIES; i++) {
        pfn = p2m_frame_list[i];
        if ((pfn >= max_pfn) || (pfn_type[pfn] != NOTAB)) {
            ERR("PFN-to-MFN frame number is bad");
            goto out;
        }

        p2m_frame_list[i] = p2m[pfn];
    }
    
    /* Copy the P2M we've constructed to the 'live' P2M */
    if (!(live_p2m = xc_map_foreign_batch(xc_handle, dom, PROT_WRITE, 
                                          p2m_frame_list, P2M_FL_ENTRIES))) {
        ERR("Couldn't map p2m table");
        goto out;
    }

    memcpy(live_p2m, p2m, P2M_SIZE); 
    munmap(live_p2m, P2M_SIZE); 

    /*
     * Safety checking of saved context:
     *  1. user_regs is fine, as Xen checks that on context switch.
     *  2. fpu_ctxt is fine, as it can't hurt Xen.
     *  3. trap_ctxt needs the code selectors checked.
     *  4. ldt base must be page-aligned, no more than 8192 ents, ...
     *  5. gdt already done, and further checking is done by Xen.
     *  6. check that kernel_ss is safe.
     *  7. pt_base is already done.
     *  8. debugregs are checked by Xen.
     *  9. callback code selectors need checking.
     */
    for ( i = 0; i < 256; i++ ) {
        ctxt.trap_ctxt[i].vector = i;
        if ((ctxt.trap_ctxt[i].cs & 3) == 0)
            ctxt.trap_ctxt[i].cs = FLAT_KERNEL_CS;
    }
    if ((ctxt.kernel_ss & 3) == 0)
        ctxt.kernel_ss = FLAT_KERNEL_DS;
#if defined(__i386__)
    if ((ctxt.event_callback_cs & 3) == 0)
        ctxt.event_callback_cs = FLAT_KERNEL_CS;
    if ((ctxt.failsafe_callback_cs & 3) == 0)
        ctxt.failsafe_callback_cs = FLAT_KERNEL_CS;
#endif
    if (((ctxt.ldt_base & (PAGE_SIZE - 1)) != 0) ||
        (ctxt.ldt_ents > 8192) ||
        (ctxt.ldt_base > hvirt_start) ||
        ((ctxt.ldt_base + ctxt.ldt_ents*8) > hvirt_start)) {
        ERR("Bad LDT base or size");
        goto out;
    }

    DPRINTF("Domain ready to be built.\n");

    op.cmd = DOM0_SETDOMAININFO;
    op.u.setdomaininfo.domain = (domid_t)dom;
    op.u.setdomaininfo.vcpu   = 0;
    op.u.setdomaininfo.ctxt   = &ctxt;
    rc = xc_dom0_op(xc_handle, &op);

    if (rc != 0) {
        ERR("Couldn't build the domain");
        goto out;
    }

 out:
    if ( (rc != 0) && (dom != 0) )
        xc_domain_destroy(xc_handle, dom);
    free(mmu);
    free(p2m);
    free(pfn_type);

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
}
