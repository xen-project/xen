/******************************************************************************
 * xi_restore_linux.c
 * 
 * Restore the state of a Xenolinux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "dom0_defs.h"
#include "mem_defs.h"
#include <asm-xeno/suspend.h>

static char *argv0 = "internal_restore_linux";

/* A table mapping each PFN to its new MFN. */
static unsigned long *pfn_to_mfn_table;

static int get_pfn_list(
    int domain_id, unsigned long *pfn_buf, unsigned long max_pfns)
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

    ret = do_dom0_op(&op);

    (void)munlock(pfn_buf, max_pfns * sizeof(unsigned long));

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

#define MAX_MMU_UPDATES 1024
static mmu_update_t mmu_updates[MAX_MMU_UPDATES];
static int mmu_update_idx;

static void flush_mmu_updates(void)
{
    privcmd_hypercall_t hypercall;

    if ( mmu_update_idx == 0 )
        return;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu_updates;
    hypercall.arg[1] = (unsigned long)mmu_update_idx;

    if ( mlock(mmu_updates, sizeof(mmu_updates)) != 0 )
    {
        PERROR("Could not lock pagetable update array");
        exit(1);
    }

    if ( do_xen_hypercall(&hypercall) < 0 )
    {
        ERROR("Failure when submitting mmu updates");
        exit(1);
    }

    mmu_update_idx = 0;
    
    (void)munlock(mmu_updates, sizeof(mmu_updates));
}

static void add_mmu_update(unsigned long ptr, unsigned long val)
{
    mmu_updates[mmu_update_idx].ptr = ptr;
    mmu_updates[mmu_update_idx].val = val;
    if ( ++mmu_update_idx == MAX_MMU_UPDATES )
        flush_mmu_updates();
}

static int devmem_fd;

static int init_pfn_mapper(void)
{
    if ( (devmem_fd = open("/dev/mem", O_RDWR)) < 0 )
    {
        PERROR("Could not open /dev/mem");
        return -1;
    }
    return 0;
}

static void *map_pfn(unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, devmem_fd, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
    {
        PERROR("Could not mmap a domain pfn using /dev/mem");
        return NULL;
    }
    return vaddr;
}

static void unmap_pfn(void *vaddr)
{
    (void)munmap(vaddr, PAGE_SIZE);
}

static int checked_read(int fd, void *buf, size_t count)
{
    int rc;
    while ( ((rc = read(fd, buf, count)) == -1) && (errno == EINTR) )
        continue;
    return rc == count;
}

int main(int argc, char **argv)
{
    dom0_op_t op;
    int rc = 1, i, j;
    unsigned long mfn, pfn, dom = 0;
    
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
    unsigned long *pfn_type;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *ppage, page[1024];

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long pfn_to_mfn_frame_list[1024];

    /* A temporary mapping of the guest's suspend record. */
    suspend_record_t *p_srec;

    /* The name and descriptor of the file that we are reading from. */
    char *filename;
    int fd;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 2 )
    {
        fprintf(stderr, "Usage: %s <state file>\n", argv0);
        return 1;
    }

    filename = argv[1];
    if ( (fd = open(name, O_RDONLY)) == -1 )
    {
        PERROR("Could not open file for writing");
        return 1;
    }

    /* Start writing out the saved-domain record. */
    if ( !checked_read(fd, signature, 16) ||
         (memcmp(signature, "XenoLinuxSuspend", 16) != 0) )
    {
        ERROR("Unrecognised state format -- no signature found");
        goto out;
    }

    if ( !checked_read(fd, name,                  sizeof(name)) ||
         !checked_read(fd, &nr_pfns,              sizeof(unsigned long)) ||
         !checked_read(fd, &ctxt,                 sizeof(ctxt)) ||
         !checked_read(fd, shared_info,           PAGE_SIZE) ||
         !checked_read(fd, pfn_to_mfn_frame_list, PAGE_SIZE) )
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

    if ( !checked_read(fd, pfn_type, 4 * nr_pfns) )
    {
        ERROR("Error when reading from state file");
        goto out;
    }

    /* Create a new domain of the appropriate size, and find it's dom_id. */
    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.memory_kb = nr_pfns * (PAGE_SIZE / 1024);
    memcpy(op.u.createdomain.name, name, MAX_DOMAIN_NAME);
    if ( do_dom0_op(&op) < 0 )
    {
        ERROR("Could not create new domain");
        goto out;
    }
    dom = op.u.createdomain.domain;

    /* Get the domain's shared-info frame. */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = dom;
    if ( do_dom0_op(&op) < 0 )
    {
        ERROR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = op.u.getdomaininfo.shared_info_frame;

    if ( init_pfn_mapper() < 0 )
        goto out;

    /* Copy saved contents of shared-info page. No checking needed. */
    ppage = map_pfn(shared_info_frame);
    memcpy(ppage, shared_info, PAGE_SIZE);
    unmap_pfn(ppage);

    /* Build the pfn-to-mfn table. We choose MFN ordering returned by Xen. */
    if ( get_pfn_list(dom, pfn_to_mfn_table, nr_pfns) != nr_pfns )
    {
        ERROR("Did not read correct number of frame numbers for new dom");
        goto out;
    }

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    for ( i = 0; i < nr_pfns; i++ )
    {
        mfn = pfn_to_mfn_table[i];

        if ( !checked_read(fd, page, PAGE_SIZE) )
        {
            ERROR("Error when reading from state file");
            goto out;
        }

        ppage = map_pfn(mfn);
        switch ( pfn_type[i] )
        {
        case L1TAB:
            memset(ppage, 0, PAGE_SIZE);
            add_mmu_update((mfn<<PAGE_SHIFT) | MMU_EXTENDED_COMMAND,
                           MMUEXT_PIN_L1_TABLE);
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
                    page[j] &= PAGE_SIZE - 1;
                    page[j] |= pfn_to_mfn_table[pfn] << PAGE_SHIFT;
                }
                add_mmu_update((unsigned long)&ppage[j], page[j]);
            }
            break;
        case L2TAB:
            memset(ppage, 0, PAGE_SIZE);
            add_mmu_update((mfn<<PAGE_SHIFT) | MMU_EXTENDED_COMMAND,
                           MMUEXT_PIN_L2_TABLE);
            for ( j = 0; j < 1024; j++ )
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
                    page[j] &= PAGE_SIZE - 1;
                    page[j] |= pfn_to_mfn_table[pfn] << PAGE_SHIFT;
                }
                add_mmu_update((unsigned long)&ppage[j], page[j]);
            }
            break;
        default:
            memcpy(ppage, page, PAGE_SIZE);
            break;
        }
        unmap_pfn(ppage);

        add_mmu_update((mfn<<PAGE_SHIFT) | MMU_MACHPHYS_UPDATE, i);
    }

    flush_mmu_updates();

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    pfn = ctxt.i386_ctxt.esi;
    if ( (pfn >= nr_pfns) || (pfn_type[pfn] != NONE) )
    {
        ERROR("Suspend record frame number is bad");
        goto out;
    }
    ctxt.i386_ctxt.esi = mfn = pfn_to_mfn_table[pfn];
    p_srec = map_pfn(mfn);
    p_srec->resume_info.nr_pages    = nr_pfns;
    p_srec->resume_info.shared_info = shared_info_frame << PAGE_SHIFT;
    p_srec->resume_info.dom_id      = dom;
    p_srec->resume_info.flags       = 0;
    unmap_pfn(p_srec);

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
        ppage = map_pfn(pfn_to_mfn_table[pfn]);
        memcpy(ppage, &pfn_to_mfn_table[i], copy_size);        
        unmap_pfn(ppage);
    }

    /*
     * Safety checking of saved context:
     *  1. i386_ctxt is fine, as Xen checks that on context switch.
     *  2. i387_ctxt is fine, as it can't hurt Xen.
     *  3. trap_ctxt needs the code selectors checked.
     *  4. fast_trap_idx is checked by Xen.
     *  5. ldt base must be page-aligned, no more than 8192 ents, ...
     *  6. gdt already done, and further checking is done by Xen.
     *  7. check that ring1_ss/esp is safe.
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
    if ( ctxt.ring1_esp > HYPERVISOR_VIRT_START )
        ctxt.ring1_esp = HYPERVISOR_VIRT_START;
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


    /* Success! */
    rc = 0;

 out:
    /* If we experience an error then kill the half-constructed domain. */
    if ( (rc != 0) && (dom != 0) )
    {
        op.cmd = DOM0_DESTROYDOMAIN;
        op.u.destroydomain.domain = dom;
        op.u.destroydomain.force  = 1;
        (void)do_dom0_op(&op);
    }

    return !!rc;
}
