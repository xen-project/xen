/******************************************************************************
 * xi_save_linux.c
 * 
 * Save the state of a running Xenolinux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "dom0_defs.h"
#include "mem_defs.h"
#include <asm-xeno/suspend.h>

static char *argv0 = "internal_save_linux";

/* A table mapping each PFN to its current MFN. */
static unsigned long *pfn_to_mfn_table;
/* A table mapping each current MFN to its canonical PFN. */
static unsigned long *mfn_to_pfn_table;

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

/*
 * Returns TRUE if the given machine frame number has a unique mapping
 * in the guest's pseudophysical map.
 */
#define MFN_IS_IN_PSEUDOPHYS_MAP(_mfn) \
    (((_mfn) < (1024*1024)) &&          \
     (pfn_to_mfn_table[mfn_to_pfn_table[_mfn]] == (_mfn)))

/* Returns TRUE if MFN is successfully converted to a PFN. */
static int translate_mfn_to_pfn(unsigned long *pmfn)
{
    unsigned long mfn = *pmfn;
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
        return 0;
    *pmfn = mfn_to_pfn_table[mfn];
    return 1;
}

static int check_pfn_ownership(unsigned long mfn, unsigned int dom)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn = mfn;
    if ( (do_dom0_op(&op) < 0) || (op.u.getpageframeinfo.domain != dom) )
        return 0;
    return 1;
}

static unsigned int get_pfn_type(unsigned long mfn)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn = mfn;
    if ( do_dom0_op(&op) < 0 )
    {
        PERROR("Unexpected failure when getting page frame info!");
        exit(1);
    }
    return op.u.getpageframeinfo.type;
}

static int checked_write(int fd, const void *buf, size_t count)
{
    int rc;
    while ( ((rc = write(fd, buf, count)) == -1) && (errno = EINTR) )
        continue;
    return rc == count;
}

int main(int argc, char **argv)
{
    dom0_op_t op;
    int rc = 1, i;
    unsigned long mfn, dom;

    /* Remember if we stopped the guest, so we can restart it on exit. */
    int we_stopped_it = 0;

    /* A copy of the CPU context of the guest. */
    full_execution_context_t ctxt;

    /* A copy of the domain's name. */
    char name[MAX_DOMAIN_NAME];

    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *ppage, page[1024];

    /* A temporary mapping, and a copy, of the pfn-to-mfn table frame list. */
    unsigned long *p_pfn_to_mfn_frame_list, pfn_to_mfn_frame_list[1024];
    /* A temporary mapping of one frame in the above list. */
    unsigned long *pfn_to_mfn_frame;

    /* A temporary mapping, and a copy, of the guest's suspend record. */
    suspend_record_t *p_srec, srec;

    /* The name and descriptor of the file that we are writing to. */
    char *filename;
    int fd;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 3 )
    {
        fprintf(stderr, "Usage: %s <domain_id> <state file>\n", argv0);
        return 1;
    }

    dom = atoi(argv[1]);
    if ( dom == 0 )
    {
        ERROR("Did you really mean domain 0?");
        return 1;
    }

    filename = argv[2];
    if ( (fd = open(name, O_CREAT|O_EXCL|O_RDWR)) == -1 )
    {
        PERROR("Could not open file for writing");
        return 1;
    }

    /* Ensure that the domain exists, and that it is stopped. */
    for ( ; ; )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = dom;
        if ( (do_dom0_op(&op) < 0) || (op.u.getdomaininfo.domain != dom) )
        {
            PERROR("Could not get info on domain");
            goto out;
        }

        memcpy(&ctxt, &op.u.getdomaininfo.ctxt, sizeof(ctxt));
        memcpy(name, op.u.getdomaininfo.name, sizeof(name));

        if ( op.u.getdomaininfo.state == DOMSTATE_STOPPED )
            break;

        we_stopped_it = 1;

        op.cmd = DOM0_STOPDOMAIN;
        op.u.stopdomain.domain = dom;
        (void)do_dom0_op(&op);

        sleep(1);
    }

    /* A cheesy test to see whether the domain contains valid state. */
    if ( ctxt.pt_base == 0 )
    {
        ERROR("Domain is not in a valid Xenolinux state");
        goto out;
    }

    if ( init_pfn_mapper() < 0 )
        goto out;

    /* Is the suspend-record MFN actually valid for this domain? */
    if ( !check_pfn_ownership(ctxt.i386_ctxt.esi, dom) )
    {
        ERROR("Invalid state record pointer");
        goto out;
    }

    /* If the suspend-record MFN is okay then grab a copy of it to @srec. */
    p_srec = map_pfn(ctxt.i386_ctxt.esi);
    memcpy(&srec, p_srec, sizeof(srec));
    unmap_pfn(p_srec);

    if ( srec.nr_pfns > 1024*1024 )
    {
        ERROR("Invalid state record -- pfn count out of range");
        goto out;
    }

    if ( !check_pfn_ownership(srec.pfn_to_mfn_frame_list, dom) )
    {
        ERROR("Invalid pfn-to-mfn frame list pointer");
        goto out;
    }

    /* Grab a copy of the pfn-to-mfn table frame list. */
    p_pfn_to_mfn_frame_list = map_pfn(srec.pfn_to_mfn_frame_list);
    memcpy(pfn_to_mfn_frame_list, p_pfn_to_mfn_frame_list, PAGE_SIZE);
    unmap_pfn(p_pfn_to_mfn_frame_list);

    /* We want zeroed memory so use calloc rather than malloc. */
    mfn_to_pfn_table = calloc(1, 4 * 1024 * 1024);
    pfn_to_mfn_table = calloc(1, 4 * srec.nr_pfns);
    pfn_type         = calloc(1, 4 * srec.nr_pfns);

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
            if ( !check_pfn_ownership(mfn, dom) )
            {
                ERROR("Invalid frame number if pfn-to-mfn frame list");
                goto out;
            }
            if ( pfn_to_mfn_frame != NULL )
                unmap_pfn(pfn_to_mfn_frame);
            pfn_to_mfn_frame = map_pfn(mfn);
        }
        
        mfn = pfn_to_mfn_frame[i & 1023];

        if ( !check_pfn_ownership(mfn, dom) )
        {
            ERROR("Invalid frame specified with pfn-to-mfn table");
            goto out;
        }

        pfn_to_mfn_table[i] = mfn;

        /* Did we map this MFN already? That would be invalid! */
        if ( MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
        {
            ERROR("A machine frame appears twice in pseudophys space");
            goto out;
        }
        
        mfn_to_pfn_table[mfn] = i;

        /* Query page type by MFN, but store it by PFN. */
        pfn_type[i] = get_pfn_type(mfn);
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
    if ( !checked_write(fd, "XenoLinuxSuspend",    16) ||
         !checked_write(fd, name,                  sizeof(name)) ||
         !checked_write(fd, &srec.nr_pfns,         sizeof(unsigned long)) ||
         !checked_write(fd, &ctxt,                 sizeof(ctxt)) ||
         !checked_write(fd, pfn_to_mfn_frame_list, PAGE_SIZE) ||
         !checked_write(fd, pfn_type,              4 * srec.nr_pfns) )
    {
        ERROR("Error when writing to state file");
        goto out;
    }

    /* Now write out each data page, canonicalising page tables as we go... */
    for ( i = 0; i < srec.nr_pfns; i++ )
    {
        mfn = pfn_to_mfn_table[i];

        ppage = map_pfn(mfn);
        memcpy(&page, ppage, PAGE_SIZE);
        unmap_pfn(ppage);

        if ( (pfn_type[i] == L1TAB) || (pfn_type[i] == L2TAB) )
        {
            for ( i = 0; i < 1024; i++ )
            {
                if ( !(page[i] & _PAGE_PRESENT) ) continue;
                mfn = page[i] >> PAGE_SHIFT;
                if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
                {
                    ERROR("Frame number in pagetable page is invalid");
                    goto out;
                }
                page[i] &= PAGE_SIZE - 1;
                page[i] |= mfn_to_pfn_table[mfn] << PAGE_SHIFT;
            }
        }

        if ( !checked_write(fd, &page, PAGE_SIZE) )
        {
            ERROR("Error when writing to state file");
            goto out;
        }
    }

    /* Success! */
    rc = 0;

 out:
    /* Restart the domain if we had to stop it to save its state. */
    if ( we_stopped_it )
    {
        op.cmd = DOM0_STARTDOMAIN;
        op.u.startdomain.domain = dom;
        (void)do_dom0_op(&op);
    }

    /* On error, make sure the file is deleted. */
    if ( rc != 0 )
        unlink(filename);
    
    return !!rc;
}
