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
    int rc = 1, i;
    unsigned long mfn, dom = 0;
    
    /* Number of page frames in use by this XenoLinux session. */
    unsigned long nr_pfns;
    
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
    /* A temporary mapping of one frame in the above list. */
    unsigned long *pfn_to_mfn_frame;

    /* A temporary mapping, and a copy, of the guest's suspend record. */
    suspend_record_t *p_srec, srec;

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
         !checked_read(fd, pfn_to_mfn_frame_list, PAGE_SIZE) )
    {
        ERROR("Error when reading from state file");
        goto out;
    }

    if ( nr_pfns > 1024*1024 )
    {
        ERROR("Invalid state file -- pfn count out of range");
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

    /* We want zeroed memory so use calloc rather than malloc. */
    mfn_to_pfn_table = calloc(1, 4 * 1024 * 1024);
    pfn_to_mfn_table = calloc(1, 4 * nr_pfns);
    pfn_type         = calloc(1, 4 * nr_pfns);    

    if ( !checked_read(fd, pfn_type, 4 * nr_pfns) )
    {
        ERROR("Error when reading from state file");
        goto out;
    }

    /* Create a new domain of teh appropriate size, and find it's dom_id. */
    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.memory_kb = nr_pfns * (PAGE_SIZE / 1024);
    memcpy(op.u.createdomain.name, name, MAX_DOMAIN_NAME);
    if ( do_dom0_op(&op) < 0 )
    {
        ERROR("Could not create new domain");
        goto out;
    }
    dom = op.u.createdomain.domain;

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

    if ( !check_pfn_ownership(srec.pfn_to_mfn_frame_list, dom) )
    {
        ERROR("Invalid pfn-to-mfn frame list pointer");
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
        write(fd, &page, PAGE_SIZE);
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
