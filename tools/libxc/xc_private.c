/******************************************************************************
 * xc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include "xc_private.h"

void *xc_map_foreign_batch(int xc_handle, u32 dom, int prot,
                           unsigned long *arr, int num )
{
    privcmd_mmapbatch_t ioctlx; 
    void *addr;
    addr = mmap(NULL, num*PAGE_SIZE, prot, MAP_SHARED, xc_handle, 0);
    if ( addr != NULL )
    {
        ioctlx.num=num;
        ioctlx.dom=dom;
        ioctlx.addr=(unsigned long)addr;
        ioctlx.arr=arr;
        if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx ) < 0 )
        {
            perror("XXXXXXXX");
            munmap(addr, num*PAGE_SIZE);
            return 0;
        }
    }
    return addr;

}

/*******************/

void *xc_map_foreign_range(int xc_handle, u32 dom,
                            int size, int prot,
                            unsigned long mfn )
{
    privcmd_mmap_t ioctlx; 
    privcmd_mmap_entry_t entry; 
    void *addr;
    addr = mmap(NULL, size, prot, MAP_SHARED, xc_handle, 0);
    if ( addr != NULL )
    {
        ioctlx.num=1;
        ioctlx.dom=dom;
        ioctlx.entry=&entry;
        entry.va=(unsigned long) addr;
        entry.mfn=mfn;
        entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
        if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx ) < 0 )
        {
            munmap(addr, size);
            return 0;
        }
    }
    return addr;
}

/*******************/

/* NB: arr must be mlock'ed */
int get_pfn_type_batch(int xc_handle, 
                       u32 dom, int num, unsigned long *arr)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO2;
    op.u.getpageframeinfo2.domain = (domid_t)dom;
    op.u.getpageframeinfo2.num    = num;
    op.u.getpageframeinfo2.array  = arr;
    return do_dom0_op(xc_handle, &op);
}

#define GETPFN_ERR (~0U)
unsigned int get_pfn_type(int xc_handle, 
                          unsigned long mfn, 
                          u32 dom)
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



/*******************/

#define FIRST_MMU_UPDATE 1

static int flush_mmu_updates(int xc_handle, mmu_t *mmu)
{
    int err = 0;
    privcmd_hypercall_t hypercall;

    if ( mmu->idx == FIRST_MMU_UPDATE )
        return 0;

    mmu->updates[0].ptr  = MMU_EXTENDED_COMMAND;
    mmu->updates[0].val  = MMUEXT_SET_FOREIGNDOM;
    mmu->updates[0].val |= (unsigned long)mmu->subject << 16;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu->updates;
    hypercall.arg[1] = (unsigned long)mmu->idx;
    hypercall.arg[2] = 0;

    if ( mlock(mmu->updates, sizeof(mmu->updates)) != 0 )
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

    mmu->idx = FIRST_MMU_UPDATE;
    
    (void)munlock(mmu->updates, sizeof(mmu->updates));

 out:
    return err;
}

mmu_t *init_mmu_updates(int xc_handle, domid_t dom)
{
    mmu_t *mmu = malloc(sizeof(mmu_t));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = FIRST_MMU_UPDATE;
    mmu->subject = dom;
    return mmu;
}

int add_mmu_update(int xc_handle, mmu_t *mmu, 
                   unsigned long ptr, unsigned long val)
{
    mmu->updates[mmu->idx].ptr = ptr;
    mmu->updates[mmu->idx].val = val;

    if ( ++mmu->idx == MAX_MMU_UPDATES )
        return flush_mmu_updates(xc_handle, mmu);

    return 0;
}

int finish_mmu_updates(int xc_handle, mmu_t *mmu)
{
    return flush_mmu_updates(xc_handle, mmu);
}


long long  xc_domain_get_cpu_usage( int xc_handle, domid_t domid )
{
    dom0_op_t op;

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    op.u.getdomaininfo.ctxt = NULL;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
         ((u16)op.u.getdomaininfo.domain != domid) )
    {
        PERROR("Could not get info on domain");
        return -1;
    }
    return op.u.getdomaininfo.cpu_time;
}


/* This is shared between save and restore, and may generally be useful. */
unsigned long csum_page (void * page)
{
    int i;
    unsigned long *p = page;
    unsigned long long sum=0;

    for ( i = 0; i < (PAGE_SIZE/sizeof(unsigned long)); i++ )
        sum += p[i];

    return sum ^ (sum>>32);
}

unsigned long xc_get_m2p_start_mfn ( int xc_handle )
{
    unsigned long mfn;

    if ( ioctl( xc_handle, IOCTL_PRIVCMD_GET_MACH2PHYS_START_MFN, &mfn ) < 0 )
    {
	perror("xc_get_m2p_start_mfn:");
	return 0;
    }
    return mfn;
}



