/******************************************************************************
 * xc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include "xc_private.h"

int init_pfn_mapper(void)
{
    return open("/dev/mem", O_RDWR);
}

int close_pfn_mapper(int pm_handle)
{
    return close(pm_handle);
}

void *map_pfn_writeable(int pm_handle, unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, pm_handle, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return vaddr;
}

void *map_pfn_readonly(int pm_handle, unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ,
                       MAP_SHARED, pm_handle, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return vaddr;
}

void unmap_pfn(int pm_handle, void *vaddr)
{
    (void)munmap(vaddr, PAGE_SIZE);
}

/*******************/

void * mfn_mapper_map_single(int xc_handle, int prot, 
			     unsigned long mfn, int size)
{
    privcmd_mmap_t ioctlx; 
    privcmd_mmap_entry_t entry; 
    void *addr;
    addr = mmap( NULL, size, prot, MAP_SHARED, xc_handle, 0 );
    if (addr)
    {
	ioctlx.num=1;
	ioctlx.entry=&entry;
	entry.va=(unsigned long) addr;
	entry.mfn=mfn;
	entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
	if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx ) <0 )
	    return 0;
    }
    return addr;
}

mfn_mapper_t * mfn_mapper_init(int xc_handle, int size, int prot)
{
    mfn_mapper_t * t;
    t = calloc( 1, sizeof(mfn_mapper_t)+
		mfn_mapper_queue_size*sizeof(privcmd_mmap_entry_t) );
    if (!t) return NULL;
    t->xc_handle = xc_handle;
    t->size = size;
    t->prot = prot;
    t->max_queue_size = mfn_mapper_queue_size;
    t->addr = mmap( NULL, size, prot, MAP_SHARED, xc_handle, 0 );
    if (!t->addr)
    {
	free(t);
	return NULL;
    }
    t->ioctl.num = 0;
    t->ioctl.entry = (privcmd_mmap_entry_t *) &t[1];
    return t;
}

void * mfn_mapper_base(mfn_mapper_t *t)
{
    return t->addr;
}

void mfn_mapper_close(mfn_mapper_t *t)
{
    if(t->addr) munmap( t->addr, t->size );
    free(t);    
}

int mfn_mapper_flush_queue(mfn_mapper_t *t)
{
    int rc;

    rc = ioctl( t->xc_handle, IOCTL_PRIVCMD_MMAP, &t->ioctl );
    if (rc<0) return rc;
    t->ioctl.num = 0;
    return 0;
}

void * mfn_mapper_queue_entry(mfn_mapper_t *t, int offset, 
			      unsigned long mfn, int size)
{
    privcmd_mmap_entry_t *entry, *prev;
    int pages;

    offset &= PAGE_MASK;
    pages =(size+PAGE_SIZE-1)>>PAGE_SHIFT;
    entry = &t->ioctl.entry[t->ioctl.num];       

    if ( t->ioctl.num > 0 )
    {
	prev = &t->ioctl.entry[t->ioctl.num-1];       

	if ( (prev->va+(prev->npages*PAGE_SIZE)) == (t->addr+offset) &&
	     (prev->mfn+prev->npages) == mfn )
	{
	    prev->npages += pages;
printf("merge\n");
	    return t->addr+offset;
	}
    }
     
    entry->va = t->addr+offset;
    entry->mfn = mfn;
    entry->npages = pages;
    t->ioctl.num++;       

    if(t->ioctl.num == t->max_queue_size)
    {
	if ( mfn_mapper_flush_queue(t) )
	return 0;
    }

    return t->addr+offset;
}




/*******************/

#define FIRST_MMU_UPDATE 2

static int flush_mmu_updates(int xc_handle, mmu_t *mmu)
{
    int err = 0;
    privcmd_hypercall_t hypercall;

    if ( mmu->idx == FIRST_MMU_UPDATE )
        return 0;

    /* The first two requests set the correct subject domain. */
    mmu->updates[0].val  = (unsigned long)(mmu->subject<<16) & ~0xFFFFUL;
    mmu->updates[0].ptr  = (unsigned long)(mmu->subject<< 0) & ~0xFFFFUL;
    mmu->updates[1].val  = (unsigned long)(mmu->subject>>16) & ~0xFFFFUL;
    mmu->updates[1].ptr  = (unsigned long)(mmu->subject>>32) & ~0xFFFFUL;
    mmu->updates[0].ptr |= MMU_EXTENDED_COMMAND;
    mmu->updates[0].val |= MMUEXT_SET_SUBJECTDOM_L;
    mmu->updates[1].ptr |= MMU_EXTENDED_COMMAND;
    mmu->updates[1].val |= MMUEXT_SET_SUBJECTDOM_H;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu->updates;
    hypercall.arg[1] = (unsigned long)mmu->idx;

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
