/******************************************************************************
 * xc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include <zlib.h>
#include "xc_private.h"
#include <xen/memory.h>

void *xc_map_foreign_batch(int xc_handle, uint32_t dom, int prot,
                           unsigned long *arr, int num )
{
    privcmd_mmapbatch_t ioctlx; 
    void *addr;
    addr = mmap(NULL, num*PAGE_SIZE, prot, MAP_SHARED, xc_handle, 0);
    if ( addr == MAP_FAILED )
        return NULL;

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx ) < 0 )
    {
        int saved_errno = errno;
        perror("XXXXXXXX");
        (void)munmap(addr, num*PAGE_SIZE);
        errno = saved_errno;
        return NULL;
    }
    return addr;

}

/*******************/

void *xc_map_foreign_range(int xc_handle, uint32_t dom,
                           int size, int prot,
                           unsigned long mfn )
{
    privcmd_mmap_t ioctlx; 
    privcmd_mmap_entry_t entry; 
    void *addr;
    addr = mmap(NULL, size, prot, MAP_SHARED, xc_handle, 0);
    if ( addr == MAP_FAILED )
        return NULL;

    ioctlx.num=1;
    ioctlx.dom=dom;
    ioctlx.entry=&entry;
    entry.va=(unsigned long) addr;
    entry.mfn=mfn;
    entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
    if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx ) < 0 )
    {
        int saved_errno = errno;
        (void)munmap(addr, size);
        errno = saved_errno;
        return NULL;
    }
    return addr;
}

/*******************/

/* NB: arr must be mlock'ed */
int xc_get_pfn_type_batch(int xc_handle, 
                          uint32_t dom, int num, unsigned long *arr)
{
    DECLARE_DOM0_OP;
    op.cmd = DOM0_GETPAGEFRAMEINFO2;
    op.u.getpageframeinfo2.domain = (domid_t)dom;
    op.u.getpageframeinfo2.num    = num;
    op.u.getpageframeinfo2.array  = arr;
    return do_dom0_op(xc_handle, &op);
}

#define GETPFN_ERR (~0U)
unsigned int get_pfn_type(int xc_handle, 
                          unsigned long mfn, 
                          uint32_t dom)
{
    DECLARE_DOM0_OP;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.mfn    = mfn;
    op.u.getpageframeinfo.domain = (domid_t)dom;
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        PERROR("Unexpected failure when getting page frame info!");
        return GETPFN_ERR;
    }
    return op.u.getpageframeinfo.type;
}

int xc_mmuext_op(
    int xc_handle,
    struct mmuext_op *op,
    unsigned int nr_ops,
    domid_t dom)
{
    DECLARE_HYPERCALL;
    long ret = -EINVAL;

    hypercall.op     = __HYPERVISOR_mmuext_op;
    hypercall.arg[0] = (unsigned long)op;
    hypercall.arg[1] = (unsigned long)nr_ops;
    hypercall.arg[2] = (unsigned long)0;
    hypercall.arg[3] = (unsigned long)dom;

    if ( mlock(op, nr_ops*sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    ret = do_xen_hypercall(xc_handle, &hypercall);

    safe_munlock(op, nr_ops*sizeof(*op));

 out1:
    return ret;
}    

static int flush_mmu_updates(int xc_handle, xc_mmu_t *mmu)
{
    int err = 0;
    DECLARE_HYPERCALL;

    if ( mmu->idx == 0 )
        return 0;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu->updates;
    hypercall.arg[1] = (unsigned long)mmu->idx;
    hypercall.arg[2] = 0;
    hypercall.arg[3] = mmu->subject;

    if ( mlock(mmu->updates, sizeof(mmu->updates)) != 0 )
    {
        PERROR("flush_mmu_updates: mmu updates mlock failed");
        err = 1;
        goto out;
    }

    if ( do_xen_hypercall(xc_handle, &hypercall) < 0 )
    {
        ERROR("Failure when submitting mmu updates");
        err = 1;
    }

    mmu->idx = 0;

    safe_munlock(mmu->updates, sizeof(mmu->updates));

 out:
    return err;
}

xc_mmu_t *xc_init_mmu_updates(int xc_handle, domid_t dom)
{
    xc_mmu_t *mmu = malloc(sizeof(xc_mmu_t));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = 0;
    mmu->subject = dom;
    return mmu;
}

int xc_add_mmu_update(int xc_handle, xc_mmu_t *mmu, 
                      unsigned long long ptr, unsigned long long val)
{
    mmu->updates[mmu->idx].ptr = ptr;
    mmu->updates[mmu->idx].val = val;

    if ( ++mmu->idx == MAX_MMU_UPDATES )
        return flush_mmu_updates(xc_handle, mmu);

    return 0;
}

int xc_finish_mmu_updates(int xc_handle, xc_mmu_t *mmu)
{
    return flush_mmu_updates(xc_handle, mmu);
}

int xc_memory_op(int xc_handle,
                 int cmd,
                 void *arg)
{
    DECLARE_HYPERCALL;
    struct xen_memory_reservation *reservation = arg;
    struct xen_machphys_mfn_list *xmml = arg;
    struct xen_translate_gpfn_list *trans = arg;
    long ret = -EINVAL;

    hypercall.op     = __HYPERVISOR_memory_op;
    hypercall.arg[0] = (unsigned long)cmd;
    hypercall.arg[1] = (unsigned long)arg;

    switch ( cmd )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        if ( mlock(reservation, sizeof(*reservation)) != 0 )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        if ( (reservation->extent_start != NULL) &&
             (mlock(reservation->extent_start,
                    reservation->nr_extents * sizeof(unsigned long)) != 0) )
        {
            PERROR("Could not mlock");
            safe_munlock(reservation, sizeof(*reservation));
            goto out1;
        }
        break;
    case XENMEM_machphys_mfn_list:
        if ( mlock(xmml, sizeof(*xmml)) != 0 )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        if ( mlock(xmml->extent_start,
                   xmml->max_extents * sizeof(unsigned long)) != 0 )
        {
            PERROR("Could not mlock");
            safe_munlock(xmml, sizeof(*xmml));
            goto out1;
        }
        break;
    case XENMEM_reserved_phys_area:
        if ( mlock(arg, sizeof(struct xen_reserved_phys_area)) )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        break;
    case XENMEM_translate_gpfn_list:
        if ( mlock(trans, sizeof(*trans)) != 0 )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        if ( mlock(trans->gpfn_list, trans->nr_gpfns * sizeof(long)) != 0 )
        {
            PERROR("Could not mlock");
            safe_munlock(trans, sizeof(*trans));
            goto out1;
        }
        if ( mlock(trans->mfn_list, trans->nr_gpfns * sizeof(long)) != 0 )
        {
            PERROR("Could not mlock");
            safe_munlock(trans->gpfn_list, trans->nr_gpfns * sizeof(long));
            safe_munlock(trans, sizeof(*trans));
            goto out1;
        }
        break;
    }

    ret = do_xen_hypercall(xc_handle, &hypercall);

    switch ( cmd )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        safe_munlock(reservation, sizeof(*reservation));
        if ( reservation->extent_start != NULL )
            safe_munlock(reservation->extent_start,
                         reservation->nr_extents * sizeof(unsigned long));
        break;
    case XENMEM_machphys_mfn_list:
        safe_munlock(xmml, sizeof(*xmml));
        safe_munlock(xmml->extent_start,
                     xmml->max_extents * sizeof(unsigned long));
        break;
    case XENMEM_reserved_phys_area:
        safe_munlock(arg, sizeof(struct xen_reserved_phys_area));
        break;
    case XENMEM_translate_gpfn_list:
            safe_munlock(trans->mfn_list, trans->nr_gpfns * sizeof(long));
            safe_munlock(trans->gpfn_list, trans->nr_gpfns * sizeof(long));
            safe_munlock(trans, sizeof(*trans));
        break;
    }

 out1:
    return ret;
}    


long long xc_domain_get_cpu_usage( int xc_handle, domid_t domid, int vcpu )
{
    DECLARE_DOM0_OP;

    op.cmd = DOM0_GETVCPUINFO;
    op.u.getvcpuinfo.domain = (domid_t)domid;
    op.u.getvcpuinfo.vcpu   = (uint16_t)vcpu;
    if ( (do_dom0_op(xc_handle, &op) < 0) )
    {
        PERROR("Could not get info on domain");
        return -1;
    }
    return op.u.getvcpuinfo.cpu_time;
}


int xc_get_pfn_list(int xc_handle,
                    uint32_t domid, 
                    unsigned long *pfn_buf, 
                    unsigned long max_pfns)
{
    DECLARE_DOM0_OP;
    int ret;
    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = (domid_t)domid;
    op.u.getmemlist.max_pfns = max_pfns;
    op.u.getmemlist.buffer   = pfn_buf;

#ifdef VALGRIND
    memset(pfn_buf, 0, max_pfns * sizeof(unsigned long));
#endif

    if ( mlock(pfn_buf, max_pfns * sizeof(unsigned long)) != 0 )
    {
        PERROR("xc_get_pfn_list: pfn_buf mlock failed");
        return -1;
    }    

    ret = do_dom0_op(xc_handle, &op);

    safe_munlock(pfn_buf, max_pfns * sizeof(unsigned long));

#if 0
#ifdef DEBUG
    DPRINTF(("Ret for xc_get_pfn_list is %d\n", ret));
    if (ret >= 0) {
        int i, j;
        for (i = 0; i < op.u.getmemlist.num_pfns; i += 16) {
            fprintf(stderr, "0x%x: ", i);
            for (j = 0; j < 16; j++)
                fprintf(stderr, "0x%lx ", pfn_buf[i + j]);
            fprintf(stderr, "\n");
        }
    }
#endif
#endif

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

long xc_get_tot_pages(int xc_handle, uint32_t domid)
{
    DECLARE_DOM0_OP;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    return (do_dom0_op(xc_handle, &op) < 0) ? 
        -1 : op.u.getdomaininfo.tot_pages;
}

int xc_copy_to_domain_page(int xc_handle,
                           uint32_t domid,
                           unsigned long dst_pfn, 
                           void *src_page)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(vaddr, src_page, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

int xc_clear_domain_page(int xc_handle,
                         uint32_t domid,
                         unsigned long dst_pfn)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memset(vaddr, 0, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

unsigned long xc_get_filesz(int fd)
{
    uint16_t sig;
    uint32_t _sz = 0;
    unsigned long sz;

    lseek(fd, 0, SEEK_SET);
    if ( read(fd, &sig, sizeof(sig)) != sizeof(sig) )
        return 0;
    sz = lseek(fd, 0, SEEK_END);
    if ( sig == 0x8b1f ) /* GZIP signature? */
    {
        lseek(fd, -4, SEEK_END);
        if ( read(fd, &_sz, 4) != 4 )
            return 0;
        sz = _sz;
    }
    lseek(fd, 0, SEEK_SET);

    return sz;
}

void xc_map_memcpy(unsigned long dst, char *src, unsigned long size,
                   int xch, uint32_t dom, unsigned long *parray,
                   unsigned long vstart)
{
    char *va;
    unsigned long chunksz, done, pa;

    for ( done = 0; done < size; done += chunksz )
    {
        pa = dst + done - vstart;
        va = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
        chunksz = size - done;
        if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
            chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
        memcpy(va + (pa & (PAGE_SIZE-1)), src + done, chunksz);
        munmap(va, PAGE_SIZE);
    }
}

int xc_dom0_op(int xc_handle, dom0_op_t *op)
{
    return do_dom0_op(xc_handle, op);
}

int xc_version(int xc_handle, int cmd, void *arg)
{
    int rc, argsize = 0;

    switch ( cmd )
    {
    case XENVER_extraversion:
        argsize = sizeof(xen_extraversion_t);
        break;
    case XENVER_compile_info:
        argsize = sizeof(xen_compile_info_t);
        break;
    case XENVER_capabilities:
        argsize = sizeof(xen_capabilities_info_t);
        break;
    case XENVER_changeset:
        argsize = sizeof(xen_changeset_info_t);
        break;
    case XENVER_platform_parameters:
        argsize = sizeof(xen_platform_parameters_t);
        break;
    }

    if ( (argsize != 0) && (mlock(arg, argsize) != 0) )
    {
        PERROR("Could not lock memory for version hypercall");
        return -ENOMEM;
    }

#ifdef VALGRIND
    if (argsize != 0)
        memset(arg, 0, argsize);
#endif

    rc = do_xen_version(xc_handle, cmd, arg);

    if ( argsize != 0 )
        safe_munlock(arg, argsize);

    return rc;
}

unsigned long xc_make_page_below_4G(
    int xc_handle, uint32_t domid, unsigned long mfn)
{
    unsigned long new_mfn;

    if ( xc_domain_memory_decrease_reservation( 
        xc_handle, domid, 1, 0, &mfn) != 0 )
    {
        fprintf(stderr,"xc_make_page_below_4G decrease failed. mfn=%lx\n",mfn);
        return 0;
    }

    if ( xc_domain_memory_increase_reservation(
        xc_handle, domid, 1, 0, 32, &new_mfn) != 0 )
    {
        fprintf(stderr,"xc_make_page_below_4G increase failed. mfn=%lx\n",mfn);
        return 0;
    }

    return new_mfn;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
