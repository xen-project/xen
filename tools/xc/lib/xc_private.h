
#ifndef __XC_PRIVATE_H__
#define __XC_PRIVATE_H__

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#include "xc.h"

#include <asm-xen/proc_cmd.h>

/* from xen/include/hypervisor-ifs */
#include <hypervisor-if.h>
#include <dom0_ops.h>
#include <vbd.h>
#include <event_channel.h>
#include <sched_ctl.h>

/* from xend/lib */
#include <domain_controller.h>

#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE       0x080
#define _PAGE_GLOBAL    0x100


#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       22
 
#define ENTRIES_PER_L1_PAGETABLE 1024
#define ENTRIES_PER_L2_PAGETABLE 1024
 
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

typedef unsigned long l1_pgentry_t;
typedef unsigned long l2_pgentry_t;

#define l1_table_offset(_a) \
          (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#define l2_table_offset(_a) \
          ((_a) >> L2_PAGETABLE_SHIFT)

#define ERROR(_m, _a...)  \
    fprintf(stderr, "ERROR: " _m "\n" , ## _a )

#define PERROR(_m, _a...) \
    fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a , \
            errno, strerror(errno))

static inline int do_privcmd(int xc_handle,
                             unsigned int cmd, 
                             unsigned long data)
{
    return ioctl(xc_handle, cmd, data);
}

static inline int do_xen_hypercall(int xc_handle,
                                   privcmd_hypercall_t *hypercall)
{
    return do_privcmd(xc_handle,
                      IOCTL_PRIVCMD_HYPERCALL, 
                      (unsigned long)hypercall);
}

static inline int do_dom0_op(int xc_handle, dom0_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    op->interface_version = DOM0_INTERFACE_VERSION;

    hypercall.op     = __HYPERVISOR_dom0_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
    {
        if ( errno == EACCES )
            fprintf(stderr, "Dom0 operation failed -- need to"
                    " rebuild the user-space tool set?\n");
        goto out2;
    }

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}

static inline int do_network_op(int xc_handle, network_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_network_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
        goto out2;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}


static inline int do_block_io_op(int xc_handle, block_io_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_block_io_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
        goto out2;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}

/*
 * PFN mapping.
 */
int init_pfn_mapper(domid_t domid);
int close_pfn_mapper(int pm_handle);
void *map_pfn_writeable(int pm_handle, unsigned long pfn);
void *map_pfn_readonly(int pm_handle, unsigned long pfn);
void unmap_pfn(int pm_handle, void *vaddr);

/*
 * MMU updates.
 */
#define MAX_MMU_UPDATES 1024
typedef struct {
    mmu_update_t updates[MAX_MMU_UPDATES];
    int          idx;
    domid_t      subject;
} mmu_t;
mmu_t *init_mmu_updates(int xc_handle, domid_t dom);
int add_mmu_update(int xc_handle, mmu_t *mmu, 
                   unsigned long ptr, unsigned long val);
int finish_mmu_updates(int xc_handle, mmu_t *mmu);


/*
 * ioctl-based mfn mapping interface
 */

/*
typedef struct privcmd_mmap_entry {
    unsigned long va;
    unsigned long mfn;
    unsigned long npages;
} privcmd_mmap_entry_t; 

typedef struct privcmd_mmap {
    int num;
    privcmd_mmap_entry_t *entry;
} privcmd_mmap_t; 
*/

#define mfn_mapper_queue_size 128

typedef struct mfn_mapper {
    int xc_handle;
    int size;
    int prot;
    int max_queue_size;
    void * addr;
    privcmd_mmap_t ioctl; 
    
} mfn_mapper_t;

void * mfn_mapper_map_single(int xc_handle, int prot, 
			     unsigned long mfn, int size);

mfn_mapper_t * mfn_mapper_init(int xc_handle, int size, int prot);

void * mfn_mapper_base(mfn_mapper_t *t);

void mfn_mapper_close(mfn_mapper_t *t);

int mfn_mapper_flush_queue(mfn_mapper_t *t);

void * mfn_mapper_queue_entry(mfn_mapper_t *t, int offset, 
			      unsigned long mfn, int size );


#endif /* __XC_PRIVATE_H__ */
