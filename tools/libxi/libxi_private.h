
#ifndef __LIBXI_PRIVATE_H__
#define __LIBXI_PRIVATE_H__

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned long      u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed long        s32;
typedef signed long long   s64;

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

#include "xi.h"

#include <asm-xeno/proc_cmd.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <hypervisor-ifs/vbd.h>

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

typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;

#define l1_table_offset(_a) \
          (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#define l2_table_offset(_a) \
          ((_a) >> L2_PAGETABLE_SHIFT)

#define ERROR(_m)  \
    fprintf(stderr, "ERROR: %s\n", (_m))

#define PERROR(_m) \
    fprintf(stderr, "ERROR: %s (%d = %s)\n", (_m), errno, strerror(errno))

extern int privcmd_fd;
static inline int do_privcmd(unsigned int cmd, unsigned long data)
{
    return ioctl(privcmd_fd, cmd, data);
}

static inline int do_xen_hypercall(privcmd_hypercall_t *hypercall)
{
    return do_privcmd(IOCTL_PRIVCMD_HYPERCALL, (unsigned long)hypercall);
}

static inline int do_dom0_op(dom0_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    op->interface_version = DOM0_INTERFACE_VERSION;

    hypercall.op     = __HYPERVISOR_dom0_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
        goto out1;

    if ( (ret = do_xen_hypercall(&hypercall)) < 0 )
    {
        if ( errno == EACCES )
            fprintf(stderr, "Dom0 operation failed -- need to"
                    " rebuild the user-space tool set?\n");
        goto out2;
    }

    ret = 0;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}

static inline int do_network_op(network_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_network_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
        goto out1;

    if ( (ret = do_xen_hypercall(&hypercall)) < 0 )
        goto out2;

    ret = 0;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}


static inline int do_block_io_op(block_io_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_block_io_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
        goto out1;

    if ( do_xen_hypercall(&hypercall) < 0 )
        goto out2;

    ret = 0;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}

/*
 * PFN mapping.
 */
int init_pfn_mapper(void);
void *map_pfn(unsigned long pfn);
void unmap_pfn(void *vaddr);

#endif /* __LIBXI_PRIVATE_H__ */
