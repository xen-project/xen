
#ifndef XC_PRIVATE_H
#define XC_PRIVATE_H

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "xenctrl.h"

#include <xen/linux/privcmd.h>

#define PAGE_SHIFT              XC_PAGE_SHIFT
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

#define ERROR(_m, _a...)                                \
do {                                                    \
    int __saved_errno = errno;                          \
    fprintf(stderr, "ERROR: " _m "\n" , ## _a );        \
    errno = __saved_errno;                              \
} while (0)


#define PERROR(_m, _a...)                                       \
do {                                                            \
    int __saved_errno = errno;                                  \
    fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,       \
            __saved_errno, strerror(__saved_errno));            \
    errno = __saved_errno;                                      \
} while (0)

static inline void safe_munlock(const void *addr, size_t len)
{
    int saved_errno = errno;
    (void)munlock(addr, len);
    errno = saved_errno;
}

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

static inline int do_xen_version(int xc_handle, int cmd, void *dest)
{
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_xen_version;
    hypercall.arg[0] = (unsigned long) cmd;
    hypercall.arg[1] = (unsigned long) dest;
    
    return do_xen_hypercall(xc_handle, &hypercall);
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
    }

    safe_munlock(op, sizeof(*op));

 out1:
    return ret;
}


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
    domid_t dom;
    privcmd_mmap_entry_t *entry;
} privcmd_mmap_t; 
*/

#endif /* __XC_PRIVATE_H__ */
