
#ifndef __DOM0_DEFS_H__
#define __DOM0_DEFS_H__

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

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned long      u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed long        s32;
typedef signed long long   s64;

#include "mem_defs.h"
#include <asm-xeno/proc_cmd.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <hypervisor-ifs/vbd.h>

#define ERROR(_m)  \
    fprintf(stderr, "ERROR: %s\n", (_m))

#define PERROR(_m) \
    fprintf(stderr, "ERROR: %s (%d = %s)\n", (_m), errno, strerror(errno))

static inline int do_privcmd(unsigned int cmd, unsigned long data)
{
    int fd, ret;

    if ( (fd = open("/proc/xeno/privcmd", O_RDWR)) < 0 )
    {
        PERROR("Could not open proc interface");
        return -1;
    }

    if ( (ret = ioctl(fd, cmd, data)) < 0 )
    {
#ifndef SILENT_ERRORS_FROM_XEN
        PERROR("Error when executing privileged control ioctl");
#endif
        close(fd);
        return ret;
    }

    close(fd);
    return ret;
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
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

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
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

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
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    if ( do_xen_hypercall(&hypercall) < 0 )
        goto out2;

    ret = 0;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}

#endif /* __DOM0_DEFS_H__ */
