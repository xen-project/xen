#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <asm-xen/xen-public/physdev.h>

asmlinkage long sys_iopl(unsigned int new_io_pl)
{
    unsigned int old_io_pl = current->thread.io_pl;
    physdev_op_t op;

    if (new_io_pl > 3)
        return -EINVAL;

	/* Need "raw I/O" privileges for direct port access. */
    if ((new_io_pl > old_io_pl) && !capable(CAP_SYS_RAWIO))
        return -EPERM;

	/* Maintain OS privileges even if user attempts to relinquish them. */
    if (new_io_pl == 0)
        new_io_pl = 1;

	/* Change our version of the privilege levels. */
    current->thread.io_pl = new_io_pl;

    /* Force the change at ring 0. */
    op.cmd             = PHYSDEVOP_SET_IOPL;
    op.u.set_iopl.iopl = new_io_pl;
    HYPERVISOR_physdev_op(&op);

    return 0;
}

asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
    return turn_on ? sys_iopl(3) : 0;
}
