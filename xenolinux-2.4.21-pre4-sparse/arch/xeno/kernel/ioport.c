#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/stddef.h>


asmlinkage int sys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
    /* No IO permission! Selective IO perms aren't virtualised yet. */
    return -EPERM;
}


asmlinkage int sys_iopl(unsigned long unused)
{
    struct pt_regs *regs = (struct pt_regs *)&unused;
    unsigned int new_io_pl = regs->ebx & 3;
    unsigned int old_io_pl = current->thread.io_pl;
    unsigned int new_hypercall_pl = (regs->ebx >> 2) & 3;
    unsigned int old_hypercall_pl = current->thread.hypercall_pl;

    /* Need "raw I/O" privileges for direct port access. */
    if ( (new_io_pl > old_io_pl) && 
         (!capable(CAP_SYS_RAWIO) || !(start_info.flags & SIF_PRIVILEGED)) )
        return -EPERM;

    /* Just need generic root/admin privileges for direct hypercall access. */
    if ( (new_hypercall_pl > old_hypercall_pl) && !capable(CAP_SYS_ADMIN) )
        return -EPERM;

    /* Maintain OS privileges even if user attempts to relinquish them. */
    if ( new_hypercall_pl == 0 )
        new_hypercall_pl = 1;
    if ( (new_io_pl == 0) && (start_info.flags & SIF_PRIVILEGED) )
        new_io_pl = 1;

    /* Change our version of the privilege levels. */
    current->thread.io_pl        = new_io_pl;
    current->thread.hypercall_pl = new_hypercall_pl;

    /* Force the change at ring 0. */
    HYPERVISOR_set_priv_levels(new_io_pl, new_hypercall_pl);

    return 0;
}
