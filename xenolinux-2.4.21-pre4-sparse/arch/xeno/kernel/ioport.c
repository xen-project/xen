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
    unsigned int level = regs->ebx;
    unsigned int old = (regs->eflags >> 12) & 3;

    if ( !(start_info.flags & SIF_PRIVILEGED) )
        return -EPERM;

    if ( level > 3 )
        return -EINVAL;
    if ( (level > old) && !capable(CAP_SYS_RAWIO) )
        return -EPERM;
    
    /* Change the one on our stack for sanity's sake. */
    regs->eflags = (regs->eflags & 0xffffcfff) | (level << 12);

    /* Force the change at ring 0. */
    HYPERVISOR_iopl(level);

    return 0;
}
