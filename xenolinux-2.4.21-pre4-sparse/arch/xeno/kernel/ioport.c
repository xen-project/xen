#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/stddef.h>


asmlinkage int sys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
    /* No IO permission! */
		return -EPERM;
}


asmlinkage int sys_iopl(unsigned long unused)
{
    /* The hypervisor won't allow it! */
			return -EPERM;
}
