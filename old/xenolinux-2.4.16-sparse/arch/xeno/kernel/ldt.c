/*
 * linux/kernel/ldt.c
 *
 * Copyright (C) 1992 Krishna Balasubramanian and Linus Torvalds
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>

/*
 * XXX KAF (28/7/02): This stuff is only used for DOS emulation, and is
 * the default way of finding current TCB in linuxthreads. Supporting
 * table update svia the hypervisor is feasible, but a hassle: for now,
 * recompiling linuxthreads is the most sensible option.
 * 
 * Oh, this may become an issue depending on what JVM we use for
 * running the xeno-daemon.
 */

asmlinkage int sys_modify_ldt(int func, void *ptr, unsigned long bytecount)
{
    return -ENOSYS;
}
