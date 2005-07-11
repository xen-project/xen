/*
 *  linux/arch/x86_64/kernel/vsyscall.c
 *
 *  Copyright (C) 2001 Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright 2003 Andi Kleen, SuSE Labs.
 *
 *  Thanks to hpa@transmeta.com for some useful hint.
 *  Special thanks to Ingo Molnar for his early experience with
 *  a different vsyscall implementation for Linux/IA32 and for the name.
 *
 *  vsyscall 1 is located at -10Mbyte, vsyscall 2 is located
 *  at virtual address -10Mbyte+1024bytes etc... There are at max 8192
 *  vsyscalls. One vsyscall can reserve more than 1 slot to avoid
 *  jumping out of line if necessary.
 *
 *  Note: the concept clashes with user mode linux. If you use UML just
 *  set the kernel.vsyscall sysctl to 0.
 */

/*
 * TODO 2001-03-20:
 *
 * 1) make page fault handler detect faults on page1-page-last of the vsyscall
 *    virtual space, and make it increase %rip and write -ENOSYS in %rax (so
 *    we'll be able to upgrade to a new glibc without upgrading kernel after
 *    we add more vsyscalls.
 * 2) Possibly we need a fixmap table for the vsyscalls too if we want
 *    to avoid SIGSEGV and we want to return -EFAULT from the vsyscalls as well.
 *    Can we segfault inside a "syscall"? We can fix this anytime and those fixes
 *    won't be visible for userspace. Not fixing this is a noop for correct programs,
 *    broken programs will segfault and there's no security risk until we choose to
 *    fix it.
 *
 * These are not urgent things that we need to address only before shipping the first
 * production binary kernels.
 */

#include <linux/time.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/seqlock.h>
#include <linux/jiffies.h>

#include <asm/vsyscall.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/fixmap.h>
#include <asm/errno.h>
#include <asm/io.h>

#define __vsyscall(nr) __attribute__ ((unused,__section__(".vsyscall_" #nr)))
#define force_inline __attribute__((always_inline)) inline

int __sysctl_vsyscall __section_sysctl_vsyscall = 1;
seqlock_t __xtime_lock __section_xtime_lock = SEQLOCK_UNLOCKED;

#include <asm/unistd.h>

static force_inline void timeval_normalize(struct timeval * tv)
{
	time_t __sec;

	__sec = tv->tv_usec / 1000000;
	if (__sec)
	{
		tv->tv_usec %= 1000000;
		tv->tv_sec += __sec;
	}
}

static force_inline void do_vgettimeofday(struct timeval * tv)
{
	long sequence, t;
	unsigned long sec, usec;

	do {
		sequence = read_seqbegin(&__xtime_lock);
		
		sec = __xtime.tv_sec;
		usec = (__xtime.tv_nsec / 1000) +
			(__jiffies - __wall_jiffies) * (1000000 / HZ);

		if (__vxtime.mode == VXTIME_TSC) {
			sync_core();
			rdtscll(t);
			if (t < __vxtime.last_tsc) t = __vxtime.last_tsc;
			usec += ((t - __vxtime.last_tsc) *
				 __vxtime.tsc_quot) >> 32;
			/* See comment in x86_64 do_gettimeofday. */ 
		} else {
			usec += ((readl((void *)fix_to_virt(VSYSCALL_HPET) + 0xf0) -
				  __vxtime.last) * __vxtime.quot) >> 32;
		}
	} while (read_seqretry(&__xtime_lock, sequence));

	tv->tv_sec = sec + usec / 1000000;
	tv->tv_usec = usec % 1000000;
}

/* RED-PEN may want to readd seq locking, but then the variable should be write-once. */
static force_inline void do_get_tz(struct timezone * tz)
{
		*tz = __sys_tz;
}


static force_inline int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	int ret;
	asm volatile("syscall" 
		: "=a" (ret)
		: "0" (__NR_gettimeofday),"D" (tv),"S" (tz) : __syscall_clobber );
	return ret;
}

static force_inline long time_syscall(long *t)
{
	long secs;
	asm volatile("syscall" 
		: "=a" (secs)
		: "0" (__NR_time),"D" (t) : __syscall_clobber);
	return secs;
}

static int __vsyscall(0) vgettimeofday(struct timeval * tv, struct timezone * tz)
{
	if (unlikely(!__sysctl_vsyscall))
	return gettimeofday(tv,tz); 
	if (tv)
		do_vgettimeofday(tv);
	if (tz)
		do_get_tz(tz);
	return 0;
}

/* This will break when the xtime seconds get inaccurate, but that is
 * unlikely */
static time_t __vsyscall(1) vtime(time_t *t)
{
	if (unlikely(!__sysctl_vsyscall))
		return time_syscall(t);
	else if (t)
		*t = __xtime.tv_sec;		
	return __xtime.tv_sec;
}

static long __vsyscall(2) venosys_0(void)
{
	return -ENOSYS;
}

static long __vsyscall(3) venosys_1(void)
{
	return -ENOSYS;

}

static void __init map_vsyscall(void)
{
	extern char __vsyscall_0;
	unsigned long physaddr_page0 = __pa_symbol(&__vsyscall_0);

	__set_fixmap(VSYSCALL_FIRST_PAGE, physaddr_page0, PAGE_KERNEL_VSYSCALL);
}

extern void __set_fixmap_user (enum fixed_addresses, unsigned long, pgprot_t);

static void __init map_vsyscall_user(void)
{
	extern char __vsyscall_0;
	unsigned long physaddr_page0 = __pa_symbol(&__vsyscall_0);

	__set_fixmap_user(VSYSCALL_FIRST_PAGE, physaddr_page0, PAGE_KERNEL_VSYSCALL);
}

static int __init vsyscall_init(void)
{
        BUG_ON(((unsigned long) &vgettimeofday != 
		      VSYSCALL_ADDR(__NR_vgettimeofday)));
	BUG_ON((unsigned long) &vtime != VSYSCALL_ADDR(__NR_vtime));
	BUG_ON((VSYSCALL_ADDR(0) != __fix_to_virt(VSYSCALL_FIRST_PAGE)));
	map_vsyscall();
        map_vsyscall_user();    /* establish tranlation for user address space */
	sysctl_vsyscall = 0;    /* TBD */

	return 0;
}

__initcall(vsyscall_init);
