/*
 *	linux/arch/x86_64/kernel/ioport.c
 *
 * This contains the io-permission bitmap code - written by obz, with changes
 * by Linus.
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/thread_info.h>
#include <xen/interface/physdev.h>

/* Set EXTENT bits starting at BASE in BITMAP to value TURN_ON. */
static void set_bitmap(unsigned long *bitmap, unsigned int base, unsigned int extent, int new_value)
{
	int i;

	if (new_value)
		for (i = base; i < base + extent; i++)
			__set_bit(i, bitmap);
	else
		for (i = base; i < base + extent; i++)
			clear_bit(i, bitmap);
}

/*
 * this changes the io permissions bitmap in the current task.
 */
asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
	struct thread_struct * t = &current->thread;
	unsigned long *bitmap;
	struct physdev_set_iobitmap set_iobitmap;

	if ((from + num <= from) || (from + num > IO_BITMAP_BITS))
		return -EINVAL;
	if (turn_on && !capable(CAP_SYS_RAWIO))
		return -EPERM;

	/*
	 * If it's the first ioperm() call in this thread's lifetime, set the
	 * IO bitmap up. ioperm() is much less timing critical than clone(),
	 * this is why we delay this operation until now:
	 */
	if (!t->io_bitmap_ptr) {
		bitmap = kmalloc(IO_BITMAP_BYTES, GFP_KERNEL);
		if (!bitmap)
			return -ENOMEM;

		memset(bitmap, 0xff, IO_BITMAP_BYTES);
		t->io_bitmap_ptr = bitmap;

		set_xen_guest_handle(set_iobitmap.bitmap, (char *)bitmap);
		set_iobitmap.nr_ports = IO_BITMAP_BITS;
		HYPERVISOR_physdev_op(PHYSDEVOP_set_iobitmap, &set_iobitmap);
	}

	set_bitmap(t->io_bitmap_ptr, from, num, !turn_on);

	return 0;
}

/*
 * sys_iopl has to be used when you want to access the IO ports
 * beyond the 0x3ff range: to get the full 65536 ports bitmapped
 * you'd need 8kB of bitmaps/process, which is a bit excessive.
 *
 */

asmlinkage long sys_iopl(unsigned int new_iopl, struct pt_regs *regs)
{
	unsigned int old_iopl = current->thread.iopl;
	struct physdev_set_iopl set_iopl;

	if (new_iopl > 3)
		return -EINVAL;

	/* Need "raw I/O" privileges for direct port access. */
	if ((new_iopl > old_iopl) && !capable(CAP_SYS_RAWIO))
		return -EPERM;

	/* Change our version of the privilege levels. */
	current->thread.iopl = new_iopl;

	/* Force the change at ring 0. */
	set_iopl.iopl = (new_iopl == 0) ? 1 : new_iopl;
	HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);

	return 0;
}
