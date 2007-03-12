/*
 *	Intel CPU Microcode Update Driver for Linux
 *
 *	Copyright (C) 2000-2004 Tigran Aivazian
 *
 *	This driver allows to upgrade microcode on Intel processors
 *	belonging to IA-32 family - PentiumPro, Pentium II, 
 *	Pentium III, Xeon, Pentium 4, etc.
 *
 *	Reference: Section 8.10 of Volume III, Intel Pentium 4 Manual, 
 *	Order Number 245472 or free download from:
 *		
 *	http://developer.intel.com/design/pentium4/manuals/245472.htm
 *
 *	For more information, go to http://www.urbanmyth.org/microcode
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

//#define DEBUG /* pr_debug */
#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>

#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/processor.h>

MODULE_DESCRIPTION("Intel CPU (IA-32) Microcode Update Driver");
MODULE_AUTHOR("Tigran Aivazian <tigran@veritas.com>");
MODULE_LICENSE("GPL");

static int verbose;
module_param(verbose, int, 0644);

#define MICROCODE_VERSION 	"1.14a-xen"

#define DEFAULT_UCODE_DATASIZE 	(2000) 	  /* 2000 bytes */
#define MC_HEADER_SIZE		(sizeof (microcode_header_t))  	  /* 48 bytes */
#define DEFAULT_UCODE_TOTALSIZE (DEFAULT_UCODE_DATASIZE + MC_HEADER_SIZE) /* 2048 bytes */

/* no concurrent ->write()s are allowed on /dev/cpu/microcode */
static DEFINE_MUTEX(microcode_mutex);
				
static int microcode_open (struct inode *unused1, struct file *unused2)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}


static int do_microcode_update (const void __user *ubuf, size_t len)
{
	int err;
	void *kbuf;

	kbuf = vmalloc(len);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, ubuf, len) == 0) {
		struct xen_platform_op op;

		op.cmd = XENPF_microcode_update;
		set_xen_guest_handle(op.u.microcode.data, kbuf);
		op.u.microcode.length = len;
		err = HYPERVISOR_platform_op(&op);
	} else
		err = -EFAULT;

	vfree(kbuf);

	return err;
}

static ssize_t microcode_write (struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	ssize_t ret;

	if (len < MC_HEADER_SIZE) {
		printk(KERN_ERR "microcode: not enough data\n"); 
		return -EINVAL;
	}

	mutex_lock(&microcode_mutex);

	ret = do_microcode_update(buf, len);
	if (!ret)
		ret = (ssize_t)len;

	mutex_unlock(&microcode_mutex);

	return ret;
}

static struct file_operations microcode_fops = {
	.owner		= THIS_MODULE,
	.write		= microcode_write,
	.open		= microcode_open,
};

static struct miscdevice microcode_dev = {
	.minor		= MICROCODE_MINOR,
	.name		= "microcode",
	.fops		= &microcode_fops,
};

static int __init microcode_init (void)
{
	int error;

	error = misc_register(&microcode_dev);
	if (error) {
		printk(KERN_ERR
			"microcode: can't misc_register on minor=%d\n",
			MICROCODE_MINOR);
		return error;
	}

	printk(KERN_INFO 
		"IA-32 Microcode Update Driver: v" MICROCODE_VERSION " <tigran@veritas.com>\n");
	return 0;
}

static void __exit microcode_exit (void)
{
	misc_deregister(&microcode_dev);
}

module_init(microcode_init)
module_exit(microcode_exit)
MODULE_ALIAS_MISCDEV(MICROCODE_MINOR);
