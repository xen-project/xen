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
#include <linux/syscalls.h>

#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/processor.h>

MODULE_DESCRIPTION("Intel CPU (IA-32) Microcode Update Driver");
MODULE_AUTHOR("Tigran Aivazian <tigran@veritas.com>");
MODULE_LICENSE("GPL");

#define MICROCODE_VERSION 	"1.14-xen"

#define DEFAULT_UCODE_DATASIZE 	(2000) 	  /* 2000 bytes */
#define MC_HEADER_SIZE		(sizeof (microcode_header_t))  	  /* 48 bytes */
#define DEFAULT_UCODE_TOTALSIZE (DEFAULT_UCODE_DATASIZE + MC_HEADER_SIZE) /* 2048 bytes */

/* no concurrent ->write()s are allowed on /dev/cpu/microcode */
static DECLARE_MUTEX(microcode_sem);

static void __user *user_buffer;	/* user area microcode data buffer */
static unsigned int user_buffer_size;	/* it's size */
				
static int microcode_open (struct inode *unused1, struct file *unused2)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}


static int do_microcode_update (void)
{
	int err;
	dom0_op_t op;

	err = sys_mlock((unsigned long)user_buffer, user_buffer_size);
	if (err != 0)
		return err;

	op.cmd = DOM0_MICROCODE;
	op.u.microcode.data = user_buffer;
	op.u.microcode.length = user_buffer_size;
	err = HYPERVISOR_dom0_op(&op);

	(void)sys_munlock((unsigned long)user_buffer, user_buffer_size);

	return err;
}

static ssize_t microcode_write (struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	ssize_t ret;

	if (len < DEFAULT_UCODE_TOTALSIZE) {
		printk(KERN_ERR "microcode: not enough data\n"); 
		return -EINVAL;
	}

	if ((len >> PAGE_SHIFT) > num_physpages) {
		printk(KERN_ERR "microcode: too much data (max %ld pages)\n", num_physpages);
		return -EINVAL;
	}

	down(&microcode_sem);

	user_buffer = (void __user *) buf;
	user_buffer_size = (int) len;

	ret = do_microcode_update();
	if (!ret)
		ret = (ssize_t)len;

	up(&microcode_sem);

	return ret;
}

static int microcode_ioctl (struct inode *inode, struct file *file, 
		unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		/* 
		 *  XXX: will be removed after microcode_ctl 
		 *  is updated to ignore failure of this ioctl()
		 */
		case MICROCODE_IOCFREE:
			return 0;
		default:
			return -EINVAL;
	}
	return -EINVAL;
}

static struct file_operations microcode_fops = {
	.owner		= THIS_MODULE,
	.write		= microcode_write,
	.ioctl		= microcode_ioctl,
	.open		= microcode_open,
};

static struct miscdevice microcode_dev = {
	.minor		= MICROCODE_MINOR,
	.name		= "microcode",
	.devfs_name	= "cpu/microcode",
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
	printk(KERN_INFO "IA-32 Microcode Update Driver v" MICROCODE_VERSION " unregistered\n");
}

module_init(microcode_init)
module_exit(microcode_exit)
MODULE_ALIAS_MISCDEV(MICROCODE_MINOR);
