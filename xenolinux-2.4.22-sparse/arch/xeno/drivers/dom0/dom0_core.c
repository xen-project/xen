/******************************************************************************
 * dom0_core.c
 * 
 * Interface to privileged domain-0 commands.
 * 
 * Copyright (c) 2002-2003, K A Fraser, B Dragovic
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/swapctl.h>
#include <linux/iobuf.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/proc_cmd.h>
#include <asm/hypervisor-ifs/dom0_ops.h>
#include <asm/xeno_proc.h>

#include "../block/xl_block.h"

static struct proc_dir_entry *privcmd_intf;


static int privcmd_ioctl(struct inode *inode, struct file *file,
                         unsigned int cmd, unsigned long data)
{
    int ret = 0;

    switch ( cmd )
    {
    case IOCTL_PRIVCMD_HYPERCALL:
    {
        privcmd_hypercall_t hypercall;
  
        if ( copy_from_user(&hypercall, (void *)data, sizeof(hypercall)) )
            return -EFAULT;

        __asm__ __volatile__ (
            "pushl %%ebx; pushl %%ecx; pushl %%edx; pushl %%esi; pushl %%edi; "
            "movl  4(%%eax),%%ebx ;"
            "movl  8(%%eax),%%ecx ;"
            "movl 12(%%eax),%%edx ;"
            "movl 16(%%eax),%%esi ;"
            "movl 20(%%eax),%%edi ;"
            "movl   (%%eax),%%eax ;"
            TRAP_INSTR "; "
            "popl %%edi; popl %%esi; popl %%edx; popl %%ecx; popl %%ebx"
            : "=a" (ret) : "0" (&hypercall) : "memory" );

    }
    break;

    case IOCTL_PRIVCMD_BLKMSG:
    {
        privcmd_blkmsg_t blkmsg;
        char            *kbuf;
        int              ret;
  
        if ( copy_from_user(&blkmsg, (void *)data, sizeof(blkmsg)) )
            return -EFAULT;
  
        if ( blkmsg.buf_size > PAGE_SIZE )
            return -EINVAL;
  
        if ( (kbuf = kmalloc(blkmsg.buf_size, GFP_KERNEL)) == NULL )
            return -ENOMEM;
  
        if ( copy_from_user(kbuf, blkmsg.buf, blkmsg.buf_size) ) {
            kfree(kbuf);
            return -EFAULT;
        }
  
        ret = xenolinux_control_msg((int)blkmsg.op, kbuf, blkmsg.buf_size);
        if ( ret != 0 ) {
            kfree(kbuf);
            return ret;
        }
  
        if ( copy_to_user(blkmsg.buf, kbuf, blkmsg.buf_size) ) {
            kfree(kbuf);
            return -EFAULT;
        }
  
        kfree(kbuf);
    }
    break;
    
    default:
        ret = -EINVAL;
    	break;
	}
    return ret;
}


static struct file_operations privcmd_file_ops = {
  ioctl : privcmd_ioctl
};


static int __init init_module(void)
{
    if ( !(start_info.flags & SIF_PRIVILEGED) )
        return 0;

    /* xeno control interface */
    privcmd_intf = create_xeno_proc_entry("privcmd", 0400);
    if ( privcmd_intf != NULL )
    {
        privcmd_intf->owner      = THIS_MODULE;
        privcmd_intf->nlink      = 1;
	privcmd_intf->proc_fops  = &privcmd_file_ops;
    }

    return 0;
}


static void __exit cleanup_module(void)
{
    if ( privcmd_intf == NULL ) return;
    remove_xeno_proc_entry("privcmd");
    privcmd_intf = NULL;
}


module_init(init_module);
module_exit(cleanup_module);
