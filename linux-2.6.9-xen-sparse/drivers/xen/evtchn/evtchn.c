/******************************************************************************
 * evtchn.c
 * 
 * Xenolinux driver for receiving and demuxing event-channel signals.
 * 
 * Copyright (c) 2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/major.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/poll.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <asm-xen/evtchn.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <linux/devfs_fs_kernel.h>
#define OLD_DEVFS
#else
#include <linux/gfp.h>
#endif

#ifdef OLD_DEVFS
/* NB. This must be shared amongst drivers if more things go in /dev/xen */
static devfs_handle_t xen_dev_dir;
#endif

/* Only one process may open /dev/xen/evtchn at any time. */
static unsigned long evtchn_dev_inuse;

/* Notification ring, accessed via /dev/xen/evtchn. */
#define RING_SIZE     2048  /* 2048 16-bit entries */
#define RING_MASK(_i) ((_i)&(RING_SIZE-1))
static u16 *ring;
static unsigned int ring_cons, ring_prod, ring_overflow;

/* Processes wait on this queue via /dev/xen/evtchn when ring is empty. */
static DECLARE_WAIT_QUEUE_HEAD(evtchn_wait);
static struct fasync_struct *evtchn_async_queue;

/* Which ports is user-space bound to? */
static u32 bound_ports[32];

static spinlock_t lock;

void evtchn_device_upcall(int port)
{
    spin_lock(&lock);

    mask_evtchn(port);
    clear_evtchn(port);

    if ( ring != NULL )
    {
        if ( (ring_prod - ring_cons) < RING_SIZE )
        {
            ring[RING_MASK(ring_prod)] = (u16)port;
            if ( ring_cons == ring_prod++ )
            {
                wake_up_interruptible(&evtchn_wait);
                kill_fasync(&evtchn_async_queue, SIGIO, POLL_IN);
            }
        }
        else
        {
            ring_overflow = 1;
        }
    }

    spin_unlock(&lock);
}

static void __evtchn_reset_buffer_ring(void)
{
    /* Initialise the ring to empty. Clear errors. */
    ring_cons = ring_prod = ring_overflow = 0;
}

static ssize_t evtchn_read(struct file *file, char *buf,
                           size_t count, loff_t *ppos)
{
    int rc;
    unsigned int c, p, bytes1 = 0, bytes2 = 0;
    DECLARE_WAITQUEUE(wait, current);

    add_wait_queue(&evtchn_wait, &wait);

    count &= ~1; /* even number of bytes */

    if ( count == 0 )
    {
        rc = 0;
        goto out;
    }

    if ( count > PAGE_SIZE )
        count = PAGE_SIZE;

    for ( ; ; )
    {
        set_current_state(TASK_INTERRUPTIBLE);

        if ( (c = ring_cons) != (p = ring_prod) )
            break;

        if ( ring_overflow )
        {
            rc = -EFBIG;
            goto out;
        }

        if ( file->f_flags & O_NONBLOCK )
        {
            rc = -EAGAIN;
            goto out;
        }

        if ( signal_pending(current) )
        {
            rc = -ERESTARTSYS;
            goto out;
        }

        schedule();
    }

    /* Byte lengths of two chunks. Chunk split (if any) is at ring wrap. */
    if ( ((c ^ p) & RING_SIZE) != 0 )
    {
        bytes1 = (RING_SIZE - RING_MASK(c)) * sizeof(u16);
        bytes2 = RING_MASK(p) * sizeof(u16);
    }
    else
    {
        bytes1 = (p - c) * sizeof(u16);
        bytes2 = 0;
    }

    /* Truncate chunks according to caller's maximum byte count. */
    if ( bytes1 > count )
    {
        bytes1 = count;
        bytes2 = 0;
    }
    else if ( (bytes1 + bytes2) > count )
    {
        bytes2 = count - bytes1;
    }

    if ( copy_to_user(buf, &ring[RING_MASK(c)], bytes1) ||
         ((bytes2 != 0) && copy_to_user(&buf[bytes1], &ring[0], bytes2)) )
    {
        rc = -EFAULT;
        goto out;
    }

    ring_cons += (bytes1 + bytes2) / sizeof(u16);

    rc = bytes1 + bytes2;

 out:
    __set_current_state(TASK_RUNNING);
    remove_wait_queue(&evtchn_wait, &wait);
    return rc;
}

static ssize_t evtchn_write(struct file *file, const char *buf,
                            size_t count, loff_t *ppos)
{
    int  rc, i;
    u16 *kbuf = (u16 *)__get_free_page(GFP_KERNEL);

    if ( kbuf == NULL )
        return -ENOMEM;

    count &= ~1; /* even number of bytes */

    if ( count == 0 )
    {
        rc = 0;
        goto out;
    }

    if ( count > PAGE_SIZE )
        count = PAGE_SIZE;

    if ( copy_from_user(kbuf, buf, count) != 0 )
    {
        rc = -EFAULT;
        goto out;
    }

    spin_lock_irq(&lock);
    for ( i = 0; i < (count/2); i++ )
        if ( test_bit(kbuf[i], (unsigned long *)&bound_ports[0]) )
            unmask_evtchn(kbuf[i]);
    spin_unlock_irq(&lock);

    rc = count;

 out:
    free_page((unsigned long)kbuf);
    return rc;
}

static int evtchn_ioctl(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg)
{
    int rc = 0;
    
    spin_lock_irq(&lock);
    
    switch ( cmd )
    {
    case EVTCHN_RESET:
        __evtchn_reset_buffer_ring();
        break;
    case EVTCHN_BIND:
        if ( !test_and_set_bit(arg, (unsigned long *)&bound_ports[0]) )
            unmask_evtchn(arg);
        else
            rc = -EINVAL;
        break;
    case EVTCHN_UNBIND:
        if ( test_and_clear_bit(arg, (unsigned long *)&bound_ports[0]) )
            mask_evtchn(arg);
        else
            rc = -EINVAL;
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    spin_unlock_irq(&lock);   

    return rc;
}

static unsigned int evtchn_poll(struct file *file, poll_table *wait)
{
    unsigned int mask = POLLOUT | POLLWRNORM;
    poll_wait(file, &evtchn_wait, wait);
    if ( ring_cons != ring_prod )
        mask |= POLLIN | POLLRDNORM;
    if ( ring_overflow )
        mask = POLLERR;
    return mask;
}

static int evtchn_fasync(int fd, struct file *filp, int on)
{
    return fasync_helper(fd, filp, on, &evtchn_async_queue);
}

static int evtchn_open(struct inode *inode, struct file *filp)
{
    u16 *_ring;

    if ( test_and_set_bit(0, &evtchn_dev_inuse) )
        return -EBUSY;

    /* Allocate outside locked region so that we can use GFP_KERNEL. */
    if ( (_ring = (u16 *)__get_free_page(GFP_KERNEL)) == NULL )
        return -ENOMEM;

    spin_lock_irq(&lock);
    ring = _ring;
    __evtchn_reset_buffer_ring();
    spin_unlock_irq(&lock);

    MOD_INC_USE_COUNT;

    return 0;
}

static int evtchn_release(struct inode *inode, struct file *filp)
{
    int i;

    spin_lock_irq(&lock);
    if ( ring != NULL )
    {
        free_page((unsigned long)ring);
        ring = NULL;
    }
    for ( i = 0; i < NR_EVENT_CHANNELS; i++ )
        if ( test_and_clear_bit(i, (unsigned long *)&bound_ports[0]) )
            mask_evtchn(i);
    spin_unlock_irq(&lock);

    evtchn_dev_inuse = 0;

    MOD_DEC_USE_COUNT;

    return 0;
}

static struct file_operations evtchn_fops = {
    owner:    THIS_MODULE,
    read:     evtchn_read,
    write:    evtchn_write,
    ioctl:    evtchn_ioctl,
    poll:     evtchn_poll,
    fasync:   evtchn_fasync,
    open:     evtchn_open,
    release:  evtchn_release
};

static struct miscdevice evtchn_miscdev = {
    .minor        = EVTCHN_MINOR,
    .name         = "evtchn",
    .fops         = &evtchn_fops,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    .devfs_name   = "misc/evtchn",
#endif
};

static int __init evtchn_init(void)
{
#ifdef OLD_DEVFS
    devfs_handle_t symlink_handle;
    int            pos;
    char           link_dest[64];
#endif
    int err;

    /* (DEVFS) create '/dev/misc/evtchn'. */
    err = misc_register(&evtchn_miscdev);
    if ( err != 0 )
    {
        printk(KERN_ALERT "Could not register /dev/misc/evtchn\n");
        return err;
    }

#ifdef OLD_DEVFS
    /* (DEVFS) create directory '/dev/xen'. */
    xen_dev_dir = devfs_mk_dir(NULL, "xen", NULL);

    /* (DEVFS) &link_dest[pos] == '../misc/evtchn'. */
    pos = devfs_generate_path(evtchn_miscdev.devfs_handle, 
                              &link_dest[3], 
                              sizeof(link_dest) - 3);
    if ( pos >= 0 )
        strncpy(&link_dest[pos], "../", 3);

    /* (DEVFS) symlink '/dev/xen/evtchn' -> '../misc/evtchn'. */
    (void)devfs_mk_symlink(xen_dev_dir, 
                           "evtchn", 
                           DEVFS_FL_DEFAULT, 
                           &link_dest[pos],
                           &symlink_handle, 
                           NULL);

    /* (DEVFS) automatically destroy the symlink with its destination. */
    devfs_auto_unregister(evtchn_miscdev.devfs_handle, symlink_handle);
#endif

    printk("Event-channel device installed.\n");

    return 0;
}

static void evtchn_cleanup(void)
{
    misc_deregister(&evtchn_miscdev);
}

module_init(evtchn_init);
module_exit(evtchn_cleanup);
