/******************************************************************************
 * xl_evtchn.c
 * 
 * Xenolinux driver for receiving and demuxing event-channel signals.
 * 
 * Copyright (c) 2004, K A Fraser
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
#include <linux/devfs_fs_kernel.h>
#include <linux/stat.h>
#include <linux/poll.h>

typedef void (*evtchn_receiver_t)(unsigned int);
#define PORT_NORMAL     0x0000
#define PORT_DISCONNECT 0x8000
#define PORTIDX_MASK    0x7fff

/* /dev/xeno/evtchn resides at device number major=10, minor=200 */
#define EVTCHN_MINOR 200

/* NB. This must be shared amongst drivers if more things go in /dev/xeno */
static devfs_handle_t xeno_dev_dir;

/* Only one process may open /dev/xeno/evtchn at any time. */
static unsigned long evtchn_dev_inuse;

/* Notification ring, accessed via /dev/xeno/evtchn. */
static u16 *ring;
static unsigned int ring_cons, ring_prod;

/* Processes wait on this queue via /dev/xeno/evtchn when ring is empty. */
static DECLARE_WAIT_QUEUE_HEAD(evtchn_wait);
static struct fasync_struct *evtchn_async_queue;

static evtchn_receiver_t rx_fns[1024];

static u32 pend_outstanding[32];
static u32 disc_outstanding[32];

static spinlock_t lock;

int evtchn_request_port(unsigned int port, evtchn_receiver_t rx_fn)
{
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&lock, flags);

    if ( rx_fns[port] != NULL )
    {
        printk(KERN_ALERT "Event channel port %d already in use.\n", port);
        rc = -EINVAL;
    }
    else
    {
        rx_fns[port] = rx_fn;
        rc = 0;
    }

    spin_unlock_irqrestore(&lock, flags);

    return rc;
}

int evtchn_free_port(unsigned int port)
{
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&lock, flags);

    if ( rx_fns[port] == NULL )
    {
        printk(KERN_ALERT "Event channel port %d not in use.\n", port);
        rc = -EINVAL;
    }
    else
    {
        rx_fns[port] = NULL;
        rc = 0;
    }

    spin_unlock_irqrestore(&lock, flags);

    return rc;
}

/*
 * NB. Clearing port can race a notification from remote end. Caller must
 * therefore recheck notification status on return to avoid missing events.
 */
void evtchn_clear_port(unsigned int port)
{
    unsigned int p = port & PORTIDX_MASK;
    if ( unlikely(port & PORT_DISCONNECT) )
    {
        clear_bit(p, &HYPERVISOR_shared_info->event_channel_disc[0]);
        wmb(); /* clear the source first, then our quenchmask */
        clear_bit(p, &disc_outstanding[0]);
    }
    else
    {
        clear_bit(p, &HYPERVISOR_shared_info->event_channel_pend[0]);
        wmb(); /* clear the source first, then our quenchmask */
        clear_bit(p, &pend_outstanding[0]);
    }
}

static inline void process_bitmask(u32 *sel, 
                                   u32 *mask,
                                   u32 *outstanding,
                                   unsigned int port_subtype)
{
    unsigned long l1, l2;
    unsigned int  l1_idx, l2_idx, port;

    l1 = xchg(sel, 0);
    while ( (l1_idx = ffs(l1)) != 0 )
    {
        l1_idx--;
        l1 &= ~(1 << l1_idx);

        l2 = mask[l1_idx] & ~outstanding[l1_idx];
        outstanding[l1_idx] |= l2;
        while ( (l2_idx = ffs(l2)) != 0 )
        {
            l2_idx--;
            l2 &= ~(1 << l2_idx);

            port = (l1_idx * 32) + l2_idx;
            if ( rx_fns[port] != NULL )
            {
                (*rx_fns[port])(port | port_subtype);
            }
            else if ( ring != NULL )
            {
                ring[ring_prod] = (u16)(port | port_subtype);
                if ( ring_cons == ring_prod++ )
                {
                    wake_up_interruptible(&evtchn_wait);
                    kill_fasync(&evtchn_async_queue, SIGIO, POLL_IN);
                }
            }
        }
    }

}

static void evtchn_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    shared_info_t *si = HYPERVISOR_shared_info;
    unsigned long flags;

    spin_lock_irqsave(&lock, flags);

    process_bitmask(&si->event_channel_pend_sel, 
                    &si->event_channel_pend[0],
                    &pend_outstanding[0],
                    PORT_NORMAL);
        
    process_bitmask(&si->event_channel_disc_sel,
                    &si->event_channel_disc[0],
                    &disc_outstanding[0],
                    PORT_DISCONNECT);
        
    spin_unlock_irqrestore(&lock, flags);
}

static ssize_t evtchn_read(struct file *file, char *buf,
                           size_t count, loff_t *ppos)
{
    int rc;
    DECLARE_WAITQUEUE(wait, current);

    add_wait_queue(&evtchn_wait, &wait);

    for ( ; ; )
    {
        set_current_state(TASK_INTERRUPTIBLE);

        if ( ring_cons != ring_prod )
            break;

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

    rc = -EINVAL;
    if ( count >= sizeof(ring_prod) )
        rc = put_user(ring_prod, (unsigned int *)buf);
    if ( rc == 0 )
        rc = sizeof(ring_prod);

 out:
    __set_current_state(TASK_RUNNING);
    remove_wait_queue(&evtchn_wait, &wait);
    return rc;
}

static ssize_t evtchn_write(struct file *file, const char *buf,
                            size_t count, loff_t *ppos)
{
    int          rc = -EINVAL;
    unsigned int new_cons = 0;

    if ( count >= sizeof(new_cons) )
        rc = get_user(new_cons, (unsigned int *)buf);

    if ( rc != 0 )
        return rc;

    rc = sizeof(new_cons);

    while ( ring_cons != new_cons )
        evtchn_clear_port(ring[ring_cons++]);

    return rc;
}

static unsigned int evtchn_poll(struct file *file, poll_table *wait)
{
    unsigned int mask = POLLOUT | POLLWRNORM;
    poll_wait(file, &evtchn_wait, wait);
    if ( ring_cons != ring_prod )
        mask |= POLLIN | POLLRDNORM;
    return mask;
}

static int evtchn_mmap(struct file *file, struct vm_area_struct *vma)
{
    /* Caller must map a single page of memory from 'file offset' zero. */
    if ( (vma->vm_pgoff != 0) || ((vma->vm_end - vma->vm_start) != PAGE_SIZE) )
        return -EINVAL;

    /* Not a pageable area. */
    vma->vm_flags |= VM_RESERVED;

    if ( remap_page_range(vma->vm_start, 0, PAGE_SIZE, vma->vm_page_prot) )
        return -EAGAIN;

    return 0;
}

static int evtchn_fasync(int fd, struct file *filp, int on)
{
    return fasync_helper(fd, filp, on, &evtchn_async_queue);
}

static int evtchn_open(struct inode *inode, struct file *filp)
{
    u16         *_ring;
    u32          m;
    unsigned int i, j;

    if ( test_and_set_bit(0, &evtchn_dev_inuse) )
        return -EBUSY;

    /* Allocate outside locked region so that we can use GFP_KERNEL. */
    if ( (_ring = (u16 *)get_free_page(GFP_KERNEL)) == NULL )
        return -ENOMEM;

    spin_lock_irq(&lock);

    ring = _ring;

    /* Initialise the ring with currently outstanding notifications. */
    ring_cons = ring_prod = 0;
    for ( i = 0; i < 32; i++ )
    {
        m = pend_outstanding[i];
        while ( (j = ffs(m)) != 0 )
        {
            m &= ~(1 << --j);
            if ( rx_fns[(i * 32) + j] == NULL )
                ring[ring_prod++] = (u16)(((i * 32) + j) | PORT_NORMAL);
        }

        m = disc_outstanding[i];
        while ( (j = ffs(m)) != 0 )
        {
            m &= ~(1 << --j);
            if ( rx_fns[(i * 32) + j] == NULL )
                ring[ring_prod++] = (u16)(((i * 32) + j) | PORT_DISCONNECT);
        }
    }

    spin_unlock_irq(&lock);

    MOD_INC_USE_COUNT;

    return 0;
}

static int evtchn_release(struct inode *inode, struct file *filp)
{
    spin_lock_irq(&lock);
    if ( ring != NULL )
    {
        free_page((unsigned long)ring);
        ring = NULL;
    }
    spin_unlock_irq(&lock);

    evtchn_dev_inuse = 0;

    MOD_DEC_USE_COUNT;

    return 0;
}

static struct file_operations evtchn_fops = {
    owner:    THIS_MODULE,
    read:     evtchn_read,
    write:    evtchn_write,
    poll:     evtchn_poll,
    mmap:     evtchn_mmap,
    fasync:   evtchn_fasync,
    open:     evtchn_open,
    release:  evtchn_release
};

static struct miscdevice evtchn_miscdev = {
    minor:    EVTCHN_MINOR,
    name:     "evtchn",
    fops:     &evtchn_fops
};

static int __init init_module(void)
{
    devfs_handle_t symlink_handle;
    int            err, pos;
    char           link_dest[64];

    /* (DEVFS) create '/dev/misc/evtchn'. */
    err = misc_register(&evtchn_miscdev);
    if ( err != 0 )
    {
        printk(KERN_ALERT "Could not register /dev/misc/evtchn\n");
        return err;
    }

    /* (DEVFS) create directory '/dev/xeno'. */
    xeno_dev_dir = devfs_mk_dir(NULL, "xeno", NULL);

    /* (DEVFS) &link_dest[pos] == '../misc/evtchn'. */
    pos = devfs_generate_path(evtchn_miscdev.devfs_handle, 
                              &link_dest[3], 
                              sizeof(link_dest) - 3);
    if ( pos >= 0 )
        strncpy(&link_dest[pos], "../", 3);

    /* (DEVFS) symlink '/dev/xeno/evtchn' -> '../misc/evtchn'. */
    (void)devfs_mk_symlink(xeno_dev_dir, 
                           "evtchn", 
                           DEVFS_FL_DEFAULT, 
                           &link_dest[pos],
                           &symlink_handle, 
                           NULL);

    /* (DEVFS) automatically destroy the symlink with its destination. */
    devfs_auto_unregister(evtchn_miscdev.devfs_handle, symlink_handle);

    err = request_irq(_EVENT_EVTCHN, evtchn_interrupt, 0, "evtchn", NULL);
    if ( err != 0 )
    {
        printk(KERN_ALERT "Could not allocate evtchn receive interrupt\n");
        return err;
    }

    return 0;
}

static void cleanup_module(void)
{
    free_irq(_EVENT_EVTCHN, NULL);
    misc_deregister(&evtchn_miscdev);
}

module_init(init_module);
module_exit(cleanup_module);
