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

/* /dev/xen/evtchn resides at device number major=10, minor=200 */
#define EVTCHN_MINOR 200

/* /dev/xen/evtchn ioctls: */
/* EVTCHN_RESET: Clear and reinit the event buffer. Clear error condition. */
#define EVTCHN_RESET _IO('E', 1)

/* NB. This must be shared amongst drivers if more things go in /dev/xen */
static devfs_handle_t xen_dev_dir;

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
                if ( (ring_prod - ring_cons) < RING_SIZE )
                {
                    ring[RING_MASK(ring_prod)] = (u16)(port | port_subtype);
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

static void __evtchn_reset_buffer_ring(void)
{
    u32          m;
    unsigned int i, j;

    /* Initialise the ring with currently outstanding notifications. */
    ring_cons = ring_prod = ring_overflow = 0;

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

    rc = -EFAULT;

    /* Byte length of first chunk. May be truncated by ring wrap. */
    if ( ((c ^ p) & RING_SIZE) != 0 )
        bytes1 = (RING_SIZE - RING_MASK(c)) * sizeof(u16);
    else
        bytes1 = (p - c) * sizeof(u16);

    /* Further truncate chunk length according to caller's maximum count. */
    if ( bytes1 > count )
        bytes1 = count;

    /* Copy the first chunk. */
    if ( copy_to_user(buf, &ring[c], bytes1) != 0 )
        goto out;

    /* More bytes to copy? */
    if ( count > bytes1 )
    {
        bytes2 = RING_MASK(p) * sizeof(u16);
        if ( bytes2 > count )
            bytes2 = count;
        if ( (bytes2 != 0) && copy_to_user(&buf[bytes1], &ring[0], bytes2) )
            goto out;
    }

    ring_cons = (bytes1 + bytes2) / sizeof(u16);

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
    u16 *kbuf = (u16 *)get_free_page(GFP_KERNEL);

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

    for ( i = 0; i < (count/2); i++ )
        evtchn_clear_port(kbuf[i]);

    rc = count;

 out:
    free_page((unsigned long)kbuf);
    return rc;
}

static int evtchn_ioctl(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg)
{
    if ( cmd != EVTCHN_RESET )
        return -EINVAL;

    spin_lock_irq(&lock);
    __evtchn_reset_buffer_ring();
    spin_unlock_irq(&lock);   

    return 0;
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
    if ( (_ring = (u16 *)get_free_page(GFP_KERNEL)) == NULL )
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
    ioctl:    evtchn_ioctl,
    poll:     evtchn_poll,
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
