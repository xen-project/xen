/******************************************************************************
 * blktap_userdev.c
 * 
 * XenLinux virtual block-device tap.
 * Control interface between the driver and a character device.
 * 
 * Copyright (c) 2004, Andrew Warfield
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/gfp.h>
#include <linux/poll.h>
#include <asm/pgalloc.h>

#include "blktap.h"


unsigned long blktap_mode = BLKTAP_MODE_PASSTHROUGH;

/* Only one process may open /dev/xen/blktap at any time. */
static unsigned long blktap_dev_inuse;
unsigned long blktap_ring_ok; /* make this ring->state */

/* for poll: */
static wait_queue_head_t blktap_wait;

/* Where things are inside the device mapping. */
struct vm_area_struct *blktap_vma;
unsigned long mmap_vstart;
unsigned long rings_vstart;

/* -------[ blktap vm ops ]------------------------------------------- */

static struct page *blktap_nopage(struct vm_area_struct *vma,
                                             unsigned long address,
                                             int *type)
{
    /*
     * if the page has not been mapped in by the driver then generate
     * a SIGBUS to the domain.
     */

    force_sig(SIGBUS, current);

    return 0;
}

struct vm_operations_struct blktap_vm_ops = {
    nopage:   blktap_nopage,
};

/* -------[ blktap file ops ]----------------------------------------- */

static int blktap_open(struct inode *inode, struct file *filp)
{
    if ( test_and_set_bit(0, &blktap_dev_inuse) )
        return -EBUSY;

    printk(KERN_ALERT "blktap open.\n");

    /* Allocate the fe ring. */
    fe_ring.ring = (blkif_ring_t *)get_zeroed_page(GFP_KERNEL);
    if (fe_ring.ring == NULL)
        goto fail_nomem;

    SetPageReserved(virt_to_page(fe_ring.ring));
    
    fe_ring.ring->req_prod = fe_ring.ring->resp_prod
                           = fe_ring.req_prod
                           = fe_ring.rsp_cons
                           = 0;

    /* Allocate the be ring. */
    be_ring.ring = (blkif_ring_t *)get_zeroed_page(GFP_KERNEL);
    if (be_ring.ring == NULL)
        goto fail_free_fe;

    SetPageReserved(virt_to_page(be_ring.ring));
    
    be_ring.ring->req_prod = be_ring.ring->resp_prod
                           = be_ring.rsp_prod
                           = be_ring.req_cons
                           = 0;

    DPRINTK(KERN_ALERT "blktap open.\n");

    return 0;

 fail_free_fe:
    free_page( (unsigned long) fe_ring.ring);

 fail_nomem:
    return -ENOMEM;
}

static int blktap_release(struct inode *inode, struct file *filp)
{
    blktap_dev_inuse = 0;
    blktap_ring_ok = 0;

    printk(KERN_ALERT "blktap closed.\n");

    /* Free the ring page. */
    ClearPageReserved(virt_to_page(fe_ring.ring));
    free_page((unsigned long) fe_ring.ring);

    ClearPageReserved(virt_to_page(be_ring.ring));
    free_page((unsigned long) be_ring.ring);
    
    return 0;
}

static int blktap_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int size;

    printk(KERN_ALERT "blktap mmap (%lx, %lx)\n",
           vma->vm_start, vma->vm_end);

    vma->vm_ops = &blktap_vm_ops;

    size = vma->vm_end - vma->vm_start;
    if ( size != ( (MMAP_PAGES + RING_PAGES) << PAGE_SHIFT ) ) {
        printk(KERN_INFO 
               "blktap: you _must_ map exactly %d pages!\n",
               MMAP_PAGES + RING_PAGES);
        return -EAGAIN;
    }

    size >>= PAGE_SHIFT;
    printk(KERN_INFO "blktap: 2 rings + %d pages.\n", size-1);
    
    rings_vstart = vma->vm_start;
    mmap_vstart  = rings_vstart + (RING_PAGES << PAGE_SHIFT);
    
    /* Map the ring pages to the start of the region and reserve it. */

    /* not sure if I really need to do this... */
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    DPRINTK("Mapping be_ring page %lx.\n", __pa(be_ring.ring));
    if (remap_page_range(vma, vma->vm_start, __pa(be_ring.ring), PAGE_SIZE, 
                         vma->vm_page_prot)) {
        printk(KERN_ERR "be_ring: remap_page_range failure!\n");
    }

    DPRINTK("Mapping fe_ring page %lx.\n", __pa(fe_ring.ring));
    if (remap_page_range(vma, vma->vm_start + PAGE_SIZE, __pa(fe_ring.ring), 
                         PAGE_SIZE, vma->vm_page_prot)) {
        printk(KERN_ERR "fe_ring: remap_page_range failure!\n");
    }

    blktap_vma = vma;
    blktap_ring_ok = 1;

    return 0;
}

static int blktap_ioctl(struct inode *inode, struct file *filp,
                        unsigned int cmd, unsigned long arg)
{
    switch(cmd) {
    case BLKTAP_IOCTL_KICK_FE: /* There are fe messages to process. */
        return blktap_read_fe_ring();

    case BLKTAP_IOCTL_KICK_BE: /* There are be messages to process. */
        return blktap_read_be_ring();

    case BLKTAP_IOCTL_SETMODE:
        if (BLKTAP_MODE_VALID(arg)) {
            blktap_mode = arg;
            /* XXX: may need to flush rings here. */
            printk(KERN_INFO "blktap: set mode to %lx\n", arg);
            return 0;
        }
        /* XXX: return a more meaningful error case here. */
    }
    return -ENOIOCTLCMD;
}

static unsigned int blktap_poll(struct file *file, poll_table *wait)
{
        poll_wait(file, &blktap_wait, wait);

        if ( (fe_ring.req_prod != fe_ring.ring->req_prod) ||
             (be_ring.rsp_prod != be_ring.ring->resp_prod) ) {

            fe_ring.ring->req_prod = fe_ring.req_prod;
            be_ring.ring->resp_prod = be_ring.rsp_prod;
            return POLLIN | POLLRDNORM;
        }

        return 0;
}

void blktap_kick_user(void)
{
    /* blktap_ring->req_prod = blktap_req_prod; */
    wake_up_interruptible(&blktap_wait);
}

static struct file_operations blktap_fops = {
    owner:    THIS_MODULE,
    poll:     blktap_poll,
    ioctl:    blktap_ioctl,
    open:     blktap_open,
    release:  blktap_release,
    mmap:     blktap_mmap,
};

/* -------[ blktap module setup ]------------------------------------- */

static struct miscdevice blktap_miscdev = {
    .minor        = BLKTAP_MINOR,
    .name         = "blktap",
    .fops         = &blktap_fops,
    .devfs_name   = "misc/blktap",
};

int blktap_init(void)
{
    int err;

    err = misc_register(&blktap_miscdev);
    if ( err != 0 )
    {
        printk(KERN_ALERT "Couldn't register /dev/misc/blktap (%d)\n", err);
        return err;
    }

    init_waitqueue_head(&blktap_wait);


    return 0;
}
