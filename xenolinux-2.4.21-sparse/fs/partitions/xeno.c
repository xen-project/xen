/* Simple hack so that client XenoLinux's can sort-of see parts of the
   host partition table. */
#include <linux/kernel.h>
#include <asm/hypervisor.h>
#include <linux/fs.h>
#include <linux/blk.h>
#include <linux/slab.h>
#include <linux/genhd.h>
#include <asm/hypervisor-ifs/block.h>
#include <linux/pagemap.h>

#include "check.h"
#include "xeno.h"

extern int xenolinux_control_msg(int operration, char *buffer, int size);
extern unsigned short xldev_to_physdev(kdev_t xldev);

/* Grab the physdisk partitions list from the hypervisor. */
int xeno_partition(struct gendisk *hd,
		   struct block_device *bdev,
		   unsigned long first_sec,
		   int first_part_minor)
{
    physdisk_probebuf_t *buf;
    int i, minor;
    
    /* Privileged domains can read partition info themselves. */
    if (start_info.flags & SIF_PRIVILEGED)
        return 0;

    /* This only deals with raw/direct devices (IDE & SCSI). */
    switch ( xldev_to_physdev(bdev->bd_dev) & XENDEV_TYPE_MASK )
    {
    case XENDEV_IDE:
    case XENDEV_SCSI:
        break;
    default:
        return 0;
    }

    if ( (buf = kmalloc(sizeof(*buf), GFP_KERNEL)) == NULL )
        return -ENOMEM;

    buf->domain = start_info.dom_id;
    buf->start_ind = 0;
    buf->n_aces = PHYSDISK_MAX_ACES_PER_REQUEST;

    xenolinux_control_msg(XEN_BLOCK_PHYSDEV_PROBE, (char *)buf,
			  sizeof(*buf));

    if ( buf->n_aces == PHYSDISK_MAX_ACES_PER_REQUEST )
        printk(KERN_ALERT "Too many returns for xeno partition parser\n");

    for ( i = 0; i < buf->n_aces; i++ )
    {
        if (buf->entries[i].partition == 0)
	    continue;
	if (buf->entries[i].device != xldev_to_physdev(bdev->bd_dev))
	    continue;
        if (!(buf->entries[i].mode & PHYSDISK_MODE_W))
        {
            if (!(buf->entries[i].mode & PHYSDISK_MODE_R))
                continue;
            set_device_ro(bdev->bd_dev, 1);
        }
	minor = buf->entries[i].partition + first_part_minor - 1;
	add_gd_partition(hd,
			 minor,
			 buf->entries[i].start_sect,
			 buf->entries[i].n_sectors);
    }  

    kfree(buf);

    printk("\n");

    return 1;
}
