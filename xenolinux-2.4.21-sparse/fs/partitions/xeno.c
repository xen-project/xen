/* Simple hack so that client XenoLinux's can sort-of see parts of the
   host partition table. */
#include <linux/kernel.h>
#include <asm/hypervisor.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/genhd.h>
#include <asm/hypervisor-ifs/block.h>
#include <linux/pagemap.h>

#include "check.h"
#include "xeno.h"

extern int xenolinux_control_msg(int operration, char *buffer, int size);

/* Grab the physdisk partitions list from the hypervisor. */
int xeno_partition(struct gendisk *hd,
		   struct block_device *bdev,
		   unsigned long first_sec,
		   int first_part_minor)
{
  physdisk_probebuf_t *buf;
  int i;
  int minor;
  int count;

  buf = kmalloc(sizeof(*buf), GFP_KERNEL);
  if (!buf)
    return -ENOMEM;
  buf->domain = start_info.dom_id;
  buf->start_ind = 0;
  buf->n_aces = PHYSDISK_MAX_ACES_PER_REQUEST;

  xenolinux_control_msg(XEN_BLOCK_PHYSDEV_PROBE, (char *)buf,
			sizeof(*buf));
  if (buf->n_aces == 0) {
    kfree(buf);
    return 0;
  }

  if (buf->n_aces == PHYSDISK_MAX_ACES_PER_REQUEST) {
    printk("Error getting Xen partition table, trying ordinary one...\n");
    kfree(buf);
    return 0;
  }

  count = 0;

  for (i = 0; i < buf->n_aces; i++) {
    if (buf->entries[i].partition == 0)
      continue;
    /* Make sure the partition is actually supposed to be on this
       disk.  This assumes that Xen and XenoLinux block device
       numbers match up. */
    if (buf->entries[i].device != bdev->bd_dev)
      continue;
    /* This is a bit of a hack - the partition numbers are specified
       by the hypervisor, and if we want them to match up, this is
       what we need to do. */
    count ++;
    minor = buf->entries[i].partition + first_part_minor - 1;
    add_gd_partition(hd,
		     minor,
		     buf->entries[i].start_sect,
		     buf->entries[i].n_sectors);
  }  
  kfree(buf);

  /* If we didn't find any suitable Xeno partitions, try the other
     types. */
  if (!count)
    return 0;

  printk("\n");
  return 1;
}
