/*
 * xen_segment.c
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <asm/io.h>
#include <xeno/slab.h>
#include <xeno/segment.h>
#include <xeno/sched.h>
#include <xeno/blkdev.h>
#include <xeno/keyhandler.h>
#include <asm/current.h>
#include <asm/domain_page.h>
#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/xeno-major.h>

int     num_xdrives;
drive_t xdrives[XEN_MAX_DISK_COUNT];

segment_t xsegments[XEN_MAX_SEGMENTS];

/*
 * xen_segment_map_request
 *
 * xen_device must be a valid device.
 */

int xen_segment_map_request(int *phys_device,                         /* out */
			    unsigned long *block_number,              /* out */
			    unsigned long *sector_number,             /* out */
			    struct task_struct *domain,
			    int operation,
			    int xen_device,
			    int xen_block_number,
			    int xen_sector_number)
{
  segment_t *seg;
  int segment_number;                   /* segment number within this domain */
  int sum; 
  int loop;

  segment_number = xen_device - XLSEG_MAJOR;
  seg = domain->segment_list[segment_number];

  if (seg == NULL)
  {
    return 1;                                       /* oops.  no vhd exists! */
  }

  /* check domain permissions */
  if (seg->domain != domain->domain)
  {
    return 2;                                  /* domain doesn't own segment */
  }

  /* check rw access */
  if ((operation == WRITE && seg->mode != XEN_SEGMENT_RW) ||
      (operation == READ  && seg->mode == XEN_SEGMENT_UNUSED))
  {
    return 3;                                            /* access violation */
  }

  /* find extent, check size */
  sum = 0; 
  loop = 0;
  while (loop < seg->num_extents && sum <= xen_block_number)
  {
    sum += seg->extents[loop++].size;
  }
  sum -= seg->extents[--loop].size;                                /* rewind */

  if (sum + seg->extents[loop].size <= xen_block_number)
  {
    return 4;                   /* tried to read past the end of the segment */
  }
  *block_number = xen_block_number - sum + seg->extents[loop].offset;
  *sector_number = xen_sector_number - sum + seg->extents[loop].offset;;

  /* get physical device from xdrives */
  *phys_device = MKDEV(xdrives[seg->extents[loop].disk].major, 0);

  /*
  printk ("%d %lx %lx %lx %lx :  %lx %lx %lx %lx\n",
	  operation,
	  *block_number, xen_block_number, sum, seg->extents[loop].offset,
	  *sector_number, xen_sector_number, sum, seg->extents[loop].offset
	  );
  */

  return 0;
}

/*
 * xen_segment_probe
 *
 * return a list of segments to the guestos
 */
void xen_segment_probe (xen_disk_info_t *raw_xdi, int *count)
{
  int loop, i;
  xen_disk_info_t *xdi = map_domain_mem(virt_to_phys(raw_xdi));

  for (loop = 0; loop < XEN_MAX_SEGMENTS; loop++ )
  {
    if (xsegments[loop].mode != XEN_SEGMENT_UNUSED)
    {
      xdi->disks[xdi->count].type = XEN_DISK_VIRTUAL;
      for (i = 0; i < xsegments[loop].num_extents; i++)
      {
	xdi->disks[xdi->count].capacity += xsegments[loop].extents[i].size;
      }
      xdi->count++;
    }
  }

  unmap_domain_mem(xdi);
  return;
}

/*
 * xen_refresh_segment_list
 *
 * find all segments associated with a domain and assign
 * them to the domain
 */
void xen_refresh_segment_list (struct task_struct *p)
{
  int loop;

  for (loop = 0; loop < XEN_MAX_SEGMENTS; loop++)
  {
    if (xsegments[loop].mode != XEN_SEGMENT_UNUSED &&
	xsegments[loop].domain == p->domain)
    {
      p->segment_list[xsegments[loop].segment_number] = &xsegments[loop];
      p->segment_count++;
    }
  }
  return;
}

/*
 * create a new segment for a domain
 *
 * return 0 on success, 1 on failure
 *
 * TODO: need to check to see if the DOM#/SEG# combination
 *       already exists. if so, reuse the slot in the segment table.
 */
int xen_segment_create(xv_disk_t *xvd_in)
{
  int idx;
  int loop;
  xv_disk_t *xvd = map_domain_mem(virt_to_phys(xvd_in));

  for (idx = 0; idx < XEN_MAX_SEGMENTS; idx++)
  {
    if (xsegments[idx].mode == XEN_SEGMENT_UNUSED) break;
  }
  if (idx == XEN_MAX_SEGMENTS)
  {
    printk (KERN_ALERT "xen_segment_create: unable to find free slot\n");
    unmap_domain_mem(xvd);
    return 1;
  }

  xsegments[idx].mode = xvd->mode;
  xsegments[idx].domain = xvd->domain;
  xsegments[idx].segment_number = xvd->segment;
  xsegments[idx].num_extents = xvd->ext_count;
  xsegments[idx].extents = (extent_t *)kmalloc(sizeof(extent_t)*xvd->ext_count,
					       GFP_KERNEL);
 
  /* could memcpy, but this is safer */
  for (loop = 0; loop < xvd->ext_count; loop++)
  {
    xsegments[idx].extents[loop].disk = xvd->extents[loop].disk;
    xsegments[idx].extents[loop].offset = xvd->extents[loop].offset;
    xsegments[idx].extents[loop].size = xvd->extents[loop].size;
    if (xsegments[idx].extents[loop].size == 0) 
    {
      printk (KERN_ALERT "xen_segment_create: extent %d is zero length\n",
	      loop);
      unmap_domain_mem(xvd);
      return 1;
    }
  }

  unmap_domain_mem(xvd);
  return 0;
}

/*
 * delete a segment from a domain
 *
 * return 0 on success, 1 on failure
 *
 * TODO: caller must ensure that only domain 0 calls this function
 */
int xen_segment_delete(struct task_struct *p, xv_disk_t *xvd)
{
  return 0;
}

static void dump_segments(u_char key, void *dev_id, struct pt_regs *regs) 
{
  int loop, i;
  struct task_struct *p;

  printk (KERN_ALERT "xdrives\n");
  for (loop = 0; loop < num_xdrives; loop++)
  {
    printk (KERN_ALERT " %2d: major: 0x%d\n", loop, xdrives[loop].major);
  }
  
  printk (KERN_ALERT "segment list\n");
  for (loop = 0; loop < XEN_MAX_SEGMENTS; loop++)
  {
    if (xsegments[loop].mode != XEN_SEGMENT_UNUSED)
    {
      printk (KERN_ALERT " %2d: %s dom%d, seg# %d, num_exts: %d\n",
	      loop, 
	      xsegments[loop].mode == XEN_SEGMENT_RO ? "RO" : "RW",
	      xsegments[loop].domain, xsegments[loop].segment_number,
	      xsegments[loop].num_extents);
      for (i = 0; i < xsegments[loop].num_extents; i++)
      {
	printk (KERN_ALERT "     ext %d: disk %d, offset 0x%lx, size 0x%lx\n",
		i, xsegments[loop].extents[i].disk,
		xsegments[loop].extents[i].offset,
		xsegments[loop].extents[i].size);
      } 
    }
  }

  printk (KERN_ALERT "segments by domain\n");
  p = current->next_task;
  do
  {
    printk (KERN_ALERT "  domain: %d\n", p->domain);
    for (loop = 0; loop < p->segment_count; loop++)
    {
      printk (KERN_ALERT "    mode:%d domain:%d seg:%d exts:%d\n",
	      p->segment_list[loop]->mode,
	      p->segment_list[loop]->domain,
	      p->segment_list[loop]->segment_number,
	      p->segment_list[loop]->num_extents);
    }
    p = p->next_task;
  } while (p != current);
}

/*
 * initialize segments
 */

void xen_segment_initialize(void)
{
  memset (xdrives, 0, sizeof(xdrives));
  memset (xsegments, 0, sizeof(xsegments));

  add_key_handler('S', dump_segments, "dump segments");
}
