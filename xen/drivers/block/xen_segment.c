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
#include <xeno/keyhandler.h>
#include <hypervisor-ifs/block.h>

int     num_xdrives;
drive_t xdrives[XEN_MAX_DISK_COUNT];

segment_t xsegments[XEN_MAX_SEGMENTS];

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
    printk (KERN_ALERT "error: xen_segment_create unable to find free slot\n");
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
  }

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

  printk (KERN_ALERT "xdrives\n");
  for (loop = 0; loop < num_xdrives; loop++)
  {
    printk (KERN_ALERT " %2d: major: 0x%d\n", loop, xdrives[loop].major);
  }
  
  printk (KERN_ALERT "segments\n");
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
