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

static segment_t xsegments[XEN_MAX_SEGMENTS];

#if 0
#define DPRINTK(_f, _a...) printk( _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

/* XXX XXX XXX Why are there absolutely no calls to any locking
   primitives anywhere in this? */

/*
 * xen_segment_map_request
 *
 * xen_device must be a valid device.
 * 
 * NB. All offsets and sizes here are in sector units.
 * eg. 'size == 1' means an actual size of 512 bytes.
 */
int xen_segment_map_request(
    phys_seg_t *pseg, struct task_struct *p, int operation,
    unsigned short segment_number,
    unsigned long sect_nr, unsigned long buffer, unsigned short nr_sects)
{
    segment_t *seg;
    extent_t  *ext;
    int sum, i;

    segment_number &= XENDEV_IDX_MASK;
    if ( segment_number >= XEN_MAX_SEGMENTS )
    {
        DPRINTK("invalid segment number. %d %d\n",
                segment_number, XEN_MAX_SEGMENTS);
        goto fail;
    }

    seg = p->segment_list[segment_number];
    if ( seg == NULL ) 
    {
        DPRINTK("segment is null. %d\n", segment_number);
        goto fail;
    }

    /* check domain permissions */
    if ( seg->domain != p->domain )
    {
        DPRINTK("seg is for another domain. %d %d\n", seg->domain, p->domain);
        goto fail;
    }

    /* check rw access */
    if ( ((operation == WRITE) && (seg->mode != XEN_SEGMENT_RW)) ||
         ((operation == READ)  && (seg->mode == XEN_SEGMENT_UNUSED)) )
    {
        DPRINTK("illegal operation: %d %d\n", operation, seg->mode);
        goto fail;
    }

    if ( (nr_sects + sect_nr) <= sect_nr )
    {
        DPRINTK("sector + size wrap! %08lx %04x\n", sect_nr, nr_sects);
        goto fail;
    }

    /* find extent, check size */
    sum = 0; 
    i = 0;
    ext = seg->extents;
    while ( (i < seg->num_extents) && ((sum + ext->size) <= sect_nr) )
    {
        sum += ext->size;
        ext++; i++;
    }

    if ( (sum + ext->size) <= sect_nr ) 
    {
        DPRINTK("extent size mismatch: %d %d : %d %ld %ld\n",
                i, seg->num_extents, sum, ext->size, sect_nr);
        goto fail;
    }

    pseg->sector_number = (sect_nr - sum) + ext->offset;
    pseg->buffer        = buffer;
    pseg->nr_sects      = nr_sects;
    pseg->dev           = xendev_to_physdev(ext->disk);
    if ( pseg->dev == 0 ) 
    {
        DPRINTK ("invalid device 0x%x 0x%lx 0x%lx\n", 
                 ext->disk, ext->offset, ext->size);
        goto fail;
    }

    /* We're finished if the virtual extent didn't overrun the phys extent. */
    if ( (sum + ext->size) >= (sect_nr + nr_sects) )
        return 1;                         /* entire read fits in this extent */

    /* Hmmm... make sure there's another extent to overrun onto! */
    if ( (i+1) == seg->num_extents ) 
    {
        DPRINTK ("not enough extents %d %d\n",
                 i, seg->num_extents);
        goto fail;
    }

    pseg[1].nr_sects = (sect_nr + nr_sects) - (sum + ext->size);
    pseg[0].nr_sects = sum + ext->size - sect_nr;
    pseg[1].buffer = buffer + (pseg->nr_sects << 9);
    pseg[1].sector_number = ext[1].offset;
    pseg[1].dev = xendev_to_physdev(ext[1].disk);
    if ( pseg[1].dev == 0 ) 
    {
        DPRINTK ("bogus device for pseg[1] \n");
        goto fail;
    }

    /* We don't allow overrun onto a third physical extent. */
    if ( pseg[1].nr_sects > ext[1].size )
    {
        DPRINTK ("third extent\n");
        DPRINTK (" sum:%d, e0:%ld, e1:%ld   p1.sect:%ld p1.nr:%d\n",
                 sum, ext[0].size, ext[1].size, 
                 pseg[1].sector_number, pseg[1].nr_sects);
        goto fail;    
    }

    return 2;                   /* We overran onto a second physical extent. */

 fail:
    DPRINTK ("xen_segment_map_request failure\n");
    DPRINTK ("operation: %d\n", operation);
    DPRINTK ("segment number: %d\n", segment_number);
    DPRINTK ("sect_nr: %ld 0x%lx\n", sect_nr, sect_nr);
    DPRINTK ("nr_sects: %d 0x%x\n", nr_sects, nr_sects);
    return -1;
}

/*
 * xen_segment_probe
 *
 * return a list of segments to the guestos
 */
void xen_segment_probe(struct task_struct *p, xen_disk_info_t *raw_xdi)
{
    int loop, i;
    xen_disk_info_t *xdi = map_domain_mem(virt_to_phys(raw_xdi));
    unsigned long capacity = 0, device;

    for ( loop = 0; loop < XEN_MAX_SEGMENTS; loop++ )
    {
        if ( (xsegments[loop].mode == XEN_SEGMENT_UNUSED) ||
             (xsegments[loop].domain != p->domain) )
            continue;

        device = MK_VIRTUAL_XENDEV(xsegments[loop].segment_number);
        for ( i = 0; i < xsegments[loop].num_extents; i++ )
            capacity += xsegments[loop].extents[i].size;

        xdi->disks[xdi->count].device   = device;
        xdi->disks[xdi->count].capacity = capacity;
        xdi->count++;
    }

    unmap_domain_mem(xdi);
}

/*
 * xen_segment_probe_all
 *
 * return a list of all segments to domain 0
 */
void xen_segment_probe_all(xen_segment_info_t *raw_xsi)
{
    int loop;
    xen_segment_info_t *xsi = map_domain_mem(virt_to_phys(raw_xsi));

    xsi->count = 0;
    for ( loop = 0; loop < XEN_MAX_SEGMENTS; loop++ )
    {
	if ( xsegments[loop].mode == XEN_SEGMENT_UNUSED )
	    continue;

	xsi->segments[xsi->count].mode = xsegments[loop].mode;
	xsi->segments[xsi->count].domain = xsegments[loop].domain;
	memcpy(xsi->segments[xsi->count].key,
	       xsegments[loop].key,
	       XEN_SEGMENT_KEYSIZE);
	xsi->segments[xsi->count].seg_nr = xsegments[loop].segment_number;
        xsi->count++;	
    }

    unmap_domain_mem(xsi);
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
        if ( (xsegments[loop].mode == XEN_SEGMENT_UNUSED) ||
             (xsegments[loop].domain != p->domain) )
            continue;

        p->segment_list[xsegments[loop].segment_number] = &xsegments[loop];
    }
}

/*
 * create a new segment for a domain
 *
 * return 0 on success, 1 on failure
 *
 * if we see the same DOM#/SEG# combination, we reuse the slot in
 * the segment table (overwriting what was there before).
 * an alternative would be to raise an error if the slot is reused.
 */
int xen_segment_create(xv_disk_t *xvd_in)
{
    int idx;
    int loop;
    xv_disk_t *xvd = map_domain_mem(virt_to_phys(xvd_in));
    struct task_struct *p;

    for (idx = 0; idx < XEN_MAX_SEGMENTS; idx++)
    {
        if (xsegments[idx].mode == XEN_SEGMENT_UNUSED ||
            (xsegments[idx].domain == xvd->domain &&
             xsegments[idx].segment_number == xvd->segment)) break;
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
    memcpy(xsegments[idx].key, xvd->key, XEN_SEGMENT_KEYSIZE);
    xsegments[idx].num_extents = xvd->ext_count;
    if (xsegments[idx].extents)
	kfree(xsegments[idx].extents);
    xsegments[idx].extents = (extent_t *)kmalloc(
        sizeof(extent_t)*xvd->ext_count,
        GFP_KERNEL);
 
    /* could memcpy, but this is safer */
    for (loop = 0; loop < xvd->ext_count; loop++)
    {
        xsegments[idx].extents[loop].disk = xvd->extents[loop].disk;
        xsegments[idx].extents[loop].offset = xvd->extents[loop].offset;
        xsegments[idx].extents[loop].size = xvd->extents[loop].size;
        if (xsegments[idx].extents[loop].size == 0) 
        {
            printk("xen_segment_create: extent %d is zero length\n", loop);
            unmap_domain_mem(xvd);
            return 1;
        }
    }

    /* if the domain exists, assign the segment to the domain */
    p = find_domain_by_id(xvd->domain);
    if (p != NULL)
    {
        p->segment_list[xvd->segment] = &xsegments[idx];
        put_task_struct(p);
    }

    unmap_domain_mem(xvd);
    return 0;
}

/*
 * delete a segment from a domain
 *
 * return 0 on success, 1 on failure
 *
 */
int xen_segment_delete(struct task_struct *p, int segnr)
{
    segment_t *seg;

    if (!p) {
	printk("xen_segment delete called with NULL domain?\n");
	BUG();
	return 1;
    }

    if (segnr < 0 || segnr > XEN_MAX_SEGMENTS) {
	printk("xen_segment_delete called with bad segnr?\n");
	BUG();
	return 1;
    }

    if (!p->segment_list[segnr])
	return 1;

    seg = p->segment_list[segnr];

    /* sanity checking */
    if (seg->domain != p->domain || seg->segment_number != segnr ||
	(seg->mode != XEN_SEGMENT_RO && seg->mode != XEN_SEGMENT_RW) ||
	seg->num_extents <= 0 || seg->extents == NULL) {
	printk("segment is insane!\n");
	BUG();
	return 1;
    }

    p->segment_list[segnr] = NULL;
    seg->domain = -1;
    seg->segment_number = -1;
    kfree(seg->extents);
    seg->mode = XEN_SEGMENT_UNUSED;

    return 0;
}

static void dump_segments(u_char key, void *dev_id, struct pt_regs *regs) 
{
    int loop, i;
    struct task_struct *p;

    printk("segment list\n");
    for (loop = 0; loop < XEN_MAX_SEGMENTS; loop++)
    {
        if (xsegments[loop].mode != XEN_SEGMENT_UNUSED)
        {
            printk(" %2d: %s dom%d, seg# %d, num_exts: %d\n",
                   loop, 
                   xsegments[loop].mode == XEN_SEGMENT_RO ? "RO" : "RW",
                   xsegments[loop].domain, xsegments[loop].segment_number,
                   xsegments[loop].num_extents);
            for (i = 0; i < xsegments[loop].num_extents; i++)
            {
                printk("     extent %d: disk 0x%x, offset 0x%lx, size 0x%lx\n",
                       i, xsegments[loop].extents[i].disk,
                       xsegments[loop].extents[i].offset,
                       xsegments[loop].extents[i].size);
            } 
        }
    }

    printk("segments by domain (index into segments list)\n");
    p = current;
    do
    {
        printk("  domain %d: ", p->domain);
        for (loop = 0; loop < XEN_MAX_SEGMENTS; loop++)
        {
            if (p->segment_list[loop])
            {
                printk (" %d", p->segment_list[loop] - xsegments);
            }
        }
        printk("\n");
        p = p->next_task;
    } while (p != current);
}

/*
 * initialize segments
 */

void xen_segment_initialize(void)
{
    memset (xsegments, 0, sizeof(xsegments));

    add_key_handler('S', dump_segments, "dump segments");
}
