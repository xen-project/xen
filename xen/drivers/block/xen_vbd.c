/*
 * xen_vbd.c : routines for managing virtual block devices 
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <asm/io.h>
#include <xeno/slab.h>
#include <xeno/sched.h>
#include <xeno/vbd.h>
#include <xeno/blkdev.h>
#include <xeno/keyhandler.h>
#include <asm/current.h>
#include <asm/domain_page.h>

/* Global list of all possible vbds.  This can be changed in
   the following way:

   1) UNUSED vbd -> RO or RW vbd.  This requires the spinlock.

   2) RO or RW -> UNUSED.  This requires the lock and can only happen
   during process teardown.

   This means that processes can access entries in the list safely
   without having to hold any lock at all: they already have an entry
   allocated, and we know that entry can't become unused, as vbds
   are only torn down when the domain is dieing, by which point it
   can't be accessing them anymore. */
static vbd_t xvbds[XEN_MAX_VBDS];
static spinlock_t xvbd_lock = SPIN_LOCK_UNLOCKED;

#if 0
#define DPRINTK(_f, _a...) printk( _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

/*
 * xen_vbd_map_request
 *
 * xen_device must be a valid device.
 * 
 * NB. All offsets and sizes here are in sector units.
 * eg. 'size == 1' means an actual size of 512 bytes.
 *
 * Note that no locking is performed here whatsoever --
 * we rely on the fact that once vbd information is
 * established, it is only modified by domain shutdown,
 * and so if this is being called, noone is trying
 * to modify the vbd list.
 */
int xen_vbd_map_request(
    phys_seg_t *pseg, struct task_struct *p, int operation,
    unsigned short vbd_number,
    unsigned long sect_nr, unsigned long buffer, unsigned short nr_sects)
{
    vbd_t *seg;
    extent_t  *ext;
    int sum, i;

    vbd_number &= XENDEV_IDX_MASK;
    if ( vbd_number >= XEN_MAX_VBDS )
    {
        DPRINTK("invalid vbd number. %d %d\n",
                vbd_number, XEN_MAX_VBDS);
        goto fail;
    }

    seg = p->vbd_list[vbd_number];
    if ( seg == NULL ) 
    {
        DPRINTK("vbd is null. %d\n", vbd_number);
        goto fail;
    }

    /* check domain permissions */
    if ( seg->domain != p->domain )
    {
        DPRINTK("seg is for another domain. %d %d\n", seg->domain, p->domain);
        goto fail;
    }

    /* check rw access */
    if ( ((operation == WRITE) && (seg->mode != XEN_VBD_RW)) ||
         ((operation == READ)  && (seg->mode == XEN_VBD_UNUSED)) )
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
    while ( (i < seg->num_extents) && ((sum + ext->nr_sectors) <= sect_nr) )
    {
        sum += ext->nr_sectors;
        ext++; i++;
    }

    if ( (sum + ext->nr_sectors) <= sect_nr ) 
    {
        DPRINTK("extent size mismatch: %d %d : %d %ld %ld\n",
                i, seg->num_extents, sum, ext->nr_sectors, sect_nr);
        goto fail;
    }

    pseg->sector_number = (sect_nr - sum) + ext->start_sector;
    pseg->buffer        = buffer;
    pseg->nr_sects      = nr_sects;
    pseg->dev           = xendev_to_physdev(ext->raw_device);
    if ( pseg->dev == 0 ) 
    {
        DPRINTK ("invalid device 0x%x 0x%lx 0x%lx\n", 
                 ext->raw_device, ext->start_sector, ext->nr_sectors);
        goto fail;
    }

    /* We're finished if the virtual extent didn't overrun the phys extent. */
    if ( (sum + ext->nr_sectors) >= (sect_nr + nr_sects) )
        return 1;                         /* entire read fits in this extent */

    /* Hmmm... make sure there's another extent to overrun onto! */
    if ( (i+1) == seg->num_extents ) 
    {
        DPRINTK ("not enough extents %d %d\n",
                 i, seg->num_extents);
        goto fail;
    }

    pseg[1].nr_sects = (sect_nr + nr_sects) - (sum + ext->nr_sectors);
    pseg[0].nr_sects = sum + ext->nr_sectors - sect_nr;
    pseg[1].buffer = buffer + (pseg->nr_sects << 9);
    pseg[1].sector_number = ext[1].start_sector;
    pseg[1].dev = xendev_to_physdev(ext[1].raw_device);
    if ( pseg[1].dev == 0 ) 
    {
        DPRINTK ("bogus device for pseg[1] \n");
        goto fail;
    }

    /* We don't allow overrun onto a third physical extent. */
    if ( pseg[1].nr_sects > ext[1].nr_sectors )
    {
        DPRINTK ("third extent\n");
        DPRINTK (" sum:%d, e0:%ld, e1:%ld   p1.sect:%ld p1.nr:%d\n",
                 sum, ext[0].nr_sectors, ext[1].nr_sectors, 
                 pseg[1].sector_number, pseg[1].nr_sects);
        goto fail;    
    }

    return 2;                   /* We overran onto a second physical extent. */

 fail:
    DPRINTK ("xen_vbd_map_request failure\n");
    DPRINTK ("operation: %d\n", operation);
    DPRINTK ("vbd number: %d\n", vbd_number);
    DPRINTK ("sect_nr: %ld 0x%lx\n", sect_nr, sect_nr);
    DPRINTK ("nr_sects: %d 0x%x\n", nr_sects, nr_sects);
    return -1;
}

/*
 * vbd_probe_devices: 
 *
 * add the virtual block devices for this domain to a xen_disk_info_t; 
 * we assume xdi->count points to the first unused place in the array. 
 */
void vbd_probe_devices(xen_disk_info_t *xdi, struct task_struct *p)
{
    int loop, i;
    unsigned long capacity = 0, device;

    spin_lock(&xvbd_lock);
    for (loop = 0; loop < XEN_MAX_VBDS; loop++ )
    {
        if ( (xvbds[loop].mode == XEN_VBD_UNUSED) ||
             (xvbds[loop].domain != p->domain) )
            continue;

        device = MK_VIRTUAL_XENDEV(xvbds[loop].vbd_number);
        for ( i = 0; i < xvbds[loop].num_extents; i++ )
            capacity += xvbds[loop].extents[i].nr_sectors;

        xdi->disks[xdi->count].device   = device;
        xdi->disks[xdi->count].capacity = capacity;
        xdi->count++;
    }
    spin_unlock(&xvbd_lock);
    return;
}

/*
 * xen_refresh_vbd_list
 *
 * find all vbds associated with a domain and assign
 * them to the domain
 *
 */
void xen_refresh_vbd_list (struct task_struct *p)
{
    int loop;

    spin_lock(&xvbd_lock);
    for (loop = 0; loop < XEN_MAX_VBDS; loop++)
    {
        if ( (xvbds[loop].mode == XEN_VBD_UNUSED) ||
             (xvbds[loop].domain != p->domain) )
            continue;

        p->vbd_list[xvbds[loop].vbd_number] = &xvbds[loop];
    }
    spin_unlock(&xvbd_lock);
}

/*
 * create a new vbd for a domain
 *
 * return 0 on success, 1 on failure
 *
 * if we see the same DOM#/SEG# combination, we reuse the slot in
 * the vbd table (overwriting what was there before).
 * an alternative would be to raise an error if the slot is reused.
 */
int xen_vbd_create(xv_disk_t *xvd_in)
{
    int idx;
    int loop;
    xv_disk_t *xvd = map_domain_mem(virt_to_phys(xvd_in));
    struct task_struct *p;

    spin_lock(&xvbd_lock);
    for (idx = 0; idx < XEN_MAX_VBDS; idx++)
    {
        if (xvbds[idx].mode == XEN_VBD_UNUSED ||
            (xvbds[idx].domain == xvd->domain &&
             xvbds[idx].vbd_number == xvd->vbd)) break;
    }
    if (idx == XEN_MAX_VBDS)
    {
        printk (KERN_ALERT "xen_vbd_create: unable to find free slot\n");
        unmap_domain_mem(xvd);
        return 1;
    }

    xvbds[idx].mode = xvd->mode;
    xvbds[idx].domain = xvd->domain;
    xvbds[idx].vbd_number = xvd->vbd;
    memcpy(xvbds[idx].key, xvd->key, XEN_VBD_KEYSIZE);
    xvbds[idx].num_extents = xvd->ext_count;


    if (xvbds[idx].extents)
	kfree(xvbds[idx].extents);    
    xvbds[idx].extents = (extent_t *)kmalloc(
        sizeof(extent_t)*xvd->ext_count,
        GFP_KERNEL);
 
    /* could memcpy, but this is safer */
    for (loop = 0; loop < xvd->ext_count; loop++)
    {
        xvbds[idx].extents[loop].raw_device = xvd->extents[loop].disk; 
        xvbds[idx].extents[loop].start_sector = 
	    xvd->extents[loop].offset;
        xvbds[idx].extents[loop].nr_sectors = xvd->extents[loop].size;
        if (xvbds[idx].extents[loop].nr_sectors == 0) 
        {
            printk("xen_vbd_create: extent %d is zero length\n", loop);
            unmap_domain_mem(xvd);
            return 1;
        }
    }

    /* if the domain exists, assign the vbd to the domain */
    p = find_domain_by_id(xvd->domain);
    if (p != NULL)
    {
        p->vbd_list[xvd->vbd] = &xvbds[idx];
        put_task_struct(p);
    }

    spin_unlock(&xvbd_lock);

    unmap_domain_mem(xvd);
    return 0;
}

/*
 * delete a vbd from a domain
 *
 * return 0 on success, 1 on failure
 *
 * This should *only* be called from domain shutdown, or else we
 * race with access checking.
 */
int xen_vbd_delete(struct task_struct *p, int segnr)
{
    vbd_t *seg;

    if (!p) {
	printk("xen_vbd delete called with NULL domain?\n");
	BUG();
	return 1;
    }

    if (segnr < 0 || segnr > XEN_MAX_VBDS) {
	printk("xen_vbd_delete called with bad segnr?\n");
	BUG();
	return 1;
    }

    if (!p->vbd_list[segnr])
	return 1;

    seg = p->vbd_list[segnr];

    /* sanity checking */
    if (seg->domain != p->domain || seg->vbd_number != segnr ||
	(seg->mode != XEN_VBD_RO && seg->mode != XEN_VBD_RW) ||
	seg->num_extents <= 0 || seg->extents == NULL) {
	printk("vbd is insane!\n");
	BUG();
	return 1;
    }

    spin_lock(&xvbd_lock);

    p->vbd_list[segnr] = NULL;
    seg->domain = -1;
    seg->vbd_number = -1;
    kfree(seg->extents);
    seg->mode = XEN_VBD_UNUSED;

    spin_unlock(&xvbd_lock);

    return 0;
}

static void dump_vbds(u_char key, void *dev_id, struct pt_regs *regs) 
{
    int loop, i;
    struct task_struct *p;

    printk("vbd list\n");
    for (loop = 0; loop < XEN_MAX_VBDS; loop++)
    {
        if (xvbds[loop].mode != XEN_VBD_UNUSED)
        {
            printk(" %2d: %s dom%d, seg# %d, num_exts: %d\n",
                   loop, 
                   xvbds[loop].mode == XEN_VBD_RO ? "RO" : "RW",
                   xvbds[loop].domain, xvbds[loop].vbd_number,
                   xvbds[loop].num_extents);
            for (i = 0; i < xvbds[loop].num_extents; i++)
            {
                printk("     extent %d: raw device 0x%x, start_sector 0x%lx"
		       " nr_sectors 0x%lx\n",
                       i, xvbds[loop].extents[i].raw_device,
                       xvbds[loop].extents[i].start_sector,
                       xvbds[loop].extents[i].nr_sectors);
            } 
        }
    }

    printk("vbds by domain (index into vbds list)\n");
    p = current;
    do
    {
	if(is_idle_task(p))
	    continue; 

        printk("  domain %d: ", p->domain);
        for (loop = 0; loop < XEN_MAX_VBDS; loop++)
        {
            if (p->vbd_list[loop])
            {
                printk (" %d", p->vbd_list[loop] - xvbds);
            }
        }
        printk("\n");
        p = p->next_task;
    } while (p != current);
}

/*
 * initialize vbds
 */

void xen_vbd_initialize(void)
{
    memset (xvbds, 0, sizeof(xvbds));

    add_key_handler('S', dump_vbds, "dump vbds");
}


/* The idea is that, for each sector of each disk, each domain has two
   bits, saying whether they can read the sector or write it.  That
   would take too much memory, so instead each process has a list of
   (device, start, end, mode) quads which say what it has access to,
   and we fake the logical view on top of that. */
struct physdisk_ace {
    struct list_head list;
    unsigned short device;
    unsigned short partition;
    unsigned long start_sect;
    unsigned long n_sectors;
    int mode;
};


/* Operation is a blkdev constant i.e. READ, WRITE, ... */
/* Must be called with p->physdev_lock held. */
static struct physdisk_ace *find_ace(const struct task_struct *p,
                     unsigned short dev,
                     unsigned long sect, int operation)
{
    struct list_head *cur_ace_head;
    struct physdisk_ace *cur_ace;

    list_for_each(cur_ace_head, &p->physdisk_aces)
    {
    cur_ace = list_entry(cur_ace_head, struct physdisk_ace, list);
    DPRINTK("Is [%lx, %lx) good for %lx?\n",
        cur_ace->start_sect,
        cur_ace->start_sect + cur_ace->n_sectors, sect);
    if ( (sect >= cur_ace->start_sect) &&
         (sect < (cur_ace->start_sect + cur_ace->n_sectors)) &&
             (dev == cur_ace->device) &&
             (((operation == READ) && (cur_ace->mode & PHYSDISK_MODE_R)) ||
              ((operation == WRITE) && (cur_ace->mode & PHYSDISK_MODE_W))) )
        return cur_ace;
    }
    return NULL;
}

/* Hold the lock on entry, it remains held on exit. */
static void xen_physdisk_revoke_access(unsigned short dev,
                       unsigned long start_sect,
                       unsigned long n_sectors,
                       struct task_struct *p)
{
    /* Find every ace which intersects [start_sect, start_sect +
       n_sectors] and either remove it completely or truncate it
       down. */
    struct list_head *cur_ace_head;
    struct physdisk_ace *cur_ace, *new_ace;
    unsigned long kill_zone_end, ace_end;

    kill_zone_end = start_sect + n_sectors;
    list_for_each(cur_ace_head, &p->physdisk_aces) 
    {
	cur_ace = list_entry(cur_ace_head, struct physdisk_ace, list);
	ace_end = cur_ace->start_sect + cur_ace->n_sectors;
	if ( (cur_ace->start_sect >= kill_zone_end) ||
             (ace_end <= start_sect) || 
             (cur_ace->device != dev) )
	    continue;

	DPRINTK("Killing ace [%lx, %lx) against kill zone [%lx, %lx)\n",
		cur_ace->start_sect, ace_end, start_sect, kill_zone_end);

	if ( (cur_ace->start_sect >= start_sect) && 
             (ace_end <= kill_zone_end) )
        {
	    /* ace entirely within kill zone -> kill it */
	    list_del(cur_ace_head);
	    cur_ace_head = cur_ace_head->prev;
	    kfree(cur_ace);
	} 
        else if ( ace_end <= kill_zone_end )
        {
	    /* ace start before kill start, ace end in kill zone, 
	       move ace end. */
	    cur_ace->n_sectors = start_sect - cur_ace->start_sect;
	} 
        else if ( cur_ace->start_sect >= start_sect )
        {
	    /* ace start after kill start, ace end outside kill zone,
	       move ace start. */
	    cur_ace->start_sect = kill_zone_end;
	    cur_ace->n_sectors = ace_end - cur_ace->start_sect;
	} 
        else 
        {
	    /* The fun one: the ace entirely includes the kill zone. */
	    /* Cut the current ace down to just the bit before the kzone,
	       create a new ace for the bit just after it. */
	    new_ace = kmalloc(sizeof(*cur_ace), GFP_KERNEL);
	    new_ace->device = dev;
	    new_ace->start_sect = kill_zone_end;
	    new_ace->n_sectors = ace_end - kill_zone_end;
	    new_ace->mode = cur_ace->mode;

	    cur_ace->n_sectors = start_sect - cur_ace->start_sect;

	    list_add(&new_ace->list, cur_ace_head);
	}
    }
}

/* Hold the lock on entry, it remains held on exit. */
static int xen_physdisk_grant_access(unsigned short dev,
				     unsigned short partition,
				     unsigned long start_sect,
				     unsigned long n_sectors,
				     int mode, struct task_struct *p)
{
    struct physdisk_ace *cur_ace;

    /* Make sure it won't overlap with any existing ACEs. */
    /* XXX this isn't quite right if the domain already has read access
       and we try to grant write access, or vice versa. */
    xen_physdisk_revoke_access(dev, start_sect, n_sectors, p);

    if ( mode ) 
    {
	cur_ace = kmalloc(sizeof(*cur_ace), GFP_KERNEL);
	cur_ace->device = dev;
	cur_ace->start_sect = start_sect;
	cur_ace->n_sectors = n_sectors;
	cur_ace->mode = mode;
	cur_ace->partition = partition;

	list_add_tail(&cur_ace->list, &p->physdisk_aces);
    }

    return 0;
}

static void xen_physdisk_probe_access(physdisk_probebuf_t * buf,
				      struct task_struct *p)
{
    int n_aces;
    struct list_head *cur_ace_head;
    struct physdisk_ace *cur_ace;
    int x = 0;

    n_aces = 0;
    list_for_each(cur_ace_head, &p->physdisk_aces) 
    {
	x++;
	if ( x >= buf->start_ind ) 
        {
	    cur_ace = list_entry(cur_ace_head, struct physdisk_ace, list);
	    buf->entries[n_aces].device = cur_ace->device;
	    buf->entries[n_aces].partition = cur_ace->partition;
	    buf->entries[n_aces].start_sect = cur_ace->start_sect;
	    buf->entries[n_aces].n_sectors = cur_ace->n_sectors;
	    buf->entries[n_aces].mode = cur_ace->mode;
	    n_aces++;
	}
    }
    buf->n_aces = n_aces;
}

int xen_physdisk_grant(xp_disk_t * xpd_in)
{
    struct task_struct *p = current;
    xp_disk_t *xpd = map_domain_mem(virt_to_phys(xpd_in));
    int res;

    p = find_domain_by_id(xpd->domain);
    if ( p == NULL )
    {
	DPRINTK("Bad domain!\n");
	res = 1;
	goto out;
    }

    spin_lock(&p->physdev_lock);
    res = xen_physdisk_grant_access(xpd->device,
				    xpd->partition,
				    xpd->start_sect,
				    xpd->n_sectors, xpd->mode, p);
    spin_unlock(&p->physdev_lock);
    put_task_struct(p);

  out:
    unmap_domain_mem(xpd);
    return res;
}

int xen_physdisk_probe(struct task_struct *requesting_domain,
		       physdisk_probebuf_t * buf_in)
{
    struct task_struct *p;
    physdisk_probebuf_t *buf = map_domain_mem(virt_to_phys(buf_in));
    int res;

    if ( (requesting_domain->domain != 0) &&
	 (requesting_domain->domain != buf->domain) )
    {
	res = 1;
	goto out;
    }

    p = find_domain_by_id(buf->domain);
    if ( p == NULL )
    {
	res = 1;
	goto out;
    }

    spin_lock(&p->physdev_lock);
    xen_physdisk_probe_access(buf, p);
    spin_unlock(&p->physdev_lock);
    put_task_struct(p);

    res = 0;
  out:
    unmap_domain_mem(buf);
    return res;
}

#define MAX(a,b) ((a) > (b) ? (a) : (b))

int xen_physdisk_access_okay(phys_seg_t * pseg, struct task_struct *p,
			     int operation)
{
    struct physdisk_ace *cur_ace;
    unsigned long sect;

    DPRINTK
	("Checking access for domain %d, start sect 0x%lx, length 0x%x.\n",
	 p->domain, pseg->sector_number, pseg->nr_sects);

    for ( sect = pseg->sector_number;
	  sect < pseg->sector_number + pseg->nr_sects; ) 
    {
	/* XXX this would be a lot faster if the aces were sorted on start
	   address.  Also in revoke_access. */
	spin_lock(&p->physdev_lock);
	cur_ace = find_ace(p, pseg->dev, sect, operation);
	spin_unlock(&p->physdev_lock);
	if ( cur_ace == NULL )
	    return 0;
	sect +=
	    MAX(cur_ace->n_sectors,
		pseg->nr_sects + pseg->sector_number - sect);
    }
    return 1;
}

void destroy_physdisk_aces(struct task_struct *p)
{
    struct list_head *cur_ace_head, *next_head;
    struct physdisk_ace *cur_ace;

    for ( cur_ace_head = p->physdisk_aces.next;
          cur_ace_head != &p->physdisk_aces; 
          cur_ace_head = next_head )
    {
	cur_ace = list_entry(cur_ace_head, struct physdisk_ace, list);
	next_head = cur_ace_head->next;
	kfree(cur_ace);
    }
}

