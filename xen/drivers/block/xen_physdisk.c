#include <xeno/sched.h>
#include <xeno/list.h>
#include <xeno/blkdev.h>
#include <xeno/sched.h>
#include <xeno/slab.h>
#include <asm/domain_page.h>
#include <asm/io.h>
#include <xeno/segment.h>
#include <xeno/physdisk.h>

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#if 0
#define DPRINTK printk
#else
#define DPRINTK(...)
#endif

/* The idea is that, for each sector of each disk, each domain has two
   bits, saying whether they can read the sector or write it.  That
   would take too much memory, so instead each process has a list of
   (device, start, end, mode) quads which say what it has access to,
   and we fake the logical view on top of that. */
struct physdisk_ace {
  struct list_head list;

  unsigned short device;
  unsigned long start_sect;
  unsigned long n_sectors;
  int mode;
};

/* Operation is a blkdev constant i.e. READ, WRITE, ... */
/* Must be called with p->physdev_lock held. */
static struct physdisk_ace *find_ace(const struct task_struct *p,
				     unsigned short dev,
				     unsigned long sect,
				     int operation)
{
  struct list_head *cur_ace_head;
  struct physdisk_ace *cur_ace;

  dev &= ~0x1f; /* ignore the partition part */

  list_for_each(cur_ace_head, &p->physdisk_aces) {
    cur_ace = list_entry(cur_ace_head, struct physdisk_ace,
			 list);
    DPRINTK("Is [%lx, %lx) good for %lx?\n",
	    cur_ace->start_sect, cur_ace->start_sect + cur_ace->n_sectors,
	    sect);
    if (sect >= cur_ace->start_sect &&
	sect < cur_ace->start_sect + cur_ace->n_sectors &&
	dev == (cur_ace->device & ~0x1f) && /* ignore partition part */
	((operation == READ && (cur_ace->mode & PHYSDISK_MODE_R)) ||
	 (operation == WRITE && (cur_ace->mode & PHYSDISK_MODE_W)))) {
      DPRINTK("Yes.\n");
      return cur_ace;
    } else {
      DPRINTK("No.\n");
    }
  }
  return NULL;
}

/* Hold the lock on entry, it remains held on exit. */
/* XXX we call kmalloc and kfree with GFP_KERNEL and a spinlock held
   in here.  That wouldn't be allowed under Linux, but, from reading
   the source, it seems to be okay under Xen... */
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
  list_for_each(cur_ace_head, &p->physdisk_aces) {
    cur_ace = list_entry(cur_ace_head, struct physdisk_ace,
			 list);
    ace_end = cur_ace->start_sect + cur_ace->n_sectors;
    if (cur_ace->start_sect >= kill_zone_end ||
	ace_end <= start_sect ||
	(cur_ace->device & ~0x1f) != (dev & ~0x1f))
      continue;
    
    DPRINTK("Killing ace [%lx, %lx) against kill zone [%lx, %lx)\n",
	    cur_ace->start_sect, ace_end, start_sect, kill_zone_end);

    if (cur_ace->start_sect >= start_sect &&
	ace_end <= kill_zone_end) {
      /* ace entirely within kill zone -> kill it */
      list_del(cur_ace_head);
      cur_ace_head = cur_ace_head->prev;
      kfree(cur_ace);
    } else if (ace_end <= kill_zone_end) {
      /* ace start before kill start, ace end in kill zone, 
	 move ace end. */
      cur_ace->n_sectors = start_sect - cur_ace->start_sect;
    } else if (cur_ace->start_sect >= start_sect) {
      /* ace start after kill start, ace end outside kill zone,
	 move ace start. */
      cur_ace->start_sect = kill_zone_end;
      cur_ace->n_sectors = ace_end - cur_ace->start_sect;
    } else {
      /* The fun one: the ace entirely includes the kill zone. */
      /* Cut the current ace down to just the bit before the kzone,
	 create a new ace for the bit just after it. */ 
      new_ace = kmalloc(sizeof(*cur_ace), GFP_KERNEL);
      new_ace->device = dev & ~0x1f;
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
				     unsigned long start_sect,
				     unsigned long n_sectors,
				     int mode,
				     struct task_struct *p)
{
  struct physdisk_ace *cur_ace;

  /* Make sure it won't overlap with any existing ACEs. */
  /* XXX this isn't quite right if the domain already has read access
     and we try to grant write access, or vice versa. */
  xen_physdisk_revoke_access(dev, start_sect, n_sectors, p);
  
  if (mode) {
    cur_ace = kmalloc(sizeof(*cur_ace), GFP_KERNEL);
    cur_ace->device = dev;
    cur_ace->start_sect = start_sect;
    cur_ace->n_sectors = n_sectors;
    cur_ace->mode = mode;

    list_add_tail(&cur_ace->list, &p->physdisk_aces);
  }

  return 0;
}

static void xen_physdisk_probe_access(physdisk_probebuf_t *buf,
				      struct task_struct *p)
{
  int max_aces;
  int n_aces;
  struct list_head *cur_ace_head;
  struct physdisk_ace *cur_ace;
  int x = 0;

  max_aces = buf->n_aces;
  n_aces = 0;
  list_for_each(cur_ace_head, &p->physdisk_aces) {
    x++;
    if (x >= buf->start_ind) {
      cur_ace = list_entry(cur_ace_head, struct physdisk_ace,
			   list);
      buf->entries[n_aces].device = cur_ace->device;
      buf->entries[n_aces].start_sect = cur_ace->start_sect;
      buf->entries[n_aces].n_sectors = cur_ace->n_sectors;
      buf->entries[n_aces].mode = cur_ace->mode;
      n_aces++;
      if (n_aces >= max_aces)
	break;
    }
  }
  buf->n_aces = n_aces;
}

int xen_physdisk_grant(xp_disk_t *xpd_in)
{
  struct task_struct *p;
  xp_disk_t *xpd = map_domain_mem(virt_to_phys(xpd_in));
  int res;

  p = current;
  DPRINTK("Have current.\n");
  DPRINTK("Target domain %x\n", xpd->domain);

  do {
    p = p->next_task;
  } while (p != current && p->domain != xpd->domain);
  if (p->domain != xpd->domain) {
    DPRINTK("Bad domain!\n");
    res = 1;
    goto out;
  }
  spin_lock(&p->physdev_lock);
  res = xen_physdisk_grant_access(xpd->device,
				  xpd->start_sect,
				  xpd->n_sectors,
				  xpd->mode,
				  p);
  spin_unlock(&p->physdev_lock);

 out:
  unmap_domain_mem(xpd);
  return res;
}

int xen_physdisk_probe(struct task_struct *requesting_domain,
		       physdisk_probebuf_t *buf_in)
{
  struct task_struct *p;
  physdisk_probebuf_t *buf = map_domain_mem(virt_to_phys(buf_in));
  int res;

  p = current;
  do {
    p = p->next_task;
  } while (p != current && p->domain != buf->domain);  
  if (p->domain != buf->domain) {
    res = 1;
    goto out;
  }
  if (requesting_domain->domain != 0 &&
      requesting_domain->domain != buf->domain) {
    res = 1;
    goto out;
  }

  spin_lock(&p->physdev_lock);
  xen_physdisk_probe_access(buf, p);
  spin_unlock(&p->physdev_lock);
  res = 0;
 out:
  unmap_domain_mem(buf);
  return res;
}

int xen_physdisk_access_okay(phys_seg_t *pseg, struct task_struct *p,
			     int operation)
{
  struct physdisk_ace *cur_ace;
  unsigned long sect;

  DPRINTK("Checking access for domain %d, start sect 0x%lx, length 0x%x.\n",
	  p->domain, pseg->sector_number, pseg->nr_sects);

  for (sect = pseg->sector_number;
       sect < pseg->sector_number + pseg->nr_sects;
       ) {
    /* XXX this would be a lot faster if the aces were sorted on start
       address.  Also in revoke_access. */
    spin_lock(&p->physdev_lock);
    cur_ace = find_ace(p, pseg->dev, sect, operation);
    spin_unlock(&p->physdev_lock);
    if (!cur_ace) {
      /* Default closed. */
      return 0;
    }
    sect += MAX(cur_ace->n_sectors, pseg->nr_sects + pseg->sector_number - sect);
  }
  return 1;
}

void destroy_physdisk_aces(struct task_struct *p)
{
  struct list_head *cur_ace_head, *next_head;
  struct physdisk_ace *cur_ace;

  spin_lock(&p->physdev_lock); /* We never release this again. */

  for (cur_ace_head = p->physdisk_aces.next;
       cur_ace_head != &p->physdisk_aces;
       cur_ace_head = next_head) {
    cur_ace = list_entry(cur_ace_head, struct physdisk_ace,
			 list);
    next_head = cur_ace_head->next;
    kfree(cur_ace);
  }
}
