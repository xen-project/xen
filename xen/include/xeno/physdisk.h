#ifndef PHYSDISK_ACES__
#define PHYSDISK_ACES__

struct task_struct;

void destroy_physdisk_aces(struct task_struct *p);

int xen_physdisk_grant(xp_disk_t *);
int xen_physdisk_probe(physdisk_probebuf_t *);
int xen_physdisk_access_okay(phys_seg_t *pseg, struct task_struct *p,
			     int operation);

#endif /* PHYSDISK_ACES__ */
