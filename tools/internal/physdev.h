#define XEN_BLOCK_PHYSDEV_GRANT 10 /* grant access to range of disk blocks */
#define XEN_BLOCK_PHYSDEV_REVOKE 11 /* revoke access to range of disk blocks */
#define XEN_BLOCK_PHYSDEV_PROBE 12 /* probe for a domain's physdev
				      accesses */

typedef struct xp_disk
{
  int mode;
  int domain;
  unsigned short device;
  unsigned long start_sect;
  unsigned long n_sectors;
} xp_disk_t;

#define PHYSDISK_MAX_ACES_PER_REQUEST 254
typedef struct {
  int n_aces;
  int domain;
  int start_ind;
  struct {
    unsigned short device;
    unsigned long start_sect;
    unsigned long n_sectors;
    unsigned mode;
  } entries[PHYSDISK_MAX_ACES_PER_REQUEST];
} physdisk_probebuf_t;
