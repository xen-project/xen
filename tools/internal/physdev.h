#define XEN_BLOCK_PHYSDEV_GRANT 10 /* grant access to range of disk blocks */
#define XEN_BLOCK_PHYSDEV_PROBE 11 /* probe for a domain's physdev
				      accesses */

#define PHYSDISK_MODE_R 1
#define PHYSDISK_MODE_W 2
typedef struct xp_disk
{
  int mode; /* PHYSDISK_MODEs or 0 for revoke. */
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
