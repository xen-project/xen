#ifndef __HYP_IFS_VBD_H__
#define __HYP_IFS_VBD_H__

#define XEN_MAX_VBDS 100     /* total number of vbds across all doms */

#define XEN_VBD_UNUSED 0          /* bzero default */
#define XEN_DISK_READ_WRITE  1
#define XEN_DISK_READ_ONLY   2
#define XEN_VBD_RO XEN_DISK_READ_ONLY
#define XEN_VBD_RW XEN_DISK_READ_WRITE

/*
 *
 * virtual disk (vhd) structures, used by XEN_BLOCK_VBD_{CREATE, DELETE}
 *
 */

typedef struct xv_extent
{
  int disk;                                          /* physical disk number */
  unsigned long offset;               /* offset in blocks into physical disk */
  unsigned long size;                                      /* size in blocks */
} xv_extent_t;

#define XEN_VBD_KEYSIZE 10

typedef struct xv_disk
{
  int mode;                     /* XEN_DISK_READ_WRITE or XEN_DISK_READ_ONLY */
  int domain;                   /* domain */
  int vbd;                      /* segment number */
  char key[XEN_VBD_KEYSIZE];    /* key for benefit of dom0 userspace */
  int ext_count;                /* number of xv_extent_t to follow */
  xv_extent_t extents[XEN_MAX_DISK_COUNT];    /* arbitrary reuse of constant */
} xv_disk_t;

#define PHYSDISK_MODE_R 1
#define PHYSDISK_MODE_W 2
typedef struct xp_disk
{
  int mode; /* 0 -> revoke existing access, otherwise bitmask of
	       PHYSDISK_MODE_? constants */
  int domain;
  unsigned short device; /* XENDEV_??? + idx */
  unsigned short partition; /* partition number */
  unsigned long start_sect;
  unsigned long n_sectors;
} xp_disk_t;

#define PHYSDISK_MAX_ACES_PER_REQUEST 254 /* Make it fit in one page */
typedef struct {
  int n_aces;
  int domain;
  int start_ind;
  struct {
    unsigned short device; /* XENDEV_??? + idx */
    unsigned short partition; /* partition number */
    unsigned long start_sect;
    unsigned long n_sectors;
    unsigned mode;
  } entries[PHYSDISK_MAX_ACES_PER_REQUEST];
} physdisk_probebuf_t;


typedef struct xen_vbd_info
{
    int count;
    struct {
        unsigned domain;
        unsigned seg_nr;
        char key[XEN_VBD_KEYSIZE];
        unsigned short mode;             /* UNUSED, RO, or RW. */
    } vbds[XEN_MAX_VBDS];
} xen_vbd_info_t;



/* Block I/O trap operations and associated structures.
 */

#define BLOCK_IO_OP_SIGNAL      0    // let xen know we have work to do 
#define BLOCK_IO_OP_ATTACH_VBD  1    // attach a VBD to a given domain 


typedef struct _extent { 
    u16       raw_device; 
    ulong     start_sector; 
    ulong     nr_sectors;
} extent_t; 

    
typedef struct _vbd_attach { 
    int       domain; 
    u16       mode;                     // read-only or read-write 
    u16       device;                   // how this domain refers to this VBD
    int       nr_extents;               // number of extents in the VBD
    extent_t *extents;                  // pointer to /array/ of extents 
} vbd_attach_t; 


typedef struct block_io_op_st
{
    unsigned long cmd;
    union
    {
        long         signal_val_unused; 
	vbd_attach_t attach_info; 
    }
    u;
} block_io_op_t;




#endif /* __HYP_IFS_VBD_H__ */
